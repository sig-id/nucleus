//! Built-in loopback forwarder for broker-socket mode.
//!
//! The workload talks TCP to a listener on loopback inside its network
//! namespace; the supervisor relays each connection to the host broker
//! socket. The host socket is never mounted into the container, so the
//! single-socket boundary holds without Landlock's unix-socket scoping.
//!
//! The container child creates the listener after raising loopback in its
//! new network namespace and hands the descriptor to the supervisor over a
//! unix socket pair (the socket-activation pattern). A listening socket
//! keeps the namespace it was created in, so the supervisor accepts from
//! the host side without joining the namespace.

use crate::error::{NucleusError, Result};
use crate::filesystem::BrokerSocket;
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::thread;
use tracing::{debug, info, warn};

/// Upper bound on relayed connections open at once.
const MAX_CONNECTIONS: usize = 256;

/// Container side: bind the workload-facing listener in the current
/// network namespace and send it to the supervisor.
pub(crate) fn bind_and_send(addr: SocketAddr, channel: &UnixStream) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| {
        NucleusError::NetworkError(format!("Cannot listen on broker proxy address {addr}: {e}"))
    })?;
    let fds = [listener.as_raw_fd()];
    sendmsg::<()>(
        channel.as_raw_fd(),
        &[IoSlice::new(b"L")],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .map_err(|e| NucleusError::NetworkError(format!("Cannot hand over broker listener: {e}")))?;
    // The supervisor owns the listener now; the workload must not inherit it.
    drop(listener);
    Ok(())
}

/// Supervisor side: receive the listener sent by [`bind_and_send`].
pub(crate) fn receive(channel: &UnixStream) -> Result<TcpListener> {
    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut space = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    let msg = recvmsg::<()>(
        channel.as_raw_fd(),
        &mut iov,
        Some(&mut space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|e| NucleusError::NetworkError(format!("Cannot receive broker listener: {e}")))?;
    let mut fds = msg.cmsgs().map_err(|e| {
        NucleusError::NetworkError(format!("Malformed broker listener handoff: {e}"))
    })?;
    let fd = fds
        .find_map(|cmsg| match cmsg {
            ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
            _ => None,
        })
        .ok_or_else(|| {
            NucleusError::NetworkError(
                "Container setup ended before handing over the broker listener".into(),
            )
        })?;
    // SAFETY: SCM_RIGHTS installed `fd` in this process; nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let listener = TcpListener::from(fd);
    // A listener has a local address; anything else is not what was sent.
    listener.local_addr().map_err(|e| {
        NucleusError::NetworkError(format!("Broker listener handoff is not a TCP socket: {e}"))
    })?;
    Ok(listener)
}

/// Accept connections on `listener` and relay each one to `broker` until the
/// supervisor exits.
pub(crate) fn spawn(listener: TcpListener, broker: &BrokerSocket) -> Result<()> {
    // Connect through the inode verified at launch, never by path.
    let pinned = broker.pin()?;
    let local = listener.local_addr()?;
    let host_path = broker.host_path().to_path_buf();
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    thread::Builder::new()
        .name("broker-forward".into())
        .spawn(move || {
            let target = format!("/proc/self/fd/{}", pinned.as_raw_fd());
            for stream in listener.incoming() {
                let client = match stream {
                    Ok(client) => client,
                    Err(e) => {
                        warn!("Broker forwarder accept failed: {e}");
                        continue;
                    }
                };
                if active.load(std::sync::atomic::Ordering::Acquire) >= MAX_CONNECTIONS {
                    warn!("Broker forwarder at {MAX_CONNECTIONS} connections; refusing one");
                    continue;
                }
                let upstream = match UnixStream::connect(&target) {
                    Ok(upstream) => upstream,
                    Err(e) => {
                        warn!("Cannot connect to broker socket {host_path:?}: {e}");
                        continue;
                    }
                };
                let active = active.clone();
                active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                if let Err(e) = relay(client, upstream, active.clone()) {
                    active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    warn!("Broker forwarder cannot relay a connection: {e}");
                }
            }
        })
        .map_err(|e| NucleusError::NetworkError(format!("Cannot start broker forwarder: {e}")))?;
    info!("Broker forwarder listening on {local} inside the container");
    Ok(())
}

/// Copy both directions of one connection on two threads, propagating
/// half-closes so request/response protocols see end-of-file.
fn relay(
    client: TcpStream,
    upstream: UnixStream,
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> std::io::Result<()> {
    let client_read = client.try_clone()?;
    let upstream_write = upstream.try_clone()?;
    thread::Builder::new()
        .name("broker-up".into())
        .spawn(move || {
            let (mut from, mut to) = (client_read, upstream_write);
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
        })?;
    thread::Builder::new()
        .name("broker-down".into())
        .spawn(move || {
            let (mut from, mut to) = (upstream, client);
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
            debug!("Broker connection closed");
            active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn listener_handoff_and_relay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        let broker_listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let broker = BrokerSocket::verify(&socket_path).unwrap();

        let (supervisor, container) = UnixStream::pair().unwrap();
        bind_and_send("127.0.0.1:0".parse().unwrap(), &container).unwrap();
        let listener = receive(&supervisor).unwrap();
        let addr = listener.local_addr().unwrap();
        spawn(listener, &broker).unwrap();

        // Echo server standing in for the broker: reads to EOF, answers.
        let server = thread::spawn(move || {
            let (mut conn, _) = broker_listener.accept().unwrap();
            let mut request = Vec::new();
            conn.read_to_end(&mut request).unwrap();
            conn.write_all(&[b"echo:".as_slice(), &request].concat())
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"CONNECT example.com:443").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();
        assert_eq!(response, b"echo:CONNECT example.com:443");
    }

    #[test]
    fn receive_fails_when_the_container_side_closes_without_a_listener() {
        let (supervisor, container) = UnixStream::pair().unwrap();
        drop(container);
        assert!(receive(&supervisor).is_err());
    }
}
