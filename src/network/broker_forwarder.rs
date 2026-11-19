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
use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
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

/// Relays the workload's broker connections for one container.
///
/// Dropping it stops accepting, shuts down every open connection and joins
/// all of its threads, so the supervisor is single-threaded again and the
/// listener (and with it the container's network namespace) and the pinned
/// broker descriptor are released.
pub(crate) struct BrokerForwarder {
    shared: Arc<Shared>,
    /// A second handle on the listening socket, used to wake the accept loop.
    wake: TcpListener,
    acceptor: Option<JoinHandle<()>>,
}

struct Shared {
    stopping: AtomicBool,
    conns: Mutex<Conns>,
}

#[derive(Default)]
struct Conns {
    next_id: u64,
    /// Both ends of every connection whose relay has not finished.
    open: HashMap<u64, (TcpStream, UnixStream)>,
    threads: Vec<JoinHandle<()>>,
}

/// A connection's claim on one of the `MAX_CONNECTIONS` slots. Both relay
/// directions hold it; the slot frees when the second one finishes.
struct Slot {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut conns) = self.shared.conns.lock() {
            conns.open.remove(&self.id);
        }
    }
}

impl BrokerForwarder {
    /// Accept connections on `listener` and relay each one to `broker`.
    pub(crate) fn spawn(listener: TcpListener, broker: &BrokerSocket) -> Result<Self> {
        // Connect through the inode verified at launch, never by path.
        let pinned = broker.pin()?;
        let local = listener.local_addr()?;
        let wake = listener.try_clone()?;
        let host_path = broker.host_path().to_path_buf();
        let shared = Arc::new(Shared {
            stopping: AtomicBool::new(false),
            conns: Mutex::new(Conns::default()),
        });
        let worker = shared.clone();
        let acceptor = thread::Builder::new()
            .name("broker-forward".into())
            .spawn(move || accept_loop(&listener, &pinned, &host_path, &worker))
            .map_err(|e| {
                NucleusError::NetworkError(format!("Cannot start broker forwarder: {e}"))
            })?;
        info!("Broker forwarder listening on {local} inside the container");
        Ok(Self {
            shared,
            wake,
            acceptor: Some(acceptor),
        })
    }
}

impl Drop for BrokerForwarder {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        // Shutting down a listening socket wakes a blocked accept.
        let _ = nix::sys::socket::shutdown(self.wake.as_raw_fd(), nix::sys::socket::Shutdown::Both);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
        let threads = match self.shared.conns.lock() {
            Ok(mut conns) => {
                for (client, upstream) in conns.open.values() {
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = upstream.shutdown(Shutdown::Both);
                }
                std::mem::take(&mut conns.threads)
            }
            Err(_) => Vec::new(),
        };
        for thread in threads {
            let _ = thread.join();
        }
    }
}

fn accept_loop(
    listener: &TcpListener,
    pinned: &OwnedFd,
    host_path: &std::path::Path,
    shared: &Arc<Shared>,
) {
    let target = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    loop {
        let accepted = listener.accept();
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        let client = match accepted {
            Ok((client, _)) => client,
            Err(e) => {
                warn!("Broker forwarder accept failed: {e}");
                // Do not spin on a persistent error such as EMFILE.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let full = shared
            .conns
            .lock()
            .map(|conns| conns.open.len() >= MAX_CONNECTIONS)
            .unwrap_or(true);
        if full {
            warn!("Broker forwarder at {MAX_CONNECTIONS} connections; refusing one");
            continue;
        }
        let upstream = match connect_without_waiting(&target) {
            Ok(upstream) => upstream,
            Err(e) => {
                warn!("Cannot connect to broker socket {host_path:?}: {e}");
                continue;
            }
        };
        if let Err(e) = relay(client, upstream, shared, spawn_thread) {
            warn!("Broker forwarder cannot relay a connection: {e}");
        }
    }
}

/// Connect to the broker without blocking. A unix-socket connect only waits
/// when the broker's backlog is full; that now fails with `EAGAIN` and the
/// one connection is refused, so the accept loop stays responsive to
/// shutdown.
fn connect_without_waiting(target: &str) -> std::io::Result<UnixStream> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    connect(fd.as_raw_fd(), &UnixAddr::new(target)?)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

type Spawn = fn(&'static str, Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>;

fn spawn_thread(
    name: &'static str,
    body: Box<dyn FnOnce() + Send>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new().name(name.into()).spawn(body)
}

/// Copy both directions of one connection on two threads, propagating
/// half-closes so request/response protocols see end-of-file. The slot and
/// the registered descriptors are released when both directions are done,
/// including when a thread cannot be started.
///
/// The connection mutex is never held while a thread is spawned or a
/// `Slot` may be dropped: `Slot::drop` takes it.
fn relay(
    client: TcpStream,
    upstream: UnixStream,
    shared: &Arc<Shared>,
    spawn: Spawn,
) -> std::io::Result<()> {
    let handles = (client.try_clone()?, upstream.try_clone()?);
    let (up_from, up_to) = (client.try_clone()?, upstream.try_clone()?);
    let id = {
        let mut conns = shared
            .conns
            .lock()
            .map_err(|_| std::io::Error::other("broker forwarder state poisoned"))?;
        let id = conns.next_id;
        conns.next_id += 1;
        conns.open.insert(id, handles);
        conns.threads.retain(|thread| !thread.is_finished());
        id
    };
    let slot = Arc::new(Slot {
        shared: shared.clone(),
        id,
    });
    // Unblocks a started direction so it finishes and drops its slot share.
    let abort = |shared: &Shared| {
        if let Ok(conns) = shared.conns.lock() {
            if let Some((client, upstream)) = conns.open.get(&id) {
                let _ = client.shutdown(Shutdown::Both);
                let _ = upstream.shutdown(Shutdown::Both);
            }
        }
    };

    let up_slot = slot.clone();
    // On failure the closure, with its slot share and descriptors, is
    // dropped inside `spawn`; `slot` drops when this returns.
    let up = spawn(
        "broker-up",
        Box::new(move || {
            let _slot = up_slot;
            let (mut from, mut to) = (up_from, up_to);
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
        }),
    )?;
    let down = spawn(
        "broker-down",
        Box::new(move || {
            let _slot = slot;
            let (mut from, mut to) = (upstream, client);
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
            debug!("Broker connection direction closed");
        }),
    );
    let mut started = vec![up];
    let result = match down {
        Ok(down) => {
            started.push(down);
            Ok(())
        }
        Err(e) => {
            abort(shared);
            Err(e)
        }
    };
    if let Ok(mut conns) = shared.conns.lock() {
        conns.threads.extend(started);
    }
    result
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
        let _forwarder = BrokerForwarder::spawn(listener, &broker).unwrap();

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

    fn wait_until(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn slot_is_held_until_both_directions_finish() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        let broker_listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let broker = BrokerSocket::verify(&socket_path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let forwarder = BrokerForwarder::spawn(listener, &broker).unwrap();
        let open = || forwarder.shared.conns.lock().unwrap().open.len();

        // The broker closes at once; the client keeps its write side open.
        let client = TcpStream::connect(addr).unwrap();
        let (conn, _) = broker_listener.accept().unwrap();
        drop(conn);
        let mut buf = [0u8; 1];
        assert_eq!((&client).read(&mut buf).unwrap(), 0, "download side closed");
        assert_eq!(open(), 1, "upload direction still holds the slot");

        drop(client);
        assert!(wait_until(|| open() == 0));
    }

    #[test]
    fn dropping_the_forwarder_joins_every_thread() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        let broker_listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let broker = BrokerSocket::verify(&socket_path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let forwarder = BrokerForwarder::spawn(listener, &broker).unwrap();
        // Two idle connections keep relay threads blocked on both sides.
        let clients: Vec<_> = (0..2).map(|_| TcpStream::connect(addr).unwrap()).collect();
        let conns: Vec<_> = (0..2).map(|_| broker_listener.accept().unwrap()).collect();
        assert!(wait_until(|| forwarder
            .shared
            .conns
            .lock()
            .unwrap()
            .threads
            .len()
            == 4));
        let threads = Arc::downgrade(&forwarder.shared);

        drop(forwarder);
        // Every worker has been joined, so no thread holds the shared state,
        // and the listener is closed.
        assert_eq!(threads.strong_count(), 0);
        assert!(TcpStream::connect(addr).is_err());
        drop((clients, conns));
    }

    fn connected_pair(
        broker: &std::os::unix::net::UnixListener,
        socket_path: &std::path::Path,
    ) -> (TcpStream, UnixStream, UnixStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let upstream = UnixStream::connect(socket_path).unwrap();
        let (broker_end, _) = broker.accept().unwrap();
        drop(client);
        (accepted, upstream, broker_end)
    }

    fn fresh_shared() -> Arc<Shared> {
        Arc::new(Shared {
            stopping: AtomicBool::new(false),
            conns: Mutex::new(Conns::default()),
        })
    }

    #[test]
    fn failed_thread_spawns_release_the_slot_without_deadlock() {
        fn fail_all(
            _: &'static str,
            _: Box<dyn FnOnce() + Send>,
        ) -> std::io::Result<JoinHandle<()>> {
            Err(std::io::Error::other("no threads"))
        }
        fn fail_second(
            name: &'static str,
            body: Box<dyn FnOnce() + Send>,
        ) -> std::io::Result<JoinHandle<()>> {
            if name == "broker-down" {
                return Err(std::io::Error::other("no threads"));
            }
            spawn_thread(name, body)
        }
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        let broker = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        for spawn in [fail_all as Spawn, fail_second as Spawn] {
            let shared = fresh_shared();
            let (client, upstream, _broker_end) = connected_pair(&broker, &socket_path);
            // Returns instead of deadlocking on the connection mutex.
            assert!(relay(client, upstream, &shared, spawn).is_err());
            assert!(wait_until(|| shared.conns.lock().unwrap().open.is_empty()));
        }
    }

    #[test]
    fn connect_refuses_instead_of_waiting_on_a_full_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("broker.sock");
        // A listener that never accepts, with the smallest backlog.
        let fd = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        nix::sys::socket::bind(
            fd.as_raw_fd(),
            &nix::sys::socket::UnixAddr::new(&socket_path).unwrap(),
        )
        .unwrap();
        nix::sys::socket::listen(&fd, nix::sys::socket::Backlog::new(0).unwrap()).unwrap();
        let target = socket_path.to_str().unwrap();
        let mut held = Vec::new();
        let start = std::time::Instant::now();
        let refused = loop {
            match connect_without_waiting(target) {
                Ok(stream) => held.push(stream),
                Err(e) => break e,
            }
            assert!(held.len() < 64, "backlog never filled");
        };
        assert_eq!(refused.raw_os_error(), Some(libc::EAGAIN));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn receive_fails_when_the_container_side_closes_without_a_listener() {
        let (supervisor, container) = UnixStream::pair().unwrap();
        drop(container);
        assert!(receive(&supervisor).is_err());
    }
}
