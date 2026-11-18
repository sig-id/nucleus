//! Keep the launch ruleset in the host supervisor. Passing the kernel fd
//! preserves inode-based grants across rename and unlink inside the sandbox.
use crate::error::{NucleusError, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread::JoinHandle;

fn send_ruleset(stream: &UnixStream, fd: &OwnedFd) -> Result<()> {
    let rights = [fd.as_raw_fd()];
    sendmsg::<()>(
        stream.as_raw_fd(),
        &[IoSlice::new(b"L")],
        &[ControlMessage::ScmRights(&rights)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    Ok(())
}

fn receive_ruleset(stream: &UnixStream) -> Result<OwnedFd> {
    let mut data = [0u8];
    let mut io = [IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut io,
        Some(&mut control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            // SAFETY: recvmsg installed fresh descriptors in this process.
            let mut owned = fds
                .into_iter()
                .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
                .collect::<Vec<_>>();
            if msg.bytes == 1 && owned.len() == 1 {
                return Ok(owned.remove(0));
            }
        }
    }
    Err(NucleusError::LandlockError(
        "Launch ruleset unavailable".into(),
    ))
}

/// The socket lives in the private state directory. Dropping the handle wakes
/// the worker even when the workload failed before sending a ruleset.
pub(crate) struct LandlockHandoff {
    stop: UnixStream,
    worker: Option<JoinHandle<()>>,
    _socket: tempfile::TempPath,
}

impl LandlockHandoff {
    pub(crate) fn start(path: &Path, launch: UnixStream) -> Result<Self> {
        let listener = UnixListener::bind(path)?;
        let socket = tempfile::TempPath::try_from_path(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let (stop, stopped) = UnixStream::pair()?;
        let worker = std::thread::Builder::new()
            .name("landlock-handoff".into())
            .spawn(move || {
                let serve = || -> Result<()> {
                    let mut ruleset = None;
                    loop {
                        let wait = if ruleset.is_some() {
                            listener.as_fd()
                        } else {
                            launch.as_fd()
                        };
                        let mut fds = [
                            PollFd::new(stopped.as_fd(), PollFlags::POLLIN),
                            PollFd::new(wait, PollFlags::POLLIN),
                        ];
                        match poll(&mut fds, PollTimeout::NONE) {
                            Err(nix::errno::Errno::EINTR) => continue,
                            result => {
                                result?;
                            }
                        }
                        if !fds[0].revents().unwrap_or(PollFlags::empty()).is_empty() {
                            return Ok(());
                        }
                        if let Some(fd) = &ruleset {
                            let (client, _) = listener.accept()?;
                            let _ = send_ruleset(&client, fd);
                        } else {
                            ruleset = Some(receive_ruleset(&launch)?);
                        }
                    }
                };
                if let Err(e) = serve() {
                    tracing::debug!("Native helper ruleset unavailable: {e}");
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            _socket: socket,
        })
    }
}

impl Drop for LandlockHandoff {
    fn drop(&mut self) {
        let _ = self.stop.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) fn load_launch_ruleset(path: Option<&Path>) -> Result<OwnedFd> {
    let path = path
        .ok_or_else(|| NucleusError::AttachError("Missing live launch Landlock ruleset".into()))?;
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    receive_ruleset(&stream)
}

pub(crate) fn restrict_to_launch_ruleset(fd: &OwnedFd) -> Result<()> {
    // SAFETY: the kernel verifies the fd's type and the caller has set no_new_privs.
    let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0) };
    if result == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn restrict_and_publish(
    ruleset: landlock::RulesetCreated,
    handoff: Option<&UnixStream>,
) -> Result<landlock::RestrictionStatus> {
    let copy: Option<OwnedFd> = if handoff.is_some() {
        ruleset.try_clone()?.into()
    } else {
        None
    };
    let status = ruleset
        .restrict_self()
        .map_err(|e| NucleusError::LandlockError(e.to_string()))?;
    if let (landlock::RulesetStatus::FullyEnforced, Some(stream), Some(fd)) =
        (&status.ruleset, handoff, copy)
    {
        send_ruleset(stream, &fd)?;
    }
    Ok(status)
}
