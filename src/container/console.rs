use crate::container::ConsoleSize;
use crate::error::{NucleusError, Result};
use nix::pty::{openpty, Winsize};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use nix::unistd::{dup, setsid};
use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread::JoinHandle;

pub(super) struct NativePty {
    pub(super) master: Option<OwnedFd>,
    pub(super) slave: Option<OwnedFd>,
}

pub(super) struct NativeConsoleRelay {
    output_handle: Option<JoinHandle<()>>,
}

impl NativeConsoleRelay {
    pub(super) fn start(master: OwnedFd) -> Result<Self> {
        let output_fd = dup(&master).map_err(|e| {
            NucleusError::ExecError(format!("Failed to duplicate PTY master for output: {}", e))
        })?;

        let output_handle = std::thread::Builder::new()
            .name("console-output".to_string())
            .spawn(move || {
                let mut master = File::from(output_fd);
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                let mut buf = [0u8; 8192];
                loop {
                    match master.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stdout.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            let _ = stdout.flush();
                        }
                        Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| {
                NucleusError::ExecError(format!("Failed to spawn console output relay: {}", e))
            })?;

        let _ = std::thread::Builder::new()
            .name("console-input".to_string())
            .spawn(move || {
                let mut master = File::from(master);
                let stdin = std::io::stdin();
                let mut stdin = stdin.lock();
                let mut buf = [0u8; 8192];
                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if master.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            let _ = master.flush();
                        }
                        Err(_) => break,
                    }
                }
            });

        Ok(Self {
            output_handle: Some(output_handle),
        })
    }

    pub(super) fn stop(&mut self) {
        if let Some(handle) = self.output_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for NativeConsoleRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{recvmsg, ControlMessageOwned};
    use nix::unistd::{pipe, read, write};
    use std::io::IoSliceMut;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::net::UnixListener;

    #[test]
    fn test_send_master_to_console_socket_passes_fd() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_path = tmp.path().join("console.sock");
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping console socket fd-passing test: {}", err);
                return;
            }
            Err(err) => panic!("failed to bind console socket: {}", err),
        };
        let (read_fd, write_fd) = pipe().unwrap();

        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut payload = [0u8; 1];
            let mut iov = [IoSliceMut::new(&mut payload)];
            let mut cmsg = nix::cmsg_space!([RawFd; 1]);
            let msg = recvmsg::<()>(
                stream.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .unwrap();

            for cmsg in msg.cmsgs().unwrap() {
                if let ControlMessageOwned::ScmRights(fds) = cmsg {
                    return unsafe { OwnedFd::from_raw_fd(fds[0]) };
                }
            }
            panic!("expected SCM_RIGHTS fd");
        });

        NativePty::send_master_to_console_socket(&socket_path, &write_fd).unwrap();
        let received_fd = handle.join().unwrap();

        write(&received_fd, b"x").unwrap();
        let mut buf = [0u8; 1];
        let n = read(&read_fd, &mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'x');
    }
}

// The NativePty impl lives after the test module by historical file layout;
// reordering carries risk for no behavioral gain.
#[allow(clippy::items_after_test_module)]
impl NativePty {
    pub(super) fn open(size: ConsoleSize) -> Result<Self> {
        let winsize = Winsize {
            ws_row: size.height,
            ws_col: size.width,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = openpty(Some(&winsize), None).map_err(|e| {
            NucleusError::ExecError(format!("Failed to allocate pseudo-terminal: {}", e))
        })?;

        Ok(Self {
            master: Some(pty.master),
            slave: Some(pty.slave),
        })
    }

    pub(super) fn send_master_to_console_socket(
        socket_path: &Path,
        master: &OwnedFd,
    ) -> Result<()> {
        let stream = UnixStream::connect(socket_path).map_err(|e| {
            NucleusError::ExecError(format!(
                "Failed to connect to console socket '{}': {}",
                socket_path.display(),
                e
            ))
        })?;

        let payload = [0u8];
        let iov = [IoSlice::new(&payload)];
        let fds = [master.as_raw_fd()];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg::<()>(stream.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None).map_err(|e| {
            NucleusError::ExecError(format!(
                "Failed to send PTY master to console socket '{}': {}",
                socket_path.display(),
                e
            ))
        })?;

        Ok(())
    }

    pub(super) fn configure_child_terminal(slave: OwnedFd) -> Result<()> {
        setsid().map_err(|e| {
            NucleusError::ExecError(format!(
                "Failed to create terminal session for container process: {}",
                e
            ))
        })?;

        let slave_fd = slave.as_raw_fd();
        let ioctl_result = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) };
        if ioctl_result < 0 {
            return Err(NucleusError::ExecError(format!(
                "Failed to make PTY slave the controlling TTY: {}",
                std::io::Error::last_os_error()
            )));
        }

        let pid = unsafe { libc::getpid() };
        let tcsetpgrp_result = unsafe { libc::tcsetpgrp(slave_fd, pid) };
        if tcsetpgrp_result < 0 {
            return Err(NucleusError::ExecError(format!(
                "Failed to set terminal foreground process group: {}",
                std::io::Error::last_os_error()
            )));
        }

        for target_fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let dup_result = unsafe { libc::dup2(slave_fd, target_fd) };
            if dup_result < 0 {
                return Err(NucleusError::ExecError(format!(
                    "Failed to attach PTY slave to fd {}: {}",
                    target_fd,
                    std::io::Error::last_os_error()
                )));
            }
        }

        drop(slave);
        Ok(())
    }
}
