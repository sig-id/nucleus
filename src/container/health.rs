use crate::error::{NucleusError, Result};
use crate::isolation::{NamespaceCommandRunner, NamespaceProbe};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::{debug, error, info, warn};

use super::runtime::Container;

/// L2: Attempt to open a pidfd for the given PID.
/// Returns `Some(OwnedFd)` on success, or `None` if the kernel doesn't support pidfd_open.
fn pidfd_open(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: pidfd_open is a safe syscall that returns a file descriptor or -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_uint, 0i32) as i32 };
    if raw >= 0 {
        // SAFETY: raw is a valid, newly-created fd from pidfd_open.
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
    } else {
        None
    }
}

/// L2: Send a signal via pidfd to avoid PID-reuse TOCTOU.
/// Falls back to kill(2) with start_ticks verification if pidfd is unavailable.
fn pidfd_send_signal_or_kill(
    pid: u32,
    pidfd: Option<&std::os::fd::OwnedFd>,
    signal: Signal,
    expected_ticks: u64,
) {
    if let Some(fd) = pidfd {
        use std::os::fd::AsRawFd;
        // SAFETY: pidfd_send_signal is safe with a valid pidfd.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if ret != 0 {
            warn!(
                "pidfd_send_signal failed for PID {}: {}",
                pid,
                std::io::Error::last_os_error()
            );
        }
    } else {
        // Fallback: verify start_ticks before sending
        if read_start_ticks(pid) == expected_ticks {
            let _ = kill(
                Pid::from_raw(i32::try_from(pid).expect("PID exceeds i32::MAX")),
                signal,
            );
        } else {
            warn!("Health check: PID {} was recycled, not sending signal", pid);
        }
    }
}

/// Read the start time (field 22) from /proc/<pid>/stat to detect PID reuse.
fn read_start_ticks(pid: u32) -> u64 {
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(content) = std::fs::read_to_string(&stat_path) {
        if let Some(after_comm) = content.rfind(')') {
            return content[after_comm + 2..]
                .split_whitespace()
                .nth(19)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

impl Container {
    /// Run a readiness probe and, if sd_notify is active, send READY=1.
    pub(super) fn run_readiness_probe(
        state: &crate::container::ContainerState,
        probe: &crate::container::ReadinessProbe,
        notify_socket: Option<&str>,
    ) -> Result<()> {
        use crate::container::ReadinessProbe;

        let pid = state.pid;
        let container_name = &state.name;
        info!("Running readiness probe for {}", container_name);

        let max_attempts = 60u32; // ~60s total with 1s sleep
        let poll_interval = std::time::Duration::from_secs(1);

        for attempt in 1..=max_attempts {
            // Check that the container is still alive using signal 0
            if kill(
                Pid::from_raw(i32::try_from(pid).expect("PID exceeds i32::MAX")),
                None,
            )
            .is_err()
            {
                return Err(NucleusError::ExecError(format!(
                    "Container process {} exited before becoming ready",
                    pid
                )));
            }

            let ready = match probe {
                ReadinessProbe::Exec { command } => NamespaceCommandRunner::run_in_container(
                    state,
                    NamespaceProbe::Exec(command.clone()),
                    Some(std::time::Duration::from_secs(5)),
                )?,
                ReadinessProbe::TcpPort(port) => NamespaceCommandRunner::run_in_container(
                    state,
                    NamespaceProbe::TcpConnect(*port),
                    Some(std::time::Duration::from_secs(3)),
                )?,
                ReadinessProbe::SdNotify => {
                    // For SdNotify probe type, the container itself sends READY=1.
                    // We just pass through; the systemd integration handles it.
                    info!("Readiness probe is SdNotify; deferring to container process");
                    return Ok(());
                }
            };

            if ready {
                info!(
                    "Readiness probe passed for {} (attempt {})",
                    container_name, attempt
                );

                // Bridge to sd_notify if configured
                if let Some(socket_path) = notify_socket {
                    Self::send_sd_notify(socket_path, "READY=1")?;
                    info!("Sent READY=1 to sd_notify for {}", container_name);
                }

                return Ok(());
            }

            debug!(
                "Readiness probe attempt {}/{} failed for {}",
                attempt, max_attempts, container_name
            );
            std::thread::sleep(poll_interval);
        }

        Err(NucleusError::ExecError(format!(
            "Readiness probe timed out after {} attempts for {}",
            max_attempts, container_name
        )))
    }

    /// Send a notification to the systemd notify socket.
    ///
    /// The socket path is validated to prevent writing to arbitrary Unix sockets:
    /// only abstract sockets (`@...`) and absolute paths under `/run/` are accepted.
    pub(super) fn send_sd_notify(socket_path: &str, message: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        use std::path::{Path, PathBuf};

        enum NotifyDestination {
            Filesystem(PathBuf),
            #[cfg(target_os = "linux")]
            Abstract(SocketAddr),
        }

        let is_abstract = socket_path.starts_with('@');
        let has_traversal = socket_path.contains("/../")
            || socket_path.ends_with("/..")
            || socket_path.contains('\0');
        if has_traversal {
            return Err(NucleusError::ExecError(format!(
                "Refusing sd_notify to untrusted socket path: {}",
                socket_path
            )));
        }

        let destination = if is_abstract {
            #[cfg(target_os = "linux")]
            {
                let name = socket_path
                    .strip_prefix('@')
                    .ok_or_else(|| {
                        NucleusError::ExecError(format!(
                            "Invalid abstract notify socket path: {}",
                            socket_path
                        ))
                    })?
                    .as_bytes();
                let addr = SocketAddr::from_abstract_name(name).map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to build abstract notify socket address {}: {}",
                        socket_path, e
                    ))
                })?;
                NotifyDestination::Abstract(addr)
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(NucleusError::ExecError(
                    "Abstract Unix notify sockets are only supported on Linux".to_string(),
                ));
            }
        } else {
            let socket = Path::new(socket_path);
            if !socket.is_absolute() {
                return Err(NucleusError::ExecError(format!(
                    "Refusing sd_notify to non-absolute socket path: {}",
                    socket_path
                )));
            }

            let resolved = if socket.exists() {
                std::fs::canonicalize(socket).map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to resolve notify socket path {}: {}",
                        socket_path, e
                    ))
                })?
            } else {
                let parent = socket.parent().ok_or_else(|| {
                    NucleusError::ExecError(format!(
                        "Notify socket path has no parent directory: {}",
                        socket_path
                    ))
                })?;
                let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to resolve notify socket parent {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
                canonical_parent.join(socket.file_name().ok_or_else(|| {
                    NucleusError::ExecError(format!(
                        "Notify socket path has no file name: {}",
                        socket_path
                    ))
                })?)
            };

            if !(resolved.starts_with("/run/") || resolved.starts_with("/var/run/")) {
                return Err(NucleusError::ExecError(format!(
                    "Refusing sd_notify to untrusted socket path: {}",
                    socket_path
                )));
            }

            NotifyDestination::Filesystem(resolved)
        };

        let sock = UnixDatagram::unbound().map_err(|e| {
            NucleusError::ExecError(format!("Failed to create notify socket: {}", e))
        })?;
        match &destination {
            NotifyDestination::Filesystem(path) => {
                sock.send_to(message.as_bytes(), path).map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to send to notify socket {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            }
            #[cfg(target_os = "linux")]
            NotifyDestination::Abstract(addr) => {
                sock.send_to_addr(message.as_bytes(), addr).map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to send to abstract notify socket {}: {}",
                        socket_path, e
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Run periodic health checks against the container via nsenter.
    pub(super) fn health_check_loop(
        state: &crate::container::ContainerState,
        hc: &crate::container::HealthCheck,
        cancel: &std::sync::atomic::AtomicBool,
    ) {
        let pid = state.pid;
        let container_name = &state.name;
        // BUG-18: Use cancellable sleep so we exit promptly on container stop.
        let cancellable_sleep = |dur: std::time::Duration| -> bool {
            let step = std::time::Duration::from_millis(100);
            let start = std::time::Instant::now();
            while start.elapsed() < dur {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return true; // cancelled
                }
                std::thread::sleep(step.min(dur.saturating_sub(start.elapsed())));
            }
            cancel.load(std::sync::atomic::Ordering::Relaxed)
        };

        // L2: Open a pidfd to avoid PID-reuse TOCTOU races when sending signals.
        // Falls back to start_ticks verification if the kernel doesn't support pidfd.
        let pidfd = pidfd_open(pid);

        // Capture start_ticks as a fallback for PID ownership verification.
        let expected_ticks = read_start_ticks(pid);
        if expected_ticks == 0 && pidfd.is_none() {
            warn!(
                "Health check: could not read start_ticks for PID {} and pidfd unavailable, aborting",
                pid
            );
            return;
        }

        // Wait for start_period before beginning checks
        if cancellable_sleep(hc.start_period) {
            return;
        }

        let mut consecutive_failures: u32 = 0;

        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("Health check: cancelled for {}", container_name);
                return;
            }

            // Verify the PID still belongs to our container (guard against recycling)
            // before sending any signal, by comparing start_ticks.
            let current_ticks = read_start_ticks(pid);
            if current_ticks != expected_ticks {
                debug!(
                    "Health check: PID {} was recycled (start_ticks {} -> {}), stopping",
                    pid, expected_ticks, current_ticks
                );
                return;
            }
            // Check if the container process is still alive using signal 0
            if kill(
                Pid::from_raw(i32::try_from(pid).expect("PID exceeds i32::MAX")),
                None,
            )
            .is_err()
            {
                debug!("Health check: container process {} gone, stopping", pid);
                return;
            }

            match NamespaceCommandRunner::run_in_container(
                state,
                NamespaceProbe::Exec(hc.command.clone()),
                Some(hc.timeout),
            ) {
                Ok(true) => {
                    if consecutive_failures > 0 {
                        info!(
                            "Health check passed for {} after {} failures",
                            container_name, consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
                }
                Ok(false) => {
                    consecutive_failures += 1;
                    warn!(
                        "Health check failed for {} ({}/{})",
                        container_name, consecutive_failures, hc.retries
                    );

                    if consecutive_failures >= hc.retries {
                        error!(
                            "Container {} is unhealthy after {} consecutive failures",
                            container_name, consecutive_failures
                        );
                        pidfd_send_signal_or_kill(
                            pid,
                            pidfd.as_ref(),
                            Signal::SIGTERM,
                            expected_ticks,
                        );
                        return;
                    }
                }
                Err(e) => {
                    error!(
                        "Health check execution failed for {}: {}",
                        container_name, e
                    );
                    pidfd_send_signal_or_kill(pid, pidfd.as_ref(), Signal::SIGTERM, expected_ticks);
                    return;
                }
            }

            if cancellable_sleep(hc.interval) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_sd_notify_supports_abstract_sockets() {
        let name = format!("nucleus-health-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = match UnixDatagram::bind_addr(&addr) {
            Ok(receiver) => receiver,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind abstract socket: {}", err),
        };

        Container::send_sd_notify(&format!("@{}", name), "READY=1").unwrap();

        let mut buf = [0u8; 32];
        let len = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"READY=1");
    }
}
