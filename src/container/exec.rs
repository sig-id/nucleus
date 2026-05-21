use crate::audit::{audit, AuditEventType};
use crate::container::ProcessIdentity;
use crate::error::{NucleusError, Result};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setgid, setgroups, setuid, ForkResult, Gid, Pid, Uid};
use std::ffi::CString;
use tracing::{debug, error, info};

use super::runtime::Container;

impl Container {
    pub(crate) fn apply_process_identity_to_current_process(
        identity: &ProcessIdentity,
        inside_user_namespace: bool,
    ) -> Result<()> {
        // Always apply identity, even for root. Skipping setuid/setgid for root
        // means processes run with real host UID 0 when user namespace is disabled,
        // which is a container escape risk (C3).

        if !inside_user_namespace {
            let groups: Vec<Gid> = identity
                .additional_gids
                .iter()
                .copied()
                .map(Gid::from_raw)
                .collect();
            setgroups(&groups).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to set supplementary groups to {:?}: {}",
                    identity.additional_gids, e
                ))
            })?;
        }

        setgid(Gid::from_raw(identity.gid)).map_err(|e| {
            NucleusError::ExecError(format!("Failed to switch to gid {}: {}", identity.gid, e))
        })?;
        setuid(Uid::from_raw(identity.uid)).map_err(|e| {
            NucleusError::ExecError(format!("Failed to switch to uid {}: {}", identity.uid, e))
        })?;

        info!(
            "Applied workload identity uid={} gid={} supplementary_gids={:?}",
            identity.uid, identity.gid, identity.additional_gids
        );

        Ok(())
    }

    /// Execute the target command.
    ///
    /// This runs in the child process after fork, after all security setup
    /// (including identity switch) is complete. The identity switch
    /// (setuid/setgid) has already been applied in the cap-drop phase of
    /// setup_and_exec, between bounding-set cleanup and final cap clear.
    pub(super) fn exec_command(&self) -> Result<()> {
        if self.config.command.is_empty() {
            return Err(NucleusError::ExecError("No command specified".to_string()));
        }

        info!(
            "Executing command: {:?}",
            crate::audit::redact_command(&self.config.command)
        );

        std::env::set_current_dir(&self.config.workdir).map_err(|e| {
            NucleusError::ExecError(format!(
                "Failed to set working directory to {}: {}",
                self.config.workdir.display(),
                e
            ))
        })?;

        let program = CString::new(self.config.command[0].as_str())
            .map_err(|e| NucleusError::ExecError(format!("Invalid program name: {}", e)))?;

        let args: Result<Vec<CString>> = self
            .config
            .command
            .iter()
            .map(|arg| {
                CString::new(arg.as_str())
                    .map_err(|e| NucleusError::ExecError(format!("Invalid argument: {}", e)))
            })
            .collect();
        let args = args?;

        let mut env = vec![
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .map_err(|e| NucleusError::ExecError(format!("Invalid environment PATH: {}", e)))?,
            CString::new("TERM=xterm")
                .map_err(|e| NucleusError::ExecError(format!("Invalid environment TERM: {}", e)))?,
        ];
        if !self.config.environment.iter().any(|(key, _)| key == "HOME") {
            env.push(
                CString::new(format!("HOME={}", self.config.home.display())).map_err(|e| {
                    NucleusError::ExecError(format!("Invalid environment HOME: {}", e))
                })?,
            );
        }

        // Pass through sd_notify socket if enabled.
        // Validate the socket path to prevent the container from communicating
        // with arbitrary host systemd sockets.
        if self.config.sd_notify {
            if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
                // Only allow abstract sockets (@...) or absolute paths under /run/
                let is_abstract = notify_socket.starts_with('@');
                let has_traversal = notify_socket.contains("/../")
                    || notify_socket.ends_with("/..")
                    || notify_socket.contains('\0');
                // M9: Canonicalize filesystem paths to resolve symlinks,
                // preventing symlink-based traversal attacks.
                let is_safe_path = if !is_abstract && !has_traversal {
                    if let Ok(canonical) = std::fs::canonicalize(&notify_socket) {
                        let canonical_str = canonical.to_string_lossy();
                        canonical_str.starts_with("/run/") || canonical_str.starts_with("/var/run/")
                    } else {
                        // Path doesn't exist yet – check the string directly
                        notify_socket.starts_with("/run/") || notify_socket.starts_with("/var/run/")
                    }
                } else {
                    false
                };

                if (is_abstract || is_safe_path) && !has_traversal {
                    env.push(
                        CString::new(format!("NOTIFY_SOCKET={}", notify_socket)).map_err(|e| {
                            NucleusError::ExecError(format!("Invalid NOTIFY_SOCKET: {}", e))
                        })?,
                    );
                } else {
                    debug!(
                        "Refusing to pass NOTIFY_SOCKET={} into container: \
                         only abstract sockets or /run/ paths are allowed",
                        notify_socket
                    );
                }
            }
        }

        // L4: Filter dangerous environment variables that could be used for
        // privilege escalation or library injection.
        const BLOCKED_ENV_VARS: &[&str] = &[
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LD_DEBUG",
            "LD_PROFILE",
            "LD_DYNAMIC_WEAK",
            "LD_SHOW_AUXV",
        ];

        // Append user-configured environment variables (filtered)
        for (key, value) in &self.config.environment {
            if BLOCKED_ENV_VARS.contains(&key.as_str()) {
                debug!("Blocking dangerous environment variable: {}", key);
                continue;
            }
            env.push(CString::new(format!("{}={}", key, value)).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Invalid environment variable value for {}: {}",
                    key, e
                ))
            })?);
        }

        nix::unistd::execve(&program, &args, &env)?;

        Ok(())
    }

    /// Run as a minimal PID 1 init process inside the container.
    ///
    /// Forks a child that execs the workload. PID 1 (this process) stays alive to:
    /// - Reap zombie processes (orphaned children)
    /// - Forward SIGTERM/SIGINT/SIGHUP to the workload child
    /// - Exit with the workload's exit code
    ///
    /// This prevents zombie accumulation in long-running production containers
    /// and ensures clean shutdown ordering.
    pub(super) fn run_as_init(&self) -> Result<()> {
        info!("Starting as PID 1 init supervisor (production mode)");
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::InitSupervisorStarted,
            "PID 1 init supervisor for zombie reaping and signal forwarding",
        );

        Self::assert_single_threaded_for_fork("init supervisor fork")?;
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                // PID 1: mini-init – reap zombies and forward signals
                //
                // This supervisor never execs, so CLOEXEC inherited from the
                // setup path is not enough to protect host/runtime descriptors.
                Self::close_nonstdio_fds();

                // Set up signal forwarding to the workload child
                let mut sigset = SigSet::empty();
                for sig in [
                    Signal::SIGTERM,
                    Signal::SIGINT,
                    Signal::SIGHUP,
                    Signal::SIGQUIT,
                    Signal::SIGUSR1,
                    Signal::SIGUSR2,
                    Signal::SIGWINCH,
                ] {
                    sigset.add(sig);
                }

                // Block forwarded signals so we can use sigtimedwait
                pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&sigset), None).map_err(|e| {
                    NucleusError::ExecError(format!("Init: failed to block signals: {}", e))
                })?;

                // Spawn a thread to forward signals to the child
                let child_pid = child;
                let sig_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let sig_stop_clone = sig_stop.clone();
                let sig_thread = std::thread::spawn(move || {
                    loop {
                        if let Ok(signal) = sigset.wait() {
                            // Check the stop flag *after* waking so that the
                            // wake-up signal is not forwarded to the child
                            // during shutdown.
                            if sig_stop_clone.load(std::sync::atomic::Ordering::Acquire) {
                                break;
                            }
                            let _ = kill(child_pid, signal);
                        }
                    }
                });

                // Main loop: reap all children, exit when workload child exits
                let workload_exit = loop {
                    match waitpid(Pid::from_raw(-1), None) {
                        Ok(WaitStatus::Exited(pid, code)) => {
                            if pid == child {
                                debug!("Init: workload child exited with code {}", code);
                                break code;
                            }
                            debug!("Init: reaped zombie PID {} (exit code {})", pid, code);
                        }
                        Ok(WaitStatus::Signaled(pid, signal, _)) => {
                            if pid == child {
                                let code = 128 + signal as i32;
                                debug!(
                                    "Init: workload child killed by signal {:?} (exit code {})",
                                    signal, code
                                );
                                break code;
                            }
                            debug!("Init: reaped zombie PID {} (killed by {:?})", pid, signal);
                        }
                        Err(nix::errno::Errno::ECHILD) => {
                            // No more children – workload must have exited
                            debug!("Init: no more children, exiting");
                            break 1;
                        }
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(e) => {
                            error!("Init: waitpid error: {}", e);
                            break 1;
                        }
                        _ => continue,
                    }
                };

                // Stop the signal-forwarding thread before exiting.
                sig_stop.store(true, std::sync::atomic::Ordering::Release);
                super::signals::wake_sigwait_thread(&sig_thread, Signal::SIGUSR1);
                let _ = sig_thread.join();
                std::process::exit(workload_exit);
            }
            ForkResult::Child => {
                // Workload child: exec the target command
                self.exec_command()?;
                // Should never reach here
                Ok(())
            }
        }
    }

    pub(super) fn enforce_no_new_privs(&self) -> Result<()> {
        // SAFETY: PR_SET_NO_NEW_PRIVS with arg 1 is always safe to call; it only
        // restricts the calling thread's future privilege transitions.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(NucleusError::ExecError(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}
