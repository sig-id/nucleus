use crate::container::{ContainerState, ContainerStateManager};
use crate::error::{NucleusError, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use nix::unistd::Uid;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Container lifecycle operations (stop, kill, delete)
pub struct ContainerLifecycle;

impl ContainerLifecycle {
    fn ensure_container_access(state: &ContainerState) -> Result<()> {
        let current_uid = Uid::effective().as_raw();
        if current_uid == 0 || current_uid == state.creator_uid {
            return Ok(());
        }

        Err(NucleusError::PermissionDenied(format!(
            "container {} owned by UID {}, caller is UID {}",
            state.id, state.creator_uid, current_uid
        )))
    }

    /// Stop a container gracefully: SIGTERM, wait for timeout, then SIGKILL
    pub fn stop(state: &ContainerState, timeout_secs: u64) -> Result<()> {
        Self::ensure_container_access(state)?;

        if !state.is_running() {
            info!("Container {} is already stopped", state.id);
            return Ok(());
        }

        let pid = Pid::from_raw(state.pid as i32);

        // Verify PID is still alive before sending signal.
        // kill(pid, None) sends signal 0 – a no-op that returns ESRCH if the
        // PID doesn't exist, protecting against PID recycling TOCTOU races.
        if let Err(e) = kill(pid, None) {
            if e == nix::errno::Errno::ESRCH {
                info!("Process already exited");
                return Ok(());
            }
        }

        // Send SIGTERM
        info!(
            "Sending SIGTERM to container {} (PID {})",
            state.id, state.pid
        );
        if let Err(e) = kill(pid, Signal::SIGTERM) {
            if e == nix::errno::Errno::ESRCH {
                info!("Process already exited");
                return Ok(());
            }
            return Err(NucleusError::ExecError(format!(
                "Failed to send SIGTERM: {}",
                e
            )));
        }

        // Wait for process to exit
        let poll_interval = Duration::from_millis(100);
        let deadline = Duration::from_secs(timeout_secs);
        let mut elapsed = Duration::ZERO;

        while elapsed < deadline {
            if !state.is_running() {
                info!("Container {} stopped gracefully", state.id);
                return Ok(());
            }
            thread::sleep(poll_interval);
            elapsed += poll_interval;
        }

        // Force kill
        warn!(
            "Container {} did not stop after {}s, sending SIGKILL",
            state.id, timeout_secs
        );
        if let Err(e) = kill(pid, Signal::SIGKILL) {
            if e == nix::errno::Errno::ESRCH {
                return Ok(());
            }
            return Err(NucleusError::ExecError(format!(
                "Failed to send SIGKILL: {}",
                e
            )));
        }

        Ok(())
    }

    /// Send an arbitrary signal to a container
    pub fn kill_container(state: &ContainerState, signal: Signal) -> Result<()> {
        Self::ensure_container_access(state)?;

        if !state.is_running() {
            return Err(NucleusError::ContainerNotRunning(format!(
                "Container {} is not running",
                state.id
            )));
        }

        let pid = Pid::from_raw(state.pid as i32);
        info!(
            "Sending {:?} to container {} (PID {})",
            signal, state.id, state.pid
        );

        kill(pid, signal).map_err(|e| {
            NucleusError::ExecError(format!("Failed to send signal {:?}: {}", signal, e))
        })?;

        Ok(())
    }

    /// Remove a stopped container's state
    pub fn remove(
        state_mgr: &ContainerStateManager,
        state: &ContainerState,
        force: bool,
    ) -> Result<()> {
        Self::ensure_container_access(state)?;

        if state.is_running() {
            if force {
                info!("Force removing running container {}", state.id);
                Self::stop(state, 5)?;
            } else {
                return Err(NucleusError::ExecError(format!(
                    "Container {} is still running. Stop it first or use --force",
                    state.id
                )));
            }
        }

        // Clean up cgroup directory if present
        if let Some(ref cgroup_path) = state.cgroup_path {
            let cgroup = std::path::Path::new(cgroup_path);
            if cgroup.exists() {
                if let Err(e) = std::fs::remove_dir_all(cgroup) {
                    warn!(
                        "Failed to remove cgroup {}: {} (may still have processes)",
                        cgroup_path, e
                    );
                } else {
                    info!("Removed cgroup {}", cgroup_path);
                }
            }
        }

        if let Ok(overlay_dir) = state_mgr.rootfs_overlay_dir_path(&state.id) {
            if overlay_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&overlay_dir) {
                    warn!(
                        "Failed to remove rootfs overlay directory {:?}: {}",
                        overlay_dir, e
                    );
                }
            }
        }

        state_mgr.delete_state(&state.id)?;
        info!("Removed container {}", state.id);
        Ok(())
    }
}

/// Parse a signal name or number string into a Signal
pub fn parse_signal(s: &str) -> Result<Signal> {
    // Try numeric
    if let Ok(num) = s.parse::<i32>() {
        return Signal::try_from(num)
            .map_err(|_| NucleusError::ConfigError(format!("Invalid signal number: {}", num)));
    }

    // Normalize: uppercase and strip optional "SIG" prefix
    let upper = s.to_ascii_uppercase();
    let normalized = upper.strip_prefix("SIG").unwrap_or(&upper);

    match normalized {
        "ABRT" | "IOT" => Ok(Signal::SIGABRT),
        "ALRM" => Ok(Signal::SIGALRM),
        "BUS" => Ok(Signal::SIGBUS),
        "CHLD" | "CLD" => Ok(Signal::SIGCHLD),
        "CONT" => Ok(Signal::SIGCONT),
        "FPE" => Ok(Signal::SIGFPE),
        "HUP" => Ok(Signal::SIGHUP),
        "ILL" => Ok(Signal::SIGILL),
        "INT" => Ok(Signal::SIGINT),
        "IO" | "POLL" => Ok(Signal::SIGIO),
        "KILL" => Ok(Signal::SIGKILL),
        "PIPE" => Ok(Signal::SIGPIPE),
        "PROF" => Ok(Signal::SIGPROF),
        "PWR" => Ok(Signal::SIGPWR),
        "QUIT" => Ok(Signal::SIGQUIT),
        "SEGV" => Ok(Signal::SIGSEGV),
        "STKFLT" => Ok(Signal::SIGSTKFLT),
        "STOP" => Ok(Signal::SIGSTOP),
        "SYS" => Ok(Signal::SIGSYS),
        "TERM" => Ok(Signal::SIGTERM),
        "TRAP" => Ok(Signal::SIGTRAP),
        "TSTP" => Ok(Signal::SIGTSTP),
        "TTIN" => Ok(Signal::SIGTTIN),
        "TTOU" => Ok(Signal::SIGTTOU),
        "URG" => Ok(Signal::SIGURG),
        "USR1" => Ok(Signal::SIGUSR1),
        "USR2" => Ok(Signal::SIGUSR2),
        "VTALRM" => Ok(Signal::SIGVTALRM),
        "WINCH" => Ok(Signal::SIGWINCH),
        "XCPU" => Ok(Signal::SIGXCPU),
        "XFSZ" => Ok(Signal::SIGXFSZ),
        _ => Err(NucleusError::ConfigError(format!("Unknown signal: {}", s))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerStateParams;

    #[test]
    fn test_parse_signal_by_name() {
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
    }

    #[test]
    fn test_parse_signal_by_number() {
        assert_eq!(parse_signal("15").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("9").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("2").unwrap(), Signal::SIGINT);
    }

    #[test]
    fn test_parse_signal_case_insensitive() {
        assert_eq!(parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("Term").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_all_standard_names() {
        let cases = vec![
            ("ABRT", Signal::SIGABRT),
            ("IOT", Signal::SIGABRT),
            ("ALRM", Signal::SIGALRM),
            ("BUS", Signal::SIGBUS),
            ("CHLD", Signal::SIGCHLD),
            ("CLD", Signal::SIGCHLD),
            ("FPE", Signal::SIGFPE),
            ("ILL", Signal::SIGILL),
            ("IO", Signal::SIGIO),
            ("POLL", Signal::SIGIO),
            ("PIPE", Signal::SIGPIPE),
            ("PROF", Signal::SIGPROF),
            ("PWR", Signal::SIGPWR),
            ("SEGV", Signal::SIGSEGV),
            ("STKFLT", Signal::SIGSTKFLT),
            ("SYS", Signal::SIGSYS),
            ("TRAP", Signal::SIGTRAP),
            ("TSTP", Signal::SIGTSTP),
            ("TTIN", Signal::SIGTTIN),
            ("TTOU", Signal::SIGTTOU),
            ("URG", Signal::SIGURG),
            ("VTALRM", Signal::SIGVTALRM),
            ("WINCH", Signal::SIGWINCH),
            ("XCPU", Signal::SIGXCPU),
            ("XFSZ", Signal::SIGXFSZ),
        ];
        for (name, expected) in cases {
            assert_eq!(
                parse_signal(name).unwrap(),
                expected,
                "parse_signal({name}) failed"
            );
            // Also with SIG prefix
            let prefixed = format!("SIG{name}");
            assert_eq!(
                parse_signal(&prefixed).unwrap(),
                expected,
                "parse_signal({prefixed}) failed"
            );
        }
    }

    #[test]
    fn test_parse_signal_invalid() {
        assert!(parse_signal("INVALID").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn test_access_check_owner_allowed() {
        let uid = Uid::effective().as_raw();
        let state = ContainerState::new(ContainerStateParams {
            id: "testid".to_string(),
            name: "testname".to_string(),
            pid: 12345,
            command: vec!["/bin/true".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: true,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        // Override creator to match current caller for this test.
        let mut state = state;
        state.creator_uid = uid;
        assert!(ContainerLifecycle::ensure_container_access(&state).is_ok());
    }
}
