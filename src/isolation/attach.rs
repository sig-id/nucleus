use crate::container::{ContainerState, ProcessIdentity};
use crate::error::{NucleusError, Result};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};
use tracing::info;

/// Attach to a running container by entering its namespaces
pub struct ContainerAttach;

/// Minimal probe operations that can be executed after joining container namespaces.
pub enum NamespaceProbe {
    Exec(Vec<String>),
    TcpConnect(u16),
}

/// Run trusted helper actions inside a container's namespaces.
pub struct NamespaceCommandRunner;

impl ContainerAttach {
    /// Attach to a running container and execute a command
    ///
    /// Opens namespace FDs from /proc/`<pid>`/ns/\*, forks, calls setns(2) for each,
    /// then execve the command. Parent waits with waitpid.
    pub fn attach(state: &ContainerState, command: Vec<String>) -> Result<i32> {
        if !state.is_running() {
            return Err(NucleusError::AttachError(format!(
                "Container {} is not running",
                state.id
            )));
        }

        // Validate caller owns the container (or is root)
        let current_uid = nix::unistd::Uid::effective().as_raw();
        if current_uid != 0 && current_uid != state.creator_uid {
            return Err(NucleusError::AttachError(format!(
                "Permission denied: container {} owned by UID {}, caller is UID {}",
                state.id, state.creator_uid, current_uid
            )));
        }

        // gVisor containers run under runsc; the host PID is the gVisor sandbox
        // supervisor, not the guest workload. nsenter cannot reach the guest.
        if state.using_gvisor {
            return Err(NucleusError::AttachError(format!(
                "Container {} uses gVisor runtime; attach is not supported \
                 (use 'runsc exec' to interact with the guest workload)",
                state.id
            )));
        }

        let pid = state.pid;
        info!("Attaching to container {} (PID {})", state.id, pid);

        let ns_fds = Self::open_namespace_fds(pid, state.rootless)?;

        // Fork child
        match unsafe { fork() }
            .map_err(|e| NucleusError::AttachError(format!("Fork failed: {}", e)))?
        {
            ForkResult::Parent { child } => {
                // Parent: wait for child
                Self::wait_for_child(child)
            }
            ForkResult::Child => {
                // Child: enter namespaces and exec
                match Self::enter_and_exec(&ns_fds, &command) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        eprintln!("Attach failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    fn enter_and_exec(ns_fds: &[(String, File)], command: &[String]) -> Result<()> {
        if command.is_empty() {
            return Err(NucleusError::AttachError(
                "No command specified for attach".to_string(),
            ));
        }

        Self::enter_namespaces(ns_fds)?;
        Self::apply_exec_hardening()?;
        let env = Self::default_exec_env()?;
        Self::exec_with_env(command, &env)
    }

    fn open_namespace_fds(pid: u32, rootless: bool) -> Result<Vec<(String, File)>> {
        let ns_types = if rootless {
            &["user", "pid", "mnt", "net", "uts", "ipc", "cgroup"][..]
        } else {
            &["pid", "mnt", "net", "uts", "ipc", "cgroup"][..]
        };
        let mut ns_fds: Vec<(String, File)> = Vec::new();

        for ns in ns_types {
            let ns_path = format!("/proc/{}/ns/{}", pid, ns);
            match File::open(&ns_path) {
                Ok(f) => ns_fds.push(((*ns).to_string(), f)),
                Err(e) => {
                    // Some namespaces may not be available
                    info!("Skipping namespace {}: {}", ns, e);
                }
            }
        }

        if ns_fds.is_empty() {
            return Err(NucleusError::AttachError(
                "Could not open any namespace FDs".to_string(),
            ));
        }

        Ok(ns_fds)
    }

    fn enter_namespaces(ns_fds: &[(String, File)]) -> Result<()> {
        // Enter user namespace first (required before other setns calls in
        // rootless containers), then non-PID namespaces.
        // PID namespace membership only applies to future children after setns().
        let mut pid_ns_fd: Option<&File> = None;

        // Phase 1: user namespace (must be first)
        for (ns_name, fd) in ns_fds {
            if ns_name == "user" {
                // SAFETY: fd is a valid open file descriptor obtained from /proc/<pid>/ns/user.
                // setns with CLONE_NEWUSER joins the user namespace; fd remains valid after the call.
                let ret = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWUSER) };
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(NucleusError::AttachError(format!(
                        "setns(user) failed: {}",
                        err
                    )));
                }
                info!("Entered user namespace");
            }
        }

        // Phase 2: non-PID, non-user namespaces
        for (ns_name, fd) in ns_fds {
            if ns_name == "pid" {
                pid_ns_fd = Some(fd);
                continue;
            }
            if ns_name == "user" {
                continue; // already joined above
            }

            let nstype = Self::ns_name_to_clone_flag(ns_name);
            let raw_fd = fd.as_raw_fd();
            // SAFETY: raw_fd is a valid open file descriptor from /proc/<pid>/ns/<ns>.
            // nstype is the correct clone flag for this namespace type.
            let ret = unsafe { libc::setns(raw_fd, nstype) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(NucleusError::AttachError(format!(
                    "setns({}) failed: {}",
                    ns_name, err
                )));
            }
            info!("Entered {} namespace", ns_name);
        }

        if let Some(fd) = pid_ns_fd {
            // SAFETY: fd is a valid open file descriptor from /proc/<pid>/ns/pid.
            // PID namespace takes effect on next fork, which follows immediately.
            let ret = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWPID) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(NucleusError::AttachError(format!(
                    "setns(pid) failed: {}",
                    err
                )));
            }
            info!("Entered pid namespace");

            // A second fork is required for PID namespace to take effect.
            match unsafe { fork() }.map_err(|e| {
                NucleusError::AttachError(format!("Fork failed after setns(pid): {}", e))
            })? {
                ForkResult::Parent { child } => {
                    let code = Self::wait_for_child(child)?;
                    std::process::exit(code);
                }
                ForkResult::Child => {
                    // Continue and exec below.
                }
            }
        }

        // Change to root directory of the namespace
        nix::unistd::chdir("/")
            .map_err(|e| NucleusError::AttachError(format!("chdir(\"/\") failed: {}", e)))?;

        Ok(())
    }

    fn apply_exec_hardening() -> Result<()> {
        // Apply security hardening before exec: no_new_privs + capability drop +
        // seccomp + Landlock (C4: attach/exec path must match container security).
        // SAFETY: PR_SET_NO_NEW_PRIVS with arg 1 is always safe to call; it only
        // restricts the calling thread's future privilege transitions.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(NucleusError::AttachError(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut cap_mgr = crate::security::CapabilityManager::new();
        cap_mgr.drop_all().map_err(|e| {
            NucleusError::AttachError(format!("Failed to drop capabilities: {}", e))
        })?;

        // Apply seccomp filter to match container's syscall restrictions
        let mut seccomp_mgr = crate::security::SeccompManager::new();
        if let Err(e) = seccomp_mgr.apply_minimal_filter() {
            tracing::warn!(
                "Failed to apply seccomp filter on attach: {} (continuing)",
                e
            );
        }

        // Apply Landlock filesystem restrictions
        let mut landlock_mgr = crate::security::LandlockManager::new();
        if let Err(e) = landlock_mgr.apply_container_policy_with_mode(true) {
            tracing::warn!("Failed to apply Landlock on attach: {} (continuing)", e);
        }

        Ok(())
    }

    fn default_exec_env() -> Result<Vec<CString>> {
        Ok(vec![
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .map_err(|e| NucleusError::AttachError(format!("Invalid PATH env: {}", e)))?,
            CString::new("TERM=xterm")
                .map_err(|e| NucleusError::AttachError(format!("Invalid TERM env: {}", e)))?,
            CString::new("HOME=/home/agent")
                .map_err(|e| NucleusError::AttachError(format!("Invalid HOME env: {}", e)))?,
        ])
    }

    fn exec_with_env(command: &[String], env: &[CString]) -> Result<()> {
        let program = CString::new(command[0].as_str())
            .map_err(|e| NucleusError::AttachError(format!("Invalid program name: {}", e)))?;

        let args: std::result::Result<Vec<CString>, _> = command
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect();
        let args =
            args.map_err(|e| NucleusError::AttachError(format!("Invalid argument: {}", e)))?;

        nix::unistd::execve::<CString, CString>(&program, &args, env)
            .map_err(|e| NucleusError::AttachError(format!("execve failed: {}", e)))?;

        Ok(())
    }

    fn ns_name_to_clone_flag(name: &str) -> libc::c_int {
        match name {
            "user" => libc::CLONE_NEWUSER,
            "pid" => libc::CLONE_NEWPID,
            "mnt" => libc::CLONE_NEWNS,
            "net" => libc::CLONE_NEWNET,
            "uts" => libc::CLONE_NEWUTS,
            "ipc" => libc::CLONE_NEWIPC,
            "cgroup" => libc::CLONE_NEWCGROUP,
            // L10: Unknown namespace type should not silently fall through to 0.
            // Log a warning and use 0 (kernel infers from FD) as a safe fallback.
            unknown => {
                tracing::warn!(
                    "Unknown namespace type '{}': setns will infer from FD (potential typo?)",
                    unknown
                );
                0
            }
        }
    }

    fn wait_for_child(child: Pid) -> Result<i32> {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    return Err(NucleusError::AttachError(format!("waitpid failed: {}", e)));
                }
                _ => continue,
            }
        }
    }
}

impl NamespaceCommandRunner {
    /// Run a probe-style helper inside the target container's namespaces.
    ///
    /// This enters namespaces in-process, then immediately applies
    /// `PR_SET_NO_NEW_PRIVS` and drops capabilities before executing any
    /// container-controlled binary. That avoids running helpers via a privileged
    /// host `nsenter` process.
    pub fn run(
        pid: u32,
        rootless: bool,
        using_gvisor: bool,
        probe: NamespaceProbe,
        process_identity: Option<&ProcessIdentity>,
        timeout: Option<Duration>,
    ) -> Result<bool> {
        if using_gvisor {
            return Err(NucleusError::ExecError(
                "Namespace-local exec probes are unsupported for gVisor containers".to_string(),
            ));
        }

        let ns_fds = ContainerAttach::open_namespace_fds(pid, rootless)?;

        match unsafe { fork() }.map_err(|e| {
            NucleusError::ExecError(format!("Failed to fork namespace helper: {}", e))
        })? {
            ForkResult::Parent { child } => Self::wait_for_probe(child, timeout),
            ForkResult::Child => {
                let exit_code =
                    match Self::enter_and_run(&ns_fds, probe, process_identity, rootless) {
                        Ok(true) => 0,
                        Ok(false) => 1,
                        Err(e) => {
                            eprintln!("Namespace helper failed: {}", e);
                            125
                        }
                    };
                std::process::exit(exit_code);
            }
        }
    }

    fn enter_and_run(
        ns_fds: &[(String, File)],
        probe: NamespaceProbe,
        process_identity: Option<&ProcessIdentity>,
        rootless: bool,
    ) -> Result<bool> {
        ContainerAttach::enter_namespaces(ns_fds)?;
        ContainerAttach::apply_exec_hardening()?;

        match probe {
            NamespaceProbe::Exec(command) => {
                if let Some(identity) = process_identity {
                    crate::container::Container::apply_process_identity_to_current_process(
                        identity, rootless,
                    )?;
                }
                let env = ContainerAttach::default_exec_env()?;
                ContainerAttach::exec_with_env(&command, &env)?;
                unreachable!()
            }
            NamespaceProbe::TcpConnect(port) => {
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                Ok(std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok())
            }
        }
    }

    fn wait_for_probe(child: Pid, timeout: Option<Duration>) -> Result<bool> {
        let start = Instant::now();
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    if let Some(limit) = timeout {
                        if start.elapsed() >= limit {
                            let _ =
                                nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                            let _ = waitpid(child, None);
                            return Ok(false);
                        }
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Ok(WaitStatus::Exited(_, code)) => return Ok(code == 0),
                Ok(WaitStatus::Signaled(_, _, _)) => return Ok(false),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed waiting for namespace helper: {}",
                        e
                    )));
                }
                _ => continue,
            }
        }
    }
}
