use crate::container::{ContainerState, ContainerStateManager, ProcessIdentity};
use crate::error::{NucleusError, Result};
use crate::resources::Cgroup;
use crate::security::landlock_handoff::{load_launch_ruleset, restrict_to_launch_ruleset};
use crate::security::{NativeSeccomp, SeccompManager};
use nix::sys::signal::{kill, killpg, Signal};
use nix::sys::wait::{waitid, waitpid, Id, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
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

        let policy = Self::saved_policy(state)?;
        let landlock = load_launch_ruleset(state.landlock_socket.as_deref())?;
        let ns_fds = Self::open_namespace_fds(pid, state.rootless)?;
        Self::verify_target(state)?;

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
                match Self::enter_and_exec(state, policy, &landlock, &ns_fds, &command) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        eprintln!("Attach failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    fn saved_policy(state: &ContainerState) -> Result<&NativeSeccomp> {
        state.native_seccomp.as_ref().ok_or_else(|| NucleusError::AttachError(
            "Launch seccomp policy unavailable. Recreate the container to enable native helpers.".into()))
    }

    fn verify_target(state: &ContainerState) -> Result<()> {
        if !state.is_running() {
            return Err(NucleusError::AttachError(
                "Target process exited or changed during helper setup".into(),
            ));
        }
        Ok(())
    }

    fn enter_and_exec(
        state: &ContainerState,
        policy: &NativeSeccomp,
        landlock: &OwnedFd,
        ns_fds: &[(String, File)],
        command: &[String],
    ) -> Result<()> {
        if command.is_empty() {
            return Err(NucleusError::AttachError(
                "No command specified for attach".to_string(),
            ));
        }

        nix::sys::prctl::set_dumpable(false)?;
        Self::enter_namespaces(state, ns_fds)?;
        Self::apply_exec_hardening(state, policy, landlock)?;
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
                Ok(f) => {
                    if *ns == "net" {
                        // After joining a mapped user namespace the helper cannot
                        // setns back into the host network namespace it already occupies.
                        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
                        let target = f.metadata()?;
                        if current.dev() == target.dev() && current.ino() == target.ino() {
                            continue;
                        }
                    }
                    ns_fds.push(((*ns).to_string(), f));
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && *ns != "pid"
                        && *ns != "user" =>
                {
                    info!("Skipping unavailable namespace {}: {}", ns, e);
                }
                Err(e) => {
                    return Err(NucleusError::AttachError(format!(
                        "Failed to open {}: {}",
                        ns_path, e
                    )))
                }
            }
        }

        Ok(ns_fds)
    }

    fn enter_namespaces(state: &ContainerState, ns_fds: &[(String, File)]) -> Result<()> {
        if state.rootless && nix::unistd::Uid::effective().is_root() {
            nix::unistd::setgroups(&[])?;
        }
        if let Some(path) = &state.cgroup_path {
            Cgroup::join_existing(path.as_ref())?;
        }
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

    fn apply_exec_hardening(
        state: &ContainerState,
        policy: &NativeSeccomp,
        landlock: &OwnedFd,
    ) -> Result<()> {
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
        cap_mgr.drop_bounding_set()?;
        crate::container::Container::apply_process_identity_to_current_process(
            &ProcessIdentity {
                uid: state.process_uid,
                gid: state.process_gid,
                additional_gids: state.additional_gids.clone(),
            },
            state.rootless,
        )?;
        nix::sys::prctl::set_dumpable(false)?;
        cap_mgr.finalize_drop()?;
        if let Some(max) = state.pids_max {
            // Preserve any tighter limits the caller already had.
            let mut limits = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: limits is writable, then initialized by getrlimit.
            nix::errno::Errno::result(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limits) })?;
            limits.rlim_cur = limits.rlim_cur.min(max);
            limits.rlim_max = limits.rlim_max.min(max);
            nix::errno::Errno::result(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limits) })?;
        }

        restrict_to_launch_ruleset(landlock)?;

        // Install last. A service profile can deny the setup syscalls themselves.
        policy.apply()
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
            .map_err(|e| NucleusError::AttachError(format!("execve failed: {}", e)))?
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
        // PID-only callers resolve the launch record from the configured state root.
        // Internal callers already hold the record and also support --root overrides.
        let state = ContainerStateManager::new()?
            .list_running()?
            .into_iter()
            .find(|s| s.pid == pid && s.rootless == rootless && s.using_gvisor == using_gvisor)
            .ok_or_else(|| {
                NucleusError::ExecError("Missing running container state for probe".into())
            })?;
        if let Some(identity) = process_identity {
            if identity.uid != state.process_uid
                || identity.gid != state.process_gid
                || identity.additional_gids != state.additional_gids
            {
                return Err(NucleusError::ExecError(
                    "Probe identity differs from the workload".into(),
                ));
            }
        }
        Self::run_in_container(&state, probe, timeout)
    }

    pub fn run_in_container(
        state: &ContainerState,
        probe: NamespaceProbe,
        timeout: Option<Duration>,
    ) -> Result<bool> {
        if state.using_gvisor {
            return Err(NucleusError::ExecError(
                "Namespace-local probes are unsupported for gVisor containers".into(),
            ));
        }
        let policy = ContainerAttach::saved_policy(state)?;
        let landlock = load_launch_ruleset(state.landlock_socket.as_deref())?;
        let ns_fds = ContainerAttach::open_namespace_fds(state.pid, state.rootless)?;
        ContainerAttach::verify_target(state)?;

        match unsafe { fork() }.map_err(|e| {
            NucleusError::ExecError(format!("Failed to fork namespace helper: {}", e))
        })? {
            ForkResult::Parent { child } => Self::wait_for_probe(child, timeout),
            ForkResult::Child => {
                let exit_code = match Self::enter_and_run(
                    state,
                    policy,
                    &landlock,
                    &ns_fds,
                    probe,
                    timeout.is_some(),
                ) {
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
        state: &ContainerState,
        policy: &NativeSeccomp,
        landlock: &OwnedFd,
        ns_fds: &[(String, File)],
        probe: NamespaceProbe,
        timed: bool,
    ) -> Result<bool> {
        nix::sys::prctl::set_dumpable(false)?;
        if timed {
            // A fresh session excludes unrelated processes from the group.
            nix::unistd::setsid()?;
            SeccompManager::confine_probe_process_group()?;
        }
        ContainerAttach::enter_namespaces(state, ns_fds)?;
        ContainerAttach::apply_exec_hardening(state, policy, landlock)?;

        match probe {
            NamespaceProbe::Exec(command) => {
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
        let Some(limit) = timeout else {
            return Ok(ContainerAttach::wait_for_child(child)? == 0);
        };
        let start = Instant::now();
        // Keep the session leader waitable until group cleanup completes. This
        // pins the numeric PGID even if the command has already returned.
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
        let success = loop {
            match waitid(Id::Pid(child), flags) {
                Ok(WaitStatus::StillAlive) if start.elapsed() < limit => {
                    thread::sleep(
                        Duration::from_millis(50).min(limit.saturating_sub(start.elapsed())),
                    );
                }
                Ok(WaitStatus::StillAlive) => break false,
                Ok(WaitStatus::Exited(_, code)) => break code == 0,
                Ok(WaitStatus::Signaled(..)) => break false,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
                _ => continue,
            }
        };
        // A timeout can precede setsid(). Stop the leader first so it cannot
        // create a session or fork after the group signal.
        match kill(child, Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => (),
            Err(e) => return Err(e.into()),
        }
        let group_result = killpg(child, Signal::SIGKILL);
        ContainerAttach::wait_for_child(child)?;
        if group_result != Err(nix::errno::Errno::ESRCH) {
            group_result?;
        }
        Ok(success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    #[test]
    fn missing_launch_policy_and_invalid_cgroup_fail_closed() {
        use crate::container::{ContainerStateParams, OciStatus};
        let dir = tempfile::tempdir().unwrap();
        let mut state = ContainerState::new(ContainerStateParams {
            id: "helper".into(),
            name: "helper".into(),
            pid: std::process::id(),
            command: vec![],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: Some(dir.path().display().to_string()),
            process_uid: 0,
            process_gid: 0,
            additional_gids: vec![],
        });
        state.status = OciStatus::Running;
        let mut legacy = serde_json::to_value(&state).unwrap();
        legacy.as_object_mut().unwrap().remove("native_seccomp");
        let legacy = serde_json::from_value(legacy).unwrap();
        assert!(ContainerAttach::attach(&legacy, vec![])
            .unwrap_err()
            .to_string()
            .contains("Launch seccomp policy unavailable"));
        assert!(NamespaceCommandRunner::run_in_container(
            &legacy,
            NamespaceProbe::TcpConnect(1),
            None
        )
        .is_err());

        // A missing or substituted cgroup must stop setup before setns/fork.
        let procs = dir.path().join("cgroup.procs");
        for regular_file in [false, true] {
            if regular_file {
                fs::write(&procs, "untouched").unwrap();
            }
            assert!(matches!(
                ContainerAttach::enter_namespaces(&state, &[]),
                Err(NucleusError::CgroupError(_))
            ));
        }
        assert_eq!(fs::read_to_string(procs).unwrap(), "untouched");
    }

    #[test]
    fn timed_probe_cleans_up_descendants() {
        const FIXTURE: &str = "NUCLEUS_TIMEOUT_TEST_MARKER";
        if let Some(marker) = std::env::var_os(FIXTURE) {
            nix::unistd::setsid().unwrap();
            SeccompManager::confine_probe_process_group().unwrap();
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "sleep 30 & echo \"$$ $!\" > \"$1\"; wait", "probe"])
                .arg(marker);
            // Verify the inherited restrictions in a non-leader before exec.
            unsafe {
                command.pre_exec(|| {
                    for rc in [libc::setsid(), libc::setpgid(0, 0)] {
                        if rc != -1 || nix::errno::Errno::last() != nix::errno::Errno::EPERM {
                            return Err(std::io::Error::other("probe group confinement missing"));
                        }
                    }
                    Ok(())
                });
            }
            command.status().unwrap();
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("children");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolation::attach::tests::timed_probe_cleans_up_descendants",
            ])
            .env(FIXTURE, &marker)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let pids = loop {
            if let Some(pids) = fs::read_to_string(&marker)
                .ok()
                .filter(|s| s.split_whitespace().count() == 2)
            {
                break pids;
            }
            assert!(child.try_wait().unwrap().is_none(), "probe fixture exited");
            assert!(Instant::now() < deadline, "probe fixture did not start");
            thread::sleep(Duration::from_millis(10));
        };
        let child_pid = Pid::from_raw(child.id() as i32);
        assert!(!NamespaceCommandRunner::wait_for_probe(child_pid, Some(Duration::ZERO)).unwrap());
        for pid in pids.split_whitespace() {
            let path = format!("/proc/{pid}/stat");
            while let Ok(stat) = fs::read_to_string(&path) {
                if stat.rsplit_once(") ").unwrap().1.starts_with('Z') {
                    break;
                }
                assert!(Instant::now() < deadline, "probe descendant {pid} survived");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
