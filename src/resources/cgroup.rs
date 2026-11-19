use crate::error::{NucleusError, Result, StateTransition};
use crate::resources::{CgroupState, ResourceLimits};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const NUCLEUS_CGROUP_ROOT_ENV: &str = "NUCLEUS_CGROUP_ROOT";
/// Controllers behind the limits Nucleus can set.
const LIMIT_CONTROLLERS: &[&str] = &["cpu", "io", "memory", "pids"];
/// Leaf a supervisor moves into when it starts directly in its delegated cgroup.
const SUPERVISOR_LEAF: &str = "nucleus-supervisor";
const CGROUP_CLEANUP_RETRIES: usize = 50;
const CGROUP_CLEANUP_SLEEP: Duration = Duration::from_millis(20);
const CGROUP_FREEZE_RETRIES: usize = 100;
const CGROUP_FREEZE_SLEEP: Duration = Duration::from_millis(10);
/// Upper bound on asking the systemd user manager about a unit.
const SYSTEMD_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Cgroup v2 manager
///
/// Implements the cgroup lifecycle state machine from
/// Nucleus_Resources_CgroupLifecycle.tla
pub struct Cgroup {
    path: PathBuf,
    state: CgroupState,
    cleanup_on_drop: bool,
    /// Why the parent could not enable resource controllers, if it could not.
    controllers_error: Option<String>,
}

/// RAII guard for a frozen cgroup v2 subtree.
pub struct CgroupFreezeGuard {
    path: PathBuf,
    active: bool,
}

impl Cgroup {
    /// Create a new cgroup with the given name
    ///
    /// State transition: Nonexistent -> Created
    pub fn create(name: &str) -> Result<Self> {
        let root = Self::root_path()?;
        Self::create_in_root(name, &root)
    }

    fn create_in_root(name: &str, root: &Path) -> Result<Self> {
        Self::validate_cgroup_name(name)?;
        Self::validate_root_path(root)?;

        let state = CgroupState::Nonexistent.transition(CgroupState::Created)?;
        let path = root.join(name);

        info!("Creating cgroup at {:?}", path);

        // Create cgroup directory
        fs::create_dir_all(&path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to create cgroup directory: {}", e))
        })?;

        Self::validate_cgroup_directory(&path)?;

        // Without controllers the cgroup still tracks and kills the
        // workload; the reason is reported if a limit later cannot be set.
        let controllers_error = Self::enable_controllers(root)
            .inspect_err(|e| debug!("{e}"))
            .err()
            .map(|e| e.to_string());

        Ok(Self {
            path,
            state,
            cleanup_on_drop: true,
            controllers_error,
        })
    }

    /// Pick the parent for container cgroups.
    ///
    /// An explicit `NUCLEUS_CGROUP_ROOT` wins. Otherwise a subtree the service
    /// manager delegated to this caller is used, so an unprivileged
    /// orchestrator running in a `Delegate=yes` unit gets real resource
    /// enforcement. The cgroup filesystem root remains the fallback; only
    /// host root can create cgroups there.
    fn root_path() -> Result<PathBuf> {
        let path = match std::env::var_os(NUCLEUS_CGROUP_ROOT_ENV) {
            Some(raw) if !raw.is_empty() => Self::root_path_from_override(Some(raw))?,
            _ => match Self::delegated_root() {
                Some(delegated) => {
                    debug!("Using delegated cgroup subtree {:?}", delegated);
                    delegated
                }
                None => PathBuf::from(CGROUP_V2_ROOT),
            },
        };
        Self::validate_root_path(&path)?;
        Ok(path)
    }

    /// The cgroup this process is a member of, as a path on the v2 mount.
    fn own_cgroup_path() -> Option<PathBuf> {
        let membership = fs::read_to_string("/proc/self/cgroup").ok()?;
        Self::own_cgroup_path_from(&membership, Path::new(CGROUP_V2_ROOT))
    }

    fn own_cgroup_path_from(membership: &str, mount: &Path) -> Option<PathBuf> {
        // The unified hierarchy is the entry with hierarchy ID 0 and no
        // controller list: "0::/user.slice/...".
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?
            .trim_end_matches(" (deleted)");
        let relative = Path::new(relative).strip_prefix("/").ok()?;
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return None;
        }
        Some(mount.join(relative))
    }

    /// Find the subtree delegated to this process, if any.
    ///
    /// Ownership alone does not identify one: every cgroup below a systemd
    /// user manager is owned by the user, yet belongs to that manager. The
    /// system manager marks the boundary of a `Delegate=` unit with a
    /// `delegate` extended attribute. The user manager sets no marker, so for
    /// a unit below `user@<uid>.service` its `Delegate` property is read from
    /// the manager instead.
    ///
    /// Two layouts are recognised: this process sits directly in the
    /// delegated cgroup, or in a direct child of it (`DelegateSubgroup=`, the
    /// layout that leaves the delegated cgroup free of member processes).
    /// Deeper arrangements must name the root with `NUCLEUS_CGROUP_ROOT`.
    fn delegated_root() -> Option<PathBuf> {
        let own = Self::own_cgroup_path()?;
        Self::delegated_root_for(
            &own,
            Path::new(CGROUP_V2_ROOT),
            Self::is_delegated_to_caller,
        )
    }

    fn delegated_root_for(
        own: &Path,
        mount: &Path,
        is_delegated: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        [Some(own), own.parent()]
            .into_iter()
            .flatten()
            .filter(|candidate| candidate.starts_with(mount) && *candidate != mount)
            .find(|candidate| is_delegated(candidate))
            .map(Path::to_path_buf)
    }

    fn is_delegated_to_caller(path: &Path) -> bool {
        let writable = [
            path.to_path_buf(),
            path.join("cgroup.subtree_control"),
            path.join("cgroup.procs"),
        ]
        .iter()
        .all(|needed| nix::unistd::access(needed, nix::unistd::AccessFlags::W_OK).is_ok());
        writable
            && (Self::is_marked_delegated(path)
                || Self::user_manager_unit(
                    path,
                    Path::new(CGROUP_V2_ROOT),
                    nix::unistd::geteuid().as_raw(),
                    Self::is_marked_delegated,
                )
                .is_some_and(|unit| Self::user_manager_delegates(&unit, path)))
    }

    fn is_marked_delegated(path: &Path) -> bool {
        ["user.delegate", "trusted.delegate"]
            .iter()
            .any(|name| Self::read_xattr(path, name).as_deref() == Some(b"1".as_slice()))
    }

    /// The unit name of `path` when it is a service or scope of this user's
    /// systemd manager: below a `user@<uid>.service` the system manager
    /// marked as delegated to `uid`.
    fn user_manager_unit(
        path: &Path,
        mount: &Path,
        uid: u32,
        is_marked: impl Fn(&Path) -> bool,
    ) -> Option<String> {
        let unit = path.file_name()?.to_str()?;
        if !(unit.ends_with(".service") || unit.ends_with(".scope")) {
            return None;
        }
        let manager = format!("user@{uid}.service");
        path.ancestors()
            .skip(1)
            .take_while(|ancestor| ancestor.starts_with(mount) && *ancestor != mount)
            .find(|ancestor| ancestor.file_name().and_then(|n| n.to_str()) == Some(&manager))
            .filter(|ancestor| is_marked(ancestor))
            .map(|_| unit.to_string())
    }

    /// Ask this user's systemd manager whether `unit` is a `Delegate=` unit
    /// whose cgroup is `path`.
    fn user_manager_delegates(unit: &str, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(CGROUP_V2_ROOT) else {
            return false;
        };
        let mut command = std::process::Command::new("systemctl");
        command
            .args([
                "--user",
                "show",
                "--property=Delegate,ControlGroup",
                "--",
                unit,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            command.env(
                "XDG_RUNTIME_DIR",
                format!("/run/user/{}", nix::unistd::geteuid().as_raw()),
            );
        }
        let output = match Self::output_within(command, SYSTEMD_QUERY_TIMEOUT) {
            Ok(output) if output.status.success() => output,
            Ok(output) => {
                debug!("systemctl --user show {unit} failed: {}", output.status);
                return false;
            }
            Err(e) => {
                debug!("Cannot query the systemd user manager for {unit}: {e}");
                return false;
            }
        };
        let delegated = Self::parse_unit_delegation(
            &String::from_utf8_lossy(&output.stdout),
            &Path::new("/").join(relative),
        );
        debug!("systemd user manager reports {unit} delegated: {delegated}");
        delegated
    }

    /// Run `command`, killing it if it has not exited within `timeout`.
    fn output_within(
        mut command: std::process::Command,
        timeout: Duration,
    ) -> std::io::Result<std::process::Output> {
        let mut child = command.spawn()?;
        let deadline = std::time::Instant::now() + timeout;
        while child.try_wait()?.is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "systemctl did not answer",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        child.wait_with_output()
    }

    /// `systemctl show` output names a delegated unit whose cgroup is `cgroup`.
    fn parse_unit_delegation(output: &str, cgroup: &Path) -> bool {
        let value = |key: &str| {
            output
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        };
        value("Delegate") == Some("yes") && value("ControlGroup").map(Path::new) == Some(cgroup)
    }

    fn read_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let c_name = CString::new(name).ok()?;
        let mut value = [0u8; 16];
        // SAFETY: both strings are NUL-terminated and `value` is valid for
        // `value.len()` bytes of writes.
        let len = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        usize::try_from(len).ok().map(|len| value[..len].to_vec())
    }

    /// Make the resource controllers available to children of `root`.
    ///
    /// The cgroup filesystem root is left to the service manager. In a
    /// delegated subtree nobody else enables controllers for us.
    fn enable_controllers(root: &Path) -> Result<()> {
        if root == Path::new(CGROUP_V2_ROOT) {
            return Ok(());
        }
        let available = Self::read_value_at(root, "cgroup.controllers")?;
        let enabled = Self::read_value_at(root, "cgroup.subtree_control")?;
        let missing: Vec<&str> = LIMIT_CONTROLLERS
            .iter()
            .copied()
            .filter(|wanted| available.split_whitespace().any(|name| name == *wanted))
            .filter(|wanted| !enabled.split_whitespace().any(|name| name == *wanted))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let request = missing
            .iter()
            .map(|name| format!("+{name}"))
            .collect::<Vec<_>>()
            .join(" ");
        if Self::write_value_at(root, "cgroup.subtree_control", &request).is_ok() {
            return Ok(());
        }
        // A cgroup cannot both hold processes and distribute controllers. If
        // the only obstacle is this process, step into a leaf and retry;
        // other members are the delegatee's to place, not ours.
        if Self::own_cgroup_path().as_deref() == Some(root) {
            let leaf = root.join(SUPERVISOR_LEAF);
            match fs::create_dir(&leaf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(NucleusError::CgroupError(format!(
                        "Failed to create supervisor cgroup {leaf:?}: {e}"
                    )))
                }
            }
            Self::join_existing(&leaf)?;
        }
        Self::write_value_at(root, "cgroup.subtree_control", &request).map_err(|e| {
            NucleusError::CgroupError(format!(
                "cannot enable controllers ({request}) in {root:?}: {e}. A cgroup that has member \
                 processes cannot enable controllers for its children; run the caller in a \
                 sub-cgroup of the delegated unit (systemd DelegateSubgroup=)"
            ))
        })
    }

    fn root_path_from_override(raw: Option<OsString>) -> Result<PathBuf> {
        match raw {
            Some(raw) if !raw.as_os_str().is_empty() => {
                let path = PathBuf::from(raw);
                if !path.is_absolute() {
                    return Err(NucleusError::CgroupError(format!(
                        "{} must be an absolute path",
                        NUCLEUS_CGROUP_ROOT_ENV
                    )));
                }
                Ok(path)
            }
            _ => Ok(PathBuf::from(CGROUP_V2_ROOT)),
        }
    }

    fn validate_cgroup_name(name: &str) -> Result<()> {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return Err(NucleusError::CgroupError(
                "cgroup name must be a non-empty path component".to_string(),
            ));
        }

        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(_)), None) => Ok(()),
            _ => Err(NucleusError::CgroupError(
                "cgroup name must be a single relative path component".to_string(),
            )),
        }
    }

    fn validate_root_path(path: &Path) -> Result<()> {
        if !path.is_absolute() {
            return Err(NucleusError::CgroupError(format!(
                "{} must be an absolute path",
                NUCLEUS_CGROUP_ROOT_ENV
            )));
        }

        Self::validate_directory_not_symlink(path, "cgroup root")?;
        let canonical = fs::canonicalize(path).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Failed to canonicalize cgroup root {:?}: {}",
                path, e
            ))
        })?;
        let canonical_cgroup_root = fs::canonicalize(CGROUP_V2_ROOT).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Failed to canonicalize {} while validating cgroup root {:?}: {}",
                CGROUP_V2_ROOT, path, e
            ))
        })?;

        if !canonical.starts_with(&canonical_cgroup_root) {
            return Err(NucleusError::CgroupError(format!(
                "cgroup root {:?} must be inside {}",
                path, CGROUP_V2_ROOT
            )));
        }

        Self::ensure_path_on_cgroup2_fs(&canonical)?;
        Self::require_cgroup_control_file(&canonical.join("cgroup.controllers"))?;
        Self::require_cgroup_control_file(&canonical.join("cgroup.subtree_control"))?;
        Self::require_cgroup_control_file(&canonical.join("cgroup.procs"))?;
        Ok(())
    }

    fn validate_cgroup_directory(path: &Path) -> Result<()> {
        Self::validate_directory_not_symlink(path, "cgroup directory")?;
        Self::ensure_path_on_cgroup2_fs(path)?;
        Self::require_cgroup_control_file(&path.join("cgroup.procs"))?;
        Ok(())
    }

    fn validate_directory_not_symlink(path: &Path, description: &str) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Failed to inspect {} {:?}: {}",
                description, path, e
            ))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(NucleusError::CgroupError(format!(
                "{} {:?} must not be a symlink",
                description, path
            )));
        }
        if !file_type.is_dir() {
            return Err(NucleusError::CgroupError(format!(
                "{} {:?} must be a directory",
                description, path
            )));
        }
        Ok(())
    }

    fn require_cgroup_control_file(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Required cgroup control file {:?} is missing or inaccessible: {}",
                path, e
            ))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(NucleusError::CgroupError(format!(
                "cgroup control file {:?} must not be a symlink",
                path
            )));
        }
        if !file_type.is_file() {
            return Err(NucleusError::CgroupError(format!(
                "{:?} is not a cgroup control file",
                path
            )));
        }
        Self::ensure_path_on_cgroup2_fs(path)
    }

    fn ensure_path_on_cgroup2_fs(path: &Path) -> Result<()> {
        let statfs = Self::statfs_path(path)?;
        Self::ensure_cgroup2_magic(statfs.f_type, path)
    }

    fn ensure_fd_on_cgroup2_fs(fd: RawFd, path: &Path) -> Result<()> {
        let mut statfs = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `statfs` points to valid uninitialized storage and `fd` is
        // borrowed from an open file for the duration of this call.
        let rc = unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) };
        if rc != 0 {
            return Err(NucleusError::CgroupError(format!(
                "Failed to statfs opened cgroup control file {:?}: {}",
                path,
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fstatfs` returned success, so the kernel initialized the
        // struct.
        let statfs = unsafe { statfs.assume_init() };
        Self::ensure_cgroup2_magic(statfs.f_type, path)
    }

    fn statfs_path(path: &Path) -> Result<libc::statfs> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            NucleusError::CgroupError(format!("cgroup path {:?} contains an interior NUL", path))
        })?;
        let mut statfs = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `c_path` is a NUL-terminated path and `statfs` points to
        // valid uninitialized storage for the kernel to fill.
        let rc = unsafe { libc::statfs(c_path.as_ptr(), statfs.as_mut_ptr()) };
        if rc != 0 {
            return Err(NucleusError::CgroupError(format!(
                "Failed to statfs cgroup path {:?}: {}",
                path,
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `statfs` returned success, so the kernel initialized the
        // struct.
        Ok(unsafe { statfs.assume_init() })
    }

    fn ensure_cgroup2_magic(fs_type: libc::c_long, path: &Path) -> Result<()> {
        if fs_type != CGROUP2_SUPER_MAGIC {
            return Err(NucleusError::CgroupError(format!(
                "{:?} is not on a cgroup v2 filesystem",
                path
            )));
        }
        Ok(())
    }

    /// Set resource limits
    ///
    /// State transition: Created -> Configured
    pub fn set_limits(&mut self, limits: &ResourceLimits) -> Result<()> {
        self.state = self.state.transition(CgroupState::Configured)?;

        info!("Configuring cgroup limits: {:?}", limits);

        // Set memory limit
        if let Some(memory_bytes) = limits.memory_bytes {
            self.write_value("memory.max", &memory_bytes.to_string())?;
            debug!("Set memory.max = {}", memory_bytes);
        }

        // Set memory soft limit (high watermark)
        if let Some(memory_high) = limits.memory_high {
            self.write_value("memory.high", &memory_high.to_string())?;
            debug!("Set memory.high = {}", memory_high);
        }

        // Set swap limit
        if let Some(swap_max) = limits.memory_swap_max {
            self.write_value("memory.swap.max", &swap_max.to_string())?;
            debug!("Set memory.swap.max = {}", swap_max);
        }
        if limits.memory_bytes.is_some()
            || limits.memory_high.is_some()
            || limits.memory_swap_max.is_some()
        {
            self.write_value("memory.oom.group", "1")?;
            debug!("Set memory.oom.group = 1");
        }

        // Set CPU limit
        if let Some(cpu_quota_us) = limits.cpu_quota_us {
            let cpu_max = format!("{} {}", cpu_quota_us, limits.cpu_period_us);
            self.write_value("cpu.max", &cpu_max)?;
            debug!("Set cpu.max = {}", cpu_max);
        }

        // Set CPU weight
        if let Some(cpu_weight) = limits.cpu_weight {
            self.write_value("cpu.weight", &cpu_weight.to_string())?;
            debug!("Set cpu.weight = {}", cpu_weight);
        }

        // Set PID limit
        if let Some(pids_max) = limits.pids_max {
            self.write_value("pids.max", &pids_max.to_string())?;
            debug!("Set pids.max = {}", pids_max);
        }

        // Set I/O limits
        for io_limit in &limits.io_limits {
            let line = io_limit.to_io_max_line();
            self.write_value("io.max", &line)?;
            debug!("Set io.max: {}", line);
        }

        info!("Successfully configured cgroup limits");

        Ok(())
    }

    /// Attach a process to this cgroup
    ///
    /// State transition: Configured -> Attached
    pub fn attach_process(&mut self, pid: u32) -> Result<()> {
        self.state = self.state.transition(CgroupState::Attached)?;

        info!("Attaching process {} to cgroup", pid);

        self.write_value("cgroup.procs", &pid.to_string())?;

        info!("Successfully attached process to cgroup");

        Ok(())
    }

    /// Migrate this helper while its mount and cgroup views are still the host's.
    pub(crate) fn join_existing(path: &Path) -> Result<()> {
        Self::write_value_at(path, "cgroup.procs", "0")
    }

    /// Write a value to a cgroup file
    fn write_value(&self, file: &str, value: &str) -> Result<()> {
        Self::write_value_at(&self.path, file, value).map_err(|e| match &self.controllers_error {
            Some(reason) => NucleusError::CgroupError(format!("{e} ({reason})")),
            None => e,
        })
    }

    fn write_value_at(path: &Path, file: &str, value: &str) -> Result<()> {
        Self::validate_cgroup_name(file)?;
        let file_path = path.join(file);
        let mut control_file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&file_path)
            .map_err(|e| {
                NucleusError::CgroupError(format!(
                    "Failed to open cgroup control file {:?}: {}",
                    file_path, e
                ))
            })?;
        Self::ensure_fd_on_cgroup2_fs(control_file.as_raw_fd(), &file_path)?;
        control_file.write_all(value.as_bytes()).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Failed to write {} to {:?}: {}",
                value, file_path, e
            ))
        })?;
        Ok(())
    }

    /// Read a value from a cgroup file
    fn read_value(&self, file: &str) -> Result<String> {
        Self::read_value_at(&self.path, file)
    }

    fn read_value_at(path: &Path, file: &str) -> Result<String> {
        Self::validate_cgroup_name(file)?;
        let file_path = path.join(file);
        fs::read_to_string(&file_path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to read {:?}: {}", file_path, e))
        })
    }

    fn set_frozen(&self, frozen: bool) -> Result<bool> {
        let freeze_path = self.path.join("cgroup.freeze");
        if !freeze_path.exists() {
            return Ok(false);
        }
        self.write_value("cgroup.freeze", if frozen { "1" } else { "0" })?;
        debug!("Set cgroup.freeze = {}", if frozen { 1 } else { 0 });
        Ok(true)
    }

    fn parse_cgroup_events_bool(events: &str, key: &str) -> Result<bool> {
        for line in events.lines() {
            if let Some(value) = line
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(' '))
            {
                return match value.trim() {
                    "0" => Ok(false),
                    "1" => Ok(true),
                    other => Err(NucleusError::CgroupError(format!(
                        "Unexpected {} value in cgroup.events: {}",
                        key, other
                    ))),
                };
            }
        }
        Err(NucleusError::CgroupError(format!(
            "Missing {} entry in cgroup.events",
            key
        )))
    }

    fn parse_cgroup_events_populated(events: &str) -> Result<bool> {
        Self::parse_cgroup_events_bool(events, "populated")
    }

    fn read_cgroup_events_frozen(path: &Path) -> Result<bool> {
        let events = Self::read_value_at(path, "cgroup.events")?;
        Self::parse_cgroup_events_bool(&events, "frozen")
    }

    fn wait_for_frozen_state(path: &Path, frozen: bool) -> Result<()> {
        let events_path = path.join("cgroup.events");
        if !events_path.exists() {
            return Ok(());
        }

        for attempt in 0..CGROUP_FREEZE_RETRIES {
            if Self::read_cgroup_events_frozen(path)? == frozen {
                return Ok(());
            }
            if attempt + 1 < CGROUP_FREEZE_RETRIES {
                thread::sleep(CGROUP_FREEZE_SLEEP);
            }
        }

        Err(NucleusError::CgroupError(format!(
            "Timed out waiting for cgroup {:?} to become {}",
            path,
            if frozen { "frozen" } else { "thawed" }
        )))
    }

    /// Freeze an existing cgroup v2 subtree until the returned guard is dropped.
    pub fn freeze_existing(path: &Path) -> Result<CgroupFreezeGuard> {
        Self::validate_cgroup_directory(path)?;
        let freeze_path = path.join("cgroup.freeze");
        if !freeze_path.exists() {
            return Err(NucleusError::CgroupError(format!(
                "Cgroup {:?} does not support cgroup.freeze",
                path
            )));
        }

        Self::write_value_at(path, "cgroup.freeze", "1")?;
        Self::wait_for_frozen_state(path, true)?;
        debug!("Frozen cgroup {:?}", path);
        Ok(CgroupFreezeGuard {
            path: path.to_path_buf(),
            active: true,
        })
    }

    fn read_pids(&self) -> Result<Vec<Pid>> {
        let file_path = self.path.join("cgroup.procs");
        if !file_path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&file_path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to read {:?}: {}", file_path, e))
        })?;
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.trim().parse::<i32>().map(Pid::from_raw).map_err(|e| {
                    NucleusError::CgroupError(format!(
                        "Failed to parse pid '{}' from {:?}: {}",
                        line.trim(),
                        file_path,
                        e
                    ))
                })
            })
            .collect()
    }

    fn is_populated(&self) -> Result<bool> {
        let events_path = self.path.join("cgroup.events");
        if events_path.exists() {
            let events = fs::read_to_string(&events_path).map_err(|e| {
                NucleusError::CgroupError(format!("Failed to read {:?}: {}", events_path, e))
            })?;
            return Self::parse_cgroup_events_populated(&events);
        }
        Ok(!self.read_pids()?.is_empty())
    }

    fn kill_visible_processes(&self) -> Result<()> {
        for pid in self.read_pids()? {
            match kill(pid, Signal::SIGKILL) {
                Ok(()) => {}
                Err(nix::errno::Errno::ESRCH) => {}
                Err(e) => {
                    return Err(NucleusError::CgroupError(format!(
                        "Failed to SIGKILL pid {} in {:?}: {}",
                        pid, self.path, e
                    )))
                }
            }
        }
        Ok(())
    }

    fn kill_all_processes(&self) -> Result<()> {
        let kill_path = self.path.join("cgroup.kill");
        if kill_path.exists() {
            self.write_value("cgroup.kill", "1")?;
            debug!("Triggered cgroup.kill for {:?}", self.path);
        }
        self.kill_visible_processes()
    }

    fn wait_until_empty(&self) -> Result<()> {
        for attempt in 0..CGROUP_CLEANUP_RETRIES {
            if !self.is_populated()? {
                return Ok(());
            }
            if attempt + 1 < CGROUP_CLEANUP_RETRIES {
                self.kill_visible_processes()?;
                thread::sleep(CGROUP_CLEANUP_SLEEP);
            }
        }

        let remaining = self
            .read_pids()?
            .into_iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>();
        Err(NucleusError::CgroupError(format!(
            "Timed out waiting for cgroup {:?} to drain (remaining pids: {})",
            self.path,
            if remaining.is_empty() {
                "<unknown>".to_string()
            } else {
                remaining.join(", ")
            }
        )))
    }

    /// Get current memory usage
    pub fn memory_current(&self) -> Result<u64> {
        let value = self.read_value("memory.current")?;
        value.trim().parse().map_err(|e| {
            NucleusError::CgroupError(format!("Failed to parse memory.current: {}", e))
        })
    }

    /// Install a cgroup v2 device allowlist (`BPF_PROG_TYPE_CGROUP_DEVICE`).
    ///
    /// When GPU passthrough is enabled, this restricts device access to the
    /// base `/dev` nodes plus the bound GPU devices, so a compromised workload
    /// cannot reach other host devices even if it creates a device node.
    ///
    /// `supervisor_specs` lists host devices required by the gVisor supervisor
    /// itself (e.g. `/dev/kvm` for the KVM platform backend). The parent
    /// attaches the runsc process to this cgroup before the sandbox starts, so
    /// those entries are required for runsc to boot; the sandboxed workload
    /// still cannot reach them.
    ///
    /// `best_effort` matches `--allow-degraded-security`: when `true`, a kernel
    /// or capability limitation degrades to a warning rather than failing the
    /// launch, because the filesystem layer (only bound device nodes exist in
    /// `/dev`) remains the primary gate.
    pub fn install_gpu_device_allowlist(
        &self,
        gpu_specs: &[crate::filesystem::DeviceNodeSpec],
        supervisor_specs: &[crate::filesystem::DeviceNodeSpec],
        include_tty: bool,
        best_effort: bool,
    ) -> Result<bool> {
        use crate::resources::{base_device_specs, install_device_allowlist, DeviceAllowSpec};
        let mut specs: Vec<DeviceAllowSpec> = base_device_specs(include_tty);
        for dev in supervisor_specs.iter().chain(gpu_specs) {
            specs.push(DeviceAllowSpec {
                is_block: dev.is_block,
                major: dev.major,
                minor: dev.minor,
            });
        }
        install_device_allowlist(&self.path, &specs, best_effort)
    }

    /// The registered, detached workload now owns this cgroup's lifetime.
    pub(crate) fn leave_registered(mut self) {
        self.cleanup_on_drop = false;
    }

    /// Open and validate the migration fd before forking the restore helper.
    pub(crate) fn membership_file(&self) -> Result<fs::File> {
        let path = self.path.join("cgroup.procs");
        let file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        Self::ensure_fd_on_cgroup2_fs(file.as_raw_fd(), &path)?;
        Ok(file)
    }

    /// Get cgroup path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the current state of this cgroup
    pub fn state(&self) -> CgroupState {
        self.state
    }

    /// Clean up the cgroup
    ///
    /// State transition: * -> Removed (only on success)
    pub fn cleanup(mut self) -> Result<()> {
        info!("Cleaning up cgroup {:?}", self.path);

        if self.path.exists() {
            let froze = self.set_frozen(true)?;
            let cleanup_result: Result<()> = (|| {
                self.kill_all_processes()?;
                self.wait_until_empty()?;
                fs::remove_dir(&self.path).map_err(|e| {
                    // BUG-06: Do NOT set state to Removed on failure – Drop should
                    // still attempt cleanup when the Cgroup is dropped.
                    NucleusError::CgroupError(format!("Failed to remove cgroup: {}", e))
                })?;
                Ok(())
            })();
            if cleanup_result.is_err() && froze {
                if let Err(e) = self.set_frozen(false) {
                    warn!(
                        "Failed to unfreeze cgroup {:?} after cleanup error: {}",
                        self.path, e
                    );
                }
            }
            cleanup_result?;
        }

        // Only mark as terminal after successful removal
        self.state = CgroupState::Removed;
        info!("Successfully cleaned up cgroup");

        Ok(())
    }
}

impl Drop for CgroupFreezeGuard {
    fn drop(&mut self) {
        if self.active && self.path.exists() {
            if let Err(e) = Cgroup::write_value_at(&self.path, "cgroup.freeze", "0")
                .and_then(|_| Cgroup::wait_for_frozen_state(&self.path, false))
            {
                warn!("Failed to thaw cgroup {:?}: {}", self.path, e);
            }
            self.active = false;
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.cleanup_on_drop && !self.state.is_terminal() && self.path.exists() {
            let froze = self.set_frozen(true).unwrap_or(false);
            let _ = self.kill_all_processes();
            let _ = self.wait_until_empty();
            let _ = fs::remove_dir(&self.path);
            if self.path.exists() && froze {
                let _ = self.set_frozen(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::symlink;
    use std::sync::Mutex;

    static CGROUP_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_resource_limits_unlimited() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.memory_bytes.is_none());
        assert!(limits.memory_high.is_none());
        assert!(limits.memory_swap_max.is_none());
        assert!(limits.cpu_quota_us.is_none());
        assert!(limits.cpu_weight.is_none());
        assert!(limits.pids_max.is_none());
        assert!(limits.io_limits.is_empty());
    }

    #[test]
    fn test_cgroup_root_override_requires_absolute_path() {
        assert_eq!(
            Cgroup::root_path_from_override(None).unwrap(),
            PathBuf::from(CGROUP_V2_ROOT)
        );
        assert_eq!(
            Cgroup::root_path_from_override(Some(OsString::from(""))).unwrap(),
            PathBuf::from(CGROUP_V2_ROOT)
        );
        assert_eq!(
            Cgroup::root_path_from_override(Some(OsString::from("/sys/fs/cgroup/example.service")))
                .unwrap(),
            PathBuf::from("/sys/fs/cgroup/example.service")
        );
        assert!(Cgroup::root_path_from_override(Some(OsString::from("relative"))).is_err());
    }

    #[test]
    fn own_cgroup_is_read_from_the_unified_hierarchy_entry() {
        let mount = Path::new("/sys/fs/cgroup");
        let own = |membership| Cgroup::own_cgroup_path_from(membership, mount);
        assert_eq!(
            own("0::/system.slice/mitos.service/supervisor\n"),
            Some(PathBuf::from(
                "/sys/fs/cgroup/system.slice/mitos.service/supervisor"
            ))
        );
        // Hybrid hosts list v1 hierarchies first.
        assert_eq!(
            own("12:pids:/user.slice\n1:name=systemd:/x\n0::/unit.scope\n"),
            Some(PathBuf::from("/sys/fs/cgroup/unit.scope"))
        );
        assert_eq!(own("0::/\n"), Some(mount.to_path_buf()));
        assert_eq!(own("1:name=systemd:/x\n"), None);
        assert_eq!(own("0::/../escape\n"), None);
    }

    #[test]
    fn delegated_root_is_the_marked_cgroup_or_its_parent() {
        let mount = Path::new("/sys/fs/cgroup");
        let unit = mount.join("system.slice/mitos.service");
        let leaf = unit.join("supervisor");
        let marked = |target: PathBuf| move |candidate: &Path| candidate == target;

        // DelegateSubgroup= layout: the process sits one level below.
        assert_eq!(
            Cgroup::delegated_root_for(&leaf, mount, marked(unit.clone())),
            Some(unit.clone())
        );
        // The process sits directly in the delegated cgroup.
        assert_eq!(
            Cgroup::delegated_root_for(&unit, mount, marked(unit.clone())),
            Some(unit.clone())
        );
        // A marked grandparent belongs to whoever manages the levels between.
        assert_eq!(
            Cgroup::delegated_root_for(&leaf.join("deeper"), mount, marked(unit.clone())),
            None
        );
        assert_eq!(Cgroup::delegated_root_for(&leaf, mount, |_| false), None);
        // The filesystem root is never treated as a delegated subtree.
        assert_eq!(
            Cgroup::delegated_root_for(&mount.join("top"), mount, |_| true),
            Some(mount.join("top"))
        );
        assert_eq!(Cgroup::delegated_root_for(mount, mount, |_| true), None);
    }

    #[test]
    fn user_manager_units_are_found_below_the_marked_manager() {
        let mount = Path::new("/sys/fs/cgroup");
        let manager = mount.join("user.slice/user-1000.slice/user@1000.service");
        let marked = |target: PathBuf| move |candidate: &Path| candidate == target;
        let unit =
            |path: &Path, uid| Cgroup::user_manager_unit(path, mount, uid, marked(manager.clone()));

        let scope = manager.join("app.slice/run-p1-i2.scope");
        assert_eq!(unit(&scope, 1000).as_deref(), Some("run-p1-i2.scope"));
        let service = manager.join("app.slice/mitos.service");
        assert_eq!(unit(&service, 1000).as_deref(), Some("mitos.service"));
        // A DelegateSubgroup= child and slices are not units.
        assert_eq!(unit(&service.join("sup"), 1000), None);
        assert_eq!(unit(&manager.join("app.slice"), 1000), None);
        // Another user's manager, or an unmarked one, is not ours to ask.
        assert_eq!(unit(&scope, 1001), None);
        assert_eq!(
            Cgroup::user_manager_unit(&scope, mount, 1000, |_| false),
            None
        );
        // System units are covered by the system manager's marker.
        assert_eq!(unit(&mount.join("system.slice/mitos.service"), 1000), None);
    }

    #[test]
    fn unit_delegation_requires_delegate_and_matching_cgroup() {
        let cgroup = Path::new("/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope");
        let show = |delegate: &str, group: &str| {
            Cgroup::parse_unit_delegation(
                &format!("Delegate={delegate}\nControlGroup={group}\n"),
                cgroup,
            )
        };
        assert!(show("yes", cgroup.to_str().unwrap()));
        assert!(!show("no", cgroup.to_str().unwrap()));
        // A unit of that name elsewhere does not delegate this cgroup.
        assert!(!show("yes", "/user.slice/other.scope"));
        assert!(!show("yes", ""));
        assert!(!Cgroup::parse_unit_delegation("", cgroup));
    }

    #[test]
    fn unmarked_cgroups_are_not_delegated() {
        // The cgroup root carries no delegation marker.
        assert!(!Cgroup::is_delegated_to_caller(Path::new(CGROUP_V2_ROOT)));
        assert!(!Cgroup::is_delegated_to_caller(Path::new("/nonexistent")));
    }

    #[test]
    fn test_cgroup_name_must_be_single_path_component() {
        assert!(Cgroup::validate_cgroup_name("nucleus-abc123").is_ok());
        assert!(Cgroup::validate_cgroup_name("").is_err());
        assert!(Cgroup::validate_cgroup_name("../escape").is_err());
        assert!(Cgroup::validate_cgroup_name("/sys/fs/cgroup/escape").is_err());
        assert!(Cgroup::validate_cgroup_name("parent/child").is_err());
    }

    #[test]
    fn test_parse_cgroup_events_bool_reads_frozen_state() {
        let events = "populated 1\nfrozen 0\n";
        assert!(!Cgroup::parse_cgroup_events_bool(events, "frozen").unwrap());
        assert!(Cgroup::parse_cgroup_events_bool("frozen 1\n", "frozen").unwrap());
        assert!(Cgroup::parse_cgroup_events_bool("frozen 2\n", "frozen").is_err());
        assert!(Cgroup::parse_cgroup_events_bool("populated 1\n", "frozen").is_err());
    }

    #[test]
    fn test_cgroup_root_validation_rejects_regular_filesystem() {
        let temp = tempfile::tempdir().unwrap();

        assert!(Cgroup::validate_root_path(temp.path()).is_err());
    }

    #[test]
    fn test_create_rejects_regular_filesystem_root_before_child_creation() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("nucleus-bypass");

        assert!(Cgroup::create_in_root("nucleus-bypass", temp.path()).is_err());
        assert!(
            !child.exists(),
            "regular filesystem root must be rejected before creating a fake cgroup"
        );
    }

    #[test]
    fn test_cgroup_root_env_rejects_regular_filesystem() {
        let _guard = CGROUP_ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os(NUCLEUS_CGROUP_ROOT_ENV);
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("nucleus-bypass");

        std::env::set_var(NUCLEUS_CGROUP_ROOT_ENV, temp.path().as_os_str());
        let result = Cgroup::create("nucleus-bypass");
        match previous {
            Some(value) => std::env::set_var(NUCLEUS_CGROUP_ROOT_ENV, value),
            None => std::env::remove_var(NUCLEUS_CGROUP_ROOT_ENV),
        }

        assert!(result.is_err());
        assert!(
            !child.exists(),
            "regular filesystem override must be rejected before creating a fake cgroup"
        );
    }

    #[test]
    fn test_write_value_rejects_preexisting_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fake-cgroup");
        fs::create_dir(&path).unwrap();
        let control_file = path.join("memory.max");
        fs::write(&control_file, "old").unwrap();

        let cgroup = Cgroup {
            cleanup_on_drop: true,
            controllers_error: None,
            path,
            state: CgroupState::Removed,
        };
        assert!(cgroup.write_value("memory.max", "123").is_err());
        assert_eq!(fs::read_to_string(control_file).unwrap(), "old");
    }

    #[test]
    fn test_write_value_rejects_symlink_control_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fake-cgroup");
        let target = temp.path().join("target");
        fs::create_dir(&path).unwrap();
        fs::write(&target, "old").unwrap();
        symlink(&target, path.join("memory.max")).unwrap();

        let cgroup = Cgroup {
            cleanup_on_drop: true,
            controllers_error: None,
            path,
            state: CgroupState::Removed,
        };
        assert!(cgroup.write_value("memory.max", "123").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "old");
    }

    // Note: Testing actual cgroup operations requires root privileges
    // and cgroup v2 filesystem. These are tested in integration tests.

    #[test]
    fn test_cleanup_sets_removed_only_after_success() {
        // BUG-06: cleanup must not mark state as Removed before the directory
        // is actually removed. Verify structurally by brace-matching the
        // function body instead of using a fragile char-window offset.
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn cleanup").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let cleanup_body = &after[..fn_end];
        let removed_pos = cleanup_body
            .find("Removed")
            .expect("must reference Removed state");
        let remove_dir_pos = cleanup_body
            .find("remove_dir")
            .expect("must call remove_dir");
        assert!(
            removed_pos > remove_dir_pos,
            "CgroupState::Removed must be set AFTER remove_dir succeeds, not before"
        );
    }

    #[test]
    fn test_parse_cgroup_events_populated() {
        assert!(Cgroup::parse_cgroup_events_populated("populated 1\nfrozen 0\n").unwrap());
        assert!(!Cgroup::parse_cgroup_events_populated("frozen 0\npopulated 0\n").unwrap());
    }

    #[test]
    fn test_set_limits_source_enables_memory_oom_group() {
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn set_limits").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..fn_end];
        assert!(
            body.contains("memory.oom.group"),
            "set_limits must enable memory.oom.group when memory controls are configured"
        );
    }

    #[test]
    fn test_cleanup_source_kills_processes_before_remove_dir() {
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn cleanup").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..fn_end];
        let freeze_pos = body.find("set_frozen(true)").unwrap();
        let kill_pos = body.find("kill_all_processes").unwrap();
        let remove_dir_pos = body.find("remove_dir").unwrap();
        assert!(
            freeze_pos < kill_pos && kill_pos < remove_dir_pos,
            "cleanup must freeze and kill the cgroup before attempting remove_dir"
        );
    }
}
