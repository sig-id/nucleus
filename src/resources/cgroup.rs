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
const CGROUP_CLEANUP_RETRIES: usize = 50;
const CGROUP_CLEANUP_SLEEP: Duration = Duration::from_millis(20);
const CGROUP_FREEZE_RETRIES: usize = 100;
const CGROUP_FREEZE_SLEEP: Duration = Duration::from_millis(10);

/// Cgroup v2 manager
///
/// Implements the cgroup lifecycle state machine from
/// Nucleus_Resources_CgroupLifecycle.tla
pub struct Cgroup {
    path: PathBuf,
    state: CgroupState,
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

        Ok(Self { path, state })
    }

    fn root_path() -> Result<PathBuf> {
        let path = Self::root_path_from_override(std::env::var_os(NUCLEUS_CGROUP_ROOT_ENV))?;
        Self::validate_root_path(&path)?;
        Ok(path)
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

    /// Write a value to a cgroup file
    fn write_value(&self, file: &str, value: &str) -> Result<()> {
        Self::write_value_at(&self.path, file, value)
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
        if !self.state.is_terminal() && self.path.exists() {
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
