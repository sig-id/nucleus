use crate::container::RootfsMode;
use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// OCI-compliant container status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OciStatus {
    /// Container is being created
    Creating,
    /// Container has been created but not started
    Created,
    /// Container process is running
    Running,
    /// Container process has stopped
    Stopped,
}

impl std::fmt::Display for OciStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OciStatus::Creating => write!(f, "creating"),
            OciStatus::Created => write!(f, "created"),
            OciStatus::Running => write!(f, "running"),
            OciStatus::Stopped => write!(f, "stopped"),
        }
    }
}

/// Container state tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// Container ID (unique 32 hex chars, 128-bit)
    pub id: String,

    /// Container name (user-supplied or same as ID)
    pub name: String,

    /// PID of the container process
    pub pid: u32,

    /// Command being executed
    pub command: Vec<String>,

    /// Environment variables supplied at container launch.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,

    /// Working directory supplied at container launch.
    #[serde(default = "default_workdir")]
    pub workdir: String,

    /// Start time (Unix timestamp)
    pub started_at: u64,

    /// Memory limit in bytes (None = unlimited)
    pub memory_limit: Option<u64>,

    /// CPU limit in millicores (None = unlimited)
    pub cpu_limit: Option<u64>,

    /// Whether using gVisor runtime
    pub using_gvisor: bool,

    /// Whether using rootless mode
    pub rootless: bool,

    /// cgroup path
    pub cgroup_path: Option<String>,

    /// Desired topology config hash associated with this container, if any.
    #[serde(default)]
    pub config_hash: Option<u64>,

    /// UID of the user who created this container
    #[serde(default)]
    pub creator_uid: u32,

    /// Effective uid of the workload process inside the container.
    #[serde(default)]
    pub process_uid: u32,

    /// Effective gid of the workload process inside the container.
    #[serde(default)]
    pub process_gid: u32,

    /// Supplementary gids of the workload process inside the container.
    #[serde(default)]
    pub additional_gids: Vec<u32>,

    /// Process start time in clock ticks (from /proc/`<pid>`/stat field 22)
    /// Used to detect PID reuse in is_running()
    #[serde(default)]
    pub start_ticks: u64,

    /// OCI container status
    #[serde(default = "default_oci_status")]
    pub status: OciStatus,

    /// OCI bundle path
    #[serde(default)]
    pub bundle_path: Option<String>,

    /// OCI annotations
    #[serde(default)]
    pub annotations: HashMap<String, String>,

    /// Rootfs path used to launch the container, if any.
    #[serde(default)]
    pub rootfs_path: Option<String>,

    /// Rootfs mount mode used at launch.
    #[serde(default)]
    pub rootfs_mode: RootfsMode,

    /// Persistent overlayfs upperdir for image commit, if rootfs_mode=overlay.
    #[serde(default)]
    pub rootfs_upperdir: Option<String>,

    /// Persistent overlayfs workdir paired with rootfs_upperdir.
    #[serde(default)]
    pub rootfs_workdir: Option<String>,
}

fn default_oci_status() -> OciStatus {
    OciStatus::Stopped
}

fn default_workdir() -> String {
    "/workspace".to_string()
}

/// Parameters for creating a new `ContainerState`.
pub struct ContainerStateParams {
    pub id: String,
    pub name: String,
    pub pid: u32,
    pub command: Vec<String>,
    pub memory_limit: Option<u64>,
    pub cpu_limit: Option<u64>,
    pub using_gvisor: bool,
    pub rootless: bool,
    pub cgroup_path: Option<String>,
    pub process_uid: u32,
    pub process_gid: u32,
    pub additional_gids: Vec<u32>,
}

impl ContainerState {
    /// Create a new container state from the given parameters.
    pub fn new(params: ContainerStateParams) -> Self {
        let started_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let start_ticks = Self::read_start_ticks(params.pid);

        Self {
            id: params.id,
            name: params.name,
            pid: params.pid,
            command: params.command,
            environment: BTreeMap::new(),
            workdir: default_workdir(),
            started_at,
            memory_limit: params.memory_limit,
            cpu_limit: params.cpu_limit,
            using_gvisor: params.using_gvisor,
            rootless: params.rootless,
            cgroup_path: params.cgroup_path,
            config_hash: None,
            creator_uid: nix::unistd::Uid::effective().as_raw(),
            process_uid: params.process_uid,
            process_gid: params.process_gid,
            additional_gids: params.additional_gids,
            start_ticks,
            status: OciStatus::Creating,
            bundle_path: None,
            annotations: HashMap::new(),
            rootfs_path: None,
            rootfs_mode: RootfsMode::Bind,
            rootfs_upperdir: None,
            rootfs_workdir: None,
        }
    }

    /// Read the start time in clock ticks from /proc/<pid>/stat (field 22)
    ///
    /// BUG-09: After fork, /proc/<pid>/stat may not be immediately available.
    /// Retry a few times with short sleeps to avoid returning 0 and breaking
    /// PID-reuse detection in is_running().
    fn read_start_ticks(pid: u32) -> u64 {
        let stat_path = format!("/proc/{}/stat", pid);
        for attempt in 0..5 {
            if let Ok(content) = std::fs::read_to_string(&stat_path) {
                if let Some(ticks) = Self::parse_start_ticks(&content) {
                    return ticks;
                }
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        0
    }

    /// Parse start time (field 22) from /proc/<pid>/stat content
    fn parse_start_ticks(content: &str) -> Option<u64> {
        // Field 2 (comm) is in parens and may contain spaces; find last ')'
        let after_comm = content.rfind(')')?;
        // After ')' we have fields 3..N; field 22 is index 19 (22 - 3 = 19)
        // Use nth() instead of collecting into a Vec to avoid a heap allocation
        // on every liveness check.
        content[after_comm + 2..]
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }

    /// Check if the container process is still running
    ///
    /// Cross-checks PID start time to detect PID reuse after process exit.
    /// Also returns false if the OCI status is `Stopped`.
    pub fn is_running(&self) -> bool {
        if self.status == OciStatus::Stopped {
            return false;
        }
        let stat_path = format!("/proc/{}/stat", self.pid);
        match std::fs::read_to_string(&stat_path) {
            Ok(content) => {
                if self.start_ticks == 0 {
                    // PID existence alone is insufficient because the PID may have
                    // been recycled since this state was recorded.
                    return false;
                }
                Self::parse_start_ticks(&content)
                    .map(|ticks| ticks == self.start_ticks)
                    .unwrap_or(false)
            }
            Err(_) => false,
        }
    }

    /// Return OCI runtime state as a JSON value
    pub fn oci_state(&self) -> serde_json::Value {
        let live_status = match self.status {
            OciStatus::Running if !self.is_running() => "stopped",
            OciStatus::Creating => "creating",
            OciStatus::Created => "created",
            OciStatus::Running => "running",
            OciStatus::Stopped => "stopped",
        };
        serde_json::json!({
            "ociVersion": "1.0.2",
            "id": self.id,
            "status": live_status,
            "pid": if live_status == "stopped" { 0 } else { self.pid },
            "bundle": self.bundle_path.as_deref().unwrap_or(""),
            "annotations": self.annotations,
        })
    }

    /// Get uptime in seconds
    pub fn uptime(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.started_at)
    }
}

/// Container state manager
///
/// Manages persistent state of running containers
pub struct ContainerStateManager {
    state_dir: PathBuf,
}

impl ContainerStateManager {
    /// Create a state manager rooted at an explicit directory, falling back to
    /// default candidates if `root` is `None`.
    pub fn new_with_root(root: Option<PathBuf>) -> Result<Self> {
        if let Some(root) = root {
            return Self::with_state_dir(root);
        }
        Self::new()
    }

    /// Create a new state manager
    ///
    /// Creates the state directory if it doesn't exist
    pub fn new() -> Result<Self> {
        let mut last_error = None;
        for candidate in Self::default_state_dir_candidates() {
            match Self::with_state_dir(candidate.clone()) {
                Ok(manager) => return Ok(manager),
                Err(err) => {
                    debug!(
                        path = ?candidate,
                        error = %err,
                        "State directory candidate unavailable, trying next fallback"
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            NucleusError::ConfigError("No usable state directory candidates found".to_string())
        }))
    }

    /// Create a state manager rooted at an explicit directory.
    pub fn with_state_dir(state_dir: PathBuf) -> Result<Self> {
        Self::reject_symlink_path(&state_dir)?;

        // Create state directory if it doesn't exist (idempotent)
        fs::create_dir_all(&state_dir).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to create state directory {:?}: {}",
                state_dir, e
            ))
        })?;
        Self::reject_symlink_path(&state_dir)?;
        Self::ensure_secure_state_dir_permissions(&state_dir)?;
        Self::ensure_state_dir_writable(&state_dir)?;

        Ok(Self { state_dir })
    }

    fn reject_symlink_path(state_dir: &Path) -> Result<()> {
        match fs::symlink_metadata(state_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(NucleusError::ConfigError(format!(
                    "Refusing symlink state directory path {:?}; use a real directory",
                    state_dir
                )))
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }

    fn ensure_secure_state_dir_permissions(state_dir: &Path) -> Result<()> {
        match fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700)) {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EROFS) | Some(libc::EPERM) | Some(libc::EACCES)
                ) =>
            {
                let metadata = fs::metadata(state_dir).map_err(|meta_err| {
                    NucleusError::ConfigError(format!(
                        "Failed to secure state directory permissions {:?}: {} (and could not \
                         inspect existing permissions: {})",
                        state_dir, e, meta_err
                    ))
                })?;

                let mode = metadata.permissions().mode() & 0o777;
                let owner = metadata.uid();
                let current_uid = nix::unistd::Uid::effective().as_raw();
                let is_owner_ok = owner == current_uid || nix::unistd::Uid::effective().is_root();
                let is_mode_ok = mode & 0o077 == 0;

                if is_owner_ok && is_mode_ok {
                    debug!(
                        path = ?state_dir,
                        mode = format!("{:o}", mode),
                        owner,
                        "State directory already has secure permissions; skipping chmod failure"
                    );
                    Ok(())
                } else {
                    Err(NucleusError::ConfigError(format!(
                        "Failed to secure state directory permissions {:?}: {} (existing mode \
                         {:o}, owner uid {})",
                        state_dir, e, mode, owner
                    )))
                }
            }
            Err(e) => Err(NucleusError::ConfigError(format!(
                "Failed to secure state directory permissions {:?}: {}",
                state_dir, e
            ))),
        }
    }

    fn ensure_state_dir_writable(state_dir: &Path) -> Result<()> {
        let probe_name = format!(
            ".nucleus-write-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let probe_path = state_dir.join(probe_name);

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe_path)
            .map_err(|e| {
                NucleusError::ConfigError(format!(
                    "State directory {:?} is not writable: {}",
                    state_dir, e
                ))
            })?;
        drop(file);

        fs::remove_file(&probe_path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to cleanup state directory probe {:?}: {}",
                probe_path, e
            ))
        })?;

        Ok(())
    }

    /// Get ordered default state directory candidates.
    fn default_state_dir_candidates() -> Vec<PathBuf> {
        if let Some(path) = std::env::var_os("NUCLEUS_STATE_DIR").filter(|p| !p.is_empty()) {
            return vec![PathBuf::from(path)];
        }

        if nix::unistd::Uid::effective().is_root() {
            vec![PathBuf::from("/var/run/nucleus")]
        } else {
            let mut candidates = Vec::new();

            if let Some(dir) = dirs::runtime_dir() {
                candidates.push(dir.join("nucleus"));
            }
            if let Some(dir) = dirs::data_local_dir() {
                candidates.push(dir.join("nucleus"));
            }
            if let Some(dir) = dirs::home_dir() {
                candidates.push(dir.join(".nucleus"));
            }

            // Final fallback for restricted sandboxes where standard runtime/home
            // paths are mounted read-only. Use a private directory under /tmp
            // with O_NOFOLLOW semantics to prevent symlink attacks.
            //
            // We avoid the TOCTOU pattern of .exists() then create_dir_all()
            // by attempting mkdir atomically and validating the result.
            let uid = nix::unistd::Uid::effective().as_raw();
            let fallback = PathBuf::from(format!("/tmp/nucleus-{}", uid));
            let fallback_ok = match std::fs::create_dir(&fallback) {
                Ok(()) => {
                    // We created it – it's ours with correct ownership.
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Already exists: validate it is not a symlink and is owned by us.
                    // symlink_metadata (lstat) does not follow symlinks.
                    use std::os::unix::fs::MetadataExt;
                    match std::fs::symlink_metadata(&fallback) {
                        Ok(meta) => {
                            if meta.file_type().is_symlink() {
                                tracing::warn!(
                                    "Skipping {} – it is a symlink (possible attack)",
                                    fallback.display()
                                );
                                false
                            } else if meta.uid() != uid {
                                tracing::warn!(
                                    "Skipping {} – owned by UID {} not {}",
                                    fallback.display(),
                                    meta.uid(),
                                    uid
                                );
                                false
                            } else {
                                true
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Skipping {} – cannot stat: {}", fallback.display(), e);
                            false
                        }
                    }
                }
                Err(_) => {
                    // Cannot create (e.g. /tmp read-only) – skip this candidate.
                    false
                }
            };
            if fallback_ok {
                candidates.push(fallback);
            }

            candidates
        }
    }

    /// Validate a container ID for safe filesystem use
    fn validate_container_id(container_id: &str) -> Result<()> {
        if container_id.is_empty() {
            return Err(NucleusError::ConfigError(
                "Container ID cannot be empty".to_string(),
            ));
        }

        if !container_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(NucleusError::ConfigError(format!(
                "Invalid container ID (allowed: a-zA-Z0-9_-): {}",
                container_id
            )));
        }

        Ok(())
    }

    fn state_file_path(&self, container_id: &str) -> Result<PathBuf> {
        Self::validate_container_id(container_id)?;
        Ok(self.state_dir.join(format!("{}.json", container_id)))
    }

    /// Return the path to the exec FIFO used for two-phase create/start.
    pub fn exec_fifo_path(&self, container_id: &str) -> Result<PathBuf> {
        Self::validate_container_id(container_id)?;
        Ok(self.state_dir.join(format!("{}.exec", container_id)))
    }

    /// Return the persistent overlayfs state directory for a container.
    pub fn rootfs_overlay_dir_path(&self, container_id: &str) -> Result<PathBuf> {
        Self::validate_container_id(container_id)?;
        Ok(self
            .state_dir
            .join(format!("{}.rootfs-overlay", container_id)))
    }

    /// Resolve a container reference by exact ID, name, or ID prefix
    pub fn resolve_container(&self, reference: &str) -> Result<ContainerState> {
        let states = self.list_states()?;

        // Try exact ID match
        if let Some(state) = states.iter().find(|s| s.id == reference) {
            return Ok(state.clone());
        }

        // Try exact name match (must be unambiguous)
        let name_matches: Vec<&ContainerState> =
            states.iter().filter(|s| s.name == reference).collect();
        match name_matches.len() {
            1 => return Ok(name_matches[0].clone()),
            n if n > 1 => {
                return Err(NucleusError::AmbiguousContainer(format!(
                    "Name '{}' matches {} containers; use container ID instead",
                    reference, n
                )))
            }
            _ => {}
        }

        // Try ID prefix match
        let prefix_matches: Vec<&ContainerState> = states
            .iter()
            .filter(|s| s.id.starts_with(reference))
            .collect();

        match prefix_matches.len() {
            0 => Err(NucleusError::ContainerNotFound(reference.to_string())),
            1 => Ok(prefix_matches[0].clone()),
            _ => Err(NucleusError::AmbiguousContainer(format!(
                "'{}' matches {} containers",
                reference,
                prefix_matches.len()
            ))),
        }
    }

    /// Save container state
    pub fn save_state(&self, state: &ContainerState) -> Result<()> {
        let path = self.state_file_path(&state.id)?;
        let tmp_path = self.state_dir.join(format!("{}.json.tmp", state.id));
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to serialize container state: {}", e))
        })?;

        // O_NOFOLLOW prevents TOCTOU symlink attacks: if an attacker replaces
        // the temp path with a symlink between check and open, the open fails
        // instead of following the symlink to an attacker-controlled location.
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| {
                NucleusError::ConfigError(format!(
                    "Failed to open temp state file {:?}: {}",
                    tmp_path, e
                ))
            })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to write state file {:?}: {}", tmp_path, e))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::ConfigError(format!("Failed to sync state file {:?}: {}", tmp_path, e))
        })?;

        fs::rename(&tmp_path, &path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to atomically replace state file {:?}: {}",
                path, e
            ))
        })?;

        debug!("Saved container state: {}", state.id);
        Ok(())
    }

    /// Read a file with O_NOFOLLOW to prevent symlink attacks.
    pub fn read_file_nofollow(
        path: &std::path::Path,
    ) -> std::result::Result<String, std::io::Error> {
        use std::io::Read;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut buf = String::new();
        std::io::BufReader::new(file).read_to_string(&mut buf)?;
        Ok(buf)
    }

    /// Load container state
    ///
    /// Opens with O_NOFOLLOW to prevent symlink-based TOCTOU attacks.
    pub fn load_state(&self, container_id: &str) -> Result<ContainerState> {
        let path = self.state_file_path(container_id)?;

        let json = Self::read_file_nofollow(&path).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to read state file {:?}: {}", path, e))
        })?;

        let state = serde_json::from_str(&json).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to parse container state: {}", e))
        })?;

        Ok(state)
    }

    /// Delete container state
    pub fn delete_state(&self, container_id: &str) -> Result<()> {
        let path = self.state_file_path(container_id)?;

        match fs::remove_file(&path) {
            Ok(()) => {
                debug!("Deleted container state: {}", container_id);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already deleted – idempotent (handles TOCTOU race)
                debug!("Container state already deleted: {}", container_id);
            }
            Err(e) => {
                return Err(NucleusError::ConfigError(format!(
                    "Failed to delete state file {:?}: {}",
                    path, e
                )));
            }
        }

        Ok(())
    }

    /// List all container states
    pub fn list_states(&self) -> Result<Vec<ContainerState>> {
        let mut states = Vec::new();

        let entries = fs::read_dir(&self.state_dir).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to read state directory {:?}: {}",
                self.state_dir, e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                NucleusError::ConfigError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Use O_NOFOLLOW to prevent symlink attacks, consistent with
                // load_state/save_state. Without this, a symlink in the state
                // directory could be used as a file-read oracle.
                match Self::read_file_nofollow(&path) {
                    Ok(json) => match serde_json::from_str::<ContainerState>(&json) {
                        Ok(state) => states.push(state),
                        Err(e) => {
                            warn!("Failed to parse state file {:?}: {}", path, e);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read state file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(states)
    }

    /// List only running containers
    pub fn list_running(&self) -> Result<Vec<ContainerState>> {
        let states = self.list_states()?;
        Ok(states.into_iter().filter(|s| s.is_running()).collect())
    }

    /// Clean up stale state files (for containers that are no longer running)
    pub fn cleanup_stale(&self) -> Result<()> {
        let states = self.list_states()?;

        for state in states {
            if !state.is_running() {
                info!(
                    "Cleaning up stale state for container {} (PID {})",
                    state.id, state.pid
                );
                self.delete_state(&state.id)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_state_manager() -> (ContainerStateManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mgr = ContainerStateManager {
            state_dir: temp_dir.path().to_path_buf(),
        };
        (mgr, temp_dir)
    }

    #[test]
    fn test_container_state_new() {
        let state = ContainerState::new(ContainerStateParams {
            id: "test".to_string(),
            name: "test".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: Some(512 * 1024 * 1024),
            cpu_limit: Some(2000),
            using_gvisor: false,
            rootless: false,
            cgroup_path: Some("/sys/fs/cgroup/nucleus-test".to_string()),
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        assert_eq!(state.id, "test");
        assert_eq!(state.pid, 1234);
        assert_eq!(state.memory_limit, Some(512 * 1024 * 1024));
        assert_eq!(state.cpu_limit, Some(2000));
        assert_eq!(state.creator_uid, nix::unistd::Uid::effective().as_raw());
    }

    #[test]
    fn test_save_and_load_state() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(ContainerStateParams {
            id: "test".to_string(),
            name: "test".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: Some(512 * 1024 * 1024),
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        mgr.save_state(&state).unwrap();

        let loaded = mgr.load_state("test").unwrap();
        assert_eq!(loaded.id, state.id);
        assert_eq!(loaded.pid, state.pid);
        assert_eq!(loaded.command, state.command);
    }

    #[test]
    fn test_delete_state() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(ContainerStateParams {
            id: "test".to_string(),
            name: "test".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        mgr.save_state(&state).unwrap();
        assert!(mgr.load_state("test").is_ok());

        mgr.delete_state("test").unwrap();
        assert!(mgr.load_state("test").is_err());
    }

    #[test]
    fn test_list_states() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state1 = ContainerState::new(ContainerStateParams {
            id: "test1".to_string(),
            name: "test1".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        let state2 = ContainerState::new(ContainerStateParams {
            id: "test2".to_string(),
            name: "test2".to_string(),
            pid: 5678,
            command: vec!["/bin/bash".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        mgr.save_state(&state1).unwrap();
        mgr.save_state(&state2).unwrap();

        let states = mgr.list_states().unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_resolve_container_by_id() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(ContainerStateParams {
            id: "abc123def456".to_string(),
            name: "mycontainer".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        mgr.save_state(&state).unwrap();

        // Exact ID
        let resolved = mgr.resolve_container("abc123def456").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // Name
        let resolved = mgr.resolve_container("mycontainer").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // ID prefix
        let resolved = mgr.resolve_container("abc123").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // Not found
        assert!(mgr.resolve_container("nonexistent").is_err());
    }

    #[test]
    fn test_load_state_rejects_symlink() {
        // H-3: O_NOFOLLOW must prevent loading state through a symlink
        let (mgr, temp_dir) = temp_state_manager();

        // Create a real state file
        let state = ContainerState::new(ContainerStateParams {
            id: "real".to_string(),
            name: "real".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        mgr.save_state(&state).unwrap();

        // Create a symlink pointing to the real state file
        let symlink_path = temp_dir.path().join("symlinked.json");
        let real_path = temp_dir.path().join("real.json");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // Loading through the symlink ID must fail (O_NOFOLLOW)
        let result = mgr.load_state("symlinked");
        assert!(result.is_err(), "load_state must reject symlinks");
    }

    #[test]
    fn test_list_states_ignores_symlinks() {
        // list_states must use O_NOFOLLOW, so symlinked state files are skipped
        // rather than followed (which would be a file-read oracle).
        let (mgr, temp_dir) = temp_state_manager();

        // Create a real state file
        let state = ContainerState::new(ContainerStateParams {
            id: "real123456789012345678".to_string(),
            name: "real".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        mgr.save_state(&state).unwrap();

        // Create a symlink masquerading as a state file
        let real_path = temp_dir.path().join("real123456789012345678.json");
        let symlink_path = temp_dir.path().join("evil.json");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // list_states should only return the real file, not follow the symlink
        let states = mgr.list_states().unwrap();
        // The symlink should fail to open with O_NOFOLLOW, leaving only the real state
        assert_eq!(states.len(), 1, "symlinked state file must be skipped");
        assert_eq!(states[0].id, "real123456789012345678");
    }

    #[test]
    fn test_save_state_rejects_symlink_tmp() {
        // H-3: O_NOFOLLOW on save must prevent writing through a symlink
        let (mgr, temp_dir) = temp_state_manager();

        let state = ContainerState::new(ContainerStateParams {
            id: "target".to_string(),
            name: "target".to_string(),
            pid: 1234,
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        // Pre-create a symlink at the temp path to simulate an attack
        let tmp_path = temp_dir.path().join("target.json.tmp");
        let evil_path = temp_dir.path().join("evil");
        std::os::unix::fs::symlink(&evil_path, &tmp_path).unwrap();

        // save_state should fail because O_NOFOLLOW rejects the symlink
        let result = mgr.save_state(&state);
        assert!(
            result.is_err(),
            "save_state must reject symlinks at tmp path"
        );
    }

    #[test]
    fn test_is_running_returns_false_when_start_ticks_is_zero() {
        // BUG-04: When start_ticks=0 (failed to read), is_running() must return
        // false to avoid PID reuse false positives, not fall back to existence check
        let mut state = ContainerState::new(ContainerStateParams {
            id: "test".to_string(),
            name: "test".to_string(),
            pid: std::process::id(), // our PID exists in /proc
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        // Force start_ticks to 0 to simulate failed read
        state.start_ticks = 0;
        // With BUG-04 present, this returns true (falls back to existence check)
        // After fix, must return false
        assert!(
            !state.is_running(),
            "is_running() must return false when start_ticks=0 (cannot verify PID identity)"
        );
    }

    #[test]
    fn test_read_start_ticks_retries_on_failure() {
        // BUG-09: read_start_ticks must retry when /proc/<pid>/stat is temporarily
        // unavailable after fork, instead of immediately returning 0.
        // Verify by calling with our own PID (should succeed) and a non-existent
        // PID (should return 0 after retries, not panic).
        let own_ticks = ContainerState::read_start_ticks(std::process::id());
        assert!(
            own_ticks > 0,
            "read_start_ticks must return non-zero for a live process"
        );
        // Non-existent PID should gracefully return 0 (after retries)
        let bogus_ticks = ContainerState::read_start_ticks(u32::MAX);
        assert_eq!(
            bogus_ticks, 0,
            "read_start_ticks must return 0 for non-existent PID"
        );
    }

    #[test]
    fn test_delete_state_handles_already_deleted() {
        // BUG-16: delete_state must not fail if file was already deleted (TOCTOU)
        let (mgr, _temp_dir) = temp_state_manager();
        // Delete a state that doesn't exist – should succeed (idempotent)
        let result = mgr.delete_state("nonexistent-id");
        assert!(
            result.is_ok(),
            "delete_state must be idempotent for missing files"
        );
    }
}
