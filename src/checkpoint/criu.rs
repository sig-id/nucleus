use crate::checkpoint::metadata::CheckpointMetadata;
use crate::checkpoint::state::CheckpointState;
use crate::container::{ContainerState, ContainerStateManager, ContainerStateParams, OciStatus};
use crate::error::{NucleusError, Result, StateTransition};
use crate::resources::Cgroup;
use nix::unistd::Uid;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::Builder;
use tracing::info;

const CHECKPOINT_HMAC_FILE: &str = "checkpoint.hmac";
const CHECKPOINT_HMAC_KEY_SIZE: usize = 32;

/// CRIU runtime for checkpoint/restore
///
/// Follows the same pattern as GVisorRuntime: find binary, validate, invoke via Command.
pub struct CriuRuntime {
    binary_path: PathBuf,
    state: CheckpointState,
}

impl CriuRuntime {
    /// Create a new CRIU runtime, finding the criu binary
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_binary()?;

        // Validate binary works
        let output = Command::new(&binary_path)
            .arg("--version")
            .output()
            .map_err(|e| NucleusError::CheckpointError(format!("Failed to execute criu: {}", e)))?;

        if !output.status.success() {
            return Err(NucleusError::CheckpointError(
                "criu --version failed".to_string(),
            ));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        info!("Found CRIU: {}", version.trim());

        Ok(Self {
            binary_path,
            state: CheckpointState::None,
        })
    }

    /// Validate a binary path for safe execution.
    ///
    /// Checks permissions (not world/group-writable) and ownership (must be
    /// owned by root or the effective UID) to prevent execution of tampered
    /// binaries.
    fn validate_binary(path: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::MetadataExt;

        let resolved = fs::canonicalize(path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Cannot canonicalize criu binary {:?}: {}",
                path, e
            ))
        })?;
        let metadata = fs::metadata(&resolved).map_err(|e| {
            NucleusError::CheckpointError(format!("Cannot stat criu binary {:?}: {}", resolved, e))
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::CheckpointError(format!(
                "criu binary {:?} is writable by group/others (mode {:o}), refusing to execute",
                resolved, mode
            )));
        }
        if mode & 0o111 == 0 {
            return Err(NucleusError::CheckpointError(format!(
                "criu binary {:?} is not executable",
                resolved
            )));
        }
        let owner_uid = metadata.uid();
        let euid = nix::unistd::Uid::effective().as_raw();
        if owner_uid != 0 && owner_uid != euid {
            return Err(NucleusError::CheckpointError(format!(
                "criu binary {:?} is owned by UID {} (expected root or euid {}), refusing to execute",
                resolved, owner_uid, euid
            )));
        }
        Ok(resolved)
    }

    fn find_binary() -> Result<PathBuf> {
        // Check common locations
        for path in &["/usr/sbin/criu", "/usr/bin/criu", "/usr/local/sbin/criu"] {
            let p = PathBuf::from(path);
            if p.exists() {
                return Self::validate_binary(&p);
            }
        }

        // For privileged execution, do not resolve runtime binaries via PATH.
        // This avoids environment-based binary hijacking when running as root.
        if Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "CRIU binary not found in trusted system paths".to_string(),
            ));
        }

        // Try PATH for unprivileged execution.
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("criu");
                if candidate.exists() {
                    return Self::validate_binary(&candidate);
                }
            }
        }

        Err(NucleusError::CheckpointError(
            "CRIU binary not found. Install criu to use checkpoint/restore.".to_string(),
        ))
    }

    // CRIU restores the original kernel uid_map/gid_map into a new container.
    // A clone (including --leave-running) would therefore share the original
    // container's host credentials. Older root-created state lacks the map.
    fn check_restorable_mapping(state: &ContainerState) -> Result<()> {
        let unknown_root_mapping =
            state.creator_uid == 0 && state.rootless && state.user_ns_config.is_none();
        if state.allocated_root_remap || unknown_root_mapping {
            return Err(NucleusError::CheckpointError(
                "CRIU cannot assign a fresh UID/GID range to a root-remapped restore".into(),
            ));
        }
        Ok(())
    }

    /// Checkpoint a running container
    ///
    /// State transitions: None -> Dumping -> Dumped (or Dumping -> None on failure)
    pub fn checkpoint(
        &mut self,
        state: &ContainerState,
        output_dir: &Path,
        leave_running: bool,
    ) -> Result<()> {
        // Requires root
        if !nix::unistd::Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "Checkpoint requires root (CRIU needs CAP_SYS_PTRACE)".to_string(),
            ));
        }

        Self::check_restorable_mapping(state)?;
        if !state.is_running() {
            return Err(NucleusError::CheckpointError(format!(
                "Container {} is not running",
                state.id
            )));
        }

        // State transition: None -> Dumping
        self.state = self.state.transition(CheckpointState::Dumping)?;

        let directory = Self::prepare_checkpoint_dir(output_dir)?;
        let output_dir = Self::pinned_path(&directory);
        let images_dir = output_dir.join("images");
        if fs::read_dir(&images_dir)?.next().is_some() {
            return Err(NucleusError::CheckpointError(
                "Checkpoint images directory must be empty".into(),
            ));
        }

        // A successful dump may terminate the original tree and trigger cgroup cleanup.
        let metadata = CheckpointMetadata::from_state(state)?;

        // Run criu dump
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("dump")
            .arg("--tree")
            .arg(state.pid.to_string())
            .arg("--images-dir")
            .arg(".")
            .current_dir(&images_dir)
            .arg("--shell-job");

        if leave_running {
            cmd.arg("--leave-running");
        }

        info!(
            "Checkpointing container {} (PID {}) to {:?}",
            state.id, state.pid, output_dir
        );

        let output = cmd.output().map_err(|e| {
            // Abort: Dumping -> None
            self.state = self
                .state
                .transition(CheckpointState::None)
                .unwrap_or(self.state);
            NucleusError::CheckpointError(format!("Failed to run criu dump: {}", e))
        })?;

        if !output.status.success() {
            // Abort: Dumping -> None
            self.state = self
                .state
                .transition(CheckpointState::None)
                .unwrap_or(self.state);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu dump failed: {}",
                stderr
            )));
        }

        // Publish metadata for this completed dump.
        metadata.save(&output_dir)?;
        Self::write_checkpoint_hmac(&output_dir)?;

        // State transition: Dumping -> Dumped
        self.state = self.state.transition(CheckpointState::Dumped)?;

        info!("Checkpoint complete: {:?}", output_dir);
        Ok(())
    }

    /// Restore a container from checkpoint
    ///
    /// State transitions: None -> Restoring -> Restored (or Restoring -> None on failure)
    pub fn restore(&mut self, input_dir: &Path) -> Result<u32> {
        Ok(self
            .restore_registered(input_dir, &ContainerStateManager::new()?)?
            .pid)
    }

    pub fn restore_registered(
        &mut self,
        input_dir: &Path,
        state_mgr: &ContainerStateManager,
    ) -> Result<ContainerState> {
        // Requires root
        if !nix::unistd::Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "Restore requires root (CRIU needs CAP_SYS_PTRACE)".to_string(),
            ));
        }

        // Keep the same directory inode through authentication, parsing and CRIU startup,
        // including when the caller can rename an ancestor of the supplied path.
        let directory = Self::open_checkpoint_directory(input_dir)?;
        directory.lock()?;
        let input_dir = Self::pinned_path(&directory);
        Self::verify_checkpoint_hmac(&input_dir)?;
        // Load and validate metadata
        let metadata = CheckpointMetadata::load(&input_dir)?;
        info!(
            "Restoring container {} from checkpoint (originally PID {})",
            metadata.container_id, metadata.original_pid
        );

        let images_dir = input_dir.join("images");
        if !images_dir.exists() {
            return Err(NucleusError::CheckpointError(format!(
                "Images directory not found: {:?}",
                images_dir
            )));
        }

        let launch = metadata.launch_state.ok_or_else(|| NucleusError::CheckpointError(
            "This checkpoint lacks the original workload identity. Create a new checkpoint before restoring.".into()
        ))?;
        Self::check_restorable_mapping(&launch)?;
        if metadata.cgroup_path.is_some() && metadata.resource_limits.is_none() {
            return Err(NucleusError::CheckpointError(
                "Missing original cgroup limits".into(),
            ));
        }
        let id = crate::container::generate_container_id()?;
        let mut cgroup = Cgroup::create(&format!("nucleus-{id}"))?;
        if let Some(limits) = &metadata.resource_limits {
            cgroup.set_limits(&limits.to_resource_limits())?;
        }
        if let Some(filter) = &launch.gpu_device_filter {
            cgroup.install_gpu_device_allowlist(
                &filter.gpu,
                &filter.supervisor,
                filter.include_tty,
                false,
            )?;
        }
        let membership = cgroup.membership_file()?;
        // CRIU creates the pidfile with O_EXCL. Give it a fresh name in a
        // supervisor-only directory and read it after CRIU reports success.
        let pid_dir = Builder::new()
            .prefix("nucleus-criu-restore-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let pidfile_path = pid_dir.path().join("init.pid");
        self.state = self.state.transition(CheckpointState::Restoring)?;

        // Run criu restore
        let mut cmd = Command::new(&self.binary_path);
        // SAFETY: the child only writes one byte to a pre-opened cgroup v2 fd.
        // Kernel migration of PID 0 moves this child before exec or any CRIU fork.
        unsafe {
            cmd.pre_exec(move || {
                nix::unistd::write(&membership, b"0")
                    .map_err(std::io::Error::from)
                    .and_then(|n| {
                        if n == 1 {
                            Ok(())
                        } else {
                            Err(std::io::ErrorKind::WriteZero.into())
                        }
                    })
            });
        }
        let output = cmd
            .arg("restore")
            .arg("--manage-cgroups=ignore")
            .arg("--work-dir")
            .arg(pid_dir.path())
            .arg("--restore-detached")
            .arg("--images-dir")
            .arg(".")
            .current_dir(&images_dir)
            .arg("--shell-job")
            .arg("--pidfile")
            .arg(&pidfile_path)
            .output()
            .map_err(|e| {
                // Abort: Restoring -> None
                self.state = self
                    .state
                    .transition(CheckpointState::None)
                    .unwrap_or(self.state);
                NucleusError::CheckpointError(format!("Failed to run criu restore: {}", e))
            })?;

        if !output.status.success() {
            // Abort: Restoring -> None
            self.state = self
                .state
                .transition(CheckpointState::None)
                .unwrap_or(self.state);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu restore failed: {}",
                stderr
            )));
        }

        let pid = Self::parse_pidfile(&fs::read_to_string(&pidfile_path)?)
            .filter(|pid| *pid > 1 && *pid <= i32::MAX as u32)
            .ok_or_else(|| {
                NucleusError::CheckpointError("Missing valid restored init PID".into())
            })?;
        if !fs::read_to_string(cgroup.path().join("cgroup.procs"))?
            .lines()
            .any(|line| line.parse() == Ok(pid))
        {
            return Err(NucleusError::CheckpointError(
                "Restored init is outside its cgroup".into(),
            ));
        }
        let mut state = ContainerState::new(ContainerStateParams {
            id,
            name: format!("{}-restored", launch.name),
            pid,
            command: launch.command,
            memory_limit: launch.memory_limit,
            cpu_limit: launch.cpu_limit,
            using_gvisor: launch.using_gvisor,
            rootless: launch.rootless,
            cgroup_path: Some(cgroup.path().display().to_string()),
            process_uid: launch.process_uid,
            process_gid: launch.process_gid,
            additional_gids: launch.additional_gids,
        });
        state.user_ns_config = launch.user_ns_config;
        state.creator_uid = launch.creator_uid;
        state.environment = launch.environment;
        state.workdir = launch.workdir;
        state.pids_max = launch.pids_max;
        // A checkpoint cannot carry a live kernel ruleset fd across restore.
        // Leave attach/probes unavailable until a fresh native launch.
        state.native_seccomp = launch.native_seccomp;
        state.gpu_device_filter = launch.gpu_device_filter;
        state.status = OciStatus::Running;
        state_mgr.save_state(&state)?;
        cgroup.leave_registered();
        self.state = self.state.transition(CheckpointState::Restored)?;
        Ok(state)
    }

    fn parse_pidfile(text: &str) -> Option<u32> {
        let trimmed = text.trim();
        if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        trimmed.parse::<u32>().ok()
    }

    fn pinned_path(directory: &fs::File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
    }

    fn check_checkpoint_owner(path: &Path, metadata: &fs::Metadata) -> Result<()> {
        if metadata.uid() != Uid::effective().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(NucleusError::CheckpointError(format!(
                "Checkpoint entry {path:?} must be owned by the supervisor and writable only by its owner"
            )));
        }
        Ok(())
    }

    fn open_checkpoint_directory(path: &Path) -> Result<fs::File> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Checkpoint path {path:?} is inaccessible, a symlink or not a directory: {e}"
                ))
            })?;
        Self::check_checkpoint_owner(path, &directory.metadata()?)?;
        Ok(directory)
    }

    fn prepare_checkpoint_dir(output_dir: &Path) -> Result<fs::File> {
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(output_dir)
        {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        let directory = Self::open_checkpoint_directory(output_dir)?;
        directory.lock()?;
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        let images = Self::pinned_path(&directory).join("images");
        match fs::DirBuilder::new().mode(0o700).create(&images) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        Self::open_checkpoint_directory(&images)?
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn write_checkpoint_hmac(dir: &Path) -> Result<()> {
        let key = Self::load_or_create_checkpoint_hmac_key()?;
        let hmac_path = dir.join(CHECKPOINT_HMAC_FILE);
        let tmp_path = dir.join(format!("{}.tmp", CHECKPOINT_HMAC_FILE));

        match fs::symlink_metadata(&tmp_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NucleusError::CheckpointError(format!(
                    "Refusing symlink checkpoint HMAC temp file {:?}",
                    tmp_path
                )));
            }
            Ok(_) => {
                fs::remove_file(&tmp_path).map_err(|e| {
                    NucleusError::CheckpointError(format!(
                        "Failed to remove stale checkpoint HMAC temp file {:?}: {}",
                        tmp_path, e
                    ))
                })?;
            }
            Err(_) => {}
        }

        let digest = Self::compute_checkpoint_hmac(dir, &key)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to open checkpoint HMAC temp file {:?}: {}",
                    tmp_path, e
                ))
            })?;
        file.write_all(digest.as_bytes()).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to write checkpoint HMAC {:?}: {}",
                tmp_path, e
            ))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to sync checkpoint HMAC {:?}: {}",
                tmp_path, e
            ))
        })?;
        fs::rename(&tmp_path, &hmac_path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to atomically replace checkpoint HMAC {:?}: {}",
                hmac_path, e
            ))
        })?;

        Ok(())
    }

    fn verify_checkpoint_hmac(dir: &Path) -> Result<()> {
        let hmac_path = dir.join(CHECKPOINT_HMAC_FILE);
        let signature = fs::symlink_metadata(&hmac_path)?;
        Self::check_checkpoint_owner(&hmac_path, &signature)?;
        if !signature.is_file() || signature.len() > 128 {
            return Err(NucleusError::CheckpointError(
                "Invalid checkpoint HMAC file".into(),
            ));
        }
        let expected = Self::read_file_nofollow_bytes(&hmac_path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to read checkpoint HMAC {:?}: {}",
                hmac_path, e
            ))
        })?;
        let expected = std::str::from_utf8(&expected)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC {:?} is not valid UTF-8: {}",
                    hmac_path, e
                ))
            })?
            .trim()
            .to_string();
        if expected.is_empty() {
            return Err(NucleusError::CheckpointError(format!(
                "Checkpoint HMAC {:?} is empty",
                hmac_path
            )));
        }

        info!("Verifying checkpoint HMAC integrity");
        let key = Self::load_or_create_checkpoint_hmac_key()?;
        let actual = Self::compute_checkpoint_hmac(dir, &key)?;
        if actual != expected {
            return Err(NucleusError::CheckpointError(
                "Checkpoint integrity verification failed: HMAC mismatch".into(),
            ));
        }

        info!("Checkpoint integrity verified");
        Ok(())
    }

    fn checkpoint_hmac_key_path() -> PathBuf {
        if let Some(path) =
            std::env::var_os("NUCLEUS_CHECKPOINT_HMAC_KEY_FILE").filter(|path| !path.is_empty())
        {
            return PathBuf::from(path);
        }

        if Uid::effective().is_root() {
            PathBuf::from("/var/lib/nucleus/checkpoint-hmac.key")
        } else {
            dirs::data_local_dir()
                .map(|dir| dir.join("nucleus/checkpoint-hmac.key"))
                .or_else(|| dirs::home_dir().map(|dir| dir.join(".nucleus/checkpoint-hmac.key")))
                .unwrap_or_else(|| PathBuf::from("/tmp/nucleus-checkpoint-hmac.key"))
        }
    }

    fn load_or_create_checkpoint_hmac_key() -> Result<Vec<u8>> {
        let key_path = Self::checkpoint_hmac_key_path();
        let parent = key_path.parent().ok_or_else(|| {
            NucleusError::CheckpointError(format!(
                "Checkpoint HMAC key path {:?} has no parent directory",
                key_path
            ))
        })?;
        Self::ensure_secure_key_parent_dir(parent)?;
        Self::reject_symlink_path(&key_path, "checkpoint HMAC key file")?;

        if key_path.exists() {
            let metadata = fs::metadata(&key_path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to stat checkpoint HMAC key {:?}: {}",
                    key_path, e
                ))
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            let owner = metadata.uid();
            let euid = Uid::effective().as_raw();
            if owner != euid {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key {:?} is owned by uid {} (expected {})",
                    key_path, owner, euid
                )));
            }
            if mode & 0o077 != 0 {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key {:?} has insecure mode {:o}; expected owner-only access",
                    key_path, mode
                )));
            }
            let key = Self::read_file_nofollow_bytes(&key_path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to read checkpoint HMAC key {:?}: {}",
                    key_path, e
                ))
            })?;
            if key.len() < CHECKPOINT_HMAC_KEY_SIZE {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key {:?} is too short ({} bytes)",
                    key_path,
                    key.len()
                )));
            }
            return Ok(key);
        }

        let mut key = vec![0u8; CHECKPOINT_HMAC_KEY_SIZE];
        Self::fill_secure_random(&mut key)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&key_path)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to create checkpoint HMAC key {:?}: {}",
                    key_path, e
                ))
            })?;
        file.write_all(&key).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to write checkpoint HMAC key {:?}: {}",
                key_path, e
            ))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to sync checkpoint HMAC key {:?}: {}",
                key_path, e
            ))
        })?;
        Ok(key)
    }

    fn ensure_secure_key_parent_dir(path: &Path) -> Result<()> {
        Self::reject_symlink_path(path, "checkpoint HMAC key directory")?;

        if path.exists() {
            let metadata = fs::metadata(path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to stat checkpoint HMAC key directory {:?}: {}",
                    path, e
                ))
            })?;
            if !metadata.is_dir() {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key directory {:?} is not a directory",
                    path
                )));
            }
            let mode = metadata.permissions().mode() & 0o777;
            let owner = metadata.uid();
            let euid = Uid::effective().as_raw();
            if owner != euid {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key directory {:?} is owned by uid {} (expected {})",
                    path, owner, euid
                )));
            }
            if mode & 0o077 != 0 {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint HMAC key directory {:?} has insecure mode {:o}; expected owner-only access",
                    path, mode
                )));
            }
            return Ok(());
        }

        fs::create_dir_all(path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to create checkpoint HMAC key directory {:?}: {}",
                path, e
            ))
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to secure checkpoint HMAC key directory {:?}: {}",
                path, e
            ))
        })?;
        Ok(())
    }

    fn fill_secure_random(buf: &mut [u8]) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/urandom")
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to open /dev/urandom for checkpoint HMAC key generation: {}",
                    e
                ))
            })?;
        let metadata = file.metadata().map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to stat /dev/urandom: {}", e))
        })?;
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_char_device() {
            return Err(NucleusError::CheckpointError(
                "/dev/urandom is not a character device".to_string(),
            ));
        }
        let mut file = file;
        file.read_exact(buf).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to read /dev/urandom for checkpoint HMAC key generation: {}",
                e
            ))
        })
    }

    fn read_file_nofollow_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        Ok(content)
    }

    fn compute_checkpoint_hmac(dir: &Path, key: &[u8]) -> Result<String> {
        let mut key_block = [0u8; 64];
        if key.len() > key_block.len() {
            let digest = Sha256::digest(key);
            key_block[..digest.len()].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for (dst, src) in ipad.iter_mut().zip(key_block.iter()) {
            *dst ^= *src;
        }
        for (dst, src) in opad.iter_mut().zip(key_block.iter()) {
            *dst ^= *src;
        }

        let mut inner = Sha256::new();
        inner.update(ipad);
        Self::update_checkpoint_hmac_inner(&mut inner, dir, dir)?;
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        Ok(hex::encode(outer.finalize()))
    }

    fn update_checkpoint_hmac_inner(hasher: &mut Sha256, root: &Path, dir: &Path) -> Result<()> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to read checkpoint directory {:?}: {}",
                dir, e
            ))
        })? {
            let entry = entry.map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to read checkpoint entry in {:?}: {}",
                    dir, e
                ))
            })?;
            entries.push(entry.path());
        }
        entries.sort();

        for path in entries {
            let relative = path.strip_prefix(root).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to compute checkpoint-relative path for {:?}: {}",
                    path, e
                ))
            })?;
            if relative == Path::new(CHECKPOINT_HMAC_FILE) {
                continue;
            }

            let metadata = fs::symlink_metadata(&path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to stat checkpoint path {:?}: {}",
                    path, e
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint integrity scan refuses symlink path {:?}",
                    path
                )));
            }

            Self::check_checkpoint_owner(&path, &metadata)?;

            let relative = relative.to_str().ok_or_else(|| {
                NucleusError::CheckpointError(format!(
                    "Checkpoint path {:?} is not valid UTF-8",
                    relative
                ))
            })?;

            if metadata.is_dir() {
                hasher.update(b"D\0");
                hasher.update(relative.as_bytes());
                hasher.update(b"\0");
                Self::update_checkpoint_hmac_inner(hasher, root, &path)?;
            } else if metadata.is_file() {
                hasher.update(b"F\0");
                hasher.update(relative.as_bytes());
                hasher.update(b"\0");
                hasher.update(metadata.len().to_le_bytes());
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)
                    .map_err(|e| {
                        NucleusError::CheckpointError(format!(
                            "Failed to open checkpoint file {:?}: {}",
                            path, e
                        ))
                    })?;
                let mut buf = [0u8; 8192];
                loop {
                    let read = file.read(&mut buf).map_err(|e| {
                        NucleusError::CheckpointError(format!(
                            "Failed to read checkpoint file {:?}: {}",
                            path, e
                        ))
                    })?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buf[..read]);
                }
            } else {
                return Err(NucleusError::CheckpointError(format!(
                    "Checkpoint integrity scan rejects special file {:?}",
                    path
                )));
            }
        }

        Ok(())
    }

    fn reject_symlink_path(path: &Path, label: &str) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(
                NucleusError::CheckpointError(format!("Refusing symlink {} {:?}", label, path)),
            ),
            Ok(_) | Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CriuRuntime;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn checkpoint_key_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct CheckpointKeyEnvGuard {
        previous: Option<OsString>,
    }

    impl CheckpointKeyEnvGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::var_os("NUCLEUS_CHECKPOINT_HMAC_KEY_FILE");
            std::env::set_var("NUCLEUS_CHECKPOINT_HMAC_KEY_FILE", path);
            Self { previous }
        }
    }

    impl Drop for CheckpointKeyEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("NUCLEUS_CHECKPOINT_HMAC_KEY_FILE", value),
                None => std::env::remove_var("NUCLEUS_CHECKPOINT_HMAC_KEY_FILE"),
            }
        }
    }

    fn prepare_secure_checkpoint_key_dir(tmp: &TempDir) -> PathBuf {
        let key_dir = tmp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        key_dir
    }

    #[test]
    fn criu_rejects_automatic_and_unknown_root_mappings_before_dump_or_restore() {
        use crate::container::{ContainerState, ContainerStateParams};
        let mut state = ContainerState::new(ContainerStateParams {
            id: "test".into(),
            name: "test".into(),
            pid: std::process::id(),
            command: vec![],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: true,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: vec![],
        });
        state.creator_uid = 0;
        assert!(CriuRuntime::check_restorable_mapping(&state).is_err());
        state.user_ns_config = Some(crate::isolation::UserNamespaceConfig::rootless());
        CriuRuntime::check_restorable_mapping(&state).unwrap();
        state.allocated_root_remap = true;
        assert!(CriuRuntime::check_restorable_mapping(&state).is_err());
    }

    #[test]
    #[ignore = "requires root and writable cgroup v2"]
    fn restore_helper_and_descendants_inherit_limits_and_saved_identity() {
        use crate::checkpoint::CheckpointMetadata;
        use crate::container::{ContainerState, ContainerStateManager, ContainerStateParams};
        let _lock = checkpoint_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _key = CheckpointKeyEnvGuard::set(&temp.path().join("keydir/key"));
        let input = temp.path().join("checkpoint");
        CriuRuntime::prepare_checkpoint_dir(&input).unwrap();
        let mut original = ContainerState::new(ContainerStateParams {
            id: "old".into(),
            name: "fixture".into(),
            pid: std::process::id(),
            command: vec![],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 1234,
            process_gid: 4321,
            additional_gids: vec![2000],
        });
        original.creator_uid = 2345;
        let mut metadata = CheckpointMetadata::from_state(&original).unwrap();
        metadata.resource_limits = Some(crate::checkpoint::CheckpointResourceLimits {
            pids_max: Some(8),
            cpu_period_us: 100_000,
            memory_bytes: None,
            memory_high: None,
            memory_swap_max: None,
            cpu_quota_us: None,
            cpu_weight: None,
            io_limits: vec![],
        });
        metadata.save(&input).unwrap();
        CriuRuntime::write_checkpoint_hmac(&input).unwrap();
        let helper = temp.path().join("restore-fixture");
        // Model CRIU's detached tree. Check the helper's cgroup before it forks.
        fs::write(
            &helper,
            r#"#!/bin/sh
set -eu
read -r membership < /proc/self/cgroup
group=${membership#0::}
case "$group" in */nucleus-*) ;; *) exit 10 ;; esac
read -r max < "/sys/fs/cgroup$group/pids.max"
test "$max" = 8
while test "$1" != --pidfile; do shift; done
(while :; do :; done) </dev/null >/dev/null 2>&1 &
echo "$!" > "$2"
"#,
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = ContainerStateManager::with_state_dir(temp.path().join("state")).unwrap();
        let mut runtime = CriuRuntime {
            binary_path: helper,
            state: crate::checkpoint::CheckpointState::None,
        };
        let state = runtime.restore_registered(&input, &manager).unwrap();
        let persisted = manager.load_state(&state.id).unwrap();
        assert_eq!(
            (
                persisted.creator_uid,
                persisted.process_uid,
                persisted.process_gid
            ),
            (2345, 1234, 4321)
        );
        assert_eq!(persisted.additional_gids, [2000]);
        let group = PathBuf::from(state.cgroup_path.unwrap());
        assert!(fs::read_to_string(group.join("cgroup.procs"))
            .unwrap()
            .lines()
            .any(|pid| pid == state.pid.to_string()));
        fs::write(group.join("cgroup.kill"), "1").unwrap();
        for _ in 0..100 {
            if fs::remove_dir(&group).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("restore test cgroup remained populated");
    }

    #[test]
    #[ignore = "requires CRIU, root and writable cgroup v2"]
    fn real_criu_round_trip_preserves_nonroot_identity() {
        use crate::container::{ContainerState, ContainerStateManager, ContainerStateParams};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let _lock = checkpoint_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _key = CheckpointKeyEnvGuard::set(&temp.path().join("keydir/key"));
        let mut runtime = CriuRuntime::new().unwrap();
        let mut command = Command::new("/bin/sleep");
        command
            .arg("60")
            .uid(1234)
            .gid(4321)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                nix::unistd::setsid()
                    .map(|_| ())
                    .map_err(std::io::Error::from)
            });
        }
        let mut child = command.spawn().unwrap();
        let original = ContainerState::new(ContainerStateParams {
            id: "fixture".into(),
            name: "fixture".into(),
            pid: child.id(),
            command: vec!["/bin/sleep".into()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 1234,
            process_gid: 4321,
            additional_gids: Vec::new(),
        });
        let checkpoint = temp.path().join("checkpoint");
        let result = runtime.checkpoint(&original, &checkpoint, false);
        if result.is_err() {
            let _ = child.kill();
        }
        child.wait().unwrap();
        result.unwrap();
        let manager = ContainerStateManager::with_state_dir(temp.path().join("state")).unwrap();
        let restored = CriuRuntime::new()
            .unwrap()
            .restore_registered(&checkpoint, &manager)
            .unwrap();
        let status = fs::read_to_string(format!("/proc/{}/status", restored.pid)).unwrap();
        let group = PathBuf::from(restored.cgroup_path.as_ref().unwrap());
        fs::write(group.join("cgroup.kill"), "1").unwrap();
        assert_eq!((restored.process_uid, restored.process_gid), (1234, 4321));
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("Uid:")
                    && line.split_whitespace().nth(1) == Some("1234"))
        );
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("Gid:")
                    && line.split_whitespace().nth(1) == Some("4321"))
        );
        for _ in 0..100 {
            if fs::remove_dir(&group).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("restored cgroup remained populated");
    }

    #[test]
    fn test_parse_pidfile_strict() {
        // BUG-22: parse_pid_text must prefer strict pidfile parsing
        // A pidfile should contain just a number, not extract first number from error messages
        assert_eq!(CriuRuntime::parse_pidfile("1234\n"), Some(1234));
        assert_eq!(CriuRuntime::parse_pidfile("  5678  \n"), Some(5678));
        // Error messages should NOT parse as PIDs
        assert_eq!(CriuRuntime::parse_pidfile("Error code: 255 (EPERM)"), None);
        assert_eq!(
            CriuRuntime::parse_pidfile("restored successfully pid=5678"),
            None
        );
        assert_eq!(CriuRuntime::parse_pidfile(""), None);
        assert_eq!(CriuRuntime::parse_pidfile("no pid here"), None);
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_symlinked_images_dir() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        let images = tmp.path().join("images");
        symlink(&target, &images).unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn test_prepare_checkpoint_dir_creates_images_subdir() {
        let tmp = TempDir::new().unwrap();
        let dir = CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap();
        let images = CriuRuntime::pinned_path(&dir).join("images");
        assert!(images.is_dir());

        // Verify permissions are 0o700
        let mode = fs::metadata(&images).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "images dir should be mode 700, got {:o}", mode);
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_file_as_output_dir() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("not-a-dir");
        fs::write(&file_path, "").unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(&file_path).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "expected 'not a directory' error, got: {err}"
        );
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_symlinked_output_dir() {
        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        symlink(&real_dir, &link).unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(&link).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_group_writable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o775)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("writable by group/others"),
            "expected group-writable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_world_writable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o757)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("writable by group/others"),
            "expected world-writable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_non_executable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o600)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("not executable"),
            "expected non-executable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_accepts_secure_binary() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        CriuRuntime::validate_binary(&bin).expect("should accept mode 0755");
    }

    #[test]
    fn test_validate_binary_accepts_owner_only_executable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();

        CriuRuntime::validate_binary(&bin).expect("should accept mode 0700");
    }

    #[test]
    fn test_validate_binary_rejects_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("nonexistent");
        assert!(CriuRuntime::validate_binary(&bin).is_err());
    }

    #[test]
    fn test_checkpoint_state_transitions() {
        use crate::checkpoint::state::CheckpointState;
        use crate::error::StateTransition;

        // Valid forward transitions
        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Dumping));
        assert!(CheckpointState::Dumping.can_transition_to(&CheckpointState::Dumped));
        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Restoring));
        assert!(CheckpointState::Restoring.can_transition_to(&CheckpointState::Restored));

        // Valid abort transitions
        assert!(CheckpointState::Dumping.can_transition_to(&CheckpointState::None));
        assert!(CheckpointState::Restoring.can_transition_to(&CheckpointState::None));

        // Invalid transitions
        assert!(!CheckpointState::None.can_transition_to(&CheckpointState::Dumped));
        assert!(!CheckpointState::None.can_transition_to(&CheckpointState::Restored));
        assert!(!CheckpointState::Dumped.can_transition_to(&CheckpointState::Restoring));
        assert!(!CheckpointState::Restored.can_transition_to(&CheckpointState::Dumping));
    }

    #[test]
    fn test_prepare_checkpoint_dir_sets_secure_permissions() {
        let tmp = TempDir::new().unwrap();
        CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap();

        // Both output dir and images subdir should be 0700
        let output_mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        let images_mode = fs::metadata(tmp.path().join("images"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(output_mode, 0o700);
        assert_eq!(images_mode, 0o700);
    }

    #[test]
    fn checkpoint_directory_rejects_a_foreign_owner_even_at_mode_0700() {
        use nix::unistd::{chown, Uid};
        let tmp = TempDir::new().unwrap();
        if Uid::effective().is_root() {
            chown(tmp.path(), Some(Uid::from_raw(65534)), None).unwrap();
            assert!(CriuRuntime::open_checkpoint_directory(tmp.path()).is_err());
        } else {
            // / is root-owned and not group/world-writable on the test host.
            assert!(CriuRuntime::open_checkpoint_directory(std::path::Path::new("/")).is_err());
        }
    }

    #[test]
    fn checkpoint_handle_survives_rename_and_rejects_writable_entries() {
        let tmp = TempDir::new().unwrap();
        let original = tmp.path().join("checkpoint");
        let pinned = CriuRuntime::prepare_checkpoint_dir(&original).unwrap();
        let path = CriuRuntime::pinned_path(&pinned);
        fs::rename(&original, tmp.path().join("old")).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("metadata.json"), "replacement").unwrap();
        assert!(!path.join("metadata.json").exists());

        let image = path.join("images/pages.img");
        fs::write(&image, b"data").unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(CriuRuntime::compute_checkpoint_hmac(&path, b"key").is_err());
        fs::set_permissions(&original, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(CriuRuntime::open_checkpoint_directory(&original).is_err());
    }

    #[test]
    fn test_checkpoint_hmac_detects_tampering_in_images() {
        let _guard = checkpoint_key_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = TempDir::new().unwrap();
        let key_dir = prepare_secure_checkpoint_key_dir(&tmp);
        let key_path = key_dir.join("checkpoint.key");
        let _env = CheckpointKeyEnvGuard::set(&key_path);

        let checkpoint_dir = tmp.path().join("checkpoint");
        fs::create_dir(&checkpoint_dir).unwrap();
        fs::create_dir(checkpoint_dir.join("images")).unwrap();
        fs::write(checkpoint_dir.join("metadata.json"), "{\"id\":\"abc\"}").unwrap();
        fs::write(
            checkpoint_dir.join("images").join("pages-1.img"),
            b"snapshot",
        )
        .unwrap();

        CriuRuntime::write_checkpoint_hmac(&checkpoint_dir).unwrap();
        CriuRuntime::verify_checkpoint_hmac(&checkpoint_dir).unwrap();

        fs::write(
            checkpoint_dir.join("images").join("pages-1.img"),
            b"tampered",
        )
        .unwrap();
        let err = CriuRuntime::verify_checkpoint_hmac(&checkpoint_dir).unwrap_err();
        assert!(err.to_string().contains("HMAC mismatch"));
    }

    #[test]
    fn test_checkpoint_hmac_rejects_symlinks_in_checkpoint_tree() {
        let _guard = checkpoint_key_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = TempDir::new().unwrap();
        let key_dir = prepare_secure_checkpoint_key_dir(&tmp);
        let key_path = key_dir.join("checkpoint.key");
        let _env = CheckpointKeyEnvGuard::set(&key_path);

        let checkpoint_dir = tmp.path().join("checkpoint");
        fs::create_dir(&checkpoint_dir).unwrap();
        fs::create_dir(checkpoint_dir.join("images")).unwrap();
        fs::write(checkpoint_dir.join("metadata.json"), "{\"id\":\"abc\"}").unwrap();
        symlink(
            checkpoint_dir.join("metadata.json"),
            checkpoint_dir.join("images").join("metadata-link"),
        )
        .unwrap();

        let err = CriuRuntime::write_checkpoint_hmac(&checkpoint_dir).unwrap_err();
        assert!(err.to_string().contains("refuses symlink"));
    }
}
