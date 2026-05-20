use crate::container::{ConsoleSize, OciStatus};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    is_immediate_nix_store_object_path, normalize_container_destination,
    normalize_provider_config_destination, normalize_volume_destination, ROOTFS_STORE_PATHS_FILE,
};
use crate::isolation::{IdMapping, NamespaceConfig, UserNamespaceConfig};
use crate::resources::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// OCI Runtime Specification configuration
///
/// This implements a subset of the OCI runtime spec for gVisor compatibility
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config.md>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciConfig {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,

    pub root: OciRoot,
    pub process: OciProcess,
    pub hostname: Option<String>,
    pub mounts: Vec<OciMount>,
    pub linux: Option<OciLinux>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<OciHooks>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
    pub capabilities: Option<OciCapabilities>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<OciRlimit>,
    #[serde(
        rename = "consoleSize",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub console_size: Option<OciConsoleSize>,
    #[serde(
        rename = "apparmorProfile",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub apparmor_profile: Option<String>,
    #[serde(
        rename = "selinuxLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selinux_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_gids: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCapabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    pub source: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciLinux {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<OciNamespace>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciResources>,
    #[serde(rename = "uidMappings", skip_serializing_if = "Vec::is_empty", default)]
    pub uid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "gidMappings", skip_serializing_if = "Vec::is_empty", default)]
    pub gid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "maskedPaths", skip_serializing_if = "Vec::is_empty", default)]
    pub masked_paths: Vec<String>,
    #[serde(
        rename = "readonlyPaths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub readonly_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<OciDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<OciSeccomp>,
    #[serde(
        rename = "rootfsPropagation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rootfs_propagation: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sysctl: HashMap<String, String>,
    #[serde(
        rename = "cgroupsPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cgroups_path: Option<String>,
    #[serde(rename = "intelRdt", default, skip_serializing_if = "Option::is_none")]
    pub intel_rdt: Option<OciIntelRdt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub namespace_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciIdMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<OciMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<OciCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<OciPids>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPids {
    pub limit: i64,
}

/// OCI process resource limit.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-process>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRlimit {
    /// Resource type (e.g. "RLIMIT_NOFILE", "RLIMIT_NPROC")
    #[serde(rename = "type")]
    pub limit_type: String,
    /// Hard limit
    pub hard: u64,
    /// Soft limit
    pub soft: u64,
}

/// OCI console size for terminal-attached processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciConsoleSize {
    pub height: u32,
    pub width: u32,
}

/// OCI linux device entry.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#devices>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciDevice {
    /// Device type: "c" (char), "b" (block), "u" (unbuffered), "p" (FIFO)
    #[serde(rename = "type")]
    pub device_type: String,
    /// Device path inside the container
    pub path: String,
    /// Major number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    /// Minor number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    /// File mode (permissions)
    #[serde(rename = "fileMode", skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<u32>,
    /// UID of the device owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// GID of the device owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

/// OCI seccomp configuration.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSeccomp {
    /// Default action when no rule matches (e.g. "SCMP_ACT_ERRNO", "SCMP_ACT_ALLOW")
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    /// Target architectures
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<String>,
    /// Syscall rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<OciSeccompSyscall>,
}

/// A single seccomp syscall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSeccompSyscall {
    /// Syscall names this rule applies to
    pub names: Vec<String>,
    /// Action to take (e.g. "SCMP_ACT_ALLOW")
    pub action: String,
    /// Optional argument conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<OciSeccompArg>,
}

/// Seccomp syscall argument filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSeccompArg {
    /// Argument index (0-based)
    pub index: u32,
    /// Value to compare against
    pub value: u64,
    /// Second value for masked operations
    #[serde(rename = "valueTwo", default, skip_serializing_if = "is_zero")]
    pub value_two: u64,
    /// Comparison operator (e.g. "SCMP_CMP_EQ", "SCMP_CMP_MASKED_EQ")
    pub op: String,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// OCI Intel RDT (Resource Director Technology) configuration.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#intel-rdt>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciIntelRdt {
    /// Unique identity for the container's cache and memory bandwidth allocation
    #[serde(rename = "closID", default, skip_serializing_if = "Option::is_none")]
    pub clos_id: Option<String>,
    /// Schema for L3 cache allocation
    #[serde(
        rename = "l3CacheSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub l3_cache_schema: Option<String>,
    /// Schema for memory bandwidth allocation
    #[serde(
        rename = "memBwSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mem_bw_schema: Option<String>,
}

/// A single OCI lifecycle hook entry.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciHook {
    /// Absolute path to the hook binary.
    pub path: String,
    /// Arguments passed to the hook (argv\[0\] should be the binary name).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variables for the hook process.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Timeout in seconds. If the hook does not exit within this duration it is killed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// OCI lifecycle hooks.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks>
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciHooks {
    /// Called after the runtime environment has been created but before pivot_root.
    #[serde(
        rename = "createRuntime",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub create_runtime: Vec<OciHook>,
    /// Called after pivot_root but before the start operation.
    #[serde(
        rename = "createContainer",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub create_container: Vec<OciHook>,
    /// Called after the start operation but before the user process executes.
    #[serde(
        rename = "startContainer",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub start_container: Vec<OciHook>,
    /// Called after the user-specified process has started.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststart: Vec<OciHook>,
    /// Called after the container has been stopped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststop: Vec<OciHook>,
}

/// Container state JSON passed to OCI hooks on stdin.
///
/// Spec: <https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state>
#[derive(Debug, Clone, Serialize)]
pub struct OciContainerState {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: OciStatus,
    pub pid: u32,
    pub bundle: String,
}

impl OciHooks {
    /// Returns true if there are no hooks configured.
    pub fn is_empty(&self) -> bool {
        self.create_runtime.is_empty()
            && self.create_container.is_empty()
            && self.start_container.is_empty()
            && self.poststart.is_empty()
            && self.poststop.is_empty()
    }

    /// Execute a list of hooks in order, passing container state JSON on stdin.
    ///
    /// If any hook exits non-zero, an error is returned immediately (remaining hooks are skipped).
    pub fn run_hooks(hooks: &[OciHook], state: &OciContainerState, phase: &str) -> Result<()> {
        let state_json = serde_json::to_string(state).map_err(|e| {
            NucleusError::HookError(format!(
                "Failed to serialize container state for hook: {}",
                e
            ))
        })?;

        for (i, hook) in hooks.iter().enumerate() {
            info!(
                "Running {} hook [{}/{}]: {}",
                phase,
                i + 1,
                hooks.len(),
                hook.path
            );
            Self::execute_hook(hook, &state_json, phase)?;
        }

        Ok(())
    }

    /// Execute a list of hooks best-effort (log errors but don't fail).
    ///
    /// Used for poststop hooks per the OCI spec: errors MUST be logged but MUST NOT
    /// prevent cleanup.
    pub fn run_hooks_best_effort(hooks: &[OciHook], state: &OciContainerState, phase: &str) {
        let state_json = match serde_json::to_string(state) {
            Ok(json) => json,
            Err(e) => {
                warn!(
                    "Failed to serialize container state for {} hooks: {}",
                    phase, e
                );
                return;
            }
        };

        for (i, hook) in hooks.iter().enumerate() {
            info!(
                "Running {} hook [{}/{}]: {}",
                phase,
                i + 1,
                hooks.len(),
                hook.path
            );
            if let Err(e) = Self::execute_hook(hook, &state_json, phase) {
                warn!("{} hook [{}] failed (continuing): {}", phase, i + 1, e);
            }
        }
    }

    fn execute_hook(hook: &OciHook, state_json: &str, phase: &str) -> Result<()> {
        #[cfg(not(test))]
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let hook_path = Path::new(&hook.path);
        if !hook_path.is_absolute() {
            return Err(NucleusError::HookError(format!(
                "{} hook path must be absolute: {}",
                phase, hook.path
            )));
        }

        // Restrict hooks to trusted system directories. Hooks execute in
        // the parent process before security hardening (by OCI spec), so
        // they must come from locations that unprivileged users cannot write to.
        #[cfg(not(test))]
        {
            const TRUSTED_HOOK_PREFIXES: &[&str] = &[
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/lib/",
                "/usr/libexec/",
                "/usr/local/bin/",
                "/usr/local/sbin/",
                "/usr/local/libexec/",
                "/bin/",
                "/sbin/",
                "/nix/store/",
                "/opt/",
            ];
            if !TRUSTED_HOOK_PREFIXES
                .iter()
                .any(|prefix| hook.path.starts_with(prefix))
            {
                return Err(NucleusError::HookError(format!(
                    "{} hook path '{}' is not under a trusted directory ({:?})",
                    phase, hook.path, TRUSTED_HOOK_PREFIXES
                )));
            }
        }

        // Use symlink_metadata (lstat) instead of .exists() to avoid
        // following symlinks in the existence check. Reject symlinked hooks
        // to prevent a TOCTOU swap between the check and exec.
        match std::fs::symlink_metadata(hook_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NucleusError::HookError(format!(
                    "{} hook path is a symlink (refusing to follow): {}",
                    phase, hook.path
                )));
            }
            Err(_) => {
                return Err(NucleusError::HookError(format!(
                    "{} hook binary not found: {}",
                    phase, hook.path
                )));
            }
            Ok(_) => {}
        }

        // C-1: Validate hook binary ownership and permissions to prevent
        // execution of world-writable or unexpectedly-owned binaries.
        // Similar to runsc's hook validation – reject hooks that could be
        // tampered with by unprivileged users.
        Self::validate_hook_binary(hook_path, phase)?;

        let mut cmd = Command::new(&hook.path);
        if !hook.args.is_empty() {
            // OCI spec: args[0] is the binary name (like execve argv); pass rest as arguments
            cmd.args(&hook.args[1..]);
        }

        if !hook.env.is_empty() {
            cmd.env_clear();
            for entry in &hook.env {
                if let Some((key, value)) = entry.split_once('=') {
                    cmd.env(key, value);
                }
            }
        }

        // C-1: Drop all capabilities and set restrictive resource limits
        // for hook execution. Hooks run in the parent process before security
        // hardening, so we sandbox them defensively.
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // C-1: Apply RLIMIT backstops only in the spawned child process
        // via pre_exec, so the parent process is not affected.
        // Note: pre_exec runs after fork but before exec, in the child process.
        #[cfg(not(test))]
        unsafe {
            cmd.pre_exec(|| {
                // Prevent the hook from gaining privileges via setuid/setgid
                // binaries or file capabilities. This must be set before exec.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let rlim_nproc = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let rlim_nofile = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim_nofile) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        const TEXT_FILE_BUSY_SPAWN_RETRIES: usize = 100;
        const TEXT_FILE_BUSY_RETRY_DELAY: std::time::Duration =
            std::time::Duration::from_millis(10);

        let mut text_file_busy_retries = 0;
        let mut child = loop {
            match cmd.spawn() {
                Ok(child) => break child,
                Err(e)
                    if e.raw_os_error() == Some(libc::ETXTBSY)
                        && text_file_busy_retries < TEXT_FILE_BUSY_SPAWN_RETRIES =>
                {
                    text_file_busy_retries += 1;
                    debug!(
                        "{} hook {} was busy during spawn; retrying ({}/{})",
                        phase, hook.path, text_file_busy_retries, TEXT_FILE_BUSY_SPAWN_RETRIES
                    );
                    std::thread::sleep(TEXT_FILE_BUSY_RETRY_DELAY);
                }
                Err(e) => {
                    return Err(NucleusError::HookError(format!(
                        "Failed to spawn {} hook {}: {}",
                        phase, hook.path, e
                    )));
                }
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write as IoWrite;
            let _ = stdin.write_all(state_json.as_bytes());
        }

        let timeout_secs = hook.timeout.unwrap_or(30) as u64;
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        debug!("{} hook {} completed successfully", phase, hook.path);
                        return Ok(());
                    } else {
                        let stderr = child
                            .stderr
                            .take()
                            .map(|mut e| {
                                let mut buf = String::new();
                                use std::io::Read;
                                let _ = e.read_to_string(&mut buf);
                                buf
                            })
                            .unwrap_or_default();
                        return Err(NucleusError::HookError(format!(
                            "{} hook {} exited with status: {}{}",
                            phase,
                            hook.path,
                            status,
                            if stderr.is_empty() {
                                String::new()
                            } else {
                                format!(" (stderr: {})", stderr.trim())
                            }
                        )));
                    }
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(NucleusError::HookError(format!(
                            "{} hook {} timed out after {}s",
                            phase, hook.path, timeout_secs
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(NucleusError::HookError(format!(
                        "Failed to wait for {} hook {}: {}",
                        phase, hook.path, e
                    )));
                }
            }
        }
    }

    /// Validate hook binary ownership and permissions.
    ///
    /// Rejects hooks that are world-writable or group-writable, or owned by
    /// a UID that doesn't match the effective UID or root. This prevents
    /// privilege escalation via tampered hook binaries.
    fn validate_hook_binary(hook_path: &Path, phase: &str) -> Result<()> {
        // Use symlink_metadata (lstat) to inspect the hook path itself
        // rather than following symlinks, consistent with the rejection
        // of symlinked hooks above.
        let metadata = std::fs::symlink_metadata(hook_path).map_err(|e| {
            NucleusError::HookError(format!(
                "Failed to stat {} hook {}: {}",
                phase,
                hook_path.display(),
                e
            ))
        })?;

        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode();
        let uid = metadata.uid();
        let gid = metadata.gid();
        let effective_uid = nix::unistd::Uid::effective().as_raw();

        // Reject world-writable hooks
        if mode & 0o002 != 0 {
            return Err(NucleusError::HookError(format!(
                "{} hook {} is world-writable (mode {:04o}) – refusing to execute",
                phase,
                hook_path.display(),
                mode & 0o7777
            )));
        }

        // Reject group-writable hooks unless owned by root
        if mode & 0o020 != 0 && uid != 0 {
            return Err(NucleusError::HookError(format!(
                "{} hook {} is group-writable and not owned by root (mode {:04o}, uid {}) – refusing to execute",
                phase,
                hook_path.display(),
                mode & 0o7777,
                uid
            )));
        }

        // Reject hooks owned by arbitrary UIDs – must be root or effective UID
        if uid != 0 && uid != effective_uid {
            return Err(NucleusError::HookError(format!(
                "{} hook {} is owned by UID {} (expected 0 or {}) – refusing to execute",
                phase,
                hook_path.display(),
                uid,
                effective_uid
            )));
        }

        // Reject hooks with setuid/setgid bits
        if mode & 0o6000 != 0 {
            return Err(NucleusError::HookError(format!(
                "{} hook {} has setuid/setgid bits (mode {:04o}) – refusing to execute",
                phase,
                hook_path.display(),
                mode & 0o7777
            )));
        }

        debug!(
            "{} hook {} validation passed (uid={}, gid={}, mode={:04o})",
            phase,
            hook_path.display(),
            uid,
            gid,
            mode & 0o7777
        );

        Ok(())
    }
}

impl OciConfig {
    /// Create a minimal OCI config for Nucleus containers
    pub fn new(command: Vec<String>, hostname: Option<String>) -> Self {
        Self {
            oci_version: "1.0.2".to_string(),
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: true,
            },
            process: OciProcess {
                terminal: false,
                user: OciUser {
                    uid: 0,
                    gid: 0,
                    additional_gids: None,
                },
                args: command,
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "HOME=/home/agent".to_string(),
                ],
                cwd: "/workspace".to_string(),
                no_new_privileges: true,
                capabilities: Some(OciCapabilities {
                    bounding: vec![],
                    effective: vec![],
                    inheritable: vec![],
                    permitted: vec![],
                    ambient: vec![],
                }),
                rlimits: vec![],
                console_size: None,
                apparmor_profile: None,
                selinux_label: None,
            },
            hostname,
            mounts: vec![
                OciMount {
                    destination: "/proc".to_string(),
                    source: "proc".to_string(),
                    mount_type: "proc".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                    ],
                },
                OciMount {
                    destination: "/dev".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                OciMount {
                    destination: "/dev/shm".to_string(),
                    source: "shm".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "mode=1777".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                OciMount {
                    destination: "/tmp".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "noexec".to_string(),
                        "mode=1777".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                OciMount {
                    destination: "/home/agent".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "noexec".to_string(),
                        "mode=0700".to_string(),
                        "size=262144k".to_string(),
                        "uid=0".to_string(),
                        "gid=0".to_string(),
                    ],
                },
                OciMount {
                    destination: "/sys".to_string(),
                    source: "sysfs".to_string(),
                    mount_type: "sysfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "ro".to_string(),
                    ],
                },
            ],
            hooks: None,
            annotations: HashMap::new(),
            linux: Some(OciLinux {
                namespaces: Some(vec![
                    OciNamespace {
                        namespace_type: "pid".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "network".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "ipc".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "uts".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "mount".to_string(),
                    },
                ]),
                resources: None,
                uid_mappings: vec![],
                gid_mappings: vec![],
                // M14: Aligned with native masked paths in mount.rs (PROC_NULL_MASKED)
                masked_paths: vec![
                    "/proc/acpi".to_string(),
                    "/proc/asound".to_string(),
                    "/proc/kcore".to_string(),
                    "/proc/keys".to_string(),
                    "/proc/latency_stats".to_string(),
                    "/proc/sched_debug".to_string(),
                    "/proc/scsi".to_string(),
                    "/proc/timer_list".to_string(),
                    "/proc/timer_stats".to_string(),
                    "/proc/sysrq-trigger".to_string(), // M14: null-mask, not read-only
                    "/proc/kpagecount".to_string(),
                    "/proc/kpageflags".to_string(),
                    "/proc/kpagecgroup".to_string(),
                    "/proc/config.gz".to_string(),
                    "/proc/kallsyms".to_string(),
                    "/sys/firmware".to_string(),
                ],
                readonly_paths: vec![
                    "/proc/bus".to_string(),
                    "/proc/fs".to_string(),
                    "/proc/irq".to_string(),
                    "/proc/sys".to_string(),
                ],
                devices: vec![
                    OciDevice {
                        device_type: "c".to_string(),
                        path: "/dev/null".to_string(),
                        major: Some(1),
                        minor: Some(3),
                        file_mode: Some(0o666),
                        uid: Some(0),
                        gid: Some(0),
                    },
                    OciDevice {
                        device_type: "c".to_string(),
                        path: "/dev/zero".to_string(),
                        major: Some(1),
                        minor: Some(5),
                        file_mode: Some(0o666),
                        uid: Some(0),
                        gid: Some(0),
                    },
                    OciDevice {
                        device_type: "c".to_string(),
                        path: "/dev/full".to_string(),
                        major: Some(1),
                        minor: Some(7),
                        file_mode: Some(0o666),
                        uid: Some(0),
                        gid: Some(0),
                    },
                    OciDevice {
                        device_type: "c".to_string(),
                        path: "/dev/random".to_string(),
                        major: Some(1),
                        minor: Some(8),
                        file_mode: Some(0o666),
                        uid: Some(0),
                        gid: Some(0),
                    },
                    OciDevice {
                        device_type: "c".to_string(),
                        path: "/dev/urandom".to_string(),
                        major: Some(1),
                        minor: Some(9),
                        file_mode: Some(0o666),
                        uid: Some(0),
                        gid: Some(0),
                    },
                ],
                seccomp: None,
                rootfs_propagation: Some("rprivate".to_string()),
                sysctl: HashMap::new(),
                cgroups_path: None,
                intel_rdt: None,
            }),
        }
    }

    /// Add resource limits to the config
    pub fn with_resources(mut self, limits: &ResourceLimits) -> Self {
        let mut resources = OciResources {
            memory: None,
            cpu: None,
            pids: None,
        };

        if let Some(memory_bytes) = limits.memory_bytes {
            resources.memory = Some(OciMemory {
                limit: Some(memory_bytes as i64),
            });
        }

        if let Some(quota_us) = limits.cpu_quota_us {
            resources.cpu = Some(OciCpu {
                quota: Some(quota_us as i64),
                period: Some(limits.cpu_period_us),
            });
        }

        if let Some(pids_max) = limits.pids_max {
            resources.pids = Some(OciPids {
                limit: pids_max as i64,
            });
        }

        if let Some(linux) = &mut self.linux {
            linux.resources = Some(resources);
        }

        self
    }

    /// Configure the OCI noNewPrivileges process flag.
    pub fn with_no_new_privileges(mut self, enabled: bool) -> Self {
        self.process.no_new_privileges = enabled;
        self
    }

    /// Configure the process as terminal-attached with an initial console size.
    pub fn with_terminal(mut self, size: ConsoleSize) -> Self {
        self.process.terminal = true;
        self.process.console_size = Some(OciConsoleSize {
            height: size.height as u32,
            width: size.width as u32,
        });
        self
    }

    /// Add environment variables to the OCI process config.
    pub fn with_env(mut self, vars: &[(String, String)]) -> Self {
        if vars.iter().any(|(key, _)| key == "HOME") {
            self.process.env.retain(|entry| !entry.starts_with("HOME="));
        }
        for (key, value) in vars {
            self.process.env.push(format!("{}={}", key, value));
        }
        self
    }

    /// Add or replace the private sandbox home tmpfs mount.
    pub fn with_home_tmpfs(
        mut self,
        home: &Path,
        identity: &crate::container::ProcessIdentity,
    ) -> Result<Self> {
        let dest = normalize_container_destination(home)?;
        let dest_str = dest.to_string_lossy().to_string();

        self.process.env.retain(|entry| !entry.starts_with("HOME="));
        self.process.env.push(format!("HOME={}", dest_str));

        self.mounts
            .retain(|mount| mount.destination != "/home/agent");
        self.mounts.push(OciMount {
            destination: dest_str,
            source: "tmpfs".to_string(),
            mount_type: "tmpfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "nodev".to_string(),
                "noexec".to_string(),
                "mode=0700".to_string(),
                "size=262144k".to_string(),
                format!("uid={}", identity.uid),
                format!("gid={}", identity.gid),
            ],
        });

        Ok(self)
    }

    /// Set the OCI process working directory.
    pub fn with_workdir(mut self, workdir: &Path) -> Result<Self> {
        let normalized = normalize_container_destination(workdir)?;
        self.process.cwd = normalized.to_string_lossy().to_string();
        Ok(self)
    }

    /// Add sd_notify socket passthrough.
    pub fn with_sd_notify(mut self) -> Self {
        if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
            self.process
                .env
                .push(format!("NOTIFY_SOCKET={}", notify_socket));
        }
        self
    }

    /// Add bind mounts for secrets.
    pub fn with_secret_mounts(mut self, secrets: &[crate::container::SecretMount]) -> Self {
        for secret in secrets {
            self.mounts.push(OciMount {
                destination: secret.dest.to_string_lossy().to_string(),
                source: secret.source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "noexec".to_string(),
                ],
            });
        }
        self
    }

    /// Set the process identity for the OCI workload.
    pub fn with_process_identity(mut self, identity: &crate::container::ProcessIdentity) -> Self {
        self.process.user.uid = identity.uid;
        self.process.user.gid = identity.gid;
        self.process.user.additional_gids = if identity.additional_gids.is_empty() {
            None
        } else {
            Some(identity.additional_gids.clone())
        };
        self
    }

    /// Add a read-only bind mount of an in-memory secret staging directory at
    /// `/run/secrets`, plus compatibility bind mounts for each staged secret to
    /// its requested container destination.
    pub fn with_inmemory_secret_mounts(
        mut self,
        stage_dir: &Path,
        secrets: &[crate::container::SecretMount],
    ) -> Result<Self> {
        self.mounts.push(OciMount {
            destination: "/run/secrets".to_string(),
            source: stage_dir.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options: vec![
                "bind".to_string(),
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
                "noexec".to_string(),
            ],
        });

        for secret in secrets {
            let dest = normalize_container_destination(&secret.dest)?;
            if !secret.source.starts_with(stage_dir) {
                return Err(NucleusError::ConfigError(format!(
                    "Staged secret source {:?} must live under {:?}",
                    secret.source, stage_dir
                )));
            }
            self.mounts.push(OciMount {
                destination: dest.to_string_lossy().to_string(),
                source: secret.source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "noexec".to_string(),
                ],
            });
        }

        Ok(self)
    }

    /// Add bind or tmpfs volume mounts.
    pub fn with_volume_mounts(mut self, volumes: &[crate::container::VolumeMount]) -> Result<Self> {
        use crate::container::VolumeSource;

        for volume in volumes {
            let dest = normalize_volume_destination(&volume.dest)?;
            match &volume.source {
                VolumeSource::Bind { source } => {
                    crate::filesystem::validate_bind_mount_source(source)?;
                    let mut options = vec![
                        "bind".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                    ];
                    if volume.read_only {
                        options.push("ro".to_string());
                    }
                    self.mounts.push(OciMount {
                        destination: dest.to_string_lossy().to_string(),
                        source: source.to_string_lossy().to_string(),
                        mount_type: "bind".to_string(),
                        options,
                    });
                }
                VolumeSource::Tmpfs { size } => {
                    let mut options = vec![
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "mode=0755".to_string(),
                    ];
                    if volume.read_only {
                        options.push("ro".to_string());
                    }
                    if let Some(size) = size {
                        options.push(format!("size={}", size));
                    }
                    self.mounts.push(OciMount {
                        destination: dest.to_string_lossy().to_string(),
                        source: "tmpfs".to_string(),
                        mount_type: "tmpfs".to_string(),
                        options,
                    });
                }
            }
        }

        Ok(self)
    }

    /// Add explicit provider CLI config bind mounts under the sandbox home.
    pub fn with_provider_config_mounts(
        mut self,
        home: &Path,
        provider_configs: &[crate::container::ProviderConfigMount],
    ) -> Result<Self> {
        for provider_config in provider_configs {
            crate::filesystem::validate_provider_config_source(&provider_config.source)?;
            let source = fs::canonicalize(&provider_config.source).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to canonicalize provider config source {:?}: {}",
                    provider_config.source, e
                ))
            })?;
            let dest = normalize_provider_config_destination(home, &provider_config.dest)?;

            let mut options = vec![
                "bind".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
                "noexec".to_string(),
            ];
            if provider_config.read_only {
                options.push("ro".to_string());
            }

            self.mounts.push(OciMount {
                destination: dest.to_string_lossy().to_string(),
                source: source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options,
            });
        }

        Ok(self)
    }

    /// Add the first-class workspace bind mount.
    pub fn with_workspace_mount(
        mut self,
        workspace: &crate::container::WorkspaceConfig,
    ) -> Result<Self> {
        let Some(source) = workspace.effective_host_path() else {
            return Ok(self);
        };
        if workspace.mode == crate::container::WorkspaceMode::CopyInOut {
            let metadata = fs::symlink_metadata(source).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to stat workspace staging path {:?}: {}",
                    source, e
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(NucleusError::FilesystemError(format!(
                    "Workspace staging path must be a real directory: {:?}",
                    source
                )));
            }
        } else {
            crate::filesystem::validate_workspace_host_path(source)?;
        }
        let dest = normalize_container_destination(&workspace.container_path)?;

        let mut options = vec![
            "bind".to_string(),
            "nosuid".to_string(),
            "nodev".to_string(),
        ];
        if workspace.is_read_only() {
            options.push("ro".to_string());
        }
        if !workspace.allow_execute {
            options.push("noexec".to_string());
        }

        self.mounts.push(OciMount {
            destination: dest.to_string_lossy().to_string(),
            source: source.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options,
        });

        Ok(self)
    }

    /// Bind mount the host context directory into the container.
    ///
    /// The gVisor integration path expects `/context` to be writable so test
    /// workloads can write results back to the host.
    pub fn with_context_bind(mut self, context_dir: &std::path::Path) -> Self {
        self.mounts.push(OciMount {
            destination: "/context".to_string(),
            source: context_dir.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options: vec![
                "bind".to_string(),
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
            ],
        });
        self
    }

    /// Add rootfs bind mounts from a pre-built rootfs path.
    pub fn with_rootfs_binds(mut self, rootfs_path: &std::path::Path) -> Result<Self> {
        let subdirs = ["bin", "sbin", "lib", "lib64", "usr", "etc", "nix"];
        for subdir in &subdirs {
            let source = rootfs_path.join(subdir);
            if source.exists() {
                let source = fs::canonicalize(&source).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to canonicalize rootfs mount source {:?}: {}",
                        source, e
                    ))
                })?;
                self.mounts
                    .push(Self::readonly_bind_mount(format!("/{}", subdir), source));
            }
        }
        self.add_rootfs_store_path_binds(rootfs_path)?;
        Ok(self)
    }

    fn readonly_bind_mount(destination: String, source: PathBuf) -> OciMount {
        OciMount {
            destination,
            source: source.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options: vec![
                "bind".to_string(),
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
            ],
        }
    }

    fn add_rootfs_store_path_binds(&mut self, rootfs_path: &Path) -> Result<()> {
        let store_paths_file = rootfs_path.join(ROOTFS_STORE_PATHS_FILE);
        if !store_paths_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&store_paths_file).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to read rootfs store paths {:?}: {}",
                store_paths_file, e
            ))
        })?;

        for (line_no, line) in content.lines().enumerate() {
            let source = line.trim();
            if source.is_empty() {
                continue;
            }
            let source = Path::new(source);
            if !is_immediate_nix_store_object_path(source) {
                return Err(NucleusError::FilesystemError(format!(
                    "Invalid rootfs store path on line {} in {:?}: {} (expected immediate /nix/store/<32-char-hash>-<name> object)",
                    line_no + 1,
                    store_paths_file,
                    source.display()
                )));
            }
            let store_name = source.file_name().ok_or_else(|| {
                NucleusError::FilesystemError(format!(
                    "Invalid rootfs store path on line {} in {:?}: {}",
                    line_no + 1,
                    store_paths_file,
                    source.display()
                ))
            })?;
            let canonical = fs::canonicalize(source).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to canonicalize rootfs store path {:?}: {}",
                    source, e
                ))
            })?;
            if !is_immediate_nix_store_object_path(&canonical) {
                return Err(NucleusError::FilesystemError(format!(
                    "Rootfs store path must resolve to an immediate /nix/store/<32-char-hash>-<name> object: {} -> {}",
                    source.display(),
                    canonical.display()
                )));
            }
            let destination = Path::new("/nix/store")
                .join(store_name)
                .to_string_lossy()
                .to_string();
            self.mounts
                .push(Self::readonly_bind_mount(destination, canonical));
        }

        Ok(())
    }

    /// Replace the default namespace list with an explicit configuration.
    pub fn with_namespace_config(mut self, config: &NamespaceConfig) -> Self {
        let mut namespaces = Vec::new();

        if config.pid {
            namespaces.push(OciNamespace {
                namespace_type: "pid".to_string(),
            });
        }
        if config.net {
            namespaces.push(OciNamespace {
                namespace_type: "network".to_string(),
            });
        }
        if config.ipc {
            namespaces.push(OciNamespace {
                namespace_type: "ipc".to_string(),
            });
        }
        if config.uts {
            namespaces.push(OciNamespace {
                namespace_type: "uts".to_string(),
            });
        }
        if config.mnt {
            namespaces.push(OciNamespace {
                namespace_type: "mount".to_string(),
            });
        }
        if config.cgroup {
            namespaces.push(OciNamespace {
                namespace_type: "cgroup".to_string(),
            });
        }
        if config.time {
            namespaces.push(OciNamespace {
                namespace_type: "time".to_string(),
            });
        }
        if config.user {
            namespaces.push(OciNamespace {
                namespace_type: "user".to_string(),
            });
        }

        if let Some(linux) = &mut self.linux {
            linux.namespaces = Some(namespaces);
        }

        self
    }

    /// Add read-only bind mounts for host runtime paths.
    ///
    /// This mirrors the native fallback path for non-production containers so
    /// common executables such as `/bin/sh` remain available inside the OCI
    /// rootfs when no explicit rootfs is configured.
    pub fn with_host_runtime_binds(mut self) -> Self {
        // Use a fixed set of standard FHS paths only. Do NOT scan host $PATH,
        // which would expose arbitrary host directories inside the container.
        let host_paths: BTreeSet<String> =
            ["/bin", "/sbin", "/usr", "/lib", "/lib64", "/nix/store"]
                .iter()
                .map(|s| s.to_string())
                .collect();

        for host_path in host_paths {
            let source = Path::new(&host_path);
            if !source.exists() {
                continue;
            }

            self.mounts.push(OciMount {
                destination: host_path.clone(),
                source: source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                ],
            });
        }
        self
    }

    /// Add user namespace configuration
    pub fn with_user_namespace(mut self) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.push(OciNamespace {
                    namespace_type: "user".to_string(),
                });
            }
        }
        self
    }

    /// Remove the OCI network namespace entry so runsc inherits the process
    /// network namespace that Nucleus prepared before exec.
    pub fn without_network_namespace(mut self) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.retain(|ns| ns.namespace_type != "network");
            }
        }

        self
    }

    /// Remove the OCI user namespace entry so runsc inherits a namespace that
    /// Nucleus already created and mapped before exec.
    pub fn without_user_namespace(mut self) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.retain(|ns| ns.namespace_type != "user");
            }
            linux.uid_mappings.clear();
            linux.gid_mappings.clear();
        }

        self
    }

    /// Configure gVisor's true rootless OCI path.
    ///
    /// gVisor expects UID/GID mappings in the OCI spec for this mode, and its
    /// rootless OCI implementation does not currently support a network
    /// namespace entry in the spec. We still control networking through
    /// runsc's top-level `--network` flag.
    pub fn with_rootless_user_namespace(mut self, config: &UserNamespaceConfig) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.retain(|ns| ns.namespace_type != "network");
                if !namespaces.iter().any(|ns| ns.namespace_type == "user") {
                    namespaces.push(OciNamespace {
                        namespace_type: "user".to_string(),
                    });
                }
            }
            linux.uid_mappings = config.uid_mappings.iter().map(OciIdMapping::from).collect();
            linux.gid_mappings = config.gid_mappings.iter().map(OciIdMapping::from).collect();
        }
        self
    }

    /// Set OCI lifecycle hooks on the config.
    pub fn with_hooks(mut self, hooks: OciHooks) -> Self {
        if hooks.is_empty() {
            self.hooks = None;
        } else {
            self.hooks = Some(hooks);
        }
        self
    }

    /// Set process rlimits from the Nucleus runtime defaults and configured limits.
    ///
    /// Mirrors the RLIMIT backstops applied in-process for native containers
    /// (runtime.rs), expressed as OCI config so gVisor can enforce them.
    pub fn with_rlimits(mut self, limits: &ResourceLimits) -> Self {
        let mut rlimits = Vec::with_capacity(3);

        if let Some(nproc_limit) = limits.pids_max {
            rlimits.push(OciRlimit {
                limit_type: "RLIMIT_NPROC".to_string(),
                hard: nproc_limit,
                soft: nproc_limit,
            });
        }

        rlimits.push(OciRlimit {
            limit_type: "RLIMIT_NOFILE".to_string(),
            hard: 1024,
            soft: 1024,
        });

        let memlock_limit = limits.memlock_bytes.unwrap_or(64 * 1024);
        rlimits.push(OciRlimit {
            limit_type: "RLIMIT_MEMLOCK".to_string(),
            hard: memlock_limit,
            soft: memlock_limit,
        });

        self.process.rlimits = rlimits;
        self
    }

    /// Set the linux.seccomp section from an OCI seccomp config.
    pub fn with_seccomp(mut self, seccomp: OciSeccomp) -> Self {
        if let Some(linux) = &mut self.linux {
            linux.seccomp = Some(seccomp);
        }
        self
    }

    /// Set the linux.cgroupsPath field.
    pub fn with_cgroups_path(mut self, path: String) -> Self {
        if let Some(linux) = &mut self.linux {
            linux.cgroups_path = Some(path);
        }
        self
    }

    /// Set sysctl key-value pairs on the linux config.
    pub fn with_sysctl(mut self, sysctl: HashMap<String, String>) -> Self {
        if let Some(linux) = &mut self.linux {
            linux.sysctl = sysctl;
        }
        self
    }

    /// Set annotations on the OCI config.
    pub fn with_annotations(mut self, annotations: HashMap<String, String>) -> Self {
        self.annotations = annotations;
        self
    }
}

impl From<&IdMapping> for OciIdMapping {
    fn from(mapping: &IdMapping) -> Self {
        Self {
            container_id: mapping.container_id,
            host_id: mapping.host_id,
            size: mapping.count,
        }
    }
}

/// OCI Bundle manager
///
/// Creates and manages OCI-compliant bundles for gVisor
pub struct OciBundle {
    bundle_path: PathBuf,
    config: OciConfig,
}

fn safe_child_name(name: &str) -> std::io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid path child name",
        ));
    }

    CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path child name contains NUL",
        )
    })
}

fn open_dir_nofollow(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn mkdirat_dir(parent: &fs::File, name: &str, mode: libc::mode_t) -> std::io::Result<()> {
    let name = safe_child_name(name)?;
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };

    if result == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(err)
    }
}

fn openat_dir_nofollow(parent: &fs::File, name: &str) -> std::io::Result<fs::File> {
    let name = safe_child_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };

    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn openat_file_nofollow(
    parent: &fs::File,
    name: &str,
    mode: libc::mode_t,
) -> std::io::Result<fs::File> {
    let name = safe_child_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };

    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

impl OciBundle {
    /// Create a new OCI bundle
    pub fn new(bundle_path: PathBuf, config: OciConfig) -> Self {
        Self {
            bundle_path,
            config,
        }
    }

    /// Create the bundle directory structure and write config.json
    pub fn create(&self) -> Result<()> {
        info!("Creating OCI bundle at {:?}", self.bundle_path);

        // Create the bundle directory, then reopen it without following a final
        // symlink before applying permissions or creating children beneath it.
        fs::create_dir_all(&self.bundle_path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to create bundle directory {:?}: {}",
                self.bundle_path, e
            ))
        })?;
        let bundle_dir = open_dir_nofollow(&self.bundle_path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to open bundle directory safely {:?}: {}",
                self.bundle_path, e
            ))
        })?;
        bundle_dir
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to secure bundle directory permissions {:?}: {}",
                    self.bundle_path, e
                ))
            })?;

        // Create rootfs relative to the trusted bundle directory. mkdirat plus
        // openat(O_NOFOLLOW) prevents a pre-existing rootfs symlink from being
        // chmodded when rootfs needs to be traversable for non-root UIDs.
        let rootfs = self.bundle_path.join("rootfs");
        mkdirat_dir(&bundle_dir, "rootfs", 0o755).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create rootfs directory: {}", e))
        })?;
        let rootfs_dir = openat_dir_nofollow(&bundle_dir, "rootfs").map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to open rootfs directory safely {:?}: {}",
                rootfs, e
            ))
        })?;
        // The rootfs is the container's "/" – it must be traversable by the
        // container UID which may be non-root (via --user).  Mode 0755 matches
        // the standard Linux root directory permission and lets gVisor's VFS
        // permit path traversal for any UID.
        rootfs_dir
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to set rootfs directory permissions {:?}: {}",
                    rootfs, e
                ))
            })?;

        // Write config.json
        let config_path = self.bundle_path.join("config.json");
        let config_json = serde_json::to_string_pretty(&self.config).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to serialize OCI config: {}", e))
        })?;

        let mut file = openat_file_nofollow(&bundle_dir, "config.json", 0o600).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to open config.json safely {:?}: {}",
                config_path, e
            ))
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to set config.json permissions {:?}: {}",
                    config_path, e
                ))
            })?;
        file.write_all(config_json.as_bytes()).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to write config.json: {}", e))
        })?;
        file.sync_all()
            .map_err(|e| NucleusError::GVisorError(format!("Failed to sync config.json: {}", e)))?;

        debug!("Created OCI bundle structure at {:?}", self.bundle_path);

        Ok(())
    }

    /// Get the rootfs path
    pub fn rootfs_path(&self) -> PathBuf {
        self.bundle_path.join("rootfs")
    }

    /// Get the bundle path
    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    /// Clean up the bundle
    pub fn cleanup(&self) -> Result<()> {
        if self.bundle_path.exists() {
            fs::remove_dir_all(&self.bundle_path).map_err(|e| {
                NucleusError::GVisorError(format!("Failed to cleanup bundle: {}", e))
            })?;
            debug!("Cleaned up OCI bundle at {:?}", self.bundle_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn test_oci_config_new() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()));

        assert_eq!(config.oci_version, "1.0.2");
        assert_eq!(config.root.path, "rootfs");
        assert_eq!(config.process.args, vec!["/bin/sh"]);
        assert_eq!(config.hostname, Some("test".to_string()));
        assert!(!config.process.terminal);
        assert!(config.process.console_size.is_none());
    }

    #[test]
    fn test_oci_config_with_terminal_sets_console_size() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_terminal(ConsoleSize {
            width: 120,
            height: 40,
        });

        assert!(config.process.terminal);
        let size = config.process.console_size.unwrap();
        assert_eq!(size.width, 120);
        assert_eq!(size.height, 40);
    }

    #[test]
    fn test_oci_config_with_resources() {
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .unwrap()
            .with_cpu_cores(2.0)
            .unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_resources(&limits);

        assert!(config.linux.is_some());
        let linux = config.linux.unwrap();
        assert!(linux.resources.is_some());

        let resources = linux.resources.unwrap();
        assert!(resources.memory.is_some());
        assert!(resources.cpu.is_some());
    }

    #[test]
    fn test_rootfs_binds_canonicalize_top_level_sources() {
        let temp_dir = TempDir::new().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        let real_bin = temp_dir.path().join("real-bin");
        fs::create_dir_all(&rootfs).unwrap();
        fs::create_dir_all(&real_bin).unwrap();
        symlink(&real_bin, rootfs.join("bin")).unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_rootfs_binds(&rootfs)
            .unwrap();
        let bin_mount = config
            .mounts
            .iter()
            .find(|mount| mount.destination == "/bin")
            .unwrap();

        assert_eq!(bin_mount.source, real_bin.to_string_lossy());
    }

    #[test]
    fn test_rootfs_binds_mount_declared_nix_store_closure_paths() {
        let Some(store_path) = fs::read_dir("/nix/store").ok().and_then(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .find(|path| path.is_dir() && is_immediate_nix_store_object_path(path))
        }) else {
            return;
        };
        let temp_dir = TempDir::new().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("nix/store")).unwrap();
        fs::write(
            rootfs.join(ROOTFS_STORE_PATHS_FILE),
            format!("{}\n", store_path.display()),
        )
        .unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_rootfs_binds(&rootfs)
            .unwrap();
        let store_name = store_path.file_name().unwrap();
        let destination = Path::new("/nix/store")
            .join(store_name)
            .to_string_lossy()
            .to_string();

        assert!(config
            .mounts
            .iter()
            .any(|mount| mount.destination == destination
                && mount.source == fs::canonicalize(&store_path).unwrap().to_string_lossy()));
    }

    #[test]
    fn test_rootfs_binds_reject_store_root_manifest_entry() {
        let temp_dir = TempDir::new().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("nix/store")).unwrap();
        fs::write(rootfs.join(ROOTFS_STORE_PATHS_FILE), "/nix/store\n").unwrap();

        let err = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_rootfs_binds(&rootfs)
            .unwrap_err();

        assert!(
            err.to_string().contains("expected immediate"),
            "expected immediate-store-object rejection, got: {err}"
        );
    }

    #[test]
    fn test_rootfs_binds_reject_store_subpath_manifest_entry() {
        let temp_dir = TempDir::new().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("nix/store")).unwrap();
        fs::write(
            rootfs.join(ROOTFS_STORE_PATHS_FILE),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-hello/bin\n",
        )
        .unwrap();

        let err = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_rootfs_binds(&rootfs)
            .unwrap_err();

        assert!(
            err.to_string().contains("expected immediate"),
            "expected immediate-store-object rejection, got: {err}"
        );
    }

    #[test]
    fn test_oci_bundle_create() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let bundle = OciBundle::new(bundle_path.clone(), config);

        bundle.create().unwrap();

        assert!(bundle_path.exists());
        assert!(bundle_path.join("rootfs").exists());
        assert!(bundle_path.join("config.json").exists());

        bundle.cleanup().unwrap();
        assert!(!bundle_path.exists());
    }

    #[test]
    fn test_oci_bundle_rejects_bundle_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");
        let protected_host_dir = temp_dir.path().join("protected-host-dir");

        fs::create_dir_all(&protected_host_dir).unwrap();
        fs::set_permissions(&protected_host_dir, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&protected_host_dir, &bundle_path).unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let bundle = OciBundle::new(bundle_path.clone(), config);

        let err = bundle.create().unwrap_err();

        assert!(format!("{err}").contains("Failed to open bundle directory safely"));
        assert_eq!(
            fs::metadata(&protected_host_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(fs::symlink_metadata(&bundle_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn test_oci_bundle_rejects_rootfs_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");
        let protected_host_dir = temp_dir.path().join("protected-host-dir");

        fs::create_dir_all(&bundle_path).unwrap();
        fs::create_dir_all(&protected_host_dir).unwrap();
        fs::set_permissions(&protected_host_dir, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&protected_host_dir, bundle_path.join("rootfs")).unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let bundle = OciBundle::new(bundle_path.clone(), config);

        let err = bundle.create().unwrap_err();

        assert!(format!("{err}").contains("Failed to open rootfs directory safely"));
        assert_eq!(
            fs::metadata(&protected_host_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(fs::symlink_metadata(bundle_path.join("rootfs"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn test_oci_config_serialization() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()));

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("ociVersion"));
        assert!(json.contains("1.0.2"));
        assert!(json.contains("/bin/sh"));

        // Test deserialization
        let deserialized: OciConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.oci_version, config.oci_version);
        assert_eq!(deserialized.process.args, config.process.args);
    }

    #[test]
    fn test_host_runtime_binds_uses_fixed_paths_not_host_path() {
        // with_host_runtime_binds must NOT scan the host $PATH. Only standard
        // FHS paths should be bind-mounted to prevent leaking arbitrary host
        // directories into the container. Verify by setting a distinctive PATH
        // and checking that none of its entries appear in the resulting mounts.
        std::env::set_var("PATH", "/tmp/evil-inject-path/bin:/opt/attacker/sbin");
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_host_runtime_binds();
        let mount_dests: Vec<&str> = config
            .mounts
            .iter()
            .map(|m| m.destination.as_str())
            .collect();
        let mount_srcs: Vec<&str> = config.mounts.iter().map(|m| m.source.as_str()).collect();
        // Verify no mount references the injected PATH entries
        for path in &["/tmp/evil-inject-path", "/opt/attacker"] {
            assert!(
                !mount_dests.iter().any(|d| d.contains(path)),
                "with_host_runtime_binds must not use host $PATH – found {:?} in mount destinations",
                path
            );
            assert!(
                !mount_srcs.iter().any(|s| s.contains(path)),
                "with_host_runtime_binds must not use host $PATH – found {:?} in mount sources",
                path
            );
        }
        // Verify only standard FHS paths are mounted
        let allowed_prefixes = ["/bin", "/sbin", "/usr", "/lib", "/lib64", "/nix/store"];
        for mount in &config.mounts {
            if mount.mount_type == "bind" {
                assert!(
                    allowed_prefixes
                        .iter()
                        .any(|p| mount.destination.starts_with(p)),
                    "unexpected bind mount destination: {} – only FHS paths allowed",
                    mount.destination
                );
            }
        }
    }

    #[test]
    fn test_without_user_namespace_removes_namespace_and_mappings() {
        let user_ns = UserNamespaceConfig::rootless();
        let mut namespaces = NamespaceConfig::default();
        namespaces.user = true;

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_namespace_config(&namespaces)
            .with_rootless_user_namespace(&user_ns)
            .without_user_namespace();
        let linux = config.linux.unwrap();

        assert!(!linux
            .namespaces
            .unwrap()
            .iter()
            .any(|namespace| namespace.namespace_type == "user"));
        assert!(linux.uid_mappings.is_empty());
        assert!(linux.gid_mappings.is_empty());
    }

    #[test]
    fn test_volume_mounts_include_bind_and_tmpfs_options() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_volume_mounts(&[
                crate::container::VolumeMount {
                    source: crate::container::VolumeSource::Bind {
                        source: tmp.path().to_path_buf(),
                    },
                    dest: std::path::PathBuf::from("/var/lib/app"),
                    read_only: true,
                },
                crate::container::VolumeMount {
                    source: crate::container::VolumeSource::Tmpfs {
                        size: Some("64M".to_string()),
                    },
                    dest: std::path::PathBuf::from("/var/cache/app"),
                    read_only: false,
                },
            ])
            .unwrap();

        assert!(config.mounts.iter().any(|mount| {
            mount.destination == "/var/lib/app"
                && mount.mount_type == "bind"
                && mount.options.contains(&"ro".to_string())
        }));
        assert!(config.mounts.iter().any(|mount| {
            mount.destination == "/var/cache/app"
                && mount.mount_type == "tmpfs"
                && mount.options.contains(&"size=64M".to_string())
        }));
    }

    #[test]
    fn test_workspace_mount_defaults_noexec_and_cwd() {
        let tmp = tempfile::TempDir::new().unwrap();
        let workspace = crate::container::WorkspaceConfig::new()
            .with_host_path(tmp.path().to_path_buf())
            .with_mode(crate::container::WorkspaceMode::BindRw);
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_workspace_mount(&workspace)
            .unwrap();

        assert_eq!(config.process.cwd, "/workspace");
        assert!(config.process.env.contains(&"HOME=/home/agent".to_string()));
        assert!(config.mounts.iter().any(|mount| {
            mount.destination == "/workspace"
                && mount.mount_type == "bind"
                && mount.options.contains(&"noexec".to_string())
                && !mount.options.contains(&"ro".to_string())
        }));
    }

    #[test]
    fn test_home_tmpfs_defaults_and_process_identity_options() {
        let identity = crate::container::ProcessIdentity {
            uid: 1000,
            gid: 1001,
            additional_gids: Vec::new(),
        };
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_home_tmpfs(std::path::Path::new("/home/agent"), &identity)
            .unwrap();

        assert!(config.process.env.contains(&"HOME=/home/agent".to_string()));
        let mount = config
            .mounts
            .iter()
            .find(|mount| mount.destination == "/home/agent")
            .unwrap();
        assert_eq!(mount.mount_type, "tmpfs");
        assert!(mount.options.contains(&"noexec".to_string()));
        assert!(mount.options.contains(&"uid=1000".to_string()));
        assert!(mount.options.contains(&"gid=1001".to_string()));
    }

    #[test]
    fn test_workspace_exec_removes_noexec() {
        let tmp = tempfile::TempDir::new().unwrap();
        let workspace = crate::container::WorkspaceConfig::new()
            .with_host_path(tmp.path().to_path_buf())
            .with_allow_execute(true);
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_workspace_mount(&workspace)
            .unwrap();

        let mount = config
            .mounts
            .iter()
            .find(|mount| mount.destination == "/workspace")
            .unwrap();
        assert!(!mount.options.contains(&"noexec".to_string()));
    }

    #[test]
    fn test_provider_config_mounts_are_home_relative_and_noexec() {
        let tmp = tempfile::TempDir::new().unwrap();
        let provider_dir = tmp.path().join("aws");
        fs::create_dir(&provider_dir).unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_provider_config_mounts(
                std::path::Path::new("/home/agent"),
                &[crate::container::ProviderConfigMount {
                    source: provider_dir.clone(),
                    dest: std::path::PathBuf::from(".aws"),
                    read_only: true,
                }],
            )
            .unwrap();

        let mount = config
            .mounts
            .iter()
            .find(|mount| mount.destination == "/home/agent/.aws")
            .unwrap();
        assert_eq!(
            mount.source,
            fs::canonicalize(provider_dir)
                .unwrap()
                .to_string_lossy()
                .to_string()
        );
        assert!(mount.options.contains(&"ro".to_string()));
        assert!(mount.options.contains(&"noexec".to_string()));
    }

    #[test]
    fn test_volume_mounts_reject_sensitive_host_sources() {
        let err = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_volume_mounts(&[crate::container::VolumeMount {
                source: crate::container::VolumeSource::Bind {
                    source: std::path::PathBuf::from("/proc/sys"),
                },
                dest: std::path::PathBuf::from("/host-proc"),
                read_only: true,
            }])
            .unwrap_err();

        assert!(err.to_string().contains("sensitive host path"));
    }

    #[test]
    fn test_volume_mounts_reject_reserved_destinations() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_volume_mounts(&[crate::container::VolumeMount {
                source: crate::container::VolumeSource::Bind {
                    source: tmp.path().to_path_buf(),
                },
                dest: std::path::PathBuf::from("/usr/bin"),
                read_only: true,
            }])
            .unwrap_err();

        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_oci_config_with_process_identity() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_process_identity(
            &crate::container::ProcessIdentity {
                uid: 1001,
                gid: 1002,
                additional_gids: vec![1003, 1004],
            },
        );

        assert_eq!(config.process.user.uid, 1001);
        assert_eq!(config.process.user.gid, 1002);
        assert_eq!(config.process.user.additional_gids, Some(vec![1003, 1004]));
    }

    #[test]
    fn test_oci_config_with_rlimits_uses_configured_memlock() {
        let limits = ResourceLimits::default()
            .with_pids(99)
            .unwrap()
            .with_memlock("8M")
            .unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_rlimits(&limits);

        assert!(config.process.rlimits.iter().any(|limit| {
            limit.limit_type == "RLIMIT_NPROC" && limit.soft == 99 && limit.hard == 99
        }));
        assert!(config.process.rlimits.iter().any(|limit| {
            limit.limit_type == "RLIMIT_MEMLOCK"
                && limit.soft == 8 * 1024 * 1024
                && limit.hard == 8 * 1024 * 1024
        }));
    }

    #[test]
    fn test_oci_config_with_rlimits_omits_nproc_when_unlimited() {
        let limits = ResourceLimits {
            pids_max: None,
            ..ResourceLimits::default()
        };

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_rlimits(&limits);

        assert!(
            !config
                .process
                .rlimits
                .iter()
                .any(|limit| limit.limit_type == "RLIMIT_NPROC"),
            "RLIMIT_NPROC must be omitted when pids_max is unlimited"
        );
    }

    #[test]
    fn test_oci_config_uses_hardcoded_path_not_host() {
        // C-3: PATH must be a hardcoded minimal value, never the host's PATH.
        // This prevents leaking host filesystem layout into the container.
        std::env::set_var("PATH", "/nix/store/secret-hash/bin:/home/user/.local/bin");
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let path_env = config
            .process
            .env
            .iter()
            .find(|e| e.starts_with("PATH="))
            .expect("PATH env must be set");
        assert_eq!(
            path_env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "OCI config must not leak host PATH"
        );
        assert!(
            !path_env.contains("/nix/store/secret"),
            "Host PATH must not leak into container"
        );
    }

    #[test]
    fn test_oci_hooks_serialization_roundtrip() {
        let hooks = OciHooks {
            create_runtime: vec![OciHook {
                path: "/usr/bin/hook1".to_string(),
                args: vec!["hook1".to_string(), "--arg1".to_string()],
                env: vec!["FOO=bar".to_string()],
                timeout: Some(10),
            }],
            create_container: vec![],
            start_container: vec![],
            poststart: vec![OciHook {
                path: "/usr/bin/hook2".to_string(),
                args: vec![],
                env: vec![],
                timeout: None,
            }],
            poststop: vec![],
        };

        let json = serde_json::to_string_pretty(&hooks).unwrap();
        assert!(json.contains("createRuntime"));
        assert!(json.contains("/usr/bin/hook1"));
        assert!(!json.contains("createContainer")); // empty vecs are skipped

        let deserialized: OciHooks = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.create_runtime.len(), 1);
        assert_eq!(deserialized.create_runtime[0].path, "/usr/bin/hook1");
        assert_eq!(deserialized.create_runtime[0].timeout, Some(10));
        assert_eq!(deserialized.poststart.len(), 1);
        assert!(deserialized.create_container.is_empty());
    }

    #[test]
    fn test_oci_hooks_is_empty() {
        let empty = OciHooks::default();
        assert!(empty.is_empty());

        let not_empty = OciHooks {
            poststop: vec![OciHook {
                path: "/bin/cleanup".to_string(),
                args: vec![],
                env: vec![],
                timeout: None,
            }],
            ..Default::default()
        };
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_oci_config_with_hooks() {
        let hooks = OciHooks {
            create_runtime: vec![OciHook {
                path: "/usr/bin/setup".to_string(),
                args: vec![],
                env: vec![],
                timeout: None,
            }],
            ..Default::default()
        };

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_hooks(hooks);
        assert!(config.hooks.is_some());

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("hooks"));
        assert!(json.contains("createRuntime"));

        let deserialized: OciConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.hooks.is_some());
        assert_eq!(deserialized.hooks.unwrap().create_runtime.len(), 1);
    }

    #[test]
    fn test_oci_config_with_empty_hooks_serializes_without_hooks() {
        let config =
            OciConfig::new(vec!["/bin/sh".to_string()], None).with_hooks(OciHooks::default());
        assert!(config.hooks.is_none()); // empty hooks are set to None

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(!json.contains("hooks"));
    }

    #[test]
    fn test_oci_hook_rejects_relative_path() {
        let hook = OciHook {
            path: "relative/path".to_string(),
            args: vec![],
            env: vec![],
            timeout: None,
        };
        let state = OciContainerState {
            oci_version: "1.0.2".to_string(),
            id: "test".to_string(),
            status: OciStatus::Creating,
            pid: 1234,
            bundle: "/tmp/bundle".to_string(),
        };
        let result = OciHooks::run_hooks(&[hook], &state, "test");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("absolute"), "error: {}", err_msg);
    }

    /// Read the original PATH from /proc/self/environ.
    ///
    /// Other tests in this module call `std::env::set_var("PATH", ...)` which
    /// corrupts the process environment. /proc/self/environ is frozen at
    /// process startup so it always reflects the real PATH.
    fn original_path() -> String {
        if let Ok(environ) = std::fs::read("/proc/self/environ") {
            for entry in environ.split(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(entry) {
                    if let Some(val) = s.strip_prefix("PATH=") {
                        return val.to_string();
                    }
                }
            }
        }
        String::new()
    }

    /// Resolve the absolute path to bash for test scripts.
    fn find_bash() -> String {
        let candidates = ["/bin/bash", "/usr/bin/bash"];
        for c in &candidates {
            if std::path::Path::new(c).exists() {
                return c.to_string();
            }
        }
        for dir in original_path().split(':') {
            let candidate = std::path::PathBuf::from(dir).join("bash");
            if candidate.exists() {
                return candidate.to_string_lossy().to_string();
            }
        }
        panic!("Cannot find bash binary for test");
    }

    /// Write a script file with proper shebang and ensure it's fully flushed before execution.
    /// Embeds the original PATH so scripts can find utilities like `cat`/`touch`
    /// even when other tests have corrupted the process PATH.
    fn write_script(path: &std::path::Path, body: &str) {
        use std::io::Write as IoWrite;
        let bash = find_bash();
        let orig_path = original_path();
        let content = format!("#!{}\nexport PATH='{}'\n{}", bash, orig_path, body);
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o755)
            .open(path)
            .unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);
    }

    #[test]
    fn test_oci_hook_executes_successfully() {
        let temp_dir = TempDir::new().unwrap();
        let hook_script = temp_dir.path().join("hook.sh");
        let output_file = temp_dir.path().join("output.json");

        write_script(
            &hook_script,
            &format!("cat > {}\n", output_file.to_string_lossy()),
        );

        let hook = OciHook {
            path: hook_script.to_string_lossy().to_string(),
            args: vec![],
            env: vec![],
            timeout: Some(5),
        };
        let state = OciContainerState {
            oci_version: "1.0.2".to_string(),
            id: "test-container".to_string(),
            status: OciStatus::Creating,
            pid: 12345,
            bundle: "/tmp/test-bundle".to_string(),
        };

        OciHooks::run_hooks(&[hook], &state, "createRuntime").unwrap();

        // Verify the hook received the container state JSON on stdin
        let written = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["id"], "test-container");
        assert_eq!(parsed["pid"], 12345);
        assert_eq!(parsed["status"], "creating");
    }

    #[test]
    fn test_oci_hook_retries_text_file_busy_spawn() {
        let temp_dir = TempDir::new().unwrap();
        let hook_script = temp_dir.path().join("hook.sh");
        let output_file = temp_dir.path().join("output.json");

        write_script(
            &hook_script,
            &format!("cat > {}\n", output_file.to_string_lossy()),
        );

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let busy_script = hook_script.clone();
        let busy_handle = std::thread::spawn(move || {
            let _busy_file = OpenOptions::new().write(true).open(&busy_script).unwrap();
            ready_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        ready_rx.recv().unwrap();

        let hook = OciHook {
            path: hook_script.to_string_lossy().to_string(),
            args: vec![],
            env: vec![],
            timeout: Some(5),
        };
        let state = OciContainerState {
            oci_version: "1.0.2".to_string(),
            id: "test-container".to_string(),
            status: OciStatus::Creating,
            pid: 12345,
            bundle: "/tmp/test-bundle".to_string(),
        };

        let result = OciHooks::run_hooks(&[hook], &state, "createRuntime");
        busy_handle.join().unwrap();
        result.unwrap();

        let written = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["id"], "test-container");
    }

    #[test]
    fn test_oci_hook_nonzero_exit_is_error() {
        let temp_dir = TempDir::new().unwrap();
        let hook_script = temp_dir.path().join("fail.sh");
        write_script(&hook_script, "exit 1\n");

        let hook = OciHook {
            path: hook_script.to_string_lossy().to_string(),
            args: vec![],
            env: vec![],
            timeout: Some(5),
        };
        let state = OciContainerState {
            oci_version: "1.0.2".to_string(),
            id: "test".to_string(),
            status: OciStatus::Creating,
            pid: 1,
            bundle: "".to_string(),
        };

        let result = OciHooks::run_hooks(&[hook], &state, "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exited with status"));
    }

    #[test]
    fn test_oci_hooks_best_effort_continues_on_failure() {
        let temp_dir = TempDir::new().unwrap();
        let fail_script = temp_dir.path().join("fail.sh");
        write_script(&fail_script, "exit 1\n");

        let marker = temp_dir.path().join("ran");
        let ok_script = temp_dir.path().join("ok.sh");
        write_script(&ok_script, &format!("touch {}\n", marker.to_string_lossy()));

        let hooks = vec![
            OciHook {
                path: fail_script.to_string_lossy().to_string(),
                args: vec![],
                env: vec![],
                timeout: Some(5),
            },
            OciHook {
                path: ok_script.to_string_lossy().to_string(),
                args: vec![],
                env: vec![],
                timeout: Some(5),
            },
        ];
        let state = OciContainerState {
            oci_version: "1.0.2".to_string(),
            id: "test".to_string(),
            status: OciStatus::Stopped,
            pid: 0,
            bundle: "".to_string(),
        };

        // best_effort should not panic or return error
        OciHooks::run_hooks_best_effort(&hooks, &state, "poststop");
        // Second hook should have run despite first failing
        assert!(marker.exists(), "second hook should run after first fails");
    }
}
