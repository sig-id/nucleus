#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use clap::Parser;
use nucleus::checkpoint::{CheckpointMetadata, CriuRuntime};
use nucleus::container::{
    parse_signal, validate_container_name, validate_hostname, ConsoleSize, Container,
    ContainerConfig, ContainerLifecycle, ContainerState, ContainerStateManager,
    ContainerStateParams, HealthCheck, KernelLockdownMode, NetworkModeArg, OciStatus,
    ProcessIdentity, ProviderConfigMount, ReadinessProbe, RuntimeSelection, SeccompMode,
    SecretMount, ServiceMode, TrustLevel, VolumeMount, VolumeSource, WorkspaceConfig,
    WorkspaceMode, DEFAULT_HOME_PATH,
};
use nucleus::error::{NucleusError, Result};
use nucleus::filesystem::{
    normalize_container_destination, normalize_provider_config_destination,
    normalize_volume_destination, validate_agent_toolchain_rootfs_path, validate_bind_mount_source,
    validate_provider_config_source, validate_workspace_host_path, ContextMode,
};
use nucleus::isolation::{ContainerAttach, NamespaceConfig};
use nucleus::network::{BridgeConfig, EgressPolicy, NatBackend, NetworkMode, PortForward};
use nucleus::resources::{Cgroup, IoDeviceLimit, ResourceLimits, ResourceStats};
use nucleus::security::GVisorPlatform;
use nucleus::topology::{
    execute_reconcile, plan_reconcile, DependencyGraph, ReconcileAction, TopologyConfig,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::info;

const SAFE_PRIVILEGED_HELPER_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_PROFILE",
];

fn validate_privileged_helper(path: &Path, name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let resolved = std::fs::canonicalize(path).map_err(|e| {
        NucleusError::ExecError(format!(
            "Failed to resolve {} helper at {:?}: {}",
            name, path, e
        ))
    })?;
    let metadata = std::fs::metadata(&resolved).map_err(|e| {
        NucleusError::ExecError(format!(
            "Failed to stat {} helper at {:?}: {}",
            name, resolved, e
        ))
    })?;
    if !metadata.is_file() {
        return Err(NucleusError::ExecError(format!(
            "{} helper at {:?} is not a regular file",
            name, resolved
        )));
    }

    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(NucleusError::ExecError(format!(
            "{} helper at {:?} is not executable",
            name, resolved
        )));
    }
    if mode & 0o022 != 0 {
        return Err(NucleusError::ExecError(format!(
            "{} helper at {:?} is writable by group/others (mode {:o}), refusing to execute",
            name, resolved, mode
        )));
    }

    let owner = metadata.uid();
    let euid = nix::unistd::Uid::effective().as_raw();
    if owner != 0 && owner != euid && !is_trusted_store_privileged_helper(&resolved, mode) {
        return Err(NucleusError::ExecError(format!(
            "{} helper at {:?} is owned by UID {} (expected root or euid {}), refusing to execute",
            name, resolved, owner, euid
        )));
    }

    Ok(resolved)
}

fn is_trusted_store_privileged_helper(path: &Path, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;

    if !path.starts_with("/nix/store") || mode & 0o222 != 0 {
        return false;
    }

    path.parent()
        .and_then(|parent| std::fs::metadata(parent).ok())
        .map(|metadata| metadata.permissions().mode() & 0o222 == 0)
        .unwrap_or(false)
}

fn resolve_privileged_helper(name: &str, trusted_paths: &[&str]) -> Result<PathBuf> {
    resolve_privileged_helper_impl(name, trusted_paths, nix::unistd::Uid::effective().is_root())
}

fn resolve_privileged_helper_impl(
    name: &str,
    trusted_paths: &[&str],
    privileged: bool,
) -> Result<PathBuf> {
    for candidate in trusted_paths {
        let path = Path::new(candidate);
        if path.exists() {
            return validate_privileged_helper(path, name);
        }
    }

    if privileged {
        return Err(NucleusError::ExecError(format!(
            "{} helper not found in trusted system paths",
            name
        )));
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.exists() {
                return validate_privileged_helper(&candidate, name);
            }
        }
    }

    Err(NucleusError::ExecError(format!(
        "{} helper not found or failed validation",
        name
    )))
}

fn resolve_journalctl_helper() -> Result<PathBuf> {
    resolve_privileged_helper(
        "journalctl",
        &[
            "/usr/bin/journalctl",
            "/bin/journalctl",
            "/usr/local/bin/journalctl",
            "/run/current-system/sw/bin/journalctl",
        ],
    )
}

fn resolve_systemd_run_helper() -> Result<PathBuf> {
    resolve_privileged_helper(
        "systemd-run",
        &[
            "/usr/bin/systemd-run",
            "/bin/systemd-run",
            "/usr/local/bin/systemd-run",
            "/run/current-system/sw/bin/systemd-run",
        ],
    )
}

fn privileged_helper_command(path: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(path);
    command.env("PATH", SAFE_PRIVILEGED_HELPER_PATH);
    command
}

fn validate_systemd_credential_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(NucleusError::ConfigError(
            "Systemd credential name cannot be empty".to_string(),
        ));
    }
    if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
        return Err(NucleusError::ConfigError(format!(
            "Invalid systemd credential name '{}'",
            name
        )));
    }
    Ok(())
}

fn resolve_systemd_credential_source(name: &str) -> Result<PathBuf> {
    validate_systemd_credential_name(name)?;
    let credentials_dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        NucleusError::ConfigError(
            "--systemd-credential requires CREDENTIALS_DIRECTORY from systemd".to_string(),
        )
    })?;
    let credentials_dir = PathBuf::from(credentials_dir);
    let canonical_dir = std::fs::canonicalize(&credentials_dir).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve CREDENTIALS_DIRECTORY {:?}: {}",
            credentials_dir, e
        ))
    })?;
    let source = std::fs::canonicalize(credentials_dir.join(name)).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Systemd credential '{}' cannot be resolved under {:?}: {}",
            name, credentials_dir, e
        ))
    })?;
    if !source.starts_with(&canonical_dir) {
        return Err(NucleusError::ConfigError(format!(
            "Systemd credential '{}' resolved outside CREDENTIALS_DIRECTORY",
            name
        )));
    }
    Ok(source)
}

fn read_secret_specs_from_fd(fd: i32) -> Result<Vec<String>> {
    if fd <= 2 {
        return Err(NucleusError::ConfigError(format!(
            "Invalid inherited secrets fd {}",
            fd
        )));
    }

    use std::io::Read;
    use std::os::fd::FromRawFd;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to read inherited secrets fd {}: {}", fd, e))
    })?;

    serde_json::from_str(&contents).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to parse inherited secrets fd {}: {}",
            fd, e
        ))
    })
}

fn collect_secret_specs(mut secrets: Vec<String>, secrets_fd: Option<i32>) -> Result<Vec<String>> {
    if let Some(fd) = secrets_fd {
        secrets.extend(read_secret_specs_from_fd(fd)?);
    }
    Ok(secrets)
}

fn read_env_specs_from_fd(fd: i32) -> Result<Vec<String>> {
    if fd <= 2 {
        return Err(NucleusError::ConfigError(format!(
            "Invalid inherited env fd {}",
            fd
        )));
    }

    use std::io::Read;
    use std::os::fd::FromRawFd;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to read inherited env fd {}: {}", fd, e))
    })?;

    let value: serde_json::Value = serde_json::from_str(&contents).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to parse inherited env fd {}: {}", fd, e))
    })?;

    match value {
        serde_json::Value::Array(entries) => entries
            .into_iter()
            .map(|entry| match entry {
                serde_json::Value::String(spec) => Ok(spec),
                _ => Err(NucleusError::ConfigError(
                    "--env-fd JSON array entries must be strings".to_string(),
                )),
            })
            .collect(),
        serde_json::Value::Object(entries) => entries
            .into_iter()
            .map(|(key, value)| match value {
                serde_json::Value::String(value) => Ok(format!("{}={}", key, value)),
                _ => Err(NucleusError::ConfigError(format!(
                    "--env-fd JSON object value for '{}' must be a string",
                    key
                ))),
            })
            .collect(),
        _ => Err(NucleusError::ConfigError(
            "--env-fd expects a JSON object or an array of KEY=VALUE strings".to_string(),
        )),
    }
}

fn collect_env_specs(mut env_vars: Vec<String>, env_fd: Option<i32>) -> Result<Vec<String>> {
    if let Some(fd) = env_fd {
        env_vars.extend(read_env_specs_from_fd(fd)?);
    }
    Ok(env_vars)
}

fn parse_env_assignment(spec: &str) -> Result<(String, String)> {
    let Some((key, value)) = spec.split_once('=') else {
        return Err(NucleusError::ConfigError(
            "Invalid env var format, expected KEY=VALUE".to_string(),
        ));
    };
    if key.is_empty()
        || key.contains('\0')
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || key.as_bytes()[0].is_ascii_digit()
    {
        return Err(NucleusError::ConfigError(format!(
            "Invalid env var key '{}'",
            key
        )));
    }
    if value.contains('\0') {
        return Err(NucleusError::ConfigError(format!(
            "Invalid env var value for '{}': contains NUL",
            key
        )));
    }
    if DANGEROUS_ENV_VARS.contains(&key) {
        return Err(NucleusError::ConfigError(format!(
            "Environment variable '{}' is blocked (dynamic linker injection risk). \
             This restriction applies in all modes.",
            key
        )));
    }
    Ok((key.to_string(), value.to_string()))
}

fn parse_provider_config_mount_spec(
    spec: &str,
    home: &Path,
    read_only: bool,
) -> Result<ProviderConfigMount> {
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(NucleusError::ConfigError(format!(
            "Invalid provider config format '{}', expected SOURCE:DEST",
            spec
        )));
    }

    let source = std::fs::canonicalize(parts[0]).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Provider config source '{}' cannot be resolved: {}",
            parts[0], e
        ))
    })?;
    validate_provider_config_source(&source)?;
    let dest = normalize_provider_config_destination(home, Path::new(parts[1]))?;

    Ok(ProviderConfigMount {
        source,
        dest,
        read_only,
    })
}

#[derive(Debug, Clone, Copy)]
enum RunConfigFormat {
    Json,
    Toml,
}

fn run_config_format_from_path(path: &Path) -> Option<RunConfigFormat> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => Some(RunConfigFormat::Json),
        Some("toml") => Some(RunConfigFormat::Toml),
        _ => None,
    }
}

fn parse_run_config(
    contents: &str,
    source: &str,
    format_hint: Option<RunConfigFormat>,
) -> Result<RunConfig> {
    match format_hint {
        Some(RunConfigFormat::Json) => serde_json::from_str(contents).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to parse launch config {} as JSON: {}",
                source, e
            ))
        }),
        Some(RunConfigFormat::Toml) => toml::from_str(contents).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to parse launch config {} as TOML: {}",
                source, e
            ))
        }),
        None => match serde_json::from_str(contents) {
            Ok(config) => Ok(config),
            Err(json_err) => toml::from_str(contents).map_err(|toml_err| {
                NucleusError::ConfigError(format!(
                    "Failed to parse launch config {} as JSON ({}) or TOML ({})",
                    source, json_err, toml_err
                ))
            }),
        },
    }
}

fn read_run_config_from_path(path: &Path) -> Result<RunConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to read launch config '{}': {}",
            path.display(),
            e
        ))
    })?;
    let source = path.display().to_string();
    parse_run_config(&contents, &source, run_config_format_from_path(path))
}

fn read_run_config_from_fd(fd: i32) -> Result<RunConfig> {
    if fd <= 2 {
        return Err(NucleusError::ConfigError(format!(
            "Invalid inherited config fd {}",
            fd
        )));
    }

    use std::io::Read;
    use std::os::fd::FromRawFd;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to read inherited config fd {}: {}", fd, e))
    })?;

    parse_run_config(&contents, &format!("fd {}", fd), None)
}

fn resolve_uid_spec(spec: &str) -> Result<(u32, Option<u32>)> {
    if let Ok(uid) = spec.parse::<u32>() {
        return Ok((uid, None));
    }

    let user = nix::unistd::User::from_name(spec)
        .map_err(|e| {
            NucleusError::ConfigError(format!("Failed to resolve user '{}': {}", spec, e))
        })?
        .ok_or_else(|| NucleusError::ConfigError(format!("Unknown user '{}'", spec)))?;

    Ok((user.uid.as_raw(), Some(user.gid.as_raw())))
}

fn resolve_gid_spec(spec: &str) -> Result<u32> {
    if let Ok(gid) = spec.parse::<u32>() {
        return Ok(gid);
    }

    let group = nix::unistd::Group::from_name(spec)
        .map_err(|e| {
            NucleusError::ConfigError(format!("Failed to resolve group '{}': {}", spec, e))
        })?
        .ok_or_else(|| NucleusError::ConfigError(format!("Unknown group '{}'", spec)))?;

    Ok(group.gid.as_raw())
}

fn resolve_process_identity(
    user: Option<&str>,
    group: Option<&str>,
    additional_groups: &[String],
) -> Result<Option<ProcessIdentity>> {
    if user.is_none() && group.is_none() && additional_groups.is_empty() {
        return Ok(None);
    }

    let user = user.ok_or_else(|| {
        NucleusError::ConfigError(
            "--group/--additional-group require --user to be set as well".to_string(),
        )
    })?;
    let (uid, default_gid) = resolve_uid_spec(user)?;
    let gid = match group {
        Some(group) => resolve_gid_spec(group)?,
        None => default_gid.ok_or_else(|| {
            NucleusError::ConfigError(
                "Numeric --user values require an explicit --group".to_string(),
            )
        })?,
    };

    let mut resolved_additional_gids = Vec::new();
    for group in additional_groups {
        let resolved = resolve_gid_spec(group)?;
        if resolved != gid && !resolved_additional_gids.contains(&resolved) {
            resolved_additional_gids.push(resolved);
        }
    }

    Ok(Some(ProcessIdentity {
        uid,
        gid,
        additional_gids: resolved_additional_gids,
    }))
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    u8::try_from(code)
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE)
}

fn restore_checkpoint_cgroup(
    container_id: &str,
    pid: u32,
    metadata: &CheckpointMetadata,
) -> Result<(Option<String>, Option<u64>, Option<u64>)> {
    let Some(resource_limits) = metadata.resource_limits.as_ref() else {
        return Ok((None, None, None));
    };

    let cgroup_name = format!("nucleus-{}", container_id);
    let mut cgroup = Cgroup::create(&cgroup_name).map_err(|e| {
        NucleusError::CheckpointError(format!("Failed to recreate cgroup on restore: {}", e))
    })?;
    let limits = resource_limits.to_resource_limits();
    if let Err(e) = cgroup.set_limits(&limits) {
        let _ = cgroup.cleanup();
        return Err(NucleusError::CheckpointError(format!(
            "Failed to restore cgroup limits for restored container: {}",
            e
        )));
    }
    if let Err(e) = cgroup.attach_process(pid) {
        let _ = cgroup.cleanup();
        return Err(NucleusError::CheckpointError(format!(
            "Failed to attach restored process {} to cgroup: {}",
            pid, e
        )));
    }

    Ok((
        Some(cgroup.path().display().to_string()),
        resource_limits.memory_bytes,
        resource_limits.cpu_limit_millicores(),
    ))
}

#[derive(Parser, Debug)]
#[command(name = "nucleus")]
#[command(about = "Extremely lightweight Docker alternative for agents", long_about = None)]
struct Cli {
    /// Root directory for state storage (overrides default)
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Log file path (OCI runtime interface)
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Log format: text (default) or json (OCI runtime interface)
    #[arg(long, global = true, default_value = "text")]
    log_format: String,

    /// Write machine-readable control events to an inherited fd (JSON Lines)
    #[arg(long, global = true)]
    events_fd: Option<i32>,

    /// Write machine-readable control events to this JSON Lines file
    #[arg(long, global = true)]
    events_jsonl: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

const RUN_CONFIG_PATH_CONFLICTS: &[&str] = &[
    "config_fd",
    "name",
    "context",
    "workspace",
    "workspace_mode",
    "workspace_exec",
    "home",
    "provider_config_ro",
    "provider_config_rw",
    "workdir",
    "memory",
    "cpus",
    "hostname",
    "cpu_weight",
    "io_limits",
    "pids",
    "memlock",
    "swap",
    "runtime",
    "detach",
    "quiet_id",
    "preset_id",
    "detached_config_json",
    "rootless",
    "user",
    "group",
    "additional_groups",
    "bundle",
    "pid_file",
    "console_socket",
    "terminal",
    "network",
    "allow_host_network",
    "allow_degraded_security",
    "allow_chroot_fallback",
    "trust_level",
    "proc_rw",
    "publish",
    "context_mode",
    "service_mode",
    "strict_agent",
    "rootfs",
    "agent_toolchain_rootfs",
    "egress_allow",
    "egress_domains",
    "egress_tcp_ports",
    "egress_udp_ports",
    "dns",
    "nat_backend",
    "health_cmd",
    "health_interval",
    "health_retries",
    "health_start_period",
    "secrets",
    "secrets_fd",
    "systemd_credentials",
    "volumes",
    "tmpfs",
    "env_vars",
    "env_fd",
    "sd_notify",
    "readiness_exec",
    "readiness_tcp",
    "readiness_sd_notify",
    "seccomp_profile",
    "seccomp_profile_sha256",
    "seccomp_mode",
    "seccomp_log",
    "seccomp_log_denied",
    "seccomp_allow",
    "caps_policy",
    "caps_policy_sha256",
    "landlock_policy",
    "landlock_policy_sha256",
    "verify_context_integrity",
    "verify_rootfs_attestation",
    "require_kernel_lockdown",
    "gvisor_platform",
    "time_namespace",
    "disable_cgroup_namespace",
    "hooks",
    "topology_config_hash",
    "command",
];

const RUN_CONFIG_FD_CONFLICTS: &[&str] = &[
    "config",
    "name",
    "context",
    "workspace",
    "workspace_mode",
    "workspace_exec",
    "home",
    "provider_config_ro",
    "provider_config_rw",
    "workdir",
    "memory",
    "cpus",
    "hostname",
    "cpu_weight",
    "io_limits",
    "pids",
    "memlock",
    "swap",
    "runtime",
    "detach",
    "quiet_id",
    "preset_id",
    "detached_config_json",
    "rootless",
    "user",
    "group",
    "additional_groups",
    "bundle",
    "pid_file",
    "console_socket",
    "terminal",
    "network",
    "allow_host_network",
    "allow_degraded_security",
    "allow_chroot_fallback",
    "trust_level",
    "proc_rw",
    "publish",
    "context_mode",
    "service_mode",
    "strict_agent",
    "rootfs",
    "agent_toolchain_rootfs",
    "egress_allow",
    "egress_domains",
    "egress_tcp_ports",
    "egress_udp_ports",
    "dns",
    "nat_backend",
    "health_cmd",
    "health_interval",
    "health_retries",
    "health_start_period",
    "secrets",
    "secrets_fd",
    "systemd_credentials",
    "volumes",
    "tmpfs",
    "env_vars",
    "env_fd",
    "sd_notify",
    "readiness_exec",
    "readiness_tcp",
    "readiness_sd_notify",
    "seccomp_profile",
    "seccomp_profile_sha256",
    "seccomp_mode",
    "seccomp_log",
    "seccomp_log_denied",
    "seccomp_allow",
    "caps_policy",
    "caps_policy_sha256",
    "landlock_policy",
    "landlock_policy_sha256",
    "verify_context_integrity",
    "verify_rootfs_attestation",
    "require_kernel_lockdown",
    "gvisor_platform",
    "time_namespace",
    "disable_cgroup_namespace",
    "hooks",
    "topology_config_hash",
    "command",
];

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Create and run a container
    #[command(alias = "run")]
    Create {
        /// Read a complete launch config from a JSON or TOML file
        #[arg(
            long = "config",
            value_name = "json|toml",
            conflicts_with_all = RUN_CONFIG_PATH_CONFLICTS
        )]
        config: Option<PathBuf>,

        /// Read a complete launch config from an inherited JSON or TOML fd
        #[arg(
            long = "config-fd",
            value_name = "fd",
            conflicts_with_all = RUN_CONFIG_FD_CONFLICTS
        )]
        config_fd: Option<i32>,

        /// Container name (optional, auto-generated if not specified)
        #[arg(long)]
        name: Option<String>,

        /// Path to context directory to pre-populate in container
        #[arg(long)]
        context: Option<String>,

        /// Host workspace directory mounted at /workspace
        #[arg(long)]
        workspace: Option<String>,

        /// Workspace exposure mode: bind-rw, bind-ro, or copy-in-out
        #[arg(long = "workspace-mode", default_value = "bind-rw")]
        workspace_mode: WorkspaceMode,

        /// Allow executing files from /workspace
        #[arg(long = "workspace-exec")]
        workspace_exec: bool,

        /// Private tmpfs home directory inside the container
        #[arg(long = "home", default_value = "/home/agent")]
        home: String,

        /// Working directory inside the container
        #[arg(long = "workdir", default_value = "/workspace")]
        workdir: String,

        /// Memory limit (e.g., 512M, 1G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit (number of cores)
        #[arg(long)]
        cpus: Option<f64>,

        /// Hostname to set in container (requires UTS namespace)
        #[arg(long)]
        hostname: Option<String>,

        /// CPU scheduling weight (1-10000)
        #[arg(long)]
        cpu_weight: Option<u64>,

        /// I/O device limit (repeatable, format: "major:minor riops=N wbps=N")
        #[arg(long = "io-limit")]
        io_limits: Vec<String>,

        /// Maximum number of PIDs (default: 512, 0 = unlimited)
        #[arg(long)]
        pids: Option<u64>,

        /// RLIMIT_MEMLOCK limit (e.g. "8M"). Required for io_uring ring buffers.
        /// Default: 64K.
        #[arg(long)]
        memlock: Option<String>,

        /// Enable swap (by default swap is disabled when --memory is set)
        #[arg(long)]
        swap: bool,

        /// Container runtime: gvisor or native
        #[arg(long, default_value = "gvisor")]
        runtime: RuntimeSelection,

        /// Run container in the background as a systemd transient service
        #[arg(short = 'd', long)]
        detach: bool,

        /// Internal: suppress printing the container ID before execution
        #[arg(long, hide = true)]
        quiet_id: bool,

        /// Internal: use a pre-generated container ID (set by --detach re-exec)
        #[arg(long, hide = true)]
        preset_id: Option<String>,

        /// Internal: serialized parsed create request used for detach re-exec
        #[arg(long, hide = true)]
        detached_config_json: Option<String>,

        /// Run in rootless mode with user namespace
        #[arg(long)]
        rootless: bool,

        /// User name or numeric UID to run the workload as after setup
        #[arg(long)]
        user: Option<String>,

        /// Group name or numeric GID to run the workload as after setup
        #[arg(long)]
        group: Option<String>,

        /// Supplementary group name or numeric GID (repeatable)
        #[arg(long = "additional-group")]
        additional_groups: Vec<String>,

        /// Path to OCI bundle directory (requires gVisor). Replaces --oci flag.
        #[arg(long)]
        bundle: Option<PathBuf>,

        /// Write container PID to this file after creation
        #[arg(long)]
        pid_file: Option<PathBuf>,

        /// Path to AF_UNIX socket for console pseudo-terminal master
        #[arg(long)]
        console_socket: Option<PathBuf>,

        /// Allocate a PTY and run the workload as a terminal-attached process
        #[arg(long)]
        terminal: bool,

        /// Network mode: none, host, gvisor-host, or bridge (default: none)
        #[arg(long, default_value = "none")]
        network: NetworkModeArg,

        /// Explicitly allow host network mode (dangerous: weakens isolation)
        #[arg(long)]
        allow_host_network: bool,

        /// Allow degraded security if seccomp/Landlock cannot be applied
        #[arg(long)]
        allow_degraded_security: bool,

        /// Allow chroot fallback if pivot_root fails (weaker than pivot_root)
        #[arg(long)]
        allow_chroot_fallback: bool,

        /// Workload trust level: trusted (native isolation) or untrusted (requires gVisor)
        #[arg(long, default_value = "untrusted")]
        trust_level: TrustLevel,

        /// Mount /proc writable (default is read-only for hardening)
        #[arg(long)]
        proc_rw: bool,

        /// Publish a port (format: HOST:CONTAINER, HOST:CONTAINER/PROTOCOL,
        /// or HOST_IP:HOST:CONTAINER[/PROTOCOL])
        #[arg(short = 'p', long = "publish")]
        publish: Vec<String>,

        /// Context population mode: copy or bind (default: copy)
        #[arg(long = "context-mode", default_value = "copy")]
        context_mode: ContextMode,

        /// Service mode: agent (default), strict-agent, or production
        #[arg(long, default_value = "agent")]
        service_mode: ServiceMode,

        /// Alias for --service-mode strict-agent
        #[arg(long = "strict-agent")]
        strict_agent: bool,

        /// Pre-built rootfs path (Nix store closure). Replaces host bind mounts.
        #[arg(long)]
        rootfs: Option<String>,

        /// Agent/strict-agent rootfs containing provider CLIs and developer tools
        #[arg(long = "agent-toolchain-rootfs", conflicts_with = "rootfs")]
        agent_toolchain_rootfs: Option<String>,

        /// Allowed egress CIDRs (repeatable). Enables egress policy when set.
        #[arg(long = "egress-allow")]
        egress_allow: Vec<String>,

        /// Allowed egress domains (repeatable). Resolves to IPv4 rules at startup.
        #[arg(long = "egress-domain")]
        egress_domains: Vec<String>,

        /// Allowed egress TCP ports (repeatable, used with --egress-allow/--egress-domain)
        #[arg(long = "egress-tcp-port")]
        egress_tcp_ports: Vec<u16>,

        /// Allowed egress UDP ports (repeatable, used with --egress-allow/--egress-domain)
        #[arg(long = "egress-udp-port")]
        egress_udp_ports: Vec<u16>,

        /// DNS servers (repeatable). Required for bridge mode in production.
        #[arg(long)]
        dns: Vec<String>,

        /// Native bridge NAT backend: auto, kernel, or userspace.
        #[arg(long = "nat-backend", default_value = "auto")]
        nat_backend: NatBackend,

        /// Health check command (run inside container)
        #[arg(long = "health-cmd")]
        health_cmd: Option<String>,

        /// Health check interval in seconds (default: 30)
        #[arg(long = "health-interval")]
        health_interval: Option<u64>,

        /// Health check retries before unhealthy (default: 3)
        #[arg(long = "health-retries")]
        health_retries: Option<u32>,

        /// Health check start period in seconds (default: 5)
        #[arg(long = "health-start-period")]
        health_start_period: Option<u64>,

        /// Mount a secret file: SOURCE:DEST (repeatable)
        #[arg(long = "secret")]
        secrets: Vec<String>,

        /// Internal: read secret specs from an inherited JSON file descriptor
        #[arg(long = "secrets-fd", hide = true)]
        secrets_fd: Option<i32>,

        /// Mount a systemd credential by name: NAME:DEST (repeatable)
        #[arg(long = "systemd-credential")]
        systemd_credentials: Vec<String>,

        /// Mount a host path as a bind volume: SOURCE:DEST[:ro|rw] (repeatable)
        #[arg(long = "volume")]
        volumes: Vec<String>,

        /// Mount a tmpfs volume: DEST[:SIZE][:ro|rw] (repeatable)
        #[arg(long = "tmpfs")]
        tmpfs: Vec<String>,

        /// Mount provider config read-only under --home: SOURCE:DEST (repeatable)
        #[arg(long = "provider-config-ro")]
        provider_config_ro: Vec<String>,

        /// Mount provider config read-write under --home: SOURCE:DEST (repeatable)
        #[arg(long = "provider-config-rw")]
        provider_config_rw: Vec<String>,

        /// Set environment variable: KEY=VALUE (repeatable)
        #[arg(short = 'e', long = "env")]
        env_vars: Vec<String>,

        /// Read environment variables from an inherited JSON fd
        #[arg(long = "env-fd")]
        env_fd: Option<i32>,

        /// Enable sd_notify integration (pass NOTIFY_SOCKET into container)
        #[arg(long)]
        sd_notify: bool,

        /// Readiness probe: exec command (ready when it exits 0)
        #[arg(long = "readiness-exec")]
        readiness_exec: Option<String>,

        /// Readiness probe: TCP port (ready when port accepts connections)
        #[arg(long = "readiness-tcp")]
        readiness_tcp: Option<u16>,

        /// Readiness probe: sd_notify (container sends READY=1 itself)
        #[arg(long = "readiness-sd-notify")]
        readiness_sd_notify: bool,

        /// Path to per-service seccomp profile (JSON, OCI subset format)
        #[arg(long = "seccomp-profile")]
        seccomp_profile: Option<String>,

        /// Expected SHA-256 hash of the seccomp profile for integrity verification
        #[arg(long = "seccomp-profile-sha256")]
        seccomp_profile_sha256: Option<String>,

        /// Seccomp mode: enforce (default) or trace (record syscalls for profile generation)
        #[arg(long = "seccomp-mode", default_value = "enforce")]
        seccomp_mode: SeccompMode,

        /// Path to write seccomp trace log (NDJSON) when --seccomp-mode=trace
        #[arg(long = "seccomp-log")]
        seccomp_log: Option<String>,

        /// Request kernel logging for denied seccomp decisions when supported
        #[arg(long = "seccomp-log-denied")]
        seccomp_log_denied: bool,

        /// Additional syscalls to allow beyond the built-in default allowlist.
        /// Can be specified multiple times (e.g. --seccomp-allow io_uring_setup --seccomp-allow sysinfo).
        /// These are merged into the built-in filter; they do NOT replace it.
        #[arg(long = "seccomp-allow")]
        seccomp_allow: Vec<String>,

        /// Path to capability policy file (TOML)
        #[arg(long = "caps-policy")]
        caps_policy: Option<String>,

        /// Expected SHA-256 hash of the capability policy file
        #[arg(long = "caps-policy-sha256")]
        caps_policy_sha256: Option<String>,

        /// Path to Landlock policy file (TOML)
        #[arg(long = "landlock-policy")]
        landlock_policy: Option<String>,

        /// Expected SHA-256 hash of the Landlock policy file
        #[arg(long = "landlock-policy-sha256")]
        landlock_policy_sha256: Option<String>,

        /// Verify context contents before the workload runs
        #[arg(long = "verify-context-integrity")]
        verify_context_integrity: bool,

        /// Verify rootfs attestation manifest before mounting it
        #[arg(long = "verify-rootfs-attestation")]
        verify_rootfs_attestation: bool,

        /// Require host kernel lockdown mode: integrity or confidentiality
        #[arg(long = "require-kernel-lockdown")]
        require_kernel_lockdown: Option<KernelLockdownMode>,

        /// gVisor platform backend: systrap, kvm, or ptrace
        #[arg(long = "gvisor-platform", default_value = "systrap")]
        gvisor_platform: GVisorPlatform,

        /// Enable time namespace isolation
        #[arg(long = "time-namespace")]
        time_namespace: bool,

        /// Disable cgroup namespace isolation
        #[arg(long = "disable-cgroup-namespace")]
        disable_cgroup_namespace: bool,

        /// Path to OCI hooks JSON file (defines lifecycle hooks)
        #[arg(long = "hooks")]
        hooks: Option<String>,

        /// Internal: topology config hash for reconciliation diffing
        #[arg(long = "topology-config-hash", hide = true)]
        topology_config_hash: Option<u64>,

        /// Command to run in container
        #[arg(
            last = true,
            required_unless_present_any = ["detached_config_json", "config", "config_fd"]
        )]
        command: Vec<String>,
    },

    /// Query container state
    State {
        /// Container ID, name, or ID prefix (outputs OCI state JSON)
        container: Option<String>,

        /// Show all containers (including stopped)
        #[arg(short, long)]
        all: bool,
    },

    /// Show resource usage statistics for containers
    Stats {
        /// Container ID (if not specified, shows all containers)
        container_id: Option<String>,
    },

    /// Stop a running container
    Stop {
        /// Container ID, name, or ID prefix
        container: String,

        /// Seconds to wait before killing (default: 10)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Start (resume) a stopped container
    Start {
        /// Container ID, name, or ID prefix
        container: String,
    },

    /// Delete a container
    Delete {
        /// Container ID, name, or ID prefix
        container: String,

        /// Force delete (stop if running)
        #[arg(short, long)]
        force: bool,
    },

    /// Send a signal to a container
    Kill {
        /// Container ID, name, or ID prefix
        container: String,

        /// Signal to send (default: SIGKILL)
        #[arg(default_value = "KILL")]
        signal: String,
    },

    /// Attach to a running container
    Attach {
        /// Container ID, name, or ID prefix
        container: String,

        /// Command to run (default: /bin/sh)
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Checkpoint a running container
    Checkpoint {
        /// Container ID, name, or ID prefix
        container: String,

        /// Output directory for checkpoint data
        #[arg(short, long)]
        output: String,

        /// Leave container running after checkpoint
        #[arg(long)]
        leave_running: bool,
    },

    /// Restore a container from checkpoint
    Restore {
        /// Input directory containing checkpoint data
        #[arg(short, long)]
        input: String,
    },

    /// View logs for a detached container (from systemd journal)
    Logs {
        /// Container ID, name, or ID prefix
        container: String,

        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Number of recent lines to show (default: all)
        #[arg(short = 'n', long)]
        lines: Option<u64>,
    },

    /// Manage multi-container topologies (Compose equivalent)
    #[command(subcommand)]
    Compose(ComposeCommands),

    /// Seccomp profile tools
    #[command(subcommand)]
    Seccomp(SeccompCommands),
}

#[derive(Parser, Debug)]
enum SeccompCommands {
    /// Generate a minimal seccomp profile from a trace log
    Generate {
        /// Path to NDJSON trace file from --seccomp-mode=trace
        trace_file: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Parser, Debug)]
enum ComposeCommands {
    /// Bring up a topology in dependency order
    Up {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,

        /// Stop timeout in seconds (default: 10)
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Graceful teardown in reverse dependency order
    Down {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,

        /// Stop timeout in seconds (default: 10)
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Show topology state
    State {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },

    /// Show reconciliation plan without executing
    Plan {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },

    /// Validate a topology file
    Validate {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RunConfig {
    name: Option<String>,
    context: Option<String>,
    workspace: Option<String>,
    workspace_mode: WorkspaceMode,
    workspace_exec: bool,
    home: String,
    workdir: String,
    memory: Option<String>,
    cpus: Option<f64>,
    hostname: Option<String>,
    cpu_weight: Option<u64>,
    io_limits: Vec<String>,
    pids: Option<u64>,
    memlock: Option<String>,
    swap: bool,
    runtime: RuntimeSelection,
    detach: bool,
    quiet_id: bool,
    preset_id: Option<String>,
    rootless: bool,
    user: Option<String>,
    group: Option<String>,
    additional_groups: Vec<String>,
    bundle: Option<PathBuf>,
    pid_file: Option<PathBuf>,
    console_socket: Option<PathBuf>,
    #[serde(default)]
    terminal: bool,
    network: NetworkModeArg,
    allow_host_network: bool,
    allow_degraded_security: bool,
    allow_chroot_fallback: bool,
    trust_level: TrustLevel,
    proc_rw: bool,
    publish: Vec<String>,
    context_mode: ContextMode,
    service_mode: ServiceMode,
    #[serde(default)]
    strict_agent: bool,
    rootfs: Option<String>,
    #[serde(default)]
    agent_toolchain_rootfs: Option<String>,
    egress_allow: Vec<String>,
    #[serde(default)]
    egress_domains: Vec<String>,
    egress_tcp_ports: Vec<u16>,
    egress_udp_ports: Vec<u16>,
    dns: Vec<String>,
    nat_backend: NatBackend,
    health_cmd: Option<String>,
    health_interval: Option<u64>,
    health_retries: Option<u32>,
    health_start_period: Option<u64>,
    secrets: Vec<String>,
    #[serde(default, skip_serializing)]
    secrets_fd: Option<i32>,
    systemd_credentials: Vec<String>,
    volumes: Vec<String>,
    tmpfs: Vec<String>,
    provider_config_ro: Vec<String>,
    provider_config_rw: Vec<String>,
    env_vars: Vec<String>,
    #[serde(default, skip_serializing)]
    env_fd: Option<i32>,
    sd_notify: bool,
    readiness_exec: Option<String>,
    readiness_tcp: Option<u16>,
    readiness_sd_notify: bool,
    seccomp_profile: Option<String>,
    seccomp_profile_sha256: Option<String>,
    seccomp_mode: SeccompMode,
    seccomp_log: Option<String>,
    seccomp_log_denied: bool,
    seccomp_allow: Vec<String>,
    caps_policy: Option<String>,
    caps_policy_sha256: Option<String>,
    landlock_policy: Option<String>,
    landlock_policy_sha256: Option<String>,
    verify_context_integrity: bool,
    verify_rootfs_attestation: bool,
    require_kernel_lockdown: Option<KernelLockdownMode>,
    gvisor_platform: GVisorPlatform,
    time_namespace: bool,
    disable_cgroup_namespace: bool,
    hooks: Option<String>,
    topology_config_hash: Option<u64>,
    command: Vec<String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            name: None,
            context: None,
            workspace: None,
            workspace_mode: WorkspaceMode::BindRw,
            workspace_exec: false,
            home: DEFAULT_HOME_PATH.to_string(),
            workdir: "/workspace".to_string(),
            memory: None,
            cpus: None,
            hostname: None,
            cpu_weight: None,
            io_limits: Vec::new(),
            pids: None,
            memlock: None,
            swap: false,
            runtime: RuntimeSelection::GVisor,
            detach: false,
            quiet_id: false,
            preset_id: None,
            rootless: false,
            user: None,
            group: None,
            additional_groups: Vec::new(),
            bundle: None,
            pid_file: None,
            console_socket: None,
            terminal: false,
            network: NetworkModeArg::None,
            allow_host_network: false,
            allow_degraded_security: false,
            allow_chroot_fallback: false,
            trust_level: TrustLevel::Untrusted,
            proc_rw: false,
            publish: Vec::new(),
            context_mode: ContextMode::Copy,
            service_mode: ServiceMode::Agent,
            strict_agent: false,
            rootfs: None,
            agent_toolchain_rootfs: None,
            egress_allow: Vec::new(),
            egress_domains: Vec::new(),
            egress_tcp_ports: Vec::new(),
            egress_udp_ports: Vec::new(),
            dns: Vec::new(),
            nat_backend: NatBackend::Auto,
            health_cmd: None,
            health_interval: None,
            health_retries: None,
            health_start_period: None,
            secrets: Vec::new(),
            secrets_fd: None,
            systemd_credentials: Vec::new(),
            volumes: Vec::new(),
            tmpfs: Vec::new(),
            provider_config_ro: Vec::new(),
            provider_config_rw: Vec::new(),
            env_vars: Vec::new(),
            env_fd: None,
            sd_notify: false,
            readiness_exec: None,
            readiness_tcp: None,
            readiness_sd_notify: false,
            seccomp_profile: None,
            seccomp_profile_sha256: None,
            seccomp_mode: SeccompMode::Enforce,
            seccomp_log: None,
            seccomp_log_denied: false,
            seccomp_allow: Vec::new(),
            caps_policy: None,
            caps_policy_sha256: None,
            landlock_policy: None,
            landlock_policy_sha256: None,
            verify_context_integrity: false,
            verify_rootfs_attestation: false,
            require_kernel_lockdown: None,
            gvisor_platform: GVisorPlatform::Systrap,
            time_namespace: false,
            disable_cgroup_namespace: false,
            hooks: None,
            topology_config_hash: None,
            command: Vec::new(),
        }
    }
}

/// Truncate a container ID to 12 chars for display.
fn truncate_id(id: &str) -> &str {
    if id.len() > 12 {
        &id[..12]
    } else {
        id
    }
}

fn resolve_service_mode(service_mode: ServiceMode, strict_agent: bool) -> Result<ServiceMode> {
    if !strict_agent {
        return Ok(service_mode);
    }

    match service_mode {
        ServiceMode::Agent | ServiceMode::StrictAgent => Ok(ServiceMode::StrictAgent),
        ServiceMode::Production => Err(NucleusError::ConfigError(
            "--strict-agent cannot be combined with --service-mode production".to_string(),
        )),
    }
}

fn resolve_rootfs_argument(
    service_mode: ServiceMode,
    rootfs: Option<String>,
    agent_toolchain_rootfs: Option<String>,
) -> Result<Option<PathBuf>> {
    match (rootfs, agent_toolchain_rootfs) {
        (Some(_), Some(_)) => Err(NucleusError::ConfigError(
            "--rootfs and --agent-toolchain-rootfs are mutually exclusive".to_string(),
        )),
        (Some(rootfs), None) => Ok(Some(PathBuf::from(rootfs))),
        (None, Some(rootfs)) => {
            if service_mode == ServiceMode::Production {
                return Err(NucleusError::ConfigError(
                    "--agent-toolchain-rootfs is only for agent and strict-agent modes; \
                     production mode must use --rootfs with attestation"
                        .to_string(),
                ));
            }
            validate_agent_toolchain_rootfs_path(Path::new(&rootfs)).map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn main() -> ExitCode {
    match try_main() {
        Ok(code) => exit_code_from_i32(code),
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> Result<i32> {
    let cli = Cli::parse();
    let state_root = cli.root.clone();
    let log_path = cli.log.clone();
    let log_format = cli.log_format.clone();
    let events_fd = cli.events_fd;
    let events_jsonl = cli.events_jsonl.clone();

    nucleus::telemetry::init_tracing(log_path.as_deref(), &log_format)?;

    match cli.command {
        Commands::State { container, all } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

            // If a specific container is given, output OCI state JSON
            if let Some(ref id) = container {
                let state = state_mgr.resolve_container(id)?;
                println!("{}", serde_json::to_string_pretty(&state.oci_state())?);
                return Ok(0);
            }

            let states = if all {
                state_mgr.list_states()?
            } else {
                state_mgr.list_running()?
            };

            if states.is_empty() {
                println!("No containers found");
                return Ok(0);
            }

            println!(
                "{:<15} {:<20} {:<10} {:<10} {:<10} {:<10} COMMAND",
                "CONTAINER ID", "NAME", "PID", "STATUS", "RUNTIME", "ROOTLESS"
            );

            for state in states {
                let status = if state.is_running() {
                    state.status.to_string()
                } else {
                    OciStatus::Stopped.to_string()
                };
                let runtime = if state.using_gvisor {
                    "gvisor"
                } else {
                    "native"
                };
                let rootless = if state.rootless { "yes" } else { "no" };
                let command = state.command.join(" ");
                let command_display = if command.len() > 40 {
                    format!("{}...", &command[..37])
                } else {
                    command
                };

                let id_display = truncate_id(&state.id);

                let name_display = if state.name.len() > 18 {
                    format!("{}...", &state.name[..15])
                } else {
                    state.name.clone()
                };

                println!(
                    "{:<15} {:<20} {:<10} {:<10} {:<10} {:<10} {}",
                    id_display, name_display, state.pid, status, runtime, rootless, command_display
                );
            }

            Ok(0)
        }

        Commands::Stats { container_id } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

            let states = if let Some(ref id) = container_id {
                vec![state_mgr.resolve_container(id)?]
            } else {
                state_mgr.list_running()?
            };

            if states.is_empty() {
                println!("No running containers found");
                return Ok(0);
            }

            println!(
                "{:<15} {:<10} {:<15} {:<15} {:<10} {:<10} {:<10}",
                "CONTAINER ID", "CPU TIME", "MEM USAGE", "MEM LIMIT", "MEM %", "SWAP", "PIDS"
            );

            for state in states {
                if !state.is_running() {
                    continue;
                }

                if let Some(cgroup_path) = &state.cgroup_path {
                    match ResourceStats::from_cgroup(cgroup_path) {
                        Ok(stats) => {
                            let mem_usage = ResourceStats::format_memory(stats.memory_usage);
                            let mem_limit = if stats.memory_limit > 0 {
                                ResourceStats::format_memory(stats.memory_limit)
                            } else {
                                "unlimited".to_string()
                            };
                            let cpu_time = ResourceStats::format_cpu_time(stats.cpu_usage_ns);
                            let swap_usage = ResourceStats::format_memory(stats.memory_swap_usage);

                            let id_display = if state.id.len() > 12 {
                                &state.id[..12]
                            } else {
                                &state.id
                            };

                            println!(
                                "{:<15} {:<10} {:<15} {:<15} {:<10.2} {:<10} {:<10}",
                                id_display,
                                cpu_time,
                                mem_usage,
                                mem_limit,
                                stats.memory_percent,
                                swap_usage,
                                stats.pid_count
                            );
                        }
                        Err(e) => {
                            eprintln!("Failed to read stats for {}: {}", state.id, e);
                        }
                    }
                } else {
                    eprintln!("No cgroup path for container {}", state.id);
                }
            }

            Ok(0)
        }

        Commands::Stop { container, timeout } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::stop(&state, timeout)?;
            println!("{}", state.id);
            Ok(0)
        }

        Commands::Start { container } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            if state.status != OciStatus::Created {
                return Err(NucleusError::InvalidStateTransition {
                    from: state.status.to_string(),
                    to: "created".to_string(),
                });
            }
            Container::trigger_start(&state.id, state_root.clone())?;
            println!("{}", state.id);
            Ok(0)
        }

        Commands::Delete { container, force } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::remove(&state_mgr, &state, force)?;
            println!("{}", state.id);
            Ok(0)
        }

        Commands::Kill { container, signal } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let sig = parse_signal(&signal)?;
            ContainerLifecycle::kill_container(&state, sig)?;
            println!("{}", state.id);
            Ok(0)
        }

        Commands::Attach { container, command } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let cmd = if command.is_empty() {
                vec!["/bin/sh".to_string()]
            } else {
                command
            };
            let exit_code = ContainerAttach::attach(&state, cmd)?;
            Ok(exit_code)
        }

        Commands::Logs {
            container,
            follow,
            lines,
        } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let unit_name = format!("nucleus-{}", &state.id[..12.min(state.id.len())]);

            let journalctl = resolve_journalctl_helper()?;
            let mut cmd = privileged_helper_command(&journalctl);
            cmd.arg("--unit").arg(&unit_name).arg("--no-pager");
            if follow {
                cmd.arg("--follow");
            }
            if let Some(n) = lines {
                cmd.arg("-n").arg(n.to_string());
            }
            let status = cmd.status().map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to run journalctl: {}. Is systemd available?",
                    e
                ))
            })?;
            if !status.success() {
                return Err(NucleusError::ExecError(format!(
                    "journalctl exited with status {}",
                    status
                )));
            }
            Ok(0)
        }

        Commands::Checkpoint {
            container,
            output,
            leave_running,
        } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;

            if state.using_gvisor {
                return Err(NucleusError::CheckpointError(format!(
                    "Container {} uses gVisor runtime; CRIU checkpoint is not supported \
                     (gVisor manages its own sandbox state)",
                    state.id
                )));
            }

            let mut criu = CriuRuntime::new()?;
            criu.checkpoint(&state, &PathBuf::from(&output), leave_running)?;
            println!("Checkpoint saved to {}", output);
            Ok(0)
        }

        Commands::Restore { input } => {
            let mut criu = CriuRuntime::new()?;
            let input_path = PathBuf::from(&input);
            let metadata = CheckpointMetadata::load(&input_path)?;
            let pid = criu.restore(&input_path)?;

            // Register restored container in state manager so state/stop/kill/attach work.
            // Generate a NEW container ID to avoid overwriting the original state file
            // (the original container may still be running with --leave-running).
            let new_id = nucleus::container::generate_container_id()?;
            let new_name = format!("{}-restored", metadata.container_name);
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let (cgroup_path, memory_limit, cpu_limit) =
                match restore_checkpoint_cgroup(&new_id, pid, &metadata) {
                    Ok(restored) => restored,
                    Err(err) => {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                        return Err(err);
                    }
                };
            let state = ContainerState::new(ContainerStateParams {
                id: new_id.clone(),
                name: new_name,
                pid,
                command: metadata.command,
                memory_limit,
                cpu_limit,
                using_gvisor: metadata.using_gvisor,
                rootless: metadata.rootless,
                cgroup_path,
                process_uid: 0,
                process_gid: 0,
                additional_gids: Vec::new(),
            });
            state_mgr.save_state(&state)?;
            info!(
                "Registered restored container {} (was {}, PID {})",
                new_id, metadata.container_id, pid
            );

            println!("{}", new_id);
            Ok(0)
        }

        Commands::Create {
            config,
            config_fd,
            name,
            context,
            workspace,
            workspace_mode,
            workspace_exec,
            home,
            workdir,
            memory,
            cpus,
            cpu_weight,
            io_limits,
            pids,
            memlock,
            swap,
            hostname,
            runtime,
            detach,
            quiet_id,
            preset_id,
            detached_config_json,
            rootless,
            user,
            group,
            additional_groups,
            bundle,
            pid_file,
            console_socket,
            terminal,
            network,
            allow_host_network,
            allow_degraded_security,
            allow_chroot_fallback,
            trust_level,
            proc_rw,
            publish,
            context_mode,
            service_mode,
            strict_agent,
            rootfs,
            agent_toolchain_rootfs,
            egress_allow,
            egress_domains,
            egress_tcp_ports,
            egress_udp_ports,
            dns,
            nat_backend,
            health_cmd,
            health_interval,
            health_retries,
            health_start_period,
            secrets,
            secrets_fd,
            systemd_credentials,
            volumes,
            tmpfs,
            provider_config_ro,
            provider_config_rw,
            env_vars,
            env_fd,
            sd_notify,
            readiness_exec,
            readiness_tcp,
            readiness_sd_notify,
            seccomp_profile,
            seccomp_profile_sha256,
            seccomp_mode,
            seccomp_log,
            seccomp_log_denied,
            seccomp_allow,
            caps_policy,
            caps_policy_sha256,
            landlock_policy,
            landlock_policy_sha256,
            verify_context_integrity,
            verify_rootfs_attestation,
            require_kernel_lockdown,
            gvisor_platform,
            time_namespace,
            disable_cgroup_namespace,
            hooks,
            topology_config_hash,
            command,
        } => {
            let create_request = match (detached_config_json, config, config_fd) {
                (Some(serialized), None, None) => {
                    let request: RunConfig = serde_json::from_str(&serialized).map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to deserialize detached create request: {}",
                            e
                        ))
                    })?;
                    if request.detach {
                        return Err(NucleusError::ConfigError(
                            "Detached create request must clear --detach before re-exec"
                                .to_string(),
                        ));
                    }
                    request
                }
                (None, Some(config_path), None) => read_run_config_from_path(&config_path)?,
                (None, None, Some(fd)) => read_run_config_from_fd(fd)?,
                (None, None, None) => RunConfig {
                    name,
                    context,
                    workspace,
                    workspace_mode,
                    workspace_exec,
                    home,
                    workdir,
                    memory,
                    cpus,
                    hostname,
                    cpu_weight,
                    io_limits,
                    pids,
                    memlock,
                    swap,
                    runtime,
                    detach,
                    quiet_id,
                    preset_id,
                    rootless,
                    user,
                    group,
                    additional_groups,
                    bundle,
                    pid_file,
                    console_socket,
                    terminal,
                    network,
                    allow_host_network,
                    allow_degraded_security,
                    allow_chroot_fallback,
                    trust_level,
                    proc_rw,
                    publish,
                    context_mode,
                    service_mode,
                    strict_agent,
                    rootfs,
                    agent_toolchain_rootfs,
                    egress_allow,
                    egress_domains,
                    egress_tcp_ports,
                    egress_udp_ports,
                    dns,
                    nat_backend,
                    health_cmd,
                    health_interval,
                    health_retries,
                    health_start_period,
                    secrets,
                    secrets_fd,
                    systemd_credentials,
                    volumes,
                    tmpfs,
                    provider_config_ro,
                    provider_config_rw,
                    env_vars,
                    env_fd,
                    sd_notify,
                    readiness_exec,
                    readiness_tcp,
                    readiness_sd_notify,
                    seccomp_profile,
                    seccomp_profile_sha256,
                    seccomp_mode,
                    seccomp_log,
                    seccomp_log_denied,
                    seccomp_allow,
                    caps_policy,
                    caps_policy_sha256,
                    landlock_policy,
                    landlock_policy_sha256,
                    verify_context_integrity,
                    verify_rootfs_attestation,
                    require_kernel_lockdown,
                    gvisor_platform,
                    time_namespace,
                    disable_cgroup_namespace,
                    hooks,
                    topology_config_hash,
                    command,
                },
                _ => {
                    return Err(NucleusError::ConfigError(
                        "--config, --config-fd, and --detached-config-json are mutually exclusive"
                            .to_string(),
                    ));
                }
            };

            if create_request.command.is_empty() {
                return Err(NucleusError::ConfigError(
                    "No command specified".to_string(),
                ));
            }
            if create_request.detach && create_request.secrets_fd.is_some() {
                return Err(NucleusError::ConfigError(
                    "--secrets-fd cannot be used with --detach".to_string(),
                ));
            }
            if create_request.detach && create_request.env_fd.is_some() {
                return Err(NucleusError::ConfigError(
                    "--env-fd cannot be used with --detach".to_string(),
                ));
            }
            if create_request.detach && events_fd.is_some() {
                return Err(NucleusError::ConfigError(
                    "--events-fd cannot be used with --detach; use --events-jsonl so the systemd-managed process can open the stream"
                        .to_string(),
                ));
            }
            let _ = resolve_service_mode(create_request.service_mode, create_request.strict_agent)?;

            // --detach: re-exec under systemd-run as a transient service using
            // a serialized parsed request instead of argv string surgery.
            if create_request.detach {
                let id = nucleus::container::generate_container_id()?;
                let exe = std::env::current_exe().map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to resolve current executable for detach re-exec: {}",
                        e
                    ))
                })?;
                let mut inner_request = create_request.clone();
                inner_request.detach = false;
                inner_request.quiet_id = true;
                inner_request.preset_id = Some(id.clone());
                let serialized = serde_json::to_string(&inner_request).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to serialize detached create request: {}",
                        e
                    ))
                })?;
                let mut inner_args: Vec<String> = Vec::new();
                if let Some(ref root) = state_root {
                    inner_args.push("--root".to_string());
                    inner_args.push(root.display().to_string());
                }
                if let Some(ref log) = log_path {
                    inner_args.push("--log".to_string());
                    inner_args.push(log.display().to_string());
                }
                if log_format != "text" {
                    inner_args.push("--log-format".to_string());
                    inner_args.push(log_format.clone());
                }
                if let Some(ref events_path) = events_jsonl {
                    inner_args.push("--events-jsonl".to_string());
                    inner_args.push(events_path.display().to_string());
                }
                inner_args.push("create".to_string());
                inner_args.push("--detached-config-json".to_string());
                inner_args.push(serialized);

                let unit_name = format!("nucleus-{}", &id[..12]);
                let systemd_run = resolve_systemd_run_helper()?;
                let status = privileged_helper_command(&systemd_run)
                    .arg("--unit")
                    .arg(&unit_name)
                    .arg("--collect")
                    .arg("--quiet")
                    .arg("-p")
                    .arg("KillMode=mixed")
                    .arg("-p")
                    .arg("KillSignal=SIGTERM")
                    .arg("-p")
                    .arg("TimeoutStopSec=30")
                    .arg("--")
                    .arg(&exe)
                    .args(&inner_args)
                    .status()
                    .map_err(|e| {
                        NucleusError::ExecError(format!(
                            "Failed to launch systemd-run for detach: {}. \
                             Is systemd available?",
                            e
                        ))
                    })?;

                if !status.success() {
                    return Err(NucleusError::ExecError(format!(
                        "systemd-run exited with status {}",
                        status
                    )));
                }

                println!("{}", id);
                return Ok(0);
            }

            let RunConfig {
                name,
                context,
                workspace,
                workspace_mode,
                workspace_exec,
                home,
                workdir,
                memory,
                cpus,
                hostname,
                cpu_weight,
                io_limits,
                pids,
                memlock,
                swap,
                runtime,
                detach: _,
                quiet_id,
                preset_id,
                rootless,
                user,
                group,
                additional_groups,
                bundle,
                pid_file,
                console_socket,
                terminal,
                network,
                allow_host_network,
                allow_degraded_security,
                allow_chroot_fallback,
                trust_level,
                proc_rw,
                publish,
                context_mode,
                service_mode,
                strict_agent,
                rootfs,
                agent_toolchain_rootfs,
                egress_allow,
                egress_domains,
                egress_tcp_ports,
                egress_udp_ports,
                dns,
                nat_backend,
                health_cmd,
                health_interval,
                health_retries,
                health_start_period,
                secrets,
                secrets_fd,
                systemd_credentials,
                volumes,
                tmpfs,
                provider_config_ro,
                provider_config_rw,
                env_vars,
                env_fd,
                sd_notify,
                readiness_exec,
                readiness_tcp,
                readiness_sd_notify,
                seccomp_profile,
                seccomp_profile_sha256,
                seccomp_mode,
                seccomp_log,
                seccomp_log_denied,
                seccomp_allow,
                caps_policy,
                caps_policy_sha256,
                landlock_policy,
                landlock_policy_sha256,
                verify_context_integrity,
                verify_rootfs_attestation,
                require_kernel_lockdown,
                gvisor_platform,
                time_namespace,
                disable_cgroup_namespace,
                hooks,
                topology_config_hash,
                command,
            } = create_request;

            if let Some(ref n) = name {
                validate_container_name(n)?;
            }

            let service_mode = resolve_service_mode(service_mode, strict_agent)?;

            // Build resource limits (default includes pids_max=512)
            let mut limits = ResourceLimits::default();

            if let Some(mem_str) = memory {
                limits = limits.with_memory(&mem_str)?;
                info!("Memory limit: {}", mem_str);
            }

            if let Some(cores) = cpus {
                limits = limits.with_cpu_cores(cores)?;
                info!("CPU limit: {} cores", cores);
            }

            if let Some(weight) = cpu_weight {
                limits = limits.with_cpu_weight(weight)?;
                info!("CPU weight: {}", weight);
            }

            if let Some(max_pids) = pids {
                if max_pids == 0 {
                    limits.pids_max = None;
                    info!("PID limit: unlimited");
                } else {
                    limits = limits.with_pids(max_pids)?;
                    info!("PID limit: {}", max_pids);
                }
            }

            if let Some(ref memlock_str) = memlock {
                limits = limits.with_memlock(memlock_str)?;
            }

            for io_spec in &io_limits {
                let io_limit = IoDeviceLimit::parse(io_spec)?;
                limits = limits.with_io_limit(io_limit);
                info!("I/O limit: {}", io_spec);
            }

            if swap {
                limits = limits.with_swap_enabled();
                info!("Swap enabled");
            }

            let net_mode = match network {
                NetworkModeArg::None => NetworkMode::None,
                NetworkModeArg::Host => NetworkMode::Host,
                NetworkModeArg::GVisorHost => NetworkMode::GVisorHost,
                NetworkModeArg::Bridge => {
                    // Strict modes require explicit DNS to avoid public resolver defaults.
                    if service_mode.requires_explicit_bridge_dns() && dns.is_empty() {
                        return Err(NucleusError::ConfigError(format!(
                            "{} with bridge networking requires explicit --dns servers",
                            service_mode.label()
                        )));
                    }
                    let mut bridge_config = if dns.is_empty() {
                        BridgeConfig::default().with_public_dns()
                    } else {
                        BridgeConfig::default().with_dns(dns.clone())
                    }
                    .with_nat_backend(nat_backend);
                    // Parse port forwards
                    for spec in &publish {
                        let pf = PortForward::parse(spec)?;
                        bridge_config.port_forwards.push(pf);
                    }
                    NetworkMode::Bridge(bridge_config)
                }
            };

            let mut namespaces = NamespaceConfig::all();
            if time_namespace {
                namespaces = namespaces.with_time_namespace(true);
            }
            if disable_cgroup_namespace {
                namespaces = namespaces.with_cgroup_namespace(false);
            }

            // Build configuration
            let mut config = ContainerConfig::try_new_with_id(preset_id, name, command)?
                .with_limits(limits)
                .with_namespaces(namespaces)
                .with_network(net_mode)
                .with_context_mode(context_mode)
                .with_allow_host_network(allow_host_network)
                .with_allow_degraded_security(allow_degraded_security)
                .with_allow_chroot_fallback(allow_chroot_fallback)
                .with_trust_level(trust_level)
                .with_proc_readonly(!proc_rw)
                .with_service_mode(service_mode)
                .with_sd_notify(sd_notify)
                .with_seccomp_log_denied(seccomp_log_denied)
                .with_verify_context_integrity(verify_context_integrity)
                .with_verify_rootfs_attestation(verify_rootfs_attestation)
                .with_gvisor_platform(gvisor_platform);

            if let Some(mode) = require_kernel_lockdown {
                config = config.with_required_kernel_lockdown(mode);
            }

            if let Some(hash) = topology_config_hash {
                config = config.with_config_hash(hash);
            }

            if let Some(ctx) = context {
                let canonical_ctx = std::fs::canonicalize(&ctx).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize context path '{}': {}",
                        ctx, e
                    ))
                })?;
                config = config.with_context(canonical_ctx);
            }

            let normalized_workdir = normalize_container_destination(Path::new(&workdir))?;
            config = config.with_workdir(normalized_workdir);

            let normalized_home = normalize_container_destination(Path::new(&home))?;
            config = config.with_home(normalized_home.clone());

            let mut workspace_config = WorkspaceConfig::new()
                .with_mode(workspace_mode)
                .with_allow_execute(workspace_exec);
            if let Some(workspace_path) = workspace {
                let canonical_workspace = validate_workspace_host_path(Path::new(&workspace_path))?;
                workspace_config = workspace_config.with_host_path(canonical_workspace);
            }
            config = config.with_workspace(workspace_config);

            if let Some(host) = hostname {
                validate_hostname(&host)?;
                config = config.with_hostname(Some(host));
            }

            config = config.apply_runtime_selection(runtime, bundle.is_some())?;

            // OCI bundle directory override
            if let Some(ref bundle_dir) = bundle {
                config = config.with_bundle_dir(bundle_dir.clone());
            }

            // Console socket – canonicalize parent to prevent symlink traversal
            if let Some(ref socket_path) = console_socket {
                let socket = PathBuf::from(socket_path);
                let canonical = if let Some(parent) = socket.parent() {
                    let canon_parent = std::fs::canonicalize(parent).map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to canonicalize console socket parent '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                    canon_parent.join(socket.file_name().unwrap_or_default())
                } else {
                    socket
                };
                config = config.with_console_socket(canonical);
            }
            if terminal || config.console_socket.is_some() {
                config = config.with_terminal(ConsoleSize::detect());
            }

            if rootless {
                info!("Enabling rootless mode");
                config = config.with_rootless();
            }

            if let Some(identity) =
                resolve_process_identity(user.as_deref(), group.as_deref(), &additional_groups)?
            {
                info!(
                    "Running workload as uid={} gid={} supplementary_gids={:?}",
                    identity.uid, identity.gid, identity.additional_gids
                );
                config = config.with_process_identity(identity);
            }

            // Rootfs path
            if let Some(rootfs_dir) =
                resolve_rootfs_argument(service_mode, rootfs, agent_toolchain_rootfs)?
            {
                config = config.with_rootfs_path(rootfs_dir);
            }

            // Seccomp profile and mode
            if let Some(profile_path) = seccomp_profile {
                let canonical = std::fs::canonicalize(&profile_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize seccomp profile path '{}': {}",
                        profile_path, e
                    ))
                })?;
                config = config.with_seccomp_profile(canonical);
            }
            if let Some(sha256) = seccomp_profile_sha256 {
                config = config.with_seccomp_profile_sha256(sha256);
            }
            match seccomp_mode {
                SeccompMode::Enforce => {}
                SeccompMode::Trace => {
                    config = config.with_seccomp_mode(SeccompMode::Trace);
                    if let Some(log_path) = seccomp_log {
                        config = config.with_seccomp_trace_log(PathBuf::from(log_path));
                    } else {
                        return Err(NucleusError::ConfigError(
                            "--seccomp-log is required when --seccomp-mode=trace".to_string(),
                        ));
                    }
                }
            }

            if !seccomp_allow.is_empty() {
                config = config.with_seccomp_allow_syscalls(seccomp_allow);
            }

            // Capability policy
            if let Some(path) = caps_policy {
                let canonical = std::fs::canonicalize(&path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize capability policy path '{}': {}",
                        path, e
                    ))
                })?;
                config = config.with_caps_policy(canonical);
            }
            if let Some(sha256) = caps_policy_sha256 {
                config = config.with_caps_policy_sha256(sha256);
            }

            // Landlock policy
            if let Some(path) = landlock_policy {
                let canonical = std::fs::canonicalize(&path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize Landlock policy path '{}': {}",
                        path, e
                    ))
                })?;
                config = config.with_landlock_policy(canonical);
            }
            if let Some(sha256) = landlock_policy_sha256 {
                config = config.with_landlock_policy_sha256(sha256);
            }

            // Egress policy: in production mode, set deny-all by default for
            // network namespaces where Nucleus can enforce it. Domain entries
            // resolve to IPv4 rules before the namespace-local iptables policy
            // is installed. gvisor-host is explicit hostinet and cannot be
            // constrained by namespace-local iptables rules.
            let gvisor_host_network = matches!(config.network, NetworkMode::GVisorHost);
            if !egress_allow.is_empty() || !egress_domains.is_empty() {
                if gvisor_host_network {
                    return Err(NucleusError::ConfigError(
                        "--egress-allow/--egress-domain cannot be enforced with --network gvisor-host"
                            .to_string(),
                    ));
                }
                let policy = EgressPolicy::default()
                    .with_allowed_cidrs(egress_allow)
                    .with_allowed_domains(egress_domains)
                    .with_allowed_tcp_ports(egress_tcp_ports)
                    .with_allowed_udp_ports(egress_udp_ports);
                config = config.with_egress_policy(policy);
            } else if service_mode == ServiceMode::Production && !gvisor_host_network {
                // Default deny-all egress for production services
                config = config.with_egress_policy(EgressPolicy::deny_all());
            }

            // Readiness probe (mutually exclusive options)
            {
                let probe_count = readiness_exec.is_some() as u8
                    + readiness_tcp.is_some() as u8
                    + readiness_sd_notify as u8;
                if probe_count > 1 {
                    return Err(NucleusError::ConfigError(
                        "Only one readiness probe type may be set \
                         (--readiness-exec, --readiness-tcp, --readiness-sd-notify)"
                            .to_string(),
                    ));
                }
                if let Some(cmd) = readiness_exec {
                    config = config.with_readiness_probe(ReadinessProbe::Exec {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
                    });
                } else if let Some(port) = readiness_tcp {
                    config = config.with_readiness_probe(ReadinessProbe::TcpPort(port));
                } else if readiness_sd_notify {
                    config = config.with_readiness_probe(ReadinessProbe::SdNotify);
                }
            }

            // Health check
            if let Some(cmd) = health_cmd {
                let hc = HealthCheck {
                    command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
                    interval: std::time::Duration::from_secs(health_interval.unwrap_or(30)),
                    retries: health_retries.unwrap_or(3),
                    start_period: std::time::Duration::from_secs(health_start_period.unwrap_or(5)),
                    timeout: std::time::Duration::from_secs(5),
                };
                config = config.with_health_check(hc);
            }

            let secrets = collect_secret_specs(secrets, secrets_fd)?;

            // Secrets
            for spec in &secrets {
                let parts: Vec<&str> = spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid secret format '{}', expected SOURCE:DEST",
                        spec
                    )));
                }
                // Canonicalize source path to resolve symlinks and prevent
                // path traversal (e.g., "../../etc/shadow:...").
                let source = std::fs::canonicalize(parts[0]).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Secret source '{}' cannot be resolved: {}",
                        parts[0], e
                    ))
                })?;
                config = config.with_secret(SecretMount {
                    source,
                    dest: PathBuf::from(parts[1]),
                    mode: 0o400,
                });
            }

            // Systemd credentials
            for spec in &systemd_credentials {
                let parts: Vec<&str> = spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid systemd credential format '{}', expected NAME:DEST",
                        spec
                    )));
                }
                let source = resolve_systemd_credential_source(parts[0])?;
                config = config.with_secret(SecretMount {
                    source,
                    dest: PathBuf::from(parts[1]),
                    mode: 0o400,
                });
            }

            // Bind volumes
            for spec in &volumes {
                let parts: Vec<&str> = spec.split(':').collect();
                let (source_raw, dest_raw, read_only) = match parts.as_slice() {
                    [source, dest] => (*source, *dest, false),
                    [source, dest, mode] if *mode == "ro" => (*source, *dest, true),
                    [source, dest, mode] if *mode == "rw" => (*source, *dest, false),
                    _ => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid volume format '{}', expected SOURCE:DEST[:ro|rw]",
                            spec
                        )));
                    }
                };
                let source = std::fs::canonicalize(source_raw).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Volume source '{}' cannot be resolved: {}",
                        source_raw, e
                    ))
                })?;
                validate_bind_mount_source(&source)?;
                normalize_volume_destination(Path::new(dest_raw))?;
                config = config.with_volume(VolumeMount {
                    source: VolumeSource::Bind { source },
                    dest: PathBuf::from(dest_raw),
                    read_only,
                });
            }

            // Tmpfs volumes – format: DEST[:SIZE][:ro|rw]
            // SIZE must match a numeric-with-suffix pattern (e.g. "64M", "1G", "512k").
            for spec in &tmpfs {
                let parts: Vec<&str> = spec.split(':').collect();
                let is_mode = |s: &str| s == "ro" || s == "rw";
                let is_size = |s: &str| {
                    s.trim_end_matches(|c: char| c.is_ascii_alphabetic())
                        .parse::<u64>()
                        .is_ok()
                };
                let (dest, size, read_only) = match parts.as_slice() {
                    [dest] => (*dest, None, false),
                    [dest, flag] if is_mode(flag) => (*dest, None, *flag == "ro"),
                    [dest, sz] if is_size(sz) => (*dest, Some((*sz).to_string()), false),
                    [dest, sz, flag] if is_size(sz) && is_mode(flag) => {
                        (*dest, Some((*sz).to_string()), *flag == "ro")
                    }
                    [_dest, bad] => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid tmpfs second field '{}' in '{}': \
                             expected a size (e.g. 64M) or mode (ro|rw)",
                            bad, spec
                        )));
                    }
                    _ => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid tmpfs format '{}', expected DEST[:SIZE][:ro|rw]",
                            spec
                        )));
                    }
                };
                if dest.is_empty() {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid tmpfs format '{}', expected DEST[:SIZE][:ro|rw]",
                        spec
                    )));
                }
                config = config.with_volume(VolumeMount {
                    source: VolumeSource::Tmpfs { size },
                    dest: PathBuf::from(dest),
                    read_only,
                });
            }

            for spec in &provider_config_ro {
                config = config.with_provider_config(parse_provider_config_mount_spec(
                    spec,
                    &normalized_home,
                    true,
                )?);
            }
            for spec in &provider_config_rw {
                config = config.with_provider_config(parse_provider_config_mount_spec(
                    spec,
                    &normalized_home,
                    false,
                )?);
            }

            // Environment variables
            let env_vars = collect_env_specs(env_vars, env_fd)?;
            for spec in &env_vars {
                let (key, value) = parse_env_assignment(spec)?;
                config = config.with_env(key, value);
            }

            // OCI lifecycle hooks
            if let Some(hooks_path) = hooks {
                let hooks_path = std::fs::canonicalize(&hooks_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize hooks path '{}': {}",
                        hooks_path, e
                    ))
                })?;
                let hooks_json = std::fs::read_to_string(&hooks_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to read hooks file '{}': {}",
                        hooks_path.display(),
                        e
                    ))
                })?;
                let oci_hooks: nucleus::security::OciHooks = serde_json::from_str(&hooks_json)
                    .map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to parse hooks file '{}': {}",
                            hooks_path.display(),
                            e
                        ))
                    })?;
                config.hooks = Some(oci_hooks);
            }

            // PID file path – canonicalize parent to prevent symlink traversal
            if let Some(ref pid_path) = pid_file {
                let pid = PathBuf::from(pid_path);
                let canonical = if let Some(parent) = pid.parent() {
                    let canon_parent = std::fs::canonicalize(parent).map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to canonicalize PID file parent '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                    canon_parent.join(pid.file_name().unwrap_or_default())
                } else {
                    pid
                };
                config = config.with_pid_file(canonical);
            }

            // Propagate --root to the container so it uses the correct state directory
            if let Some(ref root) = state_root {
                config = config.with_state_root(root.clone());
            }

            if !quiet_id {
                println!("{}", config.id);
            }

            let event_sink =
                nucleus::telemetry::EventSink::from_cli(events_fd, events_jsonl.as_deref())?;
            let container = Container::new(config).with_event_sink(event_sink);
            let exit_code = container.run()?;

            Ok(exit_code)
        }

        Commands::Compose(compose_cmd) => match compose_cmd {
            ComposeCommands::Validate { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let graph = DependencyGraph::resolve(&config)?;
                println!("Topology '{}' is valid", config.name);
                println!(
                    "Services ({}): {}",
                    config.services.len(),
                    config
                        .services
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("Startup order: {}", graph.startup_order.join(" -> "));
                Ok(0)
            }

            ComposeCommands::Plan { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let plan = plan_reconcile(&config, &state_mgr)?;

                println!("Reconciliation plan for topology '{}':", config.name);
                for (name, action) in &plan.actions {
                    let action_str = match action {
                        ReconcileAction::NoChange => "no change",
                        ReconcileAction::Start => "start",
                        ReconcileAction::Restart => "restart",
                        ReconcileAction::Stop => "stop",
                    };
                    println!("  {} -> {}", name, action_str);
                }
                Ok(0)
            }

            ComposeCommands::Up { file, timeout } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let plan = plan_reconcile(&config, &state_mgr)?;

                println!("Bringing up topology '{}'...", config.name);
                execute_reconcile(&config, &plan, &state_mgr, timeout, state_root.as_deref())?;
                println!("Topology '{}' is up", config.name);
                Ok(0)
            }

            ComposeCommands::Down { file, timeout } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let graph = DependencyGraph::resolve(&config)?;

                println!("Tearing down topology '{}'...", config.name);
                for service_name in graph.shutdown_order() {
                    let container_name = format!("{}-{}", config.name, service_name);
                    if let Ok(state) = state_mgr.resolve_container(&container_name) {
                        if state.is_running() {
                            println!("Stopping {}...", container_name);
                            ContainerLifecycle::stop(&state, timeout)?;
                        }
                    }
                }
                println!("Topology '{}' is down", config.name);
                Ok(0)
            }

            ComposeCommands::State { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

                println!(
                    "{:<25} {:<10} {:<10} {:<30}",
                    "SERVICE", "STATUS", "PID", "COMMAND"
                );

                for service_name in config.services.keys() {
                    let container_name = format!("{}-{}", config.name, service_name);
                    match state_mgr.resolve_container(&container_name) {
                        Ok(state) => {
                            let status = if state.is_running() {
                                state.status.to_string()
                            } else {
                                OciStatus::Stopped.to_string()
                            };
                            let cmd = state.command.join(" ");
                            let cmd_display = if cmd.len() > 28 {
                                format!("{}...", &cmd[..25])
                            } else {
                                cmd
                            };
                            println!(
                                "{:<25} {:<10} {:<10} {:<30}",
                                service_name, status, state.pid, cmd_display
                            );
                        }
                        Err(_) => {
                            println!(
                                "{:<25} {:<10} {:<10} {:<30}",
                                service_name, "Not found", "-", "-"
                            );
                        }
                    }
                }
                Ok(0)
            }
        },

        Commands::Seccomp(seccomp_cmd) => match seccomp_cmd {
            SeccompCommands::Generate { trace_file, output } => {
                let profile = nucleus::security::generate_from_trace(&PathBuf::from(&trace_file))?;
                let json = serde_json::to_string_pretty(&profile)?;

                if let Some(out_path) = output {
                    std::fs::write(&out_path, &json)?;
                    eprintln!("Wrote seccomp profile to {}", out_path);
                } else {
                    println!("{}", json);
                }

                eprintln!(
                    "Profile contains {} syscalls",
                    profile.syscalls.first().map(|g| g.names.len()).unwrap_or(0)
                );
                Ok(0)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn write_test_helper(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn test_validate_privileged_helper_rejects_group_writable_binary() {
        let dir = tempfile::TempDir::new().unwrap();
        let helper = dir.path().join("journalctl");
        write_test_helper(&helper, 0o775);

        let err = validate_privileged_helper(&helper, "journalctl").unwrap_err();
        assert!(err.to_string().contains("writable by group/others"));
    }

    #[test]
    fn test_privileged_helper_command_overrides_path() {
        let cmd = privileged_helper_command(Path::new("/bin/true"));
        let path_env = cmd
            .get_envs()
            .find_map(|(key, value)| (key == "PATH").then_some(value))
            .flatten()
            .unwrap();

        assert_eq!(path_env.to_string_lossy(), SAFE_PRIVILEGED_HELPER_PATH);
    }

    #[test]
    fn test_privileged_helper_resolution_prefers_trusted_path_over_path() {
        let _guard = env_lock().lock().unwrap();
        let trusted_dir = tempfile::TempDir::new().unwrap();
        let path_dir = tempfile::TempDir::new().unwrap();
        let trusted_helper = trusted_dir.path().join("journalctl");
        let path_helper = path_dir.path().join("journalctl");
        write_test_helper(&trusted_helper, 0o755);
        write_test_helper(&path_helper, 0o755);

        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", path_dir.path());

        let trusted_helper_str = trusted_helper.to_str().unwrap();
        let resolved = resolve_privileged_helper("journalctl", &[trusted_helper_str]).unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&trusted_helper).unwrap());

        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
    }

    #[test]
    fn test_root_helper_resolution_does_not_use_path() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let helper = dir.path().join("systemd-run");
        write_test_helper(&helper, 0o755);
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());

        let err = resolve_privileged_helper_impl("systemd-run", &[], true).unwrap_err();
        assert!(err.to_string().contains("trusted system paths"));

        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
    }

    #[test]
    fn test_detached_create_request_roundtrips_command_tokens() {
        let request = RunConfig {
            name: Some("svc".to_string()),
            context: Some("/tmp/context".to_string()),
            workspace: Some("/tmp/workspace".to_string()),
            workspace_mode: WorkspaceMode::CopyInOut,
            workspace_exec: true,
            home: DEFAULT_HOME_PATH.to_string(),
            workdir: "/workspace".to_string(),
            memory: Some("512M".to_string()),
            cpus: Some(1.5),
            hostname: Some("svc".to_string()),
            cpu_weight: Some(100),
            io_limits: vec!["8:0 riops=1000".to_string()],
            pids: Some(64),
            memlock: Some("8M".to_string()),
            swap: true,
            runtime: RuntimeSelection::Native,
            detach: false,
            quiet_id: true,
            preset_id: Some("0123456789abcdef0123456789abcdef".to_string()),
            rootless: true,
            user: Some("1000".to_string()),
            group: Some("1000".to_string()),
            additional_groups: vec!["27".to_string()],
            bundle: Some(PathBuf::from("/tmp/bundle")),
            pid_file: Some(PathBuf::from("/tmp/pid")),
            console_socket: Some(PathBuf::from("/tmp/console.sock")),
            terminal: true,
            network: NetworkModeArg::Bridge,
            allow_host_network: false,
            allow_degraded_security: true,
            allow_chroot_fallback: true,
            trust_level: TrustLevel::Trusted,
            proc_rw: true,
            publish: vec!["127.0.0.1:8080:80/tcp".to_string()],
            context_mode: ContextMode::BindMount,
            service_mode: ServiceMode::Production,
            strict_agent: false,
            rootfs: Some("/nix/store/rootfs".to_string()),
            agent_toolchain_rootfs: None,
            egress_allow: vec!["10.0.0.0/8".to_string()],
            egress_domains: vec!["api.example.com".to_string()],
            egress_tcp_ports: vec![443],
            egress_udp_ports: vec![53],
            dns: vec!["8.8.8.8".to_string()],
            nat_backend: NatBackend::Kernel,
            health_cmd: Some("curl -f http://127.0.0.1/health".to_string()),
            health_interval: Some(5),
            health_retries: Some(2),
            health_start_period: Some(1),
            secrets: vec!["/tmp/src:/run/secrets/token".to_string()],
            secrets_fd: None,
            systemd_credentials: vec!["db-password:/run/secrets/db".to_string()],
            volumes: vec!["/tmp/data:/data:ro".to_string()],
            tmpfs: vec!["/cache:64M:rw".to_string()],
            provider_config_ro: vec!["/tmp/provider:/home/agent/.provider".to_string()],
            provider_config_rw: Vec::new(),
            env_vars: vec!["A=B".to_string()],
            env_fd: None,
            sd_notify: true,
            readiness_exec: Some("test -f /tmp/ready".to_string()),
            readiness_tcp: None,
            readiness_sd_notify: false,
            seccomp_profile: Some("/tmp/seccomp.json".to_string()),
            seccomp_profile_sha256: Some("abcd".to_string()),
            seccomp_mode: SeccompMode::Enforce,
            seccomp_log: None,
            seccomp_log_denied: false,
            seccomp_allow: vec!["io_uring_setup".to_string(), "--detach".to_string()],
            caps_policy: Some("/tmp/caps.toml".to_string()),
            caps_policy_sha256: Some("efgh".to_string()),
            landlock_policy: Some("/tmp/landlock.toml".to_string()),
            landlock_policy_sha256: Some("ijkl".to_string()),
            verify_context_integrity: true,
            verify_rootfs_attestation: true,
            require_kernel_lockdown: Some(KernelLockdownMode::Integrity),
            gvisor_platform: GVisorPlatform::Ptrace,
            time_namespace: true,
            disable_cgroup_namespace: true,
            hooks: Some("/tmp/hooks.json".to_string()),
            topology_config_hash: Some(42),
            command: vec![
                "/bin/sh".to_string(),
                "-ceu".to_string(),
                "printf '%s\n' create --detach".to_string(),
                "--".to_string(),
                "-d".to_string(),
            ],
        };

        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: RunConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.command, request.command);
        assert_eq!(decoded.publish, request.publish);
        assert_eq!(decoded.egress_domains, request.egress_domains);
        assert_eq!(decoded.seccomp_allow, request.seccomp_allow);
    }

    #[test]
    fn test_create_hidden_detached_config_skips_command_requirement() {
        let encoded = serde_json::to_string(&RunConfig {
            name: None,
            context: None,
            workspace: None,
            workspace_mode: WorkspaceMode::BindRw,
            workspace_exec: false,
            home: DEFAULT_HOME_PATH.to_string(),
            workdir: "/workspace".to_string(),
            memory: None,
            cpus: None,
            hostname: None,
            cpu_weight: None,
            io_limits: Vec::new(),
            pids: None,
            memlock: None,
            swap: false,
            runtime: RuntimeSelection::GVisor,
            detach: false,
            quiet_id: false,
            preset_id: None,
            rootless: false,
            user: None,
            group: None,
            additional_groups: Vec::new(),
            bundle: None,
            pid_file: None,
            console_socket: None,
            terminal: false,
            network: NetworkModeArg::None,
            allow_host_network: false,
            allow_degraded_security: false,
            allow_chroot_fallback: false,
            trust_level: TrustLevel::Untrusted,
            proc_rw: false,
            publish: Vec::new(),
            context_mode: ContextMode::Copy,
            service_mode: ServiceMode::Agent,
            strict_agent: false,
            rootfs: None,
            agent_toolchain_rootfs: None,
            egress_allow: Vec::new(),
            egress_domains: Vec::new(),
            egress_tcp_ports: Vec::new(),
            egress_udp_ports: Vec::new(),
            dns: Vec::new(),
            nat_backend: NatBackend::Auto,
            health_cmd: None,
            health_interval: None,
            health_retries: None,
            health_start_period: None,
            secrets: Vec::new(),
            secrets_fd: None,
            systemd_credentials: Vec::new(),
            volumes: Vec::new(),
            tmpfs: Vec::new(),
            provider_config_ro: Vec::new(),
            provider_config_rw: Vec::new(),
            env_vars: Vec::new(),
            env_fd: None,
            sd_notify: false,
            readiness_exec: None,
            readiness_tcp: None,
            readiness_sd_notify: false,
            seccomp_profile: None,
            seccomp_profile_sha256: None,
            seccomp_mode: SeccompMode::Enforce,
            seccomp_log: None,
            seccomp_log_denied: false,
            seccomp_allow: Vec::new(),
            caps_policy: None,
            caps_policy_sha256: None,
            landlock_policy: None,
            landlock_policy_sha256: None,
            verify_context_integrity: false,
            verify_rootfs_attestation: false,
            require_kernel_lockdown: None,
            gvisor_platform: GVisorPlatform::Systrap,
            time_namespace: false,
            disable_cgroup_namespace: false,
            hooks: None,
            topology_config_hash: None,
            command: vec!["/bin/true".to_string()],
        })
        .unwrap();

        let cli =
            Cli::try_parse_from(["nucleus", "create", "--detached-config-json", &encoded]).unwrap();

        match cli.command {
            Commands::Create {
                detached_config_json,
                command,
                ..
            } => {
                assert!(command.is_empty());
                assert_eq!(detached_config_json, Some(encoded));
            }
            _ => panic!("expected create command"),
        }
    }

    #[test]
    fn test_run_alias_accepts_launch_config_without_command() {
        let cli =
            Cli::try_parse_from(["nucleus", "run", "--config", "agent.nucleus.toml"]).unwrap();

        match cli.command {
            Commands::Create {
                config, command, ..
            } => {
                assert_eq!(config, Some(PathBuf::from("agent.nucleus.toml")));
                assert!(command.is_empty());
            }
            _ => panic!("expected create command"),
        }
    }

    #[test]
    fn test_run_config_rejects_cli_option_overlay() {
        let err = Cli::try_parse_from([
            "nucleus",
            "run",
            "--config",
            "agent.nucleus.toml",
            "--memory",
            "1G",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_run_config_defaults_from_minimal_json() {
        let config = parse_run_config(
            r#"{"command":["/bin/true"]}"#,
            "test",
            Some(RunConfigFormat::Json),
        )
        .unwrap();

        assert_eq!(config.command, vec!["/bin/true"]);
        assert_eq!(config.runtime, RuntimeSelection::GVisor);
        assert_eq!(config.network, NetworkModeArg::None);
        assert_eq!(config.service_mode, ServiceMode::Agent);
        assert_eq!(config.workspace_mode, WorkspaceMode::BindRw);
        assert!(matches!(config.context_mode, ContextMode::Copy));
        assert_eq!(config.workdir, "/workspace");
        assert_eq!(config.home, DEFAULT_HOME_PATH);
    }

    #[test]
    fn test_run_config_toml_uses_cli_enum_spellings() {
        let config = parse_run_config(
            r#"
command = ["/bin/true"]
workspace_mode = "copy-in-out"
runtime = "native"
network = "gvisor-host"
service_mode = "mitos-agent"
context_mode = "bind"
gvisor_platform = "ptrace"
trust_level = "trusted"
seccomp_mode = "trace"
seccomp_log = "/tmp/seccomp.ndjson"
"#,
            "test",
            Some(RunConfigFormat::Toml),
        )
        .unwrap();

        assert_eq!(config.workspace_mode, WorkspaceMode::CopyInOut);
        assert_eq!(config.runtime, RuntimeSelection::Native);
        assert_eq!(config.network, NetworkModeArg::GVisorHost);
        assert_eq!(config.service_mode, ServiceMode::StrictAgent);
        assert!(matches!(config.context_mode, ContextMode::BindMount));
        assert_eq!(config.gvisor_platform, GVisorPlatform::Ptrace);
        assert_eq!(config.trust_level, TrustLevel::Trusted);
        assert_eq!(config.seccomp_mode, SeccompMode::Trace);
    }

    #[test]
    fn test_run_config_rejects_unknown_fields() {
        let err = parse_run_config(
            r#"
command = ["/bin/true"]
surprise = true
"#,
            "test",
            Some(RunConfigFormat::Toml),
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_read_run_config_from_fd_reads_toml() {
        use std::io::{Seek, Write};
        use std::os::fd::IntoRawFd;

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(
            br#"
command = ["/bin/true"]
service_mode = "strict-agent"
"#,
        )
        .unwrap();
        file.rewind().unwrap();

        let fd = file.into_raw_fd();
        let config = read_run_config_from_fd(fd).unwrap();
        assert_eq!(config.command, vec!["/bin/true"]);
        assert_eq!(config.service_mode, ServiceMode::StrictAgent);
    }

    #[test]
    fn test_strict_agent_flag_resolves_to_strict_agent_mode() {
        assert_eq!(
            resolve_service_mode(ServiceMode::Agent, true).unwrap(),
            ServiceMode::StrictAgent
        );
        assert_eq!(
            resolve_service_mode(ServiceMode::StrictAgent, true).unwrap(),
            ServiceMode::StrictAgent
        );
        assert!(resolve_service_mode(ServiceMode::Production, true).is_err());
    }

    #[test]
    fn test_service_mode_strict_agent_and_mitos_agent_parse() {
        let strict = Cli::try_parse_from([
            "nucleus",
            "create",
            "--service-mode",
            "strict-agent",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let alias = Cli::try_parse_from([
            "nucleus",
            "create",
            "--service-mode",
            "mitos-agent",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let flag = Cli::try_parse_from(["nucleus", "create", "--strict-agent", "--", "/bin/true"])
            .unwrap();

        match strict.command {
            Commands::Create { service_mode, .. } => {
                assert_eq!(service_mode, ServiceMode::StrictAgent);
            }
            _ => panic!("expected create command"),
        }
        match alias.command {
            Commands::Create { service_mode, .. } => {
                assert_eq!(service_mode, ServiceMode::StrictAgent);
            }
            _ => panic!("expected create command"),
        }
        match flag.command {
            Commands::Create { strict_agent, .. } => {
                assert!(strict_agent);
            }
            _ => panic!("expected create command"),
        }
    }

    #[test]
    fn test_agent_toolchain_rootfs_flag_parses() {
        let cli = Cli::try_parse_from([
            "nucleus",
            "run",
            "--service-mode",
            "mitos-agent",
            "--agent-toolchain-rootfs",
            "/nix/store/example-agent-toolchain-rootfs",
            "--",
            "/bin/true",
        ])
        .unwrap();

        match cli.command {
            Commands::Create {
                service_mode,
                agent_toolchain_rootfs,
                ..
            } => {
                assert_eq!(service_mode, ServiceMode::StrictAgent);
                assert_eq!(
                    agent_toolchain_rootfs,
                    Some("/nix/store/example-agent-toolchain-rootfs".to_string())
                );
            }
            _ => panic!("expected create command"),
        }
    }

    #[test]
    fn test_agent_toolchain_rootfs_conflicts_with_rootfs_flag() {
        let err = Cli::try_parse_from([
            "nucleus",
            "run",
            "--rootfs",
            "/nix/store/service-rootfs",
            "--agent-toolchain-rootfs",
            "/nix/store/agent-rootfs",
            "--",
            "/bin/true",
        ])
        .unwrap_err();

        assert!(
            err.to_string().contains("cannot be used with"),
            "expected clap conflict, got: {err}"
        );
    }

    #[test]
    fn test_resolve_rootfs_argument_accepts_agent_toolchain_rootfs_in_strict_agent_mode() {
        let temp = tempfile::TempDir::new().unwrap();
        let rootfs = temp.path().join("agent-rootfs");
        std::fs::create_dir(&rootfs).unwrap();

        let resolved = resolve_rootfs_argument(
            ServiceMode::StrictAgent,
            None,
            Some(rootfs.display().to_string()),
        )
        .unwrap();

        assert_eq!(resolved, Some(std::fs::canonicalize(rootfs).unwrap()));
    }

    #[test]
    fn test_resolve_rootfs_argument_rejects_agent_toolchain_rootfs_in_production_mode() {
        let temp = tempfile::TempDir::new().unwrap();
        let rootfs = temp.path().join("agent-rootfs");
        std::fs::create_dir(&rootfs).unwrap();

        let err = resolve_rootfs_argument(
            ServiceMode::Production,
            None,
            Some(rootfs.display().to_string()),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("production mode must use --rootfs"),
            "expected production mode rejection, got: {err}"
        );
    }

    #[test]
    fn test_native_runtime_disables_gvisor() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        let config = config
            .apply_runtime_selection(RuntimeSelection::Native, false)
            .unwrap();
        assert!(
            !config.use_gvisor,
            "native runtime selection must disable gVisor"
        );
        assert_eq!(
            config.trust_level,
            TrustLevel::Untrusted,
            "native runtime selection must preserve the default Untrusted trust level"
        );
    }

    #[test]
    fn test_native_runtime_preserves_explicit_trust_level() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_trust_level(TrustLevel::Trusted);
        let config = config
            .apply_runtime_selection(RuntimeSelection::Native, false)
            .unwrap();

        assert!(
            !config.use_gvisor,
            "native runtime selection must disable gVisor"
        );
        assert_eq!(
            config.trust_level,
            TrustLevel::Trusted,
            "native runtime selection must preserve explicit Trusted trust level"
        );
    }

    #[test]
    fn test_native_runtime_rejects_bundle_flag() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        let err = config
            .apply_runtime_selection(RuntimeSelection::Native, true)
            .unwrap_err();
        assert!(
            err.to_string().contains("requires gVisor"),
            "native runtime with --bundle must be rejected explicitly"
        );
    }

    #[test]
    fn test_resolve_systemd_credential_source() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let cred = dir.path().join("db-password");
        std::fs::write(&cred, "secret").unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", dir.path());

        let resolved = resolve_systemd_credential_source("db-password").unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&cred).unwrap());
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }

    #[test]
    fn test_resolve_systemd_credential_rejects_path_traversal() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", dir.path());

        let err = resolve_systemd_credential_source("../db-password").unwrap_err();
        assert!(err.to_string().contains("Invalid systemd credential name"));
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }

    #[test]
    fn test_read_secret_specs_from_fd_reads_json_specs() {
        use std::io::{Seek, Write};
        use std::os::fd::IntoRawFd;

        let mut file = tempfile::tempfile().unwrap();
        let specs = vec![
            "/tmp/token:/run/secrets/token".to_string(),
            "/tmp/key:/run/secrets/key".to_string(),
        ];
        serde_json::to_writer(&mut file, &specs).unwrap();
        file.write_all(b"\n").unwrap();
        file.rewind().unwrap();

        let fd = file.into_raw_fd();
        let decoded = read_secret_specs_from_fd(fd).unwrap();
        assert_eq!(decoded, specs);
    }

    #[test]
    fn test_read_env_specs_from_fd_reads_json_object() {
        use std::io::{Seek, Write};
        use std::os::fd::IntoRawFd;

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(br#"{"OPENAI_API_KEY":"secret","DEBUG":"1"}"#)
            .unwrap();
        file.rewind().unwrap();

        let fd = file.into_raw_fd();
        let decoded = read_env_specs_from_fd(fd).unwrap();
        assert!(decoded.contains(&"OPENAI_API_KEY=secret".to_string()));
        assert!(decoded.contains(&"DEBUG=1".to_string()));
    }

    #[test]
    fn test_parse_env_assignment_rejects_dangerous_names_without_value_echo() {
        let err = parse_env_assignment("LD_PRELOAD=/tmp/inject.so").unwrap_err();
        assert!(err.to_string().contains("LD_PRELOAD"));
        assert!(!err.to_string().contains("/tmp/inject.so"));
    }

    #[test]
    fn test_home_provider_config_and_env_fd_parse() {
        let cli = Cli::try_parse_from([
            "nucleus",
            "create",
            "--home",
            "/home/agent",
            "--provider-config-ro",
            "/tmp/aws:.aws",
            "--provider-config-rw",
            "/tmp/gh:.config/gh",
            "--env-fd",
            "3",
            "--",
            "/bin/true",
        ])
        .unwrap();

        match cli.command {
            Commands::Create {
                home,
                provider_config_ro,
                provider_config_rw,
                env_fd,
                ..
            } => {
                assert_eq!(home, "/home/agent");
                assert_eq!(provider_config_ro, vec!["/tmp/aws:.aws"]);
                assert_eq!(provider_config_rw, vec!["/tmp/gh:.config/gh"]);
                assert_eq!(env_fd, Some(3));
            }
            _ => panic!("expected create command"),
        }
    }

    #[test]
    fn test_resolve_process_identity_named_user_defaults_primary_group() {
        let identity = resolve_process_identity(Some("root"), None, &[])
            .unwrap()
            .unwrap();
        assert_eq!(identity.uid, 0);
        assert_eq!(identity.gid, 0);
        assert!(identity.additional_gids.is_empty());
    }

    #[test]
    fn test_resolve_process_identity_numeric_user_requires_group() {
        let err = resolve_process_identity(Some("1000"), None, &[]).unwrap_err();
        assert!(err.to_string().contains("explicit --group"));
    }

    #[test]
    fn test_resolve_process_identity_deduplicates_additional_groups() {
        let identity = resolve_process_identity(
            Some("123"),
            Some("456"),
            &["456".to_string(), "789".to_string(), "789".to_string()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.uid, 123);
        assert_eq!(identity.gid, 456);
        assert_eq!(identity.additional_gids, vec![789]);
    }
}
