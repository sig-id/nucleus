use crate::container::{ContainerConfig, SeccompMode, WorkspaceMode};
use crate::error::{NucleusError, Result};
use crate::network::NetworkMode;
use crate::resources::{ResourceLimits, ResourceStats};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the tracing subscriber with env-filter.
///
/// RUST_LOG is respected but capped at `debug` to prevent `trace`-level
/// output from leaking sensitive runtime data (syscall args, memory
/// contents, etc.) in production.
pub fn init_tracing(log: Option<&Path>, log_format: &str) -> Result<()> {
    let env_filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info")
            .add_directive("nucleus=debug".parse().expect("valid tracing directive")),
    };
    let writer = log_writer(log)?;

    match log_format {
        "text" => tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(writer))
            .with(env_filter)
            .with(tracing_subscriber::filter::LevelFilter::DEBUG)
            .try_init(),
        "json" => tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().json().with_writer(writer))
            .with(env_filter)
            .with(tracing_subscriber::filter::LevelFilter::DEBUG)
            .try_init(),
        other => {
            return Err(NucleusError::ConfigError(format!(
                "Unsupported --log-format '{}'; expected text or json",
                other
            )));
        }
    }
    .map_err(|e| NucleusError::ConfigError(format!("Failed to initialize telemetry: {}", e)))
}

fn log_writer(log: Option<&Path>) -> Result<SharedMakeWriter> {
    let file = match log {
        Some(path) => open_append_file(path).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to open log file {:?}: {}", path, e))
        })?,
        None => open_stderr_duplicate().map_err(|e| {
            NucleusError::ConfigError(format!("Failed to duplicate stderr for logging: {}", e))
        })?,
    };
    Ok(SharedMakeWriter::new(file))
}

fn open_append_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
}

fn open_truncated_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
}

fn open_stderr_duplicate() -> io::Result<File> {
    // SAFETY: dup returns a new owned file descriptor for stderr on success.
    let fd = unsafe { libc::dup(libc::STDERR_FILENO) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    set_cloexec(fd)?;
    // SAFETY: fd was returned by dup and is now owned by File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFD/F_SETFD does not violate memory safety.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Clone)]
struct SharedMakeWriter {
    file: Arc<Mutex<File>>,
}

impl SharedMakeWriter {
    fn new(file: File) -> Self {
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }
}

struct SharedWriter {
    file: Arc<Mutex<File>>,
}

impl<'a> MakeWriter<'a> for SharedMakeWriter {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriter {
            file: self.file.clone(),
        }
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?
            .flush()
    }
}

/// JSON Lines sink for machine-readable control-plane events.
#[derive(Clone, Debug)]
pub struct EventSink {
    file: Arc<Mutex<File>>,
}

impl EventSink {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = open_truncated_file(path).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to open event stream {:?}: {}", path, e))
        })?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn from_fd(fd: RawFd) -> Result<Self> {
        if fd <= libc::STDERR_FILENO {
            return Err(NucleusError::ConfigError(format!(
                "--events-fd must be greater than 2 to keep control events separate from stdio, got {}",
                fd
            )));
        }
        set_cloexec(fd).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to set close-on-exec on event stream fd {}: {}",
                fd, e
            ))
        })?;
        // SAFETY: The caller transfers ownership of this inherited fd to Nucleus.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn from_cli(events_fd: Option<RawFd>, events_jsonl: Option<&Path>) -> Result<Option<Self>> {
        match (events_fd, events_jsonl) {
            (Some(_), Some(_)) => Err(NucleusError::ConfigError(
                "--events-fd and --events-jsonl are mutually exclusive".to_string(),
            )),
            (Some(fd), None) => Self::from_fd(fd).map(Some),
            (None, Some(path)) => Self::from_path(path).map(Some),
            (None, None) => Ok(None),
        }
    }

    pub fn emit<T: Serialize>(&self, event: &T) -> Result<()> {
        let mut guard = self.file.lock().map_err(|_| {
            NucleusError::ConfigError("Event stream writer mutex poisoned".to_string())
        })?;
        serde_json::to_writer(&mut *guard, event).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to serialize event stream record: {}", e))
        })?;
        guard.write_all(b"\n").map_err(|e| {
            NucleusError::ConfigError(format!("Failed to write event stream record: {}", e))
        })?;
        guard.flush().map_err(|e| {
            NucleusError::ConfigError(format!("Failed to flush event stream record: {}", e))
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlEventType {
    ContainerStarted,
    ContainerSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerControlEvent {
    pub timestamp_unix_ms: u128,
    #[serde(rename = "type")]
    pub event_type: ControlEventType,
    pub container: ContainerEventMetadata,
    pub security: SecurityEventMetadata,
    pub resource_limits: ResourceLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<ExitStatusEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_stats: Option<ResourceStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_stats_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupEvent>,
}

impl ContainerControlEvent {
    pub fn started(config: &ContainerConfig, pid: u32, cgroup_path: Option<String>) -> Self {
        Self::new(ControlEventType::ContainerStarted, config, pid, cgroup_path)
    }

    pub fn summary(
        config: &ContainerConfig,
        pid: u32,
        cgroup_path: Option<String>,
        exit_status: ExitStatusEvent,
        resource_stats: Option<ResourceStats>,
        resource_stats_error: Option<String>,
        cleanup: CleanupEvent,
    ) -> Self {
        let mut event = Self::new(ControlEventType::ContainerSummary, config, pid, cgroup_path);
        event.exit_status = Some(exit_status);
        event.resource_stats = resource_stats;
        event.resource_stats_error = resource_stats_error;
        event.cleanup = Some(cleanup);
        event
    }

    fn new(
        event_type: ControlEventType,
        config: &ContainerConfig,
        pid: u32,
        cgroup_path: Option<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            event_type,
            container: ContainerEventMetadata::from_config(config, pid, cgroup_path),
            security: SecurityEventMetadata::from_config(config),
            resource_limits: config.limits.clone(),
            exit_status: None,
            resource_stats: None,
            resource_stats_error: None,
            cleanup: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerEventMetadata {
    pub id: String,
    pub name: String,
    pub pid: u32,
    pub runtime: String,
    pub cgroup_path: Option<String>,
    pub workspace_mount: Option<WorkspaceMountEvent>,
    pub network_mode: String,
}

impl ContainerEventMetadata {
    fn from_config(config: &ContainerConfig, pid: u32, cgroup_path: Option<String>) -> Self {
        Self {
            id: config.id.clone(),
            name: config.name.clone(),
            pid,
            runtime: if config.use_gvisor {
                "gvisor".to_string()
            } else {
                "native".to_string()
            },
            cgroup_path,
            workspace_mount: config.workspace.effective_host_path().map(|source| {
                WorkspaceMountEvent {
                    source: source.display().to_string(),
                    destination: config.workspace.container_path.display().to_string(),
                    mode: workspace_mode_label(config.workspace.mode).to_string(),
                    allow_execute: config.workspace.allow_execute,
                }
            }),
            network_mode: network_mode_label(&config.network).to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceMountEvent {
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub allow_execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventMetadata {
    pub seccomp_mode: String,
    pub landlock_status: String,
    pub capabilities_status: String,
    pub rootless: bool,
    pub allow_degraded_security: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuEventSummary>,
}

/// GPU passthrough summary emitted in the container started/summary events.
#[derive(Debug, Clone, Serialize)]
pub struct GpuEventSummary {
    pub vendor: String,
    pub visible_devices: String,
    pub driver_capabilities: String,
    pub bind_driver_libraries: bool,
    /// Whether the seccomp ioctl filter was relaxed for GPU driver ioctls.
    pub relaxed_seccomp_ioctl: bool,
}

impl SecurityEventMetadata {
    fn from_config(config: &ContainerConfig) -> Self {
        let gpu = config.gpu.as_ref().map(|g| GpuEventSummary {
            vendor: format!("{:?}", g.vendor).to_lowercase(),
            visible_devices: g.visible_devices.clone(),
            driver_capabilities: g.driver_capabilities.clone(),
            bind_driver_libraries: g.bind_driver_libraries,
            relaxed_seccomp_ioctl: true,
        });
        Self {
            seccomp_mode: seccomp_mode_label(config),
            landlock_status: landlock_status_label(config),
            capabilities_status: capabilities_status_label(config),
            rootless: config.user_ns_config.is_some(),
            allow_degraded_security: config.allow_degraded_security,
            gpu,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExitStatusEvent {
    pub code: Option<i32>,
    pub error: Option<String>,
}

impl ExitStatusEvent {
    pub fn code(code: i32) -> Self {
        Self {
            code: Some(code),
            error: None,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            code: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupEvent {
    pub succeeded: bool,
    pub errors: Vec<String>,
}

impl CleanupEvent {
    pub fn from_errors(errors: Vec<String>) -> Self {
        Self {
            succeeded: errors.is_empty(),
            errors,
        }
    }
}

fn network_mode_label(mode: &NetworkMode) -> &'static str {
    match mode {
        NetworkMode::None => "none",
        NetworkMode::Host => "host",
        NetworkMode::GVisorHost => "gvisor-host",
        NetworkMode::Bridge(_) => "bridge",
    }
}

fn workspace_mode_label(mode: WorkspaceMode) -> &'static str {
    match mode {
        WorkspaceMode::BindRw => "bind-rw",
        WorkspaceMode::BindRo => "bind-ro",
        WorkspaceMode::CopyInOut => "copy-in-out",
    }
}

fn seccomp_mode_label(config: &ContainerConfig) -> String {
    match config.seccomp_mode {
        SeccompMode::Trace => "trace".to_string(),
        SeccompMode::Enforce if config.seccomp_profile.is_some() => "profile".to_string(),
        SeccompMode::Enforce => "enforce".to_string(),
    }
}

fn landlock_status_label(config: &ContainerConfig) -> String {
    if config.use_gvisor {
        "managed_by_gvisor".to_string()
    } else if config.landlock_policy.is_some() {
        "policy_file".to_string()
    } else {
        "default_policy".to_string()
    }
}

fn capabilities_status_label(config: &ContainerConfig) -> String {
    if config.use_gvisor {
        "managed_by_gvisor".to_string()
    } else if config.caps_policy.is_some() {
        "policy_file".to_string()
    } else {
        "drop_all".to_string()
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_fd_rejects_stdio_descriptors() {
        assert!(EventSink::from_cli(Some(1), None).is_err());
        assert!(EventSink::from_cli(Some(2), None).is_err());
    }

    #[test]
    fn events_cli_rejects_multiple_destinations() {
        let err = EventSink::from_cli(Some(3), Some(Path::new("/tmp/events.jsonl"))).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn control_event_contains_required_runtime_fields() {
        let workspace = crate::container::WorkspaceConfig::new()
            .with_host_path(Path::new("/workspace-src").to_path_buf())
            .with_mode(WorkspaceMode::BindRo)
            .with_allow_execute(true);
        let mut config = ContainerConfig::try_new_with_id(
            Some("0123456789abcdef0123456789abcdef".to_string()),
            Some("demo".to_string()),
            vec!["/bin/true".to_string()],
        )
        .unwrap()
        .with_gvisor(false)
        .with_workspace(workspace);
        config.seccomp_mode = SeccompMode::Enforce;

        let event = ContainerControlEvent::started(
            &config,
            1234,
            Some("/sys/fs/cgroup/nucleus-demo".to_string()),
        );
        let value = serde_json::to_value(event).unwrap();

        assert_eq!(value["type"], "container_started");
        assert_eq!(value["container"]["id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(value["container"]["pid"], 1234);
        assert_eq!(value["container"]["network_mode"], "none");
        assert_eq!(
            value["container"]["cgroup_path"],
            "/sys/fs/cgroup/nucleus-demo"
        );
        assert_eq!(
            value["container"]["workspace_mount"]["destination"],
            "/workspace"
        );
        assert_eq!(value["container"]["workspace_mount"]["mode"], "bind-ro");
        assert_eq!(value["container"]["workspace_mount"]["allow_execute"], true);
        assert_eq!(value["security"]["seccomp_mode"], "enforce");
        assert_eq!(value["security"]["landlock_status"], "default_policy");
        assert_eq!(value["security"]["capabilities_status"], "drop_all");
        assert!(value.get("resource_limits").is_some());
    }
}
