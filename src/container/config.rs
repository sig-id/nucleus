use crate::filesystem::{
    normalize_container_destination, normalize_provider_config_destination,
    normalize_volume_destination, validate_production_rootfs_path, validate_provider_config_source,
    validate_workspace_host_path,
};
use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::network::{CredentialBrokerConfig, EgressPolicy};
use crate::resources::ResourceLimits;
use crate::security::GVisorPlatform;
use std::fs::OpenOptions;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_HOME_PATH: &str = "/home/agent";
pub const CREDENTIAL_BROKER_CONTAINER_ID_ENV: &str = "NUCLEUS_CONTAINER_ID";
pub const CREDENTIAL_BROKER_TOKEN_ENV: &str = "NUCLEUS_CREDENTIAL_BROKER_TOKEN";

#[must_use]
fn is_credential_broker_identity_env(key: &str) -> bool {
    key == CREDENTIAL_BROKER_CONTAINER_ID_ENV || key == CREDENTIAL_BROKER_TOKEN_ENV
}

fn open_dev_urandom() -> crate::error::Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .map_err(|e| {
            crate::error::NucleusError::ConfigError(format!(
                "Failed to open /dev/urandom for container ID generation: {}",
                e
            ))
        })?;

    let metadata = file.metadata().map_err(|e| {
        crate::error::NucleusError::ConfigError(format!("Failed to stat /dev/urandom: {}", e))
    })?;
    if !metadata.file_type().is_char_device() {
        return Err(crate::error::NucleusError::ConfigError(
            "/dev/urandom is not a character device".to_string(),
        ));
    }

    Ok(file)
}

/// Generate a unique 32-hex-char container ID (128-bit) using /dev/urandom.
pub fn generate_container_id() -> crate::error::Result<String> {
    use std::io::Read;

    let mut buf = [0u8; 16];
    let mut file = open_dev_urandom()?;
    file.read_exact(&mut buf).map_err(|e| {
        crate::error::NucleusError::ConfigError(format!(
            "Failed to read secure random bytes for container ID generation: {}",
            e
        ))
    })?;
    Ok(hex::encode(buf))
}

/// Trust level for a container workload.
///
/// Determines the minimum isolation guarantees the runtime must enforce.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Native kernel isolation (namespaces + seccomp + Landlock) is acceptable.
    Trusted,
    /// Requires gVisor; refuses to start without it unless degraded mode is allowed.
    #[default]
    Untrusted,
}

/// Service mode for the container.
///
/// Determines whether the container runs as an ephemeral agent sandbox,
/// a fail-closed agent sandbox, or a long-running production service.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    /// Ephemeral agent workload (default). Allows degraded fallbacks.
    #[default]
    Agent,
    /// Ephemeral agent workload with fail-closed isolation, but without
    /// production service rootfs, health, sd_notify, or NixOS semantics.
    #[value(name = "strict-agent", alias = "mitos-agent")]
    #[serde(alias = "mitos-agent")]
    StrictAgent,
    /// Long-running production service. Enforces strict security invariants:
    /// - Forbids degraded security, chroot fallback, and native host network mode
    /// - Allows gvisor-host only with explicit gVisor runtime and hostinet opt-in
    /// - Requires cgroup resource limits
    /// - Requires pivot_root (no chroot fallback)
    /// - Requires explicit rootfs path (no host bind mounts)
    Production,
}

impl ServiceMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Agent => "Agent mode",
            Self::StrictAgent => "Strict agent mode",
            Self::Production => "Production mode",
        }
    }

    pub fn enforces_strict_isolation(self) -> bool {
        matches!(self, Self::StrictAgent | Self::Production)
    }

    pub fn requires_user_namespace_mapping(self) -> bool {
        self.enforces_strict_isolation()
    }

    pub fn requires_cgroup_enforcement(self) -> bool {
        self.enforces_strict_isolation()
    }

    pub fn requires_explicit_bridge_dns(self) -> bool {
        self.enforces_strict_isolation()
    }
}

/// CLI-level runtime selection.
///
/// Parsed by clap at argument time – invalid values are caught immediately.
/// The variant triggers additional logic in `apply_runtime_selection`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum RuntimeSelection {
    /// gVisor sandbox runtime (default). Provides kernel-level isolation.
    #[default]
    #[value(name = "gvisor")]
    #[serde(rename = "gvisor")]
    GVisor,
    /// Native kernel isolation (namespaces + seccomp + Landlock).
    #[value(name = "native")]
    #[serde(rename = "native")]
    Native,
}

/// CLI-level network mode selection.
///
/// Parsed by clap at argument time. The `bridge` variant carries additional
/// configuration that is attached after parsing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
pub enum NetworkModeArg {
    /// No network (default).
    #[value(name = "none")]
    #[serde(rename = "none")]
    None,
    /// Native host network namespace sharing (dangerous).
    #[value(name = "host")]
    #[serde(rename = "host")]
    Host,
    /// gVisor hostinet mode; requires --runtime gvisor and --allow-host-network.
    #[value(name = "gvisor-host")]
    #[serde(rename = "gvisor-host")]
    GVisorHost,
    /// Virtual bridge with veth pair.
    #[value(name = "bridge")]
    #[serde(rename = "bridge")]
    Bridge,
}

impl Default for NetworkModeArg {
    fn default() -> Self {
        Self::None
    }
}

/// Required host kernel lockdown mode, when asserted by the runtime.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum KernelLockdownMode {
    /// Integrity mode blocks kernel writes from privileged userspace.
    Integrity,
    /// Confidentiality mode additionally blocks kernel data disclosure paths.
    Confidentiality,
}

impl KernelLockdownMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Confidentiality => "confidentiality",
        }
    }

    pub fn accepts(self, active: Self) -> bool {
        match self {
            Self::Integrity => matches!(active, Self::Integrity | Self::Confidentiality),
            Self::Confidentiality => matches!(active, Self::Confidentiality),
        }
    }
}

/// Health check configuration for long-running services.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Command to run inside the container to check health.
    pub command: Vec<String>,
    /// Interval between health checks.
    pub interval: Duration,
    /// Number of consecutive failures before marking unhealthy.
    pub retries: u32,
    /// Grace period after start before health checks begin.
    pub start_period: Duration,
    /// Timeout for each health check execution.
    pub timeout: Duration,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            interval: Duration::from_secs(30),
            retries: 3,
            start_period: Duration::from_secs(5),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Secrets configuration for mounting secret files into the container.
#[derive(Debug, Clone)]
pub struct SecretMount {
    /// Source path on the host (or Nix store path).
    pub source: PathBuf,
    /// Destination path inside the container.
    pub dest: PathBuf,
    /// File mode (default: 0o400, read-only by owner).
    pub mode: u32,
}

/// Provider CLI credential/config bind mount under the sandbox home.
#[derive(Debug, Clone)]
pub struct ProviderConfigMount {
    /// Source path on the host.
    pub source: PathBuf,
    /// Destination path inside the container home.
    pub dest: PathBuf,
    /// Whether the provider config is mounted read-only.
    pub read_only: bool,
}

/// Runtime identity for the workload process inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Primary user ID for the workload process.
    pub uid: u32,
    /// Primary group ID for the workload process.
    pub gid: u32,
    /// Supplementary group IDs for the workload process.
    pub additional_gids: Vec<u32>,
}

impl ProcessIdentity {
    /// Root identity (the historical default).
    pub fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
        }
    }

    /// Returns true when the workload keeps the default root identity.
    pub fn is_root(&self) -> bool {
        self.uid == 0 && self.gid == 0 && self.additional_gids.is_empty()
    }
}

impl Default for ProcessIdentity {
    fn default() -> Self {
        Self::root()
    }
}

/// Terminal dimensions for PTY-backed workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleSize {
    /// Width in terminal columns.
    pub width: u16,
    /// Height in terminal rows.
    pub height: u16,
}

impl ConsoleSize {
    pub const DEFAULT_WIDTH: u16 = 80;
    pub const DEFAULT_HEIGHT: u16 = 24;

    /// Detect the caller's terminal size, falling back to COLUMNS/LINES and
    /// finally 80x24 when no terminal is attached.
    pub fn detect() -> Self {
        Self::from_fd(libc::STDIN_FILENO)
            .or_else(Self::from_env)
            .unwrap_or_default()
    }

    fn from_fd(fd: RawFd) -> Option<Self> {
        let mut winsize = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsize) };
        if ret == 0 && winsize.ws_col > 0 && winsize.ws_row > 0 {
            Some(Self {
                width: winsize.ws_col,
                height: winsize.ws_row,
            })
        } else {
            None
        }
    }

    fn from_env() -> Option<Self> {
        let width = std::env::var("COLUMNS").ok()?.parse::<u16>().ok()?;
        let height = std::env::var("LINES").ok()?.parse::<u16>().ok()?;
        if width > 0 && height > 0 {
            Some(Self { width, height })
        } else {
            None
        }
    }
}

impl Default for ConsoleSize {
    fn default() -> Self {
        Self {
            width: Self::DEFAULT_WIDTH,
            height: Self::DEFAULT_HEIGHT,
        }
    }
}

/// Source backing for a volume mount.
#[derive(Debug, Clone)]
pub enum VolumeSource {
    /// Bind mount a host path into the container.
    Bind { source: PathBuf },
    /// Mount a fresh tmpfs at the destination.
    Tmpfs { size: Option<String> },
}

/// Volume configuration for mounting persistent or ephemeral storage.
#[derive(Debug, Clone)]
pub struct VolumeMount {
    /// Backing storage for the volume.
    pub source: VolumeSource,
    /// Destination path inside the container.
    pub dest: PathBuf,
    /// Whether the volume is mounted read-only.
    pub read_only: bool,
}

/// How a pre-built rootfs is exposed inside the container.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum RootfsMode {
    /// Bind-mount the rootfs read-only, preserving the historical behavior.
    #[default]
    Bind,
    /// Mount the rootfs through overlayfs with a persistent upperdir.
    Overlay,
}

/// Host-side overlayfs paths for a writable rootfs.
#[derive(Debug, Clone)]
pub struct RootfsOverlayConfig {
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
}

/// How a host workspace is exposed at `/workspace`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceMode {
    /// Bind mount the host workspace read-write.
    #[default]
    #[value(name = "bind-rw")]
    BindRw,
    /// Bind mount the host workspace read-only.
    #[value(name = "bind-ro")]
    BindRo,
    /// Copy the host workspace into a private stage and sync it back after exit.
    #[value(name = "copy-in-out")]
    CopyInOut,
}

/// First-class workspace mount configuration.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Source path on the host. `None` means no host workspace is mounted, but
    /// `/workspace` still exists as the default cwd.
    pub host_path: Option<PathBuf>,
    /// Destination inside the container. Currently fixed to `/workspace`.
    pub container_path: PathBuf,
    /// Exposure mode for `host_path`.
    pub mode: WorkspaceMode,
    /// Whether execution from the workspace is allowed.
    pub allow_execute: bool,
    /// Private staging directory used for copy-in-out mode.
    pub staging_path: Option<PathBuf>,
}

impl WorkspaceConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_host_path(mut self, host_path: PathBuf) -> Self {
        self.host_path = Some(host_path);
        self
    }

    pub fn with_mode(mut self, mode: WorkspaceMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_allow_execute(mut self, allow_execute: bool) -> Self {
        self.allow_execute = allow_execute;
        self
    }

    pub fn with_staging_path(mut self, staging_path: PathBuf) -> Self {
        self.staging_path = Some(staging_path);
        self
    }

    pub fn is_read_only(&self) -> bool {
        matches!(self.mode, WorkspaceMode::BindRo)
    }

    pub fn is_writable(&self) -> bool {
        !self.is_read_only()
    }

    pub fn effective_host_path(&self) -> Option<&PathBuf> {
        if self.mode == WorkspaceMode::CopyInOut {
            self.staging_path.as_ref()
        } else {
            self.host_path.as_ref()
        }
    }
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            host_path: None,
            container_path: PathBuf::from("/workspace"),
            mode: WorkspaceMode::default(),
            allow_execute: false,
            staging_path: None,
        }
    }
}

/// Readiness probe configuration.
#[derive(Debug, Clone)]
pub enum ReadinessProbe {
    /// Run a command; ready when it exits 0.
    Exec { command: Vec<String> },
    /// Check TCP port connectivity.
    TcpPort(u16),
    /// Use sd_notify protocol (service sends READY=1).
    SdNotify,
}

/// GPU vendor to expose to the container.
///
/// `Auto` scans the host and exposes whatever is present. The explicit
/// variants restrict passthrough to a single stack. `All` binds every
/// recognized GPU device node on the host regardless of vendor.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]#[serde(rename_all = "kebab-case")]
pub enum GpuVendor {
    /// Discover and bind whatever GPU devices are present on the host.
    #[default]
    Auto,
    /// NVIDIA (CUDA): `/dev/nvidia*`, `/dev/nvidia-uvm*`, `/dev/nvidiactl`.
    Nvidia,
    /// AMD ROCm: `/dev/kfd` plus DRI render nodes.
    Amd,
    /// Intel / Mesa: DRI render and card nodes.
    Intel,
    /// Bind every recognized GPU device node on the host.
    All,
}

impl GpuVendor {
    /// Returns `true` when this selection can bind NVIDIA device nodes.
    pub fn includes_nvidia(self) -> bool {
        matches!(self, Self::Auto | Self::Nvidia | Self::All)
    }

    /// Returns `true` when this selection can bind AMD (ROCm) device nodes.
    pub fn includes_amd(self) -> bool {
        matches!(self, Self::Auto | Self::Amd | Self::All)
    }

    /// Returns `true` when this selection can bind Intel/Mesa DRI nodes.
    pub fn includes_intel(self) -> bool {
        matches!(self, Self::Auto | Self::Intel | Self::All)
    }
}

/// Default NVIDIA driver capability set exposed to the workload.
///
/// Matches the NVIDIA Container Toolkit default: compute + utility is enough
/// for `nvidia-smi` and CUDA compute workloads without pulling in display,
/// video, or graphics stacks that widen the device surface.
pub const DEFAULT_GPU_DRIVER_CAPABILITIES: &str = "compute,utility";

/// Default value for `NVIDIA_VISIBLE_DEVICES` when passthrough is enabled.
pub const DEFAULT_GPU_VISIBLE_DEVICES: &str = "all";

/// GPU passthrough configuration.
///
/// When present on a `ContainerConfig`, the runtime binds the selected GPU
/// device nodes (and the minimal driver support files they need) into the
/// container, installs a cgroup device allowlist, and relaxes the seccomp
/// `ioctl` filter so vendor driver ioctls reach the hardware.
///
/// See `spec/gpu-passthrough.md` for the full design.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpuPassthroughConfig {
    /// Vendor selection controlling device discovery.
    #[serde(default)]
    pub vendor: GpuVendor,
    /// Explicit device node overrides. When non-empty, discovery is skipped
    /// and exactly these host paths are bound (after validation).
    #[serde(default)]
    pub devices: Vec<PathBuf>,
    /// Value for `NVIDIA_DRIVER_CAPABILITIES`. Defaults to
    /// [`DEFAULT_GPU_DRIVER_CAPABILITIES`].
    pub driver_capabilities: String,
    /// Value for `NVIDIA_VISIBLE_DEVICES`. Defaults to
    /// [`DEFAULT_GPU_VISIBLE_DEVICES`].
    pub visible_devices: String,
    /// Attempt to bind host driver userspace libraries (NVIDIA toolkit /
    /// ROCm). Set `false` when the container rootfs ships its own stack.
    #[serde(default = "default_bind_driver_libraries")]
    pub bind_driver_libraries: bool,
}

fn default_bind_driver_libraries() -> bool {
    true
}

impl Default for GpuPassthroughConfig {
    fn default() -> Self {
        Self {
            vendor: GpuVendor::Auto,
            devices: Vec::new(),
            driver_capabilities: DEFAULT_GPU_DRIVER_CAPABILITIES.to_string(),
            visible_devices: DEFAULT_GPU_VISIBLE_DEVICES.to_string(),
            bind_driver_libraries: true,
        }
    }
}

impl GpuPassthroughConfig {
    /// Returns `true` if passthrough is active (always true for this type;
    /// presence of the `Option<GpuPassthroughConfig>` is the real switch).
    pub fn is_enabled(&self) -> bool {
        true
    }
}

/// Environment variables a GPU-enabled workload expects.
///
/// These are launch-derived from [`GpuPassthroughConfig`] and injected at
/// exec time (and into the gVisor OCI process env). They are intentionally
/// minimal: `NVIDIA_VISIBLE_DEVICES`, `NVIDIA_DRIVER_CAPABILITIES`, and the
/// EGL vendor manifest pointer that lets Mesa find the bound host driver.
pub fn gpu_environment(gpu: &GpuPassthroughConfig) -> Vec<(&'static str, String)> {
    let mut env = vec![
        ("NVIDIA_VISIBLE_DEVICES", gpu.visible_devices.clone()),
        ("NVIDIA_DRIVER_CAPABILITIES", gpu.driver_capabilities.clone()),
    ];
    if gpu.vendor.includes_nvidia() {
        env.push((
            "__EGL_VENDOR_LIBRARY_FILENAMES",
            "/usr/share/glvnd/egl_vendor.d/10_nvidia.json".to_string(),
        ));
    }
    env
}

/// Container configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Unique container ID (auto-generated 32 hex chars, 128-bit)
    pub id: String,

    /// User-supplied container name (optional, defaults to ID)
    pub name: String,

    /// Command to execute in the container
    pub command: Vec<String>,

    /// Context directory to pre-populate (optional)
    pub context_dir: Option<PathBuf>,

    /// Resource limits
    pub limits: ResourceLimits,

    /// Namespace configuration
    pub namespaces: NamespaceConfig,

    /// User namespace configuration (for rootless mode)
    pub user_ns_config: Option<UserNamespaceConfig>,

    /// Hostname to set in UTS namespace (optional)
    pub hostname: Option<String>,

    /// Whether to use gVisor runtime
    pub use_gvisor: bool,

    /// Trust level for this workload
    pub trust_level: TrustLevel,

    /// Network mode
    pub network: crate::network::NetworkMode,

    /// Context mode (copy or bind mount)
    pub context_mode: crate::filesystem::ContextMode,

    /// Allow degraded security behavior if a hardening layer cannot be applied
    pub allow_degraded_security: bool,

    /// Allow chroot fallback when pivot_root fails (weaker isolation)
    pub allow_chroot_fallback: bool,

    /// Require explicit opt-in for host networking
    pub allow_host_network: bool,

    /// Mount /proc read-only inside the container
    pub proc_readonly: bool,

    /// Service mode (agent vs production)
    pub service_mode: ServiceMode,

    /// Pre-built rootfs path (Nix store path). When set, this is bind-mounted
    /// as the container root instead of bind-mounting host /bin, /usr, /lib, etc.
    pub rootfs_path: Option<PathBuf>,

    /// Mount mode for `rootfs_path`.
    pub rootfs_mode: RootfsMode,

    /// Prepared overlayfs upper/work directories. Normally populated by the
    /// runtime; image run may pre-seed it from an image diff.
    pub rootfs_overlay: Option<RootfsOverlayConfig>,

    /// Egress policy for audited outbound network access.
    pub egress_policy: Option<EgressPolicy>,

    /// Host-side credential broker that is the sandbox's only allowed
    /// authenticated egress path.
    pub credential_broker: Option<CredentialBrokerConfig>,

    /// Random per-container token surfaced to brokered workloads so the
    /// host-side broker can authenticate and attribute requests.
    pub credential_broker_token: String,

    /// Health check configuration for long-running services.
    pub health_check: Option<HealthCheck>,

    /// Readiness probe for service startup detection.
    pub readiness_probe: Option<ReadinessProbe>,

    /// Secret files to mount into the container.
    pub secrets: Vec<SecretMount>,

    /// Volume mounts to attach to the container filesystem.
    pub volumes: Vec<VolumeMount>,

    /// First-class workspace mount/staging configuration.
    pub workspace: WorkspaceConfig,

    /// Private home directory mounted as tmpfs for provider CLIs.
    pub home: PathBuf,

    /// Provider CLI credential/config mounts under `home`.
    pub provider_configs: Vec<ProviderConfigMount>,

    /// Working directory for the workload process.
    pub workdir: PathBuf,

    /// Environment variables to pass to the container process.
    pub environment: Vec<(String, String)>,

    /// Launch-derived environment variables applied at exec time but excluded
    /// from `ContainerState` capture and `image commit` manifests.
    ///
    /// This carries values that are derived from other launch config (e.g.
    /// credential-broker proxy env, per-container broker identity) and must
    /// not be baked into portable artifacts. The workload still observes
    /// them at runtime via the same exec-time env vector as `environment`.
    pub derived_environment: Vec<(String, String)>,

    /// Runtime uid/gid and supplementary groups for the workload process.
    pub process_identity: ProcessIdentity,

    /// Desired topology config hash for reconciliation change detection.
    pub config_hash: Option<u64>,

    /// Enable sd_notify integration (pass NOTIFY_SOCKET into container).
    pub sd_notify: bool,

    /// Require the host kernel to be in at least this lockdown mode.
    pub required_kernel_lockdown: Option<KernelLockdownMode>,

    /// Verify context contents before executing the workload.
    pub verify_context_integrity: bool,

    /// Verify rootfs attestation manifest before mounting it.
    pub verify_rootfs_attestation: bool,

    /// Request kernel logging for denied seccomp decisions when supported.
    pub seccomp_log_denied: bool,

    /// Select the gVisor platform backend.
    pub gvisor_platform: GVisorPlatform,

    /// Path to a per-service seccomp profile (JSON, OCI subset format).
    /// When set, this profile is used instead of the built-in allowlist.
    pub seccomp_profile: Option<PathBuf>,

    /// Expected SHA-256 hash of the seccomp profile file for integrity verification.
    pub seccomp_profile_sha256: Option<String>,

    /// Seccomp operating mode.
    pub seccomp_mode: SeccompMode,

    /// Path to write seccomp trace log (NDJSON) when seccomp_mode == Trace.
    pub seccomp_trace_log: Option<PathBuf>,

    /// Additional syscalls to allow beyond the built-in default allowlist.
    /// Each entry is a syscall name (e.g. "io_uring_setup", "sysinfo").
    /// These are merged into the built-in filter; they do NOT replace it.
    pub seccomp_allow_syscalls: Vec<String>,

    /// Path to capability policy file (TOML).
    pub caps_policy: Option<PathBuf>,

    /// Expected SHA-256 hash of the capability policy file.
    pub caps_policy_sha256: Option<String>,

    /// Path to Landlock policy file (TOML).
    pub landlock_policy: Option<PathBuf>,

    /// Expected SHA-256 hash of the Landlock policy file.
    pub landlock_policy_sha256: Option<String>,

    /// OCI lifecycle hooks to execute at various container lifecycle points.
    pub hooks: Option<crate::security::OciHooks>,

    /// Path to write the container PID (OCI --pid-file).
    pub pid_file: Option<PathBuf>,

    /// Path to AF_UNIX socket for console pseudo-terminal master (OCI --console-socket).
    pub console_socket: Option<PathBuf>,

    /// Run the workload behind a PTY and make it a terminal-attached process.
    pub terminal: bool,

    /// Initial PTY window size.
    pub console_size: ConsoleSize,

    /// Override OCI bundle directory path (OCI --bundle).
    pub bundle_dir: Option<PathBuf>,

    /// Override root directory for state storage (--root).
    /// When set, ContainerStateManager uses this instead of the default.
    pub state_root: Option<PathBuf>,

    /// GPU passthrough configuration. When set, selected host GPU device nodes
    /// and their minimal driver support files are bound into the container,
    /// a cgroup device allowlist is installed, and the seccomp `ioctl` filter
    /// is relaxed for vendor driver ioctls. See `spec/gpu-passthrough.md`.
    pub gpu: Option<GpuPassthroughConfig>,
}

/// Seccomp operating mode.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompMode {
    /// Normal enforcement – deny unlisted syscalls.
    #[default]
    Enforce,
    /// Trace mode – allow all syscalls but log them for profile generation.
    /// Development only; rejected in production mode.
    Trace,
}

impl ContainerConfig {
    /// Create a new container config with a random ID.
    ///
    /// # Panics
    /// Panics if secure random bytes cannot be read from `/dev/urandom`.
    pub fn try_new(name: Option<String>, command: Vec<String>) -> crate::error::Result<Self> {
        Self::try_new_with_id(None, name, command)
    }

    /// Create a new container config, optionally using a pre-generated ID.
    ///
    /// When `preset_id` is `Some`, it is used as the container ID instead of
    /// generating a new one. This is used by `--detach` to ensure the outer
    /// CLI process and the systemd-managed inner process share the same ID.
    pub fn try_new_with_id(
        preset_id: Option<String>,
        name: Option<String>,
        command: Vec<String>,
    ) -> crate::error::Result<Self> {
        let id = match preset_id {
            Some(id) => {
                // Validate preset ID: must be exactly 32 hex chars
                if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(crate::error::NucleusError::ConfigError(format!(
                        "Invalid preset container ID '{}': must be 32 hex characters",
                        id
                    )));
                }
                id
            }
            None => generate_container_id()?,
        };
        let credential_broker_token = generate_container_id()?;
        let name = name.unwrap_or_else(|| id.clone());
        Ok(Self {
            id,
            name: name.clone(),
            command,
            context_dir: None,
            limits: ResourceLimits::default(),
            namespaces: NamespaceConfig::default(),
            user_ns_config: None,
            hostname: Some(name),
            use_gvisor: true,
            trust_level: TrustLevel::default(),
            network: crate::network::NetworkMode::None,
            context_mode: crate::filesystem::ContextMode::Copy,
            allow_degraded_security: false,
            allow_chroot_fallback: false,
            allow_host_network: false,
            proc_readonly: true,
            service_mode: ServiceMode::default(),
            rootfs_path: None,
            rootfs_mode: RootfsMode::default(),
            rootfs_overlay: None,
            egress_policy: None,
            credential_broker: None,
            credential_broker_token,
            health_check: None,
            readiness_probe: None,
            secrets: Vec::new(),
            volumes: Vec::new(),
            workspace: WorkspaceConfig::default(),
            home: PathBuf::from(DEFAULT_HOME_PATH),
            provider_configs: Vec::new(),
            workdir: PathBuf::from("/workspace"),
            environment: Vec::new(),
            derived_environment: Vec::new(),
            process_identity: ProcessIdentity::default(),
            config_hash: None,
            sd_notify: false,
            required_kernel_lockdown: None,
            verify_context_integrity: false,
            verify_rootfs_attestation: false,
            seccomp_log_denied: false,
            gvisor_platform: GVisorPlatform::default(),
            seccomp_profile: None,
            seccomp_profile_sha256: None,
            seccomp_mode: SeccompMode::default(),
            seccomp_trace_log: None,
            seccomp_allow_syscalls: Vec::new(),
            caps_policy: None,
            caps_policy_sha256: None,
            landlock_policy: None,
            landlock_policy_sha256: None,
            hooks: None,
            pid_file: None,
            console_socket: None,
            terminal: false,
            console_size: ConsoleSize::default(),
            bundle_dir: None,
            state_root: None,
            gpu: None,
        })
    }

    /// Enable rootless mode with user namespace mapping
    #[must_use]
    pub fn with_rootless(mut self) -> Self {
        self.namespaces.user = true;
        self.user_ns_config = Some(UserNamespaceConfig::rootless());
        self
    }

    /// Configure custom user namespace mapping
    #[must_use]
    pub fn with_user_namespace(mut self, config: UserNamespaceConfig) -> Self {
        self.namespaces.user = true;
        self.user_ns_config = Some(config);
        self
    }

    #[must_use]
    pub fn with_context(mut self, dir: PathBuf) -> Self {
        self.context_dir = Some(dir);
        self
    }

    #[must_use]
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn with_namespaces(mut self, namespaces: NamespaceConfig) -> Self {
        self.namespaces = namespaces;
        self
    }

    #[must_use]
    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }

    #[must_use]
    pub fn with_gvisor(mut self, enabled: bool) -> Self {
        self.use_gvisor = enabled;
        self
    }

    #[must_use]
    pub fn with_trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = level;
        self
    }

    /// Enable OCI bundle runtime path (always OCI for gVisor).
    #[must_use]
    pub fn with_oci_bundle(mut self) -> Self {
        self.use_gvisor = true;
        self
    }

    #[must_use]
    pub fn with_network(mut self, mode: crate::network::NetworkMode) -> Self {
        self.network = mode;
        self
    }

    #[must_use]
    pub fn with_context_mode(mut self, mode: crate::filesystem::ContextMode) -> Self {
        self.context_mode = mode;
        self
    }

    #[must_use]
    pub fn with_allow_degraded_security(mut self, allow: bool) -> Self {
        self.allow_degraded_security = allow;
        self
    }

    #[must_use]
    pub fn with_allow_chroot_fallback(mut self, allow: bool) -> Self {
        self.allow_chroot_fallback = allow;
        self
    }

    #[must_use]
    pub fn with_allow_host_network(mut self, allow: bool) -> Self {
        self.allow_host_network = allow;
        self
    }

    #[must_use]
    pub fn with_proc_readonly(mut self, proc_readonly: bool) -> Self {
        self.proc_readonly = proc_readonly;
        self
    }

    #[must_use]
    pub fn with_service_mode(mut self, mode: ServiceMode) -> Self {
        self.service_mode = mode;
        self
    }

    #[must_use]
    pub fn with_rootfs_path(mut self, path: PathBuf) -> Self {
        self.rootfs_path = Some(path);
        self
    }

    #[must_use]
    pub fn with_rootfs_mode(mut self, mode: RootfsMode) -> Self {
        self.rootfs_mode = mode;
        self
    }

    #[must_use]
    pub fn with_rootfs_overlay(mut self, upperdir: PathBuf, workdir: PathBuf) -> Self {
        self.rootfs_overlay = Some(RootfsOverlayConfig { upperdir, workdir });
        self
    }

    #[must_use]
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_credential_broker(mut self, broker: CredentialBrokerConfig) -> Self {
        self.credential_broker = Some(broker);
        self = self.with_credential_broker_identity_env();
        self
    }

    #[must_use]
    pub fn with_health_check(mut self, hc: HealthCheck) -> Self {
        self.health_check = Some(hc);
        self
    }

    #[must_use]
    pub fn with_readiness_probe(mut self, probe: ReadinessProbe) -> Self {
        self.readiness_probe = Some(probe);
        self
    }

    #[must_use]
    pub fn with_secret(mut self, secret: SecretMount) -> Self {
        self.secrets.push(secret);
        self
    }

    #[must_use]
    pub fn with_volume(mut self, volume: VolumeMount) -> Self {
        self.volumes.push(volume);
        self
    }

    #[must_use]
    pub fn with_workspace(mut self, workspace: WorkspaceConfig) -> Self {
        self.workspace = workspace;
        self
    }

    #[must_use]
    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home = home;
        self
    }

    #[must_use]
    pub fn with_provider_config(mut self, provider_config: ProviderConfigMount) -> Self {
        self.provider_configs.push(provider_config);
        self
    }

    #[must_use]
    pub fn with_workdir(mut self, workdir: PathBuf) -> Self {
        self.workdir = workdir;
        self
    }

    #[must_use]
    pub fn with_env(mut self, key: String, value: String) -> Self {
        if self.credential_broker_owns_env(&key) {
            return self;
        }
        self.environment.push((key, value));
        self
    }

    /// Append a launch-derived env var. Derived env is applied to the workload
    /// at exec time but excluded from `ContainerState` capture and image
    /// commit manifests. Use this for values computed from other launch state
    /// (broker endpoints, per-container tokens) that must not be baked into
    /// portable artifacts.
    #[must_use]
    pub fn with_derived_env(mut self, key: String, value: String) -> Self {
        self.derived_environment.push((key, value));
        self
    }

    fn upsert_derived_env(&mut self, key: &str, value: String) {
        self.derived_environment
            .retain(|(existing_key, _)| existing_key != key);
        self.derived_environment.push((key.to_string(), value));
    }

    #[must_use]
    pub fn with_credential_broker_identity_env(mut self) -> Self {
        if self.credential_broker.is_some() {
            // These values are per-container and must not be committed into
            // image manifests. Route them through `derived_environment` so
            // `state.environment` capture and `ImageConfig::from_state` stay
            // clean.
            self.environment
                .retain(|(key, _)| !is_credential_broker_identity_env(key));
            self.upsert_derived_env(CREDENTIAL_BROKER_CONTAINER_ID_ENV, self.id.clone());
            self.upsert_derived_env(
                CREDENTIAL_BROKER_TOKEN_ENV,
                self.credential_broker_token.clone(),
            );
        }
        self
    }

    #[must_use]
    pub(crate) fn credential_broker_owns_env(&self, key: &str) -> bool {
        self.credential_broker.is_some() && is_credential_broker_identity_env(key)
    }

    #[must_use]
    pub fn with_process_identity(mut self, identity: ProcessIdentity) -> Self {
        self.process_identity = identity;
        self
    }

    #[must_use]
    pub fn with_config_hash(mut self, hash: u64) -> Self {
        self.config_hash = Some(hash);
        self
    }

    #[must_use]
    pub fn with_sd_notify(mut self, enabled: bool) -> Self {
        self.sd_notify = enabled;
        self
    }

    #[must_use]
    pub fn with_required_kernel_lockdown(mut self, mode: KernelLockdownMode) -> Self {
        self.required_kernel_lockdown = Some(mode);
        self
    }

    #[must_use]
    pub fn with_verify_context_integrity(mut self, enabled: bool) -> Self {
        self.verify_context_integrity = enabled;
        self
    }

    #[must_use]
    pub fn with_verify_rootfs_attestation(mut self, enabled: bool) -> Self {
        self.verify_rootfs_attestation = enabled;
        self
    }

    #[must_use]
    pub fn with_seccomp_log_denied(mut self, enabled: bool) -> Self {
        self.seccomp_log_denied = enabled;
        self
    }

    #[must_use]
    pub fn with_gvisor_platform(mut self, platform: GVisorPlatform) -> Self {
        self.gvisor_platform = platform;
        self
    }

    #[must_use]
    pub fn with_seccomp_profile(mut self, path: PathBuf) -> Self {
        self.seccomp_profile = Some(path);
        self
    }

    #[must_use]
    pub fn with_seccomp_profile_sha256(mut self, hash: String) -> Self {
        self.seccomp_profile_sha256 = Some(hash);
        self
    }

    #[must_use]
    pub fn with_seccomp_mode(mut self, mode: SeccompMode) -> Self {
        self.seccomp_mode = mode;
        self
    }

    #[must_use]
    pub fn with_seccomp_trace_log(mut self, path: PathBuf) -> Self {
        self.seccomp_trace_log = Some(path);
        self
    }

    #[must_use]
    pub fn with_seccomp_allow_syscalls(mut self, syscalls: Vec<String>) -> Self {
        self.seccomp_allow_syscalls = syscalls;
        self
    }

    #[must_use]
    pub fn with_caps_policy(mut self, path: PathBuf) -> Self {
        self.caps_policy = Some(path);
        self
    }

    #[must_use]
    pub fn with_caps_policy_sha256(mut self, hash: String) -> Self {
        self.caps_policy_sha256 = Some(hash);
        self
    }

    #[must_use]
    pub fn with_landlock_policy(mut self, path: PathBuf) -> Self {
        self.landlock_policy = Some(path);
        self
    }

    #[must_use]
    pub fn with_landlock_policy_sha256(mut self, hash: String) -> Self {
        self.landlock_policy_sha256 = Some(hash);
        self
    }

    #[must_use]
    pub fn with_pid_file(mut self, path: PathBuf) -> Self {
        self.pid_file = Some(path);
        self
    }

    #[must_use]
    pub fn with_console_socket(mut self, path: PathBuf) -> Self {
        self.console_socket = Some(path);
        self.terminal = true;
        self
    }

    #[must_use]
    pub fn with_terminal(mut self, size: ConsoleSize) -> Self {
        self.terminal = true;
        self.console_size = size;
        self
    }

    #[must_use]
    pub fn with_bundle_dir(mut self, path: PathBuf) -> Self {
        self.bundle_dir = Some(path);
        self
    }

    pub fn with_state_root(mut self, root: PathBuf) -> Self {
        self.state_root = Some(root);
        self
    }

    /// Enable GPU passthrough with the given configuration.
    ///
    /// This is the programmatic equivalent of `--gpu`. See
    /// `spec/gpu-passthrough.md` for the security model.
    #[must_use]
    pub fn with_gpu(mut self, gpu: GpuPassthroughConfig) -> Self {
        self.gpu = Some(gpu);
        self
    }

    fn validate_credential_broker(&self) -> crate::error::Result<()> {
        let Some(broker) = &self.credential_broker else {
            return Ok(());
        };

        let crate::network::NetworkMode::Bridge(bridge_config) = &self.network else {
            return Err(crate::error::NucleusError::ConfigError(
                "Credential broker egress requires --network bridge so Nucleus can force the \
                 sandbox through the host-side broker endpoint"
                    .to_string(),
            ));
        };

        if bridge_config.nat_backend == crate::network::NatBackend::Userspace {
            return Err(crate::error::NucleusError::ConfigError(
                "Credential broker egress requires the kernel NAT backend; \
                 slirp4netns userspace NAT cannot route to the host-side bridge broker"
                    .to_string(),
            ));
        }

        broker
            .validate_for_bridge(bridge_config)
            .map_err(crate::error::NucleusError::ConfigError)?;

        let Some(policy) = &self.egress_policy else {
            return Err(crate::error::NucleusError::ConfigError(
                "Credential broker egress requires a broker-only egress policy".to_string(),
            ));
        };

        if !policy.is_credential_broker_only(broker) {
            return Err(crate::error::NucleusError::ConfigError(
                "Credential broker egress must allow only the broker IP/port and must deny DNS"
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn validate_fail_closed_isolation(&self) -> crate::error::Result<()> {
        let mode = self.service_mode.label();
        if self.allow_degraded_security {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "{} forbids --allow-degraded-security",
                mode
            )));
        }

        if self.allow_chroot_fallback {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "{} forbids --allow-chroot-fallback",
                mode
            )));
        }

        if matches!(self.network, crate::network::NetworkMode::Host) {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "{} forbids native host network mode because it collapses the \
                 runtime boundary; use --network gvisor-host with --runtime gvisor and \
                 --allow-host-network when hostinet is required",
                mode
            )));
        }

        if matches!(self.network, crate::network::NetworkMode::GVisorHost) {
            if !self.use_gvisor {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "{} requires --runtime gvisor for --network gvisor-host",
                    mode
                )));
            }
            if !self.allow_host_network {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "{} requires --allow-host-network for --network gvisor-host",
                    mode
                )));
            }
            if self.egress_policy.is_some() {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "{} cannot enforce egress policy with --network gvisor-host",
                    mode
                )));
            }
        } else if self.allow_host_network {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "{} permits --allow-host-network only with --network gvisor-host",
                mode
            )));
        }

        if self.seccomp_mode == SeccompMode::Trace {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "{} forbids --seccomp-mode trace",
                mode
            )));
        }

        if !self.seccomp_allow_syscalls.is_empty() {
            let allow_network = !matches!(self.network, crate::network::NetworkMode::None);
            crate::security::SeccompManager::validate_extra_syscalls_for_production(
                allow_network,
                &self.seccomp_allow_syscalls,
            )?;
        }

        Ok(())
    }

    /// Validate that strict agent mode invariants are satisfied.
    /// Called before container startup when service_mode == StrictAgent.
    pub fn validate_strict_agent_mode(&self) -> crate::error::Result<()> {
        if self.service_mode != ServiceMode::StrictAgent {
            return Ok(());
        }

        self.validate_fail_closed_isolation()?;

        if !self.limits.has_cgroup_control() {
            return Err(crate::error::NucleusError::ConfigError(
                "Strict agent mode requires at least one cgroup control \
                 (default --pids limit or explicit --memory/--cpus/--pids/--io-limit)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Validate that production mode invariants are satisfied.
    /// Called before container startup when service_mode == Production.
    pub fn validate_production_mode(&self) -> crate::error::Result<()> {
        if self.service_mode != ServiceMode::Production {
            return Ok(());
        }

        self.validate_fail_closed_isolation()?;

        if self.gpu.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids --gpu host device passthrough; production services must \
                 declare GPU needs through an attested rootfs"
                    .to_string(),
            ));
        }

        if self.workspace.allow_execute && self.workspace.is_writable() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids writable executable workspaces; use bind-ro with \
                 --workspace-exec or remove --workspace-exec"
                    .to_string(),
            ));
        }

        // Production mode requires explicit rootfs (no host bind mount fallback)
        let Some(rootfs_path) = self.rootfs_path.as_ref() else {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --rootfs path (no host bind mounts)".to_string(),
            ));
        };

        if self.rootfs_mode == RootfsMode::Overlay {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode does not yet support --rootfs-mode overlay; production mount \
                 auditing currently requires read-only rootfs bind mounts"
                    .to_string(),
            ));
        }

        // L6: Policy files must have SHA-256 verification in production
        if self.caps_policy.is_some() && self.caps_policy_sha256.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires --caps-policy-sha256 when using --caps-policy"
                    .to_string(),
            ));
        }
        if self.landlock_policy.is_some() && self.landlock_policy_sha256.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires --landlock-policy-sha256 when using --landlock-policy"
                    .to_string(),
            ));
        }
        if self.seccomp_profile.is_some() && self.seccomp_profile_sha256.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires --seccomp-profile-sha256 when using --seccomp-profile"
                    .to_string(),
            ));
        }

        // Production mode requires explicit resource limits
        if self.limits.memory_bytes.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --memory limit".to_string(),
            ));
        }

        if self.limits.cpu_quota_us.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --cpus limit".to_string(),
            ));
        }

        if !self.verify_rootfs_attestation {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires --verify-rootfs-attestation".to_string(),
            ));
        }

        validate_production_rootfs_path(rootfs_path)?;

        Ok(())
    }

    /// Validate runtime-specific feature support.
    pub fn validate_runtime_support(&self) -> crate::error::Result<()> {
        self.limits.validate_runtime_sanity()?;

        if let Some(user_ns_config) = &self.user_ns_config {
            if !self.process_identity.additional_gids.is_empty() {
                return Err(crate::error::NucleusError::ConfigError(
                    "Supplementary groups are currently unsupported with user namespaces"
                        .to_string(),
                ));
            }

            let uid_mapped = user_ns_config.uid_mappings.iter().any(|mapping| {
                self.process_identity.uid >= mapping.container_id
                    && self.process_identity.uid
                        < mapping.container_id.saturating_add(mapping.count)
            });
            if !uid_mapped {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "Process uid {} is not mapped in the configured user namespace",
                    self.process_identity.uid
                )));
            }

            let gid_mapped = user_ns_config.gid_mappings.iter().any(|mapping| {
                self.process_identity.gid >= mapping.container_id
                    && self.process_identity.gid
                        < mapping.container_id.saturating_add(mapping.count)
            });
            if !gid_mapped {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "Process gid {} is not mapped in the configured user namespace",
                    self.process_identity.gid
                )));
            }
        }

        if self.seccomp_mode == SeccompMode::Trace && self.seccomp_trace_log.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Seccomp trace mode requires --seccomp-log / seccomp_trace_log".to_string(),
            ));
        }

        normalize_container_destination(&self.workdir)?;
        let workspace_path = normalize_container_destination(&self.workspace.container_path)?;
        if workspace_path != PathBuf::from("/workspace") {
            return Err(crate::error::NucleusError::ConfigError(
                "Workspace destination is fixed at /workspace".to_string(),
            ));
        }
        let home_path = normalize_container_destination(&self.home)?;
        if home_path == workspace_path
            || home_path.starts_with(&workspace_path)
            || workspace_path.starts_with(&home_path)
        {
            return Err(crate::error::NucleusError::ConfigError(
                "--home must not overlap /workspace".to_string(),
            ));
        }
        if let Some(host_path) = &self.workspace.host_path {
            validate_workspace_host_path(host_path)?;
        }
        if self.workspace.mode == WorkspaceMode::CopyInOut && self.workspace.host_path.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "--workspace-mode copy-in-out requires --workspace".to_string(),
            ));
        }

        for secret in &self.secrets {
            normalize_container_destination(&secret.dest)?;
        }

        for provider_config in &self.provider_configs {
            validate_provider_config_source(&provider_config.source)?;
            normalize_provider_config_destination(&home_path, &provider_config.dest)?;
        }

        for volume in &self.volumes {
            let volume_dest = normalize_volume_destination(&volume.dest)?;
            if volume_dest == workspace_path {
                return Err(crate::error::NucleusError::ConfigError(
                    "Volume destination /workspace conflicts with --workspace".to_string(),
                ));
            }
            if volume_dest == home_path {
                return Err(crate::error::NucleusError::ConfigError(
                    "Volume destination conflicts with --home".to_string(),
                ));
            }
            match &volume.source {
                VolumeSource::Bind { source } => {
                    if !source.is_absolute() {
                        return Err(crate::error::NucleusError::ConfigError(format!(
                            "Volume source must be absolute: {:?}",
                            source
                        )));
                    }
                    if !source.exists() {
                        return Err(crate::error::NucleusError::ConfigError(format!(
                            "Volume source does not exist: {:?}",
                            source
                        )));
                    }
                    crate::filesystem::validate_bind_mount_source(source)?;
                }
                VolumeSource::Tmpfs { .. } => {}
            }
        }

        self.validate_credential_broker()?;

        if self.rootfs_mode == RootfsMode::Overlay {
            if self.rootfs_path.is_none() {
                return Err(crate::error::NucleusError::ConfigError(
                    "--rootfs-mode overlay requires --rootfs or --agent-toolchain-rootfs"
                        .to_string(),
                ));
            }
            if self.use_gvisor {
                return Err(crate::error::NucleusError::ConfigError(
                    "--rootfs-mode overlay is currently supported only with --runtime native"
                        .to_string(),
                ));
            }
        }

        if !self.use_gvisor {
            return Ok(());
        }

        if self.seccomp_mode == SeccompMode::Trace {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support --seccomp-mode trace; use --runtime native"
                    .to_string(),
            ));
        }

        if self.seccomp_log_denied {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support seccomp deny logging; use --runtime native"
                    .to_string(),
            ));
        }

        if !self.seccomp_allow_syscalls.is_empty() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support --seccomp-allow; use a custom --seccomp-profile or --runtime native"
                    .to_string(),
            ));
        }

        if self.caps_policy.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support capability policy files; use --runtime native"
                    .to_string(),
            ));
        }

        if self.landlock_policy.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support Landlock policy files; use --runtime native"
                    .to_string(),
            ));
        }

        if self.health_check.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support exec health checks; use --runtime native or remove --health-cmd"
                    .to_string(),
            ));
        }

        if matches!(
            self.readiness_probe.as_ref(),
            Some(ReadinessProbe::Exec { .. }) | Some(ReadinessProbe::TcpPort(_))
        ) {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support exec/TCP readiness probes; use --runtime native or --readiness-sd-notify"
                    .to_string(),
            ));
        }

        if self.verify_context_integrity
            && self.context_dir.is_some()
            && matches!(self.context_mode, crate::filesystem::ContextMode::BindMount)
        {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime cannot verify bind-mounted context integrity; use --context-mode copy or disable --verify-context-integrity"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Apply runtime selection (native vs gVisor) and OCI bundle mode.
    pub fn apply_runtime_selection(
        mut self,
        runtime: RuntimeSelection,
        oci: bool,
    ) -> crate::error::Result<Self> {
        match runtime {
            RuntimeSelection::Native => {
                if oci {
                    return Err(crate::error::NucleusError::ConfigError(
                        "--bundle requires gVisor runtime; use --runtime gvisor".to_string(),
                    ));
                }
                self = self.with_gvisor(false);
            }
            RuntimeSelection::GVisor => {
                self = self.with_gvisor(true);
                if !oci {
                    tracing::info!(
                        "Security hardening: enabling OCI bundle mode for gVisor runtime"
                    );
                }
                self = self.with_oci_bundle();
            }
        }
        Ok(self)
    }
}

/// Validate a container name for safe use.
pub fn validate_container_name(name: &str) -> crate::error::Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(crate::error::NucleusError::ConfigError(
            "Invalid container name: must be 1-128 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(crate::error::NucleusError::ConfigError(
            "Invalid container name: allowed characters are a-zA-Z0-9, '-', '_', '.'".to_string(),
        ));
    }
    Ok(())
}

/// Validate a hostname according to RFC 1123.
pub fn validate_hostname(hostname: &str) -> crate::error::Result<()> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(crate::error::NucleusError::ConfigError(
            "Invalid hostname: must be 1-253 characters".to_string(),
        ));
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "Invalid hostname label: '{}'",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "Invalid hostname label '{}': cannot start or end with '-'",
                label
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "Invalid hostname label '{}': allowed characters are a-zA-Z0-9 and '-'",
                label
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::network::NetworkMode;

    #[test]
    fn test_generate_container_id_is_32_hex_chars() {
        let id = generate_container_id().unwrap();
        assert_eq!(
            id.len(),
            32,
            "Container ID must be full 128-bit (32 hex chars), got {}",
            id.len()
        );
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "Container ID must be hex: {}",
            id
        );
    }

    #[test]
    fn test_generate_container_id_is_unique() {
        let id1 = generate_container_id().unwrap();
        let id2 = generate_container_id().unwrap();
        assert_ne!(id1, id2, "Two consecutive IDs must differ");
    }

    #[test]
    fn test_config_security_defaults_are_hardened() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!cfg.allow_degraded_security);
        assert!(!cfg.allow_chroot_fallback);
        assert!(!cfg.allow_host_network);
        assert!(cfg.proc_readonly);
        assert_eq!(cfg.service_mode, ServiceMode::Agent);
        assert!(cfg.rootfs_path.is_none());
        assert!(cfg.egress_policy.is_none());
        assert!(cfg.credential_broker.is_none());
        assert!(cfg.secrets.is_empty());
        assert!(cfg.volumes.is_empty());
        assert_eq!(cfg.home, PathBuf::from(DEFAULT_HOME_PATH));
        assert!(cfg.provider_configs.is_empty());
        assert!(!cfg.sd_notify);
        assert!(cfg.required_kernel_lockdown.is_none());
        assert!(!cfg.verify_context_integrity);
        assert!(!cfg.verify_rootfs_attestation);
        assert!(!cfg.seccomp_log_denied);
        assert_eq!(cfg.gvisor_platform, GVisorPlatform::Systrap);
    }

    #[test]
    fn test_credential_broker_validates_broker_only_bridge_egress() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(crate::network::BridgeConfig::default()))
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy());

        assert!(cfg.validate_runtime_support().is_ok());
    }

    #[test]
    fn test_credential_broker_injects_per_container_identity_env() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let cfg = ContainerConfig::try_new_with_id(
            Some("0123456789abcdef0123456789abcdef".to_string()),
            None,
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_env(
            CREDENTIAL_BROKER_TOKEN_ENV.to_string(),
            "user-supplied-token".to_string(),
        )
        .with_env(
            CREDENTIAL_BROKER_CONTAINER_ID_ENV.to_string(),
            "user-supplied-container-id".to_string(),
        )
        .with_credential_broker(broker)
        .with_env(
            CREDENTIAL_BROKER_TOKEN_ENV.to_string(),
            "late-user-supplied-token".to_string(),
        )
        .with_env(
            CREDENTIAL_BROKER_CONTAINER_ID_ENV.to_string(),
            "late-user-supplied-container-id".to_string(),
        );

        // Per-container identity env is launch-derived: it must live in
        // `derived_environment` so committed image manifests stay portable.
        assert!(cfg.derived_environment.contains(&(
            CREDENTIAL_BROKER_CONTAINER_ID_ENV.to_string(),
            cfg.id.clone()
        )));
        assert_ne!(cfg.credential_broker_token, cfg.id);
        assert!(cfg.derived_environment.contains(&(
            CREDENTIAL_BROKER_TOKEN_ENV.to_string(),
            cfg.credential_broker_token.clone()
        )));
        // User-supplied broker identity env is overwritten in broker mode,
        // regardless of whether it was supplied before or after broker setup.
        for key in [
            CREDENTIAL_BROKER_TOKEN_ENV,
            CREDENTIAL_BROKER_CONTAINER_ID_ENV,
        ] {
            assert!(!cfg.environment.iter().any(|(env_key, _)| env_key == key));
        }
    }

    #[test]
    fn test_credential_broker_rejects_non_bridge_network() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::None)
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy());

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("requires --network bridge"));
    }

    #[test]
    fn test_credential_broker_rejects_extra_egress_routes() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(crate::network::BridgeConfig::default()))
            .with_credential_broker(broker)
            .with_egress_policy(
                crate::network::EgressPolicy::default()
                    .with_allowed_cidrs(vec![
                        "10.0.42.1/32".to_string(),
                        "203.0.113.0/24".to_string(),
                    ])
                    .with_allowed_tcp_ports(vec![8080]),
            );

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("allow only the broker"));
    }

    #[test]
    fn test_credential_broker_rejects_userspace_nat_backend() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(
                crate::network::BridgeConfig::default()
                    .with_nat_backend(crate::network::NatBackend::Userspace),
            ))
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy());

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("kernel NAT backend"));
    }

    #[test]
    fn test_credential_broker_rejects_ip_outside_bridge_gateway() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("8.8.8.8:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(crate::network::BridgeConfig::default()))
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy());

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err
            .to_string()
            .contains("host-side bridge address 10.0.42.1"));
    }

    #[test]
    fn test_credential_broker_rejects_non_gateway_bridge_ip() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.2:8080").unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(crate::network::BridgeConfig::default()))
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy());

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err
            .to_string()
            .contains("host-side bridge address 10.0.42.1"));
    }

    #[test]
    fn test_production_mode_rejects_degraded_flags() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_allow_degraded_security(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        assert!(cfg.validate_production_mode().is_err());
    }

    #[test]
    fn test_production_mode_rejects_chroot_fallback() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_allow_chroot_fallback(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(
            err.to_string().contains("chroot"),
            "Production mode must reject chroot fallback"
        );
    }

    #[test]
    fn test_production_mode_requires_rootfs() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--rootfs"));
    }

    fn test_rootfs_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/nix/store")
    }

    #[test]
    fn test_production_mode_requires_memory_limit() {
        let rootfs = test_rootfs_path();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs);
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--memory"));
    }

    #[test]
    fn test_production_mode_valid_config() {
        let rootfs = test_rootfs_path();
        if !rootfs.is_dir() {
            return;
        }
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs.clone())
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let result = cfg.validate_production_mode();
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_mode_allows_explicit_gvisor_host_network() {
        let rootfs = test_rootfs_path();
        if !rootfs.is_dir() {
            return;
        }
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(true)
            .with_service_mode(ServiceMode::Production)
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(true)
            .with_rootfs_path(rootfs)
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        assert!(cfg.validate_production_mode().is_ok());
    }

    #[test]
    fn test_production_mode_rejects_gvisor_host_network_with_egress_policy() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(true)
            .with_service_mode(ServiceMode::Production)
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(true)
            .with_egress_policy(crate::network::EgressPolicy::deny_all())
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("egress policy"));
    }

    #[test]
    fn test_production_mode_rejects_native_host_network() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_service_mode(ServiceMode::Production)
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("host network"));
    }

    #[test]
    fn test_production_mode_rejects_gvisor_host_without_gvisor_runtime() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_service_mode(ServiceMode::Production)
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--runtime gvisor"));
    }

    #[test]
    fn test_production_mode_rejects_gvisor_host_without_explicit_opt_in() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(true)
            .with_service_mode(ServiceMode::Production)
            .with_network(NetworkMode::GVisorHost)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--allow-host-network"));
    }

    #[test]
    fn test_production_mode_rejects_rootfs_parent_traversal() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/../../tmp/evil-rootfs"))
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();

        assert!(
            err.to_string().contains("parent traversal"),
            "Production mode must reject raw rootfs traversal before canonicalization"
        );
    }

    #[test]
    fn test_production_mode_rejects_out_of_store_rootfs() {
        let temp = tempfile::TempDir::new().unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs)
            .with_verify_rootfs_attestation(true)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();

        assert!(
            err.to_string().contains("/nix/store"),
            "Production mode must reject rootfs paths that resolve outside /nix/store"
        );
    }

    #[test]
    fn test_production_mode_requires_rootfs_attestation() {
        let rootfs = test_rootfs_path();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs.clone())
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("attestation"));
    }

    #[test]
    fn test_production_mode_rejects_seccomp_trace() {
        let rootfs = test_rootfs_path();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs.clone())
            .with_seccomp_mode(SeccompMode::Trace)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(
            err.to_string().contains("trace"),
            "Production mode must reject seccomp trace mode"
        );
    }

    #[test]
    fn test_production_mode_rejects_security_critical_seccomp_allow() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(test_rootfs_path())
            .with_verify_rootfs_attestation(true)
            .with_seccomp_allow_syscalls(vec!["keyctl".to_string()])
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("seccomp-allow"));
        assert!(err.to_string().contains("keyctl"));
    }

    #[test]
    fn test_strict_agent_mode_valid_without_production_rootfs() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent);

        assert!(cfg.validate_strict_agent_mode().is_ok());
        assert!(cfg.rootfs_path.is_none());
        assert!(!cfg.verify_rootfs_attestation);
    }

    #[test]
    fn test_strict_agent_mode_rejects_degraded_security() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_allow_degraded_security(true);

        let err = cfg.validate_strict_agent_mode().unwrap_err();
        assert!(err.to_string().contains("degraded"));
    }

    #[test]
    fn test_strict_agent_mode_rejects_chroot_fallback() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_allow_chroot_fallback(true);

        let err = cfg.validate_strict_agent_mode().unwrap_err();
        assert!(err.to_string().contains("chroot"));
    }

    #[test]
    fn test_strict_agent_mode_rejects_seccomp_trace() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_seccomp_mode(SeccompMode::Trace);

        let err = cfg.validate_strict_agent_mode().unwrap_err();
        assert!(err.to_string().contains("trace"));
    }

    #[test]
    fn test_strict_agent_mode_rejects_native_host_network() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_service_mode(ServiceMode::StrictAgent)
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true);

        let err = cfg.validate_strict_agent_mode().unwrap_err();
        assert!(err.to_string().contains("host network"));
    }

    #[test]
    fn test_strict_agent_mode_requires_some_cgroup_control() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_limits(crate::resources::ResourceLimits::unlimited());

        let err = cfg.validate_strict_agent_mode().unwrap_err();
        assert!(err.to_string().contains("cgroup"));
    }

    #[test]
    fn test_strict_agent_mode_allows_explicit_gvisor_host_network() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(true)
            .with_service_mode(ServiceMode::StrictAgent)
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(true);

        assert!(cfg.validate_strict_agent_mode().is_ok());
    }

    #[test]
    fn test_production_mode_requires_cpu_limit() {
        let rootfs = test_rootfs_path();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs.clone())
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--cpus"));
    }

    #[test]
    fn test_config_security_builders_override_defaults() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_allow_degraded_security(true)
            .with_allow_chroot_fallback(true)
            .with_allow_host_network(true)
            .with_proc_readonly(false)
            .with_network(NetworkMode::Host);

        assert!(cfg.allow_degraded_security);
        assert!(cfg.allow_chroot_fallback);
        assert!(cfg.allow_host_network);
        assert!(!cfg.proc_readonly);
        assert!(matches!(cfg.network, NetworkMode::Host));
    }

    #[test]
    fn test_hardening_builders_override_defaults() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_required_kernel_lockdown(KernelLockdownMode::Confidentiality)
            .with_verify_context_integrity(true)
            .with_verify_rootfs_attestation(true)
            .with_seccomp_log_denied(true)
            .with_gvisor_platform(GVisorPlatform::Kvm);

        assert_eq!(
            cfg.required_kernel_lockdown,
            Some(KernelLockdownMode::Confidentiality)
        );
        assert!(cfg.verify_context_integrity);
        assert!(cfg.verify_rootfs_attestation);
        assert!(cfg.seccomp_log_denied);
        assert_eq!(cfg.gvisor_platform, GVisorPlatform::Kvm);
    }

    #[test]
    fn test_seccomp_trace_requires_log_path() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_seccomp_mode(SeccompMode::Trace);

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("seccomp-log"));
    }

    #[test]
    fn test_gvisor_allows_custom_seccomp_profile_but_rejects_native_policy_files() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_seccomp_profile(PathBuf::from("/tmp/seccomp.json"))
            .with_caps_policy(PathBuf::from("/tmp/caps.toml"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("capability policy"));
    }

    #[test]
    fn test_gvisor_accepts_custom_seccomp_profile() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_seccomp_profile(PathBuf::from("/tmp/seccomp.json"));

        cfg.validate_runtime_support().unwrap();
    }

    #[test]
    fn test_gvisor_rejects_landlock_policy_file() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_landlock_policy(PathBuf::from("/tmp/landlock.toml"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("Landlock"));
    }

    #[test]
    fn test_gvisor_rejects_trace_mode_even_with_log_path() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_seccomp_mode(SeccompMode::Trace)
            .with_seccomp_trace_log(PathBuf::from("/tmp/trace.ndjson"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("gVisor runtime"));
    }

    #[test]
    fn test_gvisor_rejects_seccomp_allow_without_custom_profile_projection() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_seccomp_allow_syscalls(vec!["io_uring_setup".to_string()]);

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("seccomp-allow"));
    }

    #[test]
    fn test_secret_dest_must_be_absolute() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_secret(crate::container::SecretMount {
                source: PathBuf::from("/run/secrets/api-key"),
                dest: PathBuf::from("secrets/api-key"),
                mode: 0o400,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn test_secret_dest_rejects_parent_traversal() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_secret(crate::container::SecretMount {
                source: PathBuf::from("/run/secrets/api-key"),
                dest: PathBuf::from("/../../etc/passwd"),
                mode: 0o400,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("parent traversal"));
    }

    #[test]
    fn test_bind_volume_source_must_exist() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: PathBuf::from("/tmp/definitely-missing-nucleus-volume"),
                },
                dest: PathBuf::from("/var/lib/app"),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("Volume source does not exist"));
    }

    #[test]
    fn test_bind_volume_source_rejects_sensitive_host_subtrees() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: PathBuf::from("/proc/sys"),
                },
                dest: PathBuf::from("/host-proc"),
                read_only: true,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("sensitive host path"));
    }

    #[test]
    fn test_bind_volume_dest_must_be_absolute() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: dir.path().to_path_buf(),
                },
                dest: PathBuf::from("var/lib/app"),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn test_bind_volume_dest_rejects_reserved_container_paths() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: dir.path().to_path_buf(),
                },
                dest: PathBuf::from("/etc"),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_default_workspace_and_workdir_contract() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();

        assert_eq!(cfg.workspace.container_path, PathBuf::from("/workspace"));
        assert_eq!(cfg.workdir, PathBuf::from("/workspace"));
        assert_eq!(cfg.home, PathBuf::from(DEFAULT_HOME_PATH));
        assert_eq!(cfg.workspace.mode, WorkspaceMode::BindRw);
        assert!(!cfg.workspace.allow_execute);
    }

    #[test]
    fn test_home_must_not_overlap_workspace() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_home(PathBuf::from("/workspace/.home"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("must not overlap /workspace"));
    }

    #[test]
    fn test_workspace_source_validates_existing_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_workspace(WorkspaceConfig::new().with_host_path(dir.path().to_path_buf()));

        cfg.validate_runtime_support().unwrap();
    }

    #[test]
    fn test_copy_in_out_requires_workspace_source() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_workspace(WorkspaceConfig::new().with_mode(WorkspaceMode::CopyInOut));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("requires --workspace"));
    }

    #[test]
    fn test_volume_destination_cannot_replace_workspace() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: dir.path().to_path_buf(),
                },
                dest: PathBuf::from("/workspace"),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("conflicts with --workspace"));
    }

    #[test]
    fn test_volume_destination_cannot_replace_home() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Bind {
                    source: dir.path().to_path_buf(),
                },
                dest: PathBuf::from(DEFAULT_HOME_PATH),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("conflicts with --home"));
    }

    #[test]
    fn test_production_rejects_writable_executable_workspace() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_workspace(
                WorkspaceConfig::new()
                    .with_mode(WorkspaceMode::BindRw)
                    .with_allow_execute(true),
            );

        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("writable executable workspaces"));
    }

    #[test]
    fn test_tmpfs_volume_rejects_parent_traversal() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_volume(VolumeMount {
                source: VolumeSource::Tmpfs {
                    size: Some("64M".to_string()),
                },
                dest: PathBuf::from("/../../var/lib/app"),
                read_only: false,
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("parent traversal"));
    }

    #[test]
    fn test_gvisor_rejects_bind_mount_context_integrity_verification() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_context(PathBuf::from("/tmp/context"))
            .with_context_mode(crate::filesystem::ContextMode::BindMount)
            .with_verify_context_integrity(true);

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("context integrity"));
    }

    #[test]
    fn test_gvisor_rejects_exec_health_checks() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_health_check(HealthCheck {
                command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                interval: Duration::from_secs(30),
                retries: 3,
                start_period: Duration::from_secs(1),
                timeout: Duration::from_secs(5),
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("health checks"));
    }

    #[test]
    fn test_gvisor_rejects_exec_readiness_probes() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_readiness_probe(ReadinessProbe::Exec {
                command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("readiness"));
    }

    #[test]
    fn test_gvisor_allows_copy_mode_context_integrity_verification() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_context(PathBuf::from("/tmp/context"))
            .with_context_mode(crate::filesystem::ContextMode::Copy)
            .with_verify_context_integrity(true);

        assert!(cfg.validate_runtime_support().is_ok());
    }

    #[test]
    fn test_user_namespace_rejects_unmapped_process_identity() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_rootless()
            .with_process_identity(ProcessIdentity {
                uid: 1000,
                gid: 1000,
                additional_gids: Vec::new(),
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("not mapped"));
    }

    #[test]
    fn test_user_namespace_rejects_supplementary_groups() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_rootless()
            .with_process_identity(ProcessIdentity {
                uid: 0,
                gid: 0,
                additional_gids: vec![1],
            });

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("Supplementary groups"));
    }

    #[test]
    fn test_native_runtime_disables_gvisor() {
        // --runtime native selects the native runtime without changing trust policy.
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .apply_runtime_selection(RuntimeSelection::Native, false)
            .unwrap();
        assert!(!cfg.use_gvisor, "native runtime must disable gVisor");
        assert_eq!(
            cfg.trust_level,
            TrustLevel::Untrusted,
            "native runtime must preserve the default Untrusted trust level"
        );
    }

    #[test]
    fn test_native_runtime_preserves_explicit_trusted_policy() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_trust_level(TrustLevel::Trusted)
            .apply_runtime_selection(RuntimeSelection::Native, false)
            .unwrap();

        assert!(!cfg.use_gvisor, "native runtime must disable gVisor");
        assert_eq!(
            cfg.trust_level,
            TrustLevel::Trusted,
            "native runtime must preserve explicit Trusted trust level"
        );
    }

    #[test]
    fn test_default_config_has_gvisor_enabled() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(cfg.use_gvisor, "default must have gVisor enabled");
        assert_eq!(
            cfg.trust_level,
            TrustLevel::Untrusted,
            "default must be Untrusted"
        );
    }

    #[test]
    fn test_console_socket_implies_terminal_mode() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_console_socket(PathBuf::from("/tmp/console.sock"));

        assert!(cfg.terminal);
        assert_eq!(cfg.console_socket, Some(PathBuf::from("/tmp/console.sock")));
    }

    #[test]
    fn test_terminal_size_can_be_configured() {
        let size = ConsoleSize {
            width: 132,
            height: 43,
        };
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_terminal(size);

        assert!(cfg.terminal);
        assert_eq!(cfg.console_size, size);
    }

    #[test]
    fn test_generate_container_id_returns_result() {
        // BUG-07: generate_container_id must return Result, not panic.
        // Verify by calling it and checking the Ok value is valid hex.
        let id: crate::error::Result<String> = generate_container_id();
        let id = id.expect("generate_container_id must return Ok, not panic");
        assert_eq!(id.len(), 32, "container ID must be 32 hex chars");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "container ID must be valid hex: {}",
            id
        );
    }

    #[test]
    fn gpu_defaults_match_nvidia_toolkit() {
        let cfg = GpuPassthroughConfig::default();
        assert_eq!(cfg.vendor, GpuVendor::Auto);
        assert!(cfg.devices.is_empty());
        assert_eq!(cfg.driver_capabilities, DEFAULT_GPU_DRIVER_CAPABILITIES);
        assert_eq!(cfg.visible_devices, DEFAULT_GPU_VISIBLE_DEVICES);
        assert!(cfg.bind_driver_libraries);
    }

    #[test]
    fn production_mode_rejects_gpu_passthrough() {
        let mut cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gpu(GpuPassthroughConfig::default());
        cfg.service_mode = ServiceMode::Production;
        cfg.rootfs_path = Some(std::path::PathBuf::from("/nix/some/rootfs"));
        let err = cfg.validate_production_mode().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Production mode forbids --gpu"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn agent_mode_allows_gpu_passthrough() {
        let cfg = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gpu(GpuPassthroughConfig::default());
        // Agent is the default service mode and must permit GPU.
        assert_eq!(cfg.service_mode, ServiceMode::Agent);
        assert!(cfg.gpu.is_some());
        cfg.validate_production_mode().expect("agent mode permits gpu");
    }

    #[test]
    fn gpu_environment_includes_nvidia_vars() {
        let gpu = GpuPassthroughConfig {
            vendor: GpuVendor::Nvidia,
            ..GpuPassthroughConfig::default()
        };
        let env = gpu_environment(&gpu);
        let keys: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"NVIDIA_VISIBLE_DEVICES"));
        assert!(keys.contains(&"NVIDIA_DRIVER_CAPABILITIES"));
        assert!(keys.contains(&"__EGL_VENDOR_LIBRARY_FILENAMES"));
    }

    #[test]
    fn gpu_environment_omits_egl_when_not_nvidia() {
        let gpu = GpuPassthroughConfig {
            vendor: GpuVendor::Amd,
            ..GpuPassthroughConfig::default()
        };
        let env = gpu_environment(&gpu);
        assert!(!env.iter().any(|(k, _)| *k == "__EGL_VENDOR_LIBRARY_FILENAMES"));
    }
}
