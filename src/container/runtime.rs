use crate::audit::{audit, audit_error, AuditEventType};
use crate::container::{
    ContainerConfig, ContainerState, ContainerStateManager, ContainerStateParams, OciStatus,
    RootfsMode, ServiceMode, WorkspaceMode,
};
use crate::error::{NucleusError, Result, StateTransition};
use crate::filesystem::{
    audit_mounts, bind_mount_host_paths, bind_mount_rootfs, copy_workspace_in, create_dev_nodes,
    create_minimal_fs, mask_proc_paths, mount_home_tmpfs, mount_procfs, mount_provider_configs,
    mount_secrets_inmemory, mount_volumes, mount_workspace, overlay_mount_rootfs,
    snapshot_context_dir, switch_root, sync_workspace_out, validate_production_rootfs_path,
    verify_context_manifest, verify_rootfs_attestation, FilesystemState, LazyContextPopulator,
    TmpfsMount,
};
use crate::isolation::{NamespaceManager, UserNamespaceMapper};
use crate::network::{BridgeDriver, BridgeNetwork, NatBackend, NetworkMode, UserspaceNetwork};
use crate::resources::{Cgroup, ResourceStats};
use crate::security::{
    CapabilityManager, GVisorRuntime, LandlockManager, OciContainerState, OciHooks,
    SeccompDenyLogger, SeccompManager, SeccompTraceReader, SecurityState,
};
use crate::telemetry::{CleanupEvent, ContainerControlEvent, EventSink, ExitStatusEvent};
use caps::{CapSet, Capability, CapsHashSet};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    chown, fork, pipe, read, setresgid, setresuid, write, ForkResult, Gid, Pid, Uid,
};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::Builder;
use tracing::{debug, error, info, info_span, warn};

use super::console::{NativeConsoleRelay, NativePty};

/// Container runtime that orchestrates all isolation mechanisms
///
/// Execution flow matches the formal specifications:
/// 1. Create namespaces (Nucleus_Isolation_NamespaceLifecycle.tla)
/// 2. Create and configure cgroups (Nucleus_Resources_CgroupLifecycle.tla)
/// 3. Mount tmpfs and populate context (Nucleus_Filesystem_FilesystemLifecycle.tla)
/// 4. Drop capabilities and apply seccomp (Nucleus_Security_SecurityEnforcement.tla)
/// 5. Execute target process
pub struct Container {
    pub(super) config: ContainerConfig,
    /// Pre-resolved runsc path, resolved before fork so that user-namespace
    /// UID changes don't block PATH-based lookup.
    pub(super) runsc_path: Option<String>,
    pub(super) event_sink: Option<EventSink>,
}

/// Handle returned by `Container::create()` representing a container whose
/// child process has been forked and is blocked on the exec FIFO, waiting for
/// `start()` to release it.
pub struct CreatedContainer {
    pub(super) config: ContainerConfig,
    pub(super) state_mgr: ContainerStateManager,
    pub(super) state: ContainerState,
    pub(super) child: Pid,
    pub(super) cgroup_opt: Option<Cgroup>,
    pub(super) network_driver: Option<BridgeDriver>,
    pub(super) trace_reader: Option<SeccompTraceReader>,
    pub(super) deny_logger: Option<SeccompDenyLogger>,
    pub(super) exec_fifo_path: Option<PathBuf>,
    pub(super) native_console_master: Option<OwnedFd>,
    pub(super) event_sink: Option<EventSink>,
    pub(super) _lifecycle_span: tracing::Span,
}

const CREDENTIAL_BROKER_CONNECT_TIMEOUT: Duration = Duration::from_millis(750);

impl Container {
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            runsc_path: None,
            event_sink: None,
        }
    }

    pub fn with_event_sink(mut self, event_sink: Option<EventSink>) -> Self {
        self.event_sink = event_sink;
        self
    }

    fn probe_credential_broker(broker: &crate::network::CredentialBrokerConfig) -> Result<()> {
        let addr = SocketAddr::V4(SocketAddrV4::new(broker.broker_ip, broker.broker_port));
        TcpStream::connect_timeout(&addr, CREDENTIAL_BROKER_CONNECT_TIMEOUT)
            .map(|_| ())
            .map_err(|e| {
                NucleusError::NetworkError(format!(
                    "Credential broker {} was not reachable within {:?}: {}",
                    addr, CREDENTIAL_BROKER_CONNECT_TIMEOUT, e
                ))
            })
    }

    fn validate_credential_broker_resolved_nat(
        config: &ContainerConfig,
        host_is_root: bool,
    ) -> Result<()> {
        if config.credential_broker.is_none() {
            return Ok(());
        }
        let NetworkMode::Bridge(ref bridge_config) = config.network else {
            return Ok(());
        };

        let backend =
            bridge_config.selected_nat_backend(host_is_root, config.user_ns_config.is_some());
        if backend == NatBackend::Userspace {
            return Err(NucleusError::ConfigError(
                "Credential broker egress requires the kernel NAT backend; \
                 --nat-backend auto resolves to userspace for rootless/native containers"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Run the container (convenience wrapper: create + start)
    pub fn run(&self) -> Result<i32> {
        self.create_internal(false)?.start()
    }

    /// Create phase: fork the child, set up cgroup/bridge, leave child blocked
    /// on the exec FIFO. Returns a `CreatedContainer` whose `start()` method
    /// releases the child process.
    pub fn create(&self) -> Result<CreatedContainer> {
        self.create_internal(true)
    }

    /// H6: Mark all file descriptors > 2 close-on-exec in the child process after fork.
    ///
    /// This prevents leaking host sockets, pipes, and state files into the executed
    /// workload while preserving setup-time pipes and PTY handles until exec.
    /// Uses close_range(2) when available, falls back to /proc/self/fd.
    fn sanitize_fds() {
        // Try close_range(3, u32::MAX, CLOSE_RANGE_CLOEXEC) first – it's
        // O(1) on Linux 5.9+ and marks all FDs as close-on-exec.
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
        // SAFETY: close_range is a safe syscall that marks FDs as close-on-exec.
        let ret =
            unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if ret == 0 {
            return;
        }
        // Fallback: iterate /proc/self/fd and set FD_CLOEXEC individually.
        // Collect fds first, then update – changing fds during iteration would
        // invalidate the ReadDir's own directory fd.
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let fds: Vec<i32> = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd > 2)
                .collect();
            for fd in fds {
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
        }
    }

    /// Close all file descriptors > 2 in the current process.
    ///
    /// The production PID 1 supervisor does not exec, so FD_CLOEXEC does not
    /// protect inherited host/runtime descriptors in that process.
    pub(crate) fn close_nonstdio_fds() {
        // SAFETY: close_range with flags 0 closes descriptors immediately.
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if ret == 0 {
            return;
        }

        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let fds: Vec<i32> = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|s| s.parse::<i32>().ok())
                .filter(|&fd| fd > 2)
                .collect();
            for fd in fds {
                unsafe { libc::close(fd) };
            }
            return;
        }

        let max_fd = match unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } {
            n if n > 3 && n <= i32::MAX as libc::c_long => n as i32,
            _ => 1024,
        };
        for fd in 3..max_fd {
            unsafe { libc::close(fd) };
        }
    }

    pub(crate) fn assert_single_threaded_for_fork(context: &str) -> Result<()> {
        let thread_count = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|line| line.starts_with("Threads:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|count| count.parse::<u32>().ok())
            });

        if thread_count == Some(1) {
            return Ok(());
        }

        Err(NucleusError::ExecError(format!(
            "{} requires a single-threaded process before fork, found {:?} threads",
            context, thread_count
        )))
    }

    fn gvisor_needs_precreated_userns(config: &ContainerConfig, host_is_root: bool) -> bool {
        config.use_gvisor
            && !host_is_root
            && config.user_ns_config.is_some()
            && matches!(
                config.network,
                NetworkMode::Bridge(_) | NetworkMode::GVisorHost
            )
    }

    fn prepare_runtime_base_override(
        config: &ContainerConfig,
        host_is_root: bool,
        needs_external_userns_mapping: bool,
    ) -> Result<Option<PathBuf>> {
        if !needs_external_userns_mapping {
            return Ok(None);
        }

        if !host_is_root {
            return Ok(Some(
                dirs::runtime_dir()
                    .map(|d| d.join("nucleus"))
                    .unwrap_or_else(std::env::temp_dir),
            ));
        }

        let user_config = config.user_ns_config.as_ref().ok_or_else(|| {
            NucleusError::ExecError("Missing user namespace configuration".to_string())
        })?;
        let host_uid =
            Self::mapped_host_id_for_container_id(&user_config.uid_mappings, 0, "uid mappings")?;
        let host_gid =
            Self::mapped_host_id_for_container_id(&user_config.gid_mappings, 0, "gid mappings")?;

        let root = PathBuf::from("/run/nucleus");
        Self::ensure_runtime_parent_dir(&root)?;

        let runtime_root = root.join("runtime");
        Self::ensure_runtime_parent_dir(&runtime_root)?;

        let base = runtime_root.join(&config.id);
        std::fs::create_dir_all(&base).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create user namespace runtime base {:?}: {}",
                base, e
            ))
        })?;
        chown(
            &base,
            Some(Uid::from_raw(host_uid)),
            Some(Gid::from_raw(host_gid)),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to chown user namespace runtime base {:?} to {}:{}: {}",
                base, host_uid, host_gid, e
            ))
        })?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to secure user namespace runtime base {:?}: {}",
                base, e
            ))
        })?;

        Ok(Some(base))
    }

    fn ensure_runtime_parent_dir(path: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create runtime parent dir {:?}: {}",
                path, e
            ))
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o711)).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to secure runtime parent dir {:?}: {}",
                path, e
            ))
        })?;
        Ok(())
    }

    fn prepare_workspace_staging(
        config: &mut ContainerConfig,
        runtime_base_override: Option<&Path>,
        host_is_root: bool,
        needs_external_userns_mapping: bool,
    ) -> Result<()> {
        if config.workspace.mode != WorkspaceMode::CopyInOut {
            return Ok(());
        }

        let source = config.workspace.host_path.clone().ok_or_else(|| {
            NucleusError::ConfigError(
                "--workspace-mode copy-in-out requires --workspace".to_string(),
            )
        })?;
        let parent = runtime_base_override
            .map(Path::to_path_buf)
            .unwrap_or_else(|| {
                dirs::runtime_dir()
                    .map(|d| d.join("nucleus"))
                    .unwrap_or_else(std::env::temp_dir)
            });
        std::fs::create_dir_all(&parent).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create workspace staging parent {:?}: {}",
                parent, e
            ))
        })?;

        let staging = parent.join(format!("workspace-{}", config.id));
        if staging.exists() {
            return Err(NucleusError::FilesystemError(format!(
                "Workspace staging directory already exists: {}",
                staging.display()
            )));
        }
        std::fs::create_dir(&staging).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create workspace staging directory {:?}: {}",
                staging, e
            ))
        })?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                NucleusError::FilesystemError(format!(
                    "Failed to secure workspace staging directory {:?}: {}",
                    staging, e
                ))
            },
        )?;

        copy_workspace_in(&source, &staging)?;

        if host_is_root && needs_external_userns_mapping {
            let user_config = config.user_ns_config.as_ref().ok_or_else(|| {
                NucleusError::ExecError("Missing user namespace configuration".to_string())
            })?;
            let host_uid = Self::mapped_host_id_for_container_id(
                &user_config.uid_mappings,
                0,
                "uid mappings",
            )?;
            let host_gid = Self::mapped_host_id_for_container_id(
                &user_config.gid_mappings,
                0,
                "gid mappings",
            )?;
            Self::chown_tree_no_symlinks(&staging, host_uid, host_gid)?;
        }

        config.workspace.staging_path = Some(staging);
        Ok(())
    }

    fn prepare_rootfs_overlay(
        config: &mut ContainerConfig,
        state_mgr: &ContainerStateManager,
        host_is_root: bool,
        needs_external_userns_mapping: bool,
    ) -> Result<()> {
        if config.rootfs_mode != RootfsMode::Overlay {
            return Ok(());
        }
        if config.rootfs_path.is_none() {
            return Err(NucleusError::ConfigError(
                "--rootfs-mode overlay requires a rootfs path".to_string(),
            ));
        }
        if config.rootfs_overlay.is_some() {
            return Ok(());
        }

        let overlay_dir = state_mgr.rootfs_overlay_dir_path(&config.id)?;
        if overlay_dir.exists() {
            return Err(NucleusError::FilesystemError(format!(
                "Rootfs overlay directory already exists: {}",
                overlay_dir.display()
            )));
        }
        std::fs::create_dir(&overlay_dir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create rootfs overlay directory {:?}: {}",
                overlay_dir, e
            ))
        })?;
        std::fs::set_permissions(&overlay_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                NucleusError::FilesystemError(format!(
                    "Failed to secure rootfs overlay directory {:?}: {}",
                    overlay_dir, e
                ))
            },
        )?;

        let upperdir = overlay_dir.join("upper");
        let workdir = overlay_dir.join("work");
        std::fs::create_dir(&upperdir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create rootfs overlay upperdir {:?}: {}",
                upperdir, e
            ))
        })?;
        std::fs::create_dir(&workdir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create rootfs overlay workdir {:?}: {}",
                workdir, e
            ))
        })?;

        if host_is_root && needs_external_userns_mapping {
            let user_config = config.user_ns_config.as_ref().ok_or_else(|| {
                NucleusError::ExecError("Missing user namespace configuration".to_string())
            })?;
            let host_uid = Self::mapped_host_id_for_container_id(
                &user_config.uid_mappings,
                0,
                "uid mappings",
            )?;
            let host_gid = Self::mapped_host_id_for_container_id(
                &user_config.gid_mappings,
                0,
                "gid mappings",
            )?;
            Self::chown_tree_no_symlinks(&overlay_dir, host_uid, host_gid)?;
        }

        config.rootfs_overlay = Some(crate::container::RootfsOverlayConfig { upperdir, workdir });
        Ok(())
    }

    fn chown_tree_no_symlinks(path: &Path, uid: u32, gid: u32) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat workspace staging path {:?}: {}",
                path, e
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Ok(());
        }

        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to chown workspace staging path {:?} to {}:{}: {}",
                path, uid, gid, e
            ))
        })?;

        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to read workspace staging dir {:?}: {}",
                    path, e
                ))
            })? {
                let entry = entry.map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to read workspace staging entry in {:?}: {}",
                        path, e
                    ))
                })?;
                Self::chown_tree_no_symlinks(&entry.path(), uid, gid)?;
            }
        }

        Ok(())
    }

    fn sync_workspace_copy_in_out(config: &ContainerConfig) -> Result<()> {
        if config.workspace.mode != WorkspaceMode::CopyInOut {
            return Ok(());
        }
        let Some(staging) = config.workspace.staging_path.as_ref() else {
            return Err(NucleusError::FilesystemError(
                "copy-in-out workspace missing staging path".to_string(),
            ));
        };
        let Some(host_path) = config.workspace.host_path.as_ref() else {
            return Err(NucleusError::FilesystemError(
                "copy-in-out workspace missing host path".to_string(),
            ));
        };

        sync_workspace_out(staging, host_path)
    }

    fn cleanup_workspace_staging(config: &ContainerConfig) {
        if config.workspace.mode != WorkspaceMode::CopyInOut {
            return;
        }
        if let Some(staging) = config.workspace.staging_path.as_ref() {
            if let Err(e) = std::fs::remove_dir_all(staging) {
                warn!(
                    "Failed to remove workspace staging directory {:?}: {}",
                    staging, e
                );
            }
        }
    }

    fn mapped_host_id_for_container_id(
        mappings: &[crate::isolation::IdMapping],
        container_id: u32,
        label: &str,
    ) -> Result<u32> {
        for mapping in mappings {
            let end = mapping
                .container_id
                .checked_add(mapping.count)
                .ok_or_else(|| {
                    NucleusError::ConfigError(format!(
                        "{} overflow for container id {}",
                        label, container_id
                    ))
                })?;
            if container_id >= mapping.container_id && container_id < end {
                return mapping
                    .host_id
                    .checked_add(container_id - mapping.container_id)
                    .ok_or_else(|| {
                        NucleusError::ConfigError(format!(
                            "{} host id overflow for container id {}",
                            label, container_id
                        ))
                    });
            }
        }

        Err(NucleusError::ConfigError(format!(
            "{} do not map container id {}",
            label, container_id
        )))
    }

    fn create_internal(&self, defer_exec_until_start: bool) -> Result<CreatedContainer> {
        let lifecycle_span = info_span!(
            "container.lifecycle",
            container.id = %self.config.id,
            container.name = %self.config.name,
            runtime = if self.config.use_gvisor { "gvisor" } else { "native" }
        );
        let _enter = lifecycle_span.enter();

        info!(
            "Creating container: {} (ID: {})",
            self.config.name, self.config.id
        );
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::ContainerStart,
            format!(
                "command={:?} mode={:?} runtime={}",
                crate::audit::redact_command(&self.config.command),
                self.config.service_mode,
                if self.config.use_gvisor {
                    "gvisor"
                } else {
                    "native"
                }
            ),
        );

        // Auto-detect if we need rootless mode
        let is_root = nix::unistd::Uid::effective().is_root();
        let mut config = self.config.clone();

        if !is_root && config.user_ns_config.is_none() {
            info!("Not running as root, automatically enabling rootless mode");
            config.namespaces.user = true;
            config.user_ns_config = Some(crate::isolation::UserNamespaceConfig::rootless());
        }

        // C2: When running as root without user namespace, enable UID remapping
        // in strict modes (mandatory) or warn in relaxed agent mode. Without user
        // namespace, a container escape yields full host root.
        if is_root && !config.namespaces.user {
            if config.service_mode.requires_user_namespace_mapping() {
                info!(
                    "Running as root in {}: enabling user namespace with UID remapping",
                    config.service_mode.label()
                );
                config.namespaces.user = true;
                config.user_ns_config =
                    Some(crate::isolation::UserNamespaceConfig::root_remapped());
            } else {
                warn!(
                    "Running as root WITHOUT user namespace isolation. \
                     Container processes will run as real host UID 0. \
                     Use --user-ns, strict-agent mode, or production mode for UID remapping."
                );
            }
        }

        // Validate service-mode invariants before anything else.
        config.validate_strict_agent_mode()?;
        config.validate_production_mode()?;
        if config.service_mode == ServiceMode::Production {
            let rootfs_path = config.rootfs_path.as_ref().ok_or_else(|| {
                NucleusError::ConfigError(
                    "Production mode requires explicit --rootfs path (no host bind mounts)"
                        .to_string(),
                )
            })?;
            config.rootfs_path = Some(validate_production_rootfs_path(rootfs_path)?);
        }
        Self::assert_kernel_lockdown(&config)?;

        Self::apply_network_mode_guards(&mut config, is_root)?;
        Self::apply_trust_level_guards(&mut config)?;
        config.validate_runtime_support()?;
        Self::validate_credential_broker_resolved_nat(&config, is_root)?;

        if let NetworkMode::Bridge(ref bridge_config) = config.network {
            let backend =
                bridge_config.selected_nat_backend(is_root, config.user_ns_config.is_some());
            if backend == NatBackend::Kernel && !is_root {
                return Err(NucleusError::NetworkError(
                    "Kernel bridge networking requires root. Use --nat-backend userspace or leave the default auto selection for rootless/native containers."
                        .to_string(),
                ));
            }
        }

        // Create state manager, honoring --root override if set
        let state_mgr = ContainerStateManager::new_with_root(config.state_root.clone())?;

        // Enforce name uniqueness among running containers
        if let Ok(all_states) = state_mgr.list_states() {
            if all_states.iter().any(|s| s.name == config.name) {
                return Err(NucleusError::ConfigError(format!(
                    "A container named '{}' already exists; use a different --name, \
                     or remove the stale state with 'nucleus delete'",
                    config.name
                )));
            }
        }

        // Create exec FIFO only for the two-phase create/start lifecycle.
        // The immediate `run()` lifecycle is still gated by parent_setup_pipe
        // below; it just does not need an externally-triggered start FIFO.
        let exec_fifo = if defer_exec_until_start {
            let exec_fifo = state_mgr.exec_fifo_path(&config.id)?;
            nix::unistd::mkfifo(&exec_fifo, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to create exec FIFO {:?}: {}",
                    exec_fifo, e
                ))
            })?;
            Some(exec_fifo)
        } else {
            None
        };

        // Try to create cgroup (optional for rootless mode)
        let cgroup_name = format!("nucleus-{}", config.id);
        let mut cgroup_opt = match Cgroup::create(&cgroup_name) {
            Ok(mut cgroup) => {
                // Try to set limits
                match cgroup.set_limits(&config.limits) {
                    Ok(_) => {
                        info!("Created cgroup with resource limits");
                        Some(cgroup)
                    }
                    Err(e) => {
                        if config.service_mode.requires_cgroup_enforcement() {
                            let _ = cgroup.cleanup();
                            return Err(NucleusError::CgroupError(format!(
                                "{} requires cgroup resource enforcement, but \
                                 applying limits failed: {}",
                                config.service_mode.label(),
                                e
                            )));
                        }
                        warn!("Failed to set cgroup limits: {}", e);
                        let _ = cgroup.cleanup();
                        None
                    }
                }
            }
            Err(e) => {
                if config.service_mode.requires_cgroup_enforcement() {
                    return Err(NucleusError::CgroupError(format!(
                        "{} requires cgroup resource enforcement, but \
                         cgroup creation failed: {}",
                        config.service_mode.label(),
                        e
                    )));
                }

                if config.user_ns_config.is_some() {
                    if config.limits.memory_bytes.is_some()
                        || config.limits.cpu_quota_us.is_some()
                        || config.limits.pids_max.is_some()
                    {
                        warn!(
                            "Running in rootless mode: requested resource limits cannot be \
                             enforced – cgroup creation requires root ({})",
                            e
                        );
                    } else {
                        debug!("Running in rootless mode without cgroup resource limits");
                    }
                } else {
                    warn!(
                        "Failed to create cgroup (running without resource limits): {}",
                        e
                    );
                }
                None
            }
        };

        // Resolve runsc path before fork, while still unprivileged.
        let runsc_path = if config.use_gvisor {
            Some(GVisorRuntime::resolve_path().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to resolve runsc path: {}", e))
            })?)
        } else {
            None
        };
        let gvisor_needs_precreated_userns = Self::gvisor_needs_precreated_userns(&config, is_root);
        let needs_external_userns_mapping = config.user_ns_config.is_some()
            && (!config.use_gvisor || gvisor_needs_precreated_userns);
        let runtime_base_override =
            Self::prepare_runtime_base_override(&config, is_root, needs_external_userns_mapping)?;
        Self::prepare_rootfs_overlay(
            &mut config,
            &state_mgr,
            is_root,
            needs_external_userns_mapping,
        )?;
        Self::prepare_workspace_staging(
            &mut config,
            runtime_base_override.as_deref(),
            is_root,
            needs_external_userns_mapping,
        )?;

        let event_sink = self.event_sink.clone();
        let mut native_pty = if config.terminal && !config.use_gvisor {
            Some(NativePty::open(config.console_size)?)
        } else {
            None
        };

        // Child notifies parent after namespaces are ready.
        let (ready_read, ready_write) = pipe().map_err(|e| {
            NucleusError::ExecError(format!("Failed to create namespace sync pipe: {}", e))
        })?;
        let userns_sync = if needs_external_userns_mapping {
            let (request_read, request_write) = pipe().map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to create user namespace request pipe: {}",
                    e
                ))
            })?;
            let (ack_read, ack_write) = pipe().map_err(|e| {
                NucleusError::ExecError(format!("Failed to create user namespace ack pipe: {}", e))
            })?;
            Some((request_read, request_write, ack_read, ack_write))
        } else {
            None
        };
        let (parent_setup_read, parent_setup_write) = pipe().map_err(|e| {
            NucleusError::ExecError(format!("Failed to create parent setup sync pipe: {}", e))
        })?;

        // M11: fork() in multi-threaded context. Flush log buffers and drop
        // tracing guards before fork to minimize deadlock risk from locks held
        // by other threads (tracing, allocator). The Tokio runtime is not yet
        // started at this point, so async thread contention is not a concern.
        Self::assert_single_threaded_for_fork("container create fork")?;
        // SAFETY: fork() is called before any Tokio runtime is created.
        // Only the main thread should be active at this point.
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(ready_write);
                drop(parent_setup_read);
                let (userns_request_read, userns_ack_write) =
                    if let Some((request_read, request_write, ack_read, ack_write)) = userns_sync {
                        drop(request_write);
                        drop(ack_read);
                        (Some(request_read), Some(ack_write))
                    } else {
                        (None, None)
                    };
                let mut native_console_master = native_pty.as_mut().and_then(|pty| {
                    drop(pty.slave.take());
                    pty.master.take()
                });
                info!("Forked child process: {}", child);

                // Use a closure so that on any error we kill the forked child.
                // If the PID-namespace child has already reported readiness,
                // also kill that target PID; it may otherwise be reparented
                // away from the intermediate process.
                let mut target_pid_for_cleanup: Option<u32> = None;
                let parent_setup = || -> Result<CreatedContainer> {
                    if needs_external_userns_mapping {
                        let user_config = config.user_ns_config.as_ref().ok_or_else(|| {
                            NucleusError::ExecError(
                                "Missing user namespace configuration in parent".to_string(),
                            )
                        })?;
                        let request_read = userns_request_read.as_ref().ok_or_else(|| {
                            NucleusError::ExecError(
                                "Missing user namespace request pipe in parent".to_string(),
                            )
                        })?;
                        let ack_write = userns_ack_write.as_ref().ok_or_else(|| {
                            NucleusError::ExecError(
                                "Missing user namespace ack pipe in parent".to_string(),
                            )
                        })?;

                        Self::wait_for_sync_byte(
                            request_read,
                            &format!(
                                "Child {} exited before requesting user namespace mappings",
                                child
                            ),
                            "Failed waiting for child user namespace request",
                        )?;
                        UserNamespaceMapper::new(user_config.clone())
                            .write_mappings_for_pid(child.as_raw() as u32)?;
                        Self::send_sync_byte(
                            ack_write,
                            "Failed to notify child that user namespace mappings are ready",
                        )?;
                    }

                    let target_pid = Self::wait_for_namespace_ready(&ready_read, child)?;
                    target_pid_for_cleanup = Some(target_pid);

                    if !config.use_gvisor {
                        if let Some(ref socket_path) = config.console_socket {
                            let master = native_console_master.take().ok_or_else(|| {
                                NucleusError::ExecError(
                                    "Terminal mode requested but no native PTY master is available"
                                        .to_string(),
                                )
                            })?;
                            NativePty::send_master_to_console_socket(socket_path, &master)?;
                            info!(
                                "Sent PTY master for container {} to console socket {}",
                                config.id,
                                socket_path.display()
                            );
                        }
                    }

                    let cgroup_path = cgroup_opt
                        .as_ref()
                        .map(|cgroup| cgroup.path().display().to_string());
                    let cpu_millicores = config
                        .limits
                        .cpu_quota_us
                        .map(|quota| quota.saturating_mul(1000) / config.limits.cpu_period_us);
                    let mut state = ContainerState::new(ContainerStateParams {
                        id: config.id.clone(),
                        name: config.name.clone(),
                        pid: target_pid,
                        command: config.command.clone(),
                        memory_limit: config.limits.memory_bytes,
                        cpu_limit: cpu_millicores,
                        using_gvisor: config.use_gvisor,
                        rootless: config.user_ns_config.is_some(),
                        cgroup_path,
                        process_uid: config.process_identity.uid,
                        process_gid: config.process_identity.gid,
                        additional_gids: config.process_identity.additional_gids.clone(),
                    });
                    state.environment = config.environment.iter().cloned().collect();
                    state.workdir = config.workdir.display().to_string();
                    state.config_hash = config.config_hash;
                    state.bundle_path =
                        config.rootfs_path.as_ref().map(|p| p.display().to_string());
                    state.rootfs_path =
                        config.rootfs_path.as_ref().map(|p| p.display().to_string());
                    state.rootfs_mode = config.rootfs_mode;
                    if let Some(overlay) = config.rootfs_overlay.as_ref() {
                        state.rootfs_upperdir = Some(overlay.upperdir.display().to_string());
                        state.rootfs_workdir = Some(overlay.workdir.display().to_string());
                    }

                    let mut network_driver: Option<BridgeDriver> = None;
                    let trace_reader = Self::maybe_start_seccomp_trace_reader(&config, target_pid)?;

                    // Transition: Creating -> Created
                    state.status = OciStatus::Created;
                    state_mgr.save_state(&state)?;

                    // Write PID file (OCI --pid-file)
                    if let Some(ref pid_path) = config.pid_file {
                        std::fs::write(pid_path, target_pid.to_string()).map_err(|e| {
                            NucleusError::ConfigError(format!(
                                "Failed to write pid-file '{}': {}",
                                pid_path.display(),
                                e
                            ))
                        })?;
                        info!("Wrote PID {} to {}", target_pid, pid_path.display());
                    }

                    if let Some(ref mut cgroup) = cgroup_opt {
                        cgroup.attach_process(target_pid)?;
                    }

                    let deny_logger = Self::maybe_start_seccomp_deny_logger(
                        &config,
                        target_pid,
                        cgroup_opt.as_ref().map(|cgroup| cgroup.path()),
                    )?;

                    if let NetworkMode::Bridge(ref bridge_config) = config.network {
                        match BridgeDriver::setup_with_id(
                            target_pid,
                            bridge_config,
                            &config.id,
                            is_root,
                            config.user_ns_config.is_some(),
                        ) {
                            Ok(net) => {
                                if let Some(ref egress) = config.egress_policy {
                                    if let Err(e) = net.apply_egress_policy(
                                        target_pid,
                                        egress,
                                        config.user_ns_config.is_some(),
                                    ) {
                                        if config.service_mode.enforces_strict_isolation() {
                                            return Err(NucleusError::NetworkError(format!(
                                                "Failed to apply egress policy: {}",
                                                e
                                            )));
                                        }
                                        warn!("Failed to apply egress policy: {}", e);
                                    }
                                }
                                if let Some(ref broker) = config.credential_broker {
                                    Self::probe_credential_broker(broker)?;
                                }
                                network_driver = Some(net);
                            }
                            Err(e) => {
                                if config.service_mode.enforces_strict_isolation() {
                                    return Err(e);
                                }
                                warn!("Failed to set up bridge networking: {}", e);
                            }
                        }
                    }

                    Self::send_sync_byte(
                        &parent_setup_write,
                        "Failed to notify child that parent setup is complete",
                    )?;

                    info!(
                        "Container {} created (child pid {}), waiting for start",
                        config.id, target_pid
                    );

                    Ok(CreatedContainer {
                        config,
                        state_mgr,
                        state,
                        child,
                        cgroup_opt,
                        network_driver,
                        trace_reader,
                        deny_logger,
                        exec_fifo_path: exec_fifo,
                        native_console_master,
                        event_sink,
                        _lifecycle_span: lifecycle_span.clone(),
                    })
                };

                parent_setup().map_err(|e| {
                    if let Some(target_pid) = target_pid_for_cleanup {
                        let _ = kill(Pid::from_raw(target_pid as i32), Signal::SIGKILL);
                    }
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    e
                })
            }
            ForkResult::Child => {
                drop(ready_read);
                drop(parent_setup_write);
                let (userns_request_write, userns_ack_read) =
                    if let Some((request_read, request_write, ack_read, ack_write)) = userns_sync {
                        drop(request_read);
                        drop(ack_write);
                        (Some(request_write), Some(ack_read))
                    } else {
                        (None, None)
                    };
                let native_console_slave = native_pty.as_mut().and_then(|pty| {
                    drop(pty.master.take());
                    pty.slave.take()
                });
                // H6: Mark inherited FDs > 2 close-on-exec before setup.
                Self::sanitize_fds();
                let temp_container = Container {
                    config,
                    runsc_path,
                    event_sink: None,
                };
                match temp_container.setup_and_exec(
                    Some(ready_write),
                    userns_request_write,
                    userns_ack_read,
                    Some(parent_setup_read),
                    exec_fifo,
                    runtime_base_override,
                    native_console_slave,
                ) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        error!("Container setup failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    /// Trigger a previously-created container to start by opening its exec FIFO.
    /// Used by the CLI `start` command.
    pub fn trigger_start(container_id: &str, state_root: Option<PathBuf>) -> Result<()> {
        let state_mgr = ContainerStateManager::new_with_root(state_root)?;
        let fifo_path = state_mgr.exec_fifo_path(container_id)?;
        if !fifo_path.exists() {
            return Err(NucleusError::ConfigError(format!(
                "No exec FIFO found for container {}; is it in 'created' state?",
                container_id
            )));
        }

        // Opening the FIFO for reading unblocks the child's open-for-write.
        let file = std::fs::File::open(&fifo_path)
            .map_err(|e| NucleusError::ExecError(format!("Failed to open exec FIFO: {}", e)))?;
        let mut buf = [0u8; 1];
        std::io::Read::read(&mut &file, &mut buf)
            .map_err(|e| NucleusError::ExecError(format!("Failed to read exec FIFO: {}", e)))?;
        drop(file);

        let _ = std::fs::remove_file(&fifo_path);

        // Update state to Running
        let mut state = state_mgr.resolve_container(container_id)?;
        state.status = OciStatus::Running;
        state_mgr.save_state(&state)?;

        Ok(())
    }

    /// Set up container environment and exec target process
    ///
    /// This runs in the child process after fork.
    /// Tracks FilesystemState and SecurityState machines to enforce correct ordering.
    fn setup_and_exec(
        &self,
        ready_pipe: Option<OwnedFd>,
        userns_request_pipe: Option<OwnedFd>,
        userns_ack_pipe: Option<OwnedFd>,
        parent_setup_pipe: Option<OwnedFd>,
        exec_fifo: Option<PathBuf>,
        runtime_base_override: Option<PathBuf>,
        native_console_slave: Option<OwnedFd>,
    ) -> Result<()> {
        let is_rootless = self.config.user_ns_config.is_some();
        let allow_degraded_security = Self::allow_degraded_security(&self.config);
        let context_manifest = if self.config.verify_context_integrity {
            self.config
                .context_dir
                .as_ref()
                .map(|dir| snapshot_context_dir(dir))
                .transpose()?
        } else {
            None
        };

        // Initialize state machines
        let mut fs_state = FilesystemState::Unmounted;
        let mut sec_state = SecurityState::Privileged;

        // gVisor creates the container namespaces. Rootless bridge and
        // gvisor-host pre-create the user namespace so runsc inherits a mapped
        // launch context. Bridge also pre-creates a netns for slirp/NAT setup;
        // gvisor-host intentionally keeps the host netns for runsc hostinet.
        if self.config.use_gvisor {
            let gvisor_precreated_userns =
                if Self::gvisor_needs_precreated_userns(&self.config, Uid::effective().is_root()) {
                    self.prepare_gvisor_handoff_namespace(
                        userns_request_pipe.as_ref(),
                        userns_ack_pipe.as_ref(),
                    )?
                } else {
                    false
                };

            if let Some(fd) = ready_pipe {
                Self::notify_namespace_ready(&fd, std::process::id())?;
            }
            if let Some(fd) = parent_setup_pipe.as_ref() {
                Self::wait_for_sync_byte(
                    fd,
                    "Parent closed setup pipe before signalling gVisor child",
                    "Failed waiting for parent setup acknowledgement",
                )?;
            }
            return self.setup_and_exec_gvisor(gvisor_precreated_userns);
        }

        // 1. Create namespaces in child and optionally configure user mapping.
        let mut namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());
        namespace_mgr.unshare_namespaces()?;
        if self.config.user_ns_config.is_some() {
            let request_fd = userns_request_pipe.as_ref().ok_or_else(|| {
                NucleusError::ExecError(
                    "Missing user namespace request pipe in container child".to_string(),
                )
            })?;
            let ack_fd = userns_ack_pipe.as_ref().ok_or_else(|| {
                NucleusError::ExecError(
                    "Missing user namespace acknowledgement pipe in container child".to_string(),
                )
            })?;

            Self::send_sync_byte(
                request_fd,
                "Failed to request user namespace mappings from parent",
            )?;
            Self::wait_for_sync_byte(
                ack_fd,
                "Parent closed user namespace ack pipe before mappings were written",
                "Failed waiting for parent to finish user namespace mappings",
            )?;
            Self::become_userns_root_for_setup()?;
        }

        // CLONE_NEWPID only applies to children created after unshare().
        // Create a child that will become PID 1 in the new namespace and exec the workload.
        if self.config.namespaces.pid {
            Self::assert_single_threaded_for_fork("PID namespace init fork")?;
            match unsafe { fork() }? {
                ForkResult::Parent { child } => {
                    if let Some(fd) = ready_pipe {
                        Self::notify_namespace_ready(&fd, child.as_raw() as u32)?;
                    }
                    std::process::exit(Self::wait_for_pid_namespace_child(child));
                }
                ForkResult::Child => {
                    if let Some(fd) = parent_setup_pipe.as_ref() {
                        Self::wait_for_sync_byte(
                            fd,
                            "Parent closed setup pipe before signalling PID 1 child",
                            "Failed waiting for parent setup acknowledgement",
                        )?;
                    }
                    // Continue container setup as PID 1 in the new namespace.
                }
            }
        } else {
            if let Some(fd) = ready_pipe {
                Self::notify_namespace_ready(&fd, std::process::id())?;
            }
            if let Some(fd) = parent_setup_pipe.as_ref() {
                Self::wait_for_sync_byte(
                    fd,
                    "Parent closed setup pipe before signalling container child",
                    "Failed waiting for parent setup acknowledgement",
                )?;
            }
        }

        // Namespace: Unshared -> Entered (process is now inside all namespaces)
        namespace_mgr.enter()?;

        // 2. Ensure no_new_privs BEFORE any mount operations.
        // This prevents exploitation of setuid binaries on bind-mounted paths
        // even if a subsequent MS_NOSUID remount fails.
        self.enforce_no_new_privs()?;
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::NoNewPrivsSet,
            "prctl(PR_SET_NO_NEW_PRIVS, 1) applied (early, before mounts)",
        );

        // 3. Set hostname if UTS namespace is enabled
        if let Some(hostname) = &self.config.hostname {
            namespace_mgr.set_hostname(hostname)?;
        }

        // 4. Mount tmpfs as container root
        // Filesystem: Unmounted -> Mounted
        // Use a private runtime directory instead of /tmp to avoid symlink
        // attacks and information disclosure on multi-user systems.
        let runtime_base = if let Some(path) = runtime_base_override {
            path
        } else if nix::unistd::Uid::effective().is_root() {
            PathBuf::from("/run/nucleus")
        } else {
            dirs::runtime_dir()
                .map(|d| d.join("nucleus"))
                .unwrap_or_else(std::env::temp_dir)
        };
        let _ = std::fs::create_dir_all(&runtime_base);
        let runtime_dir = Builder::new()
            .prefix("nucleus-runtime-")
            .tempdir_in(&runtime_base)
            .map_err(|e| {
                NucleusError::FilesystemError(format!("Failed to create runtime dir: {}", e))
            })?;
        let container_root = runtime_dir.path().to_path_buf();
        let mut tmpfs = TmpfsMount::new(&container_root, Some(1024 * 1024 * 1024)); // 1GB default
        tmpfs.mount()?;
        fs_state = fs_state.transition(FilesystemState::Mounted)?;

        let rootfs_overlay_mounted = if self.config.rootfs_mode == RootfsMode::Overlay {
            let rootfs_path = self.config.rootfs_path.as_ref().ok_or_else(|| {
                NucleusError::ConfigError(
                    "--rootfs-mode overlay requires a rootfs path".to_string(),
                )
            })?;
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(rootfs_path)?;
            }
            let overlay = self.config.rootfs_overlay.as_ref().ok_or_else(|| {
                NucleusError::FilesystemError(
                    "rootfs overlay mode missing prepared upper/work dirs".to_string(),
                )
            })?;
            overlay_mount_rootfs(
                &container_root,
                rootfs_path,
                &overlay.upperdir,
                &overlay.workdir,
            )?;
            true
        } else {
            false
        };

        // 4. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 5. Create device nodes and standard tmpfs mounts under /dev
        let dev_path = container_root.join("dev");
        create_dev_nodes(&dev_path, self.config.terminal)?;

        // /dev/shm – POSIX shared memory (shm_open). Required by PostgreSQL,
        // Redis, and other programs that use POSIX shared memory segments.
        let shm_path = dev_path.join("shm");
        std::fs::create_dir_all(&shm_path).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to create /dev/shm: {}", e))
        })?;
        nix::mount::mount(
            Some("shm"),
            &shm_path,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("mode=1777,size=64m"),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to mount tmpfs on /dev/shm: {}", e))
        })?;
        debug!("Mounted tmpfs on /dev/shm");

        // 6. Populate context if provided
        // Filesystem: Mounted -> Populated
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            LazyContextPopulator::populate(&self.config.context_mode, context_dir, &context_dest)?;
            if let Some(expected) = &context_manifest {
                verify_context_manifest(expected, &context_dest)?;
            }
        }
        fs_state = fs_state.transition(FilesystemState::Populated)?;

        // 7. Mount runtime paths: either a pre-built rootfs or host bind mounts
        if rootfs_overlay_mounted {
            debug!("Rootfs already mounted through overlayfs");
        } else if let Some(ref rootfs_path) = self.config.rootfs_path {
            let rootfs_path = if self.config.service_mode == ServiceMode::Production {
                validate_production_rootfs_path(rootfs_path)?
            } else {
                rootfs_path.clone()
            };
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(&rootfs_path)?;
            }
            bind_mount_rootfs(&container_root, &rootfs_path)?;
        } else {
            bind_mount_host_paths(&container_root, is_rootless)?;
        }

        // 7a. Mount the private sandbox home.
        mount_home_tmpfs(
            &container_root,
            &self.config.home,
            &self.config.process_identity,
        )?;

        // 7b. Mount explicit provider CLI config paths under the sandbox home.
        mount_provider_configs(
            &container_root,
            &self.config.home,
            &self.config.provider_configs,
        )?;

        // 7c. Mount or stage the first-class workspace at /workspace.
        mount_workspace(&container_root, &self.config.workspace)?;

        // 7d. Mount persistent or ephemeral volumes over the base filesystem.
        mount_volumes(&container_root, &self.config.volumes)?;

        // 7e. Write resolv.conf for bridge networking.
        // When rootfs is mounted, /etc is read-only, so we bind-mount a writable
        // resolv.conf over the top (same technique as secrets).
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            let bridge_dns = if bridge_config.selected_nat_backend(!is_rootless, is_rootless)
                == NatBackend::Userspace
                && bridge_config.dns.is_empty()
            {
                vec![UserspaceNetwork::default_dns_server(&bridge_config.subnet)?]
            } else {
                bridge_config.dns.clone()
            };
            if self.config.rootfs_path.is_some() {
                BridgeNetwork::bind_mount_resolv_conf(&container_root, &bridge_dns)?;
            } else {
                BridgeNetwork::write_resolv_conf(&container_root, &bridge_dns)?;
            }
        }

        // 7f. Mount secrets on an in-memory tmpfs in all modes.
        mount_secrets_inmemory(
            &container_root,
            &self.config.secrets,
            &self.config.process_identity,
        )?;

        // 8. Mount procfs (hidepid=2 in production mode to prevent PID enumeration)
        let proc_path = container_root.join("proc");
        let production_mode = self.config.service_mode == ServiceMode::Production;
        let hide_pids = production_mode;
        let procfs_best_effort = is_rootless && !production_mode;
        mount_procfs(
            &proc_path,
            procfs_best_effort,
            self.config.proc_readonly,
            hide_pids,
        )?;

        // 8b. Mask sensitive /proc paths to reduce kernel info leakage
        // SEC-06: In production mode, failures to mask critical paths are fatal.
        mask_proc_paths(
            &proc_path,
            self.config.service_mode == ServiceMode::Production,
        )?;

        // 9c. Run createRuntime hooks (after namespaces created, before pivot_root)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.create_runtime.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Creating,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.create_runtime, &hook_state, "createRuntime")?;
            }
        }

        // 10. Switch root filesystem
        // Filesystem: Populated -> Pivoted
        switch_root(&container_root, self.config.allow_chroot_fallback)?;
        fs_state = fs_state.transition(FilesystemState::Pivoted)?;
        debug!("Filesystem state: {:?}", fs_state);

        // 10b. Audit mount flags to verify filesystem hardening invariants
        audit_mounts(self.config.service_mode == ServiceMode::Production)?;
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::MountAuditPassed,
            "all mount flags verified",
        );

        // 10c. Run createContainer hooks (after pivot_root, before start)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.create_container.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Created,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.create_container, &hook_state, "createContainer")?;
            }
        }

        // 11. Drop capabilities and switch identity (Docker/runc convention).
        //
        // The identity switch (setuid/setgid) must happen between two cap phases:
        //   Phase 1: drop bounding set (needs CAP_SETPCAP), clear ambient/inheritable
        //   Identity: setgroups/setgid/setuid (needs CAP_SETUID/CAP_SETGID)
        //   Phase 2: clear permitted/effective (or kernel auto-clears on setuid)
        //
        // Custom cap policies (drop_except / apply_sets) do their own full drop,
        // so the two-phase approach only applies to the default drop-all path.
        let mut cap_mgr = CapabilityManager::new();
        if let Some(ref policy_path) = self.config.caps_policy {
            let policy: crate::security::CapsPolicy = crate::security::load_toml_policy(
                policy_path,
                self.config.caps_policy_sha256.as_deref(),
            )?;
            // H3: Reject dangerous capabilities in production mode
            if self.config.service_mode == ServiceMode::Production {
                policy.validate_production()?;
            }
            policy.apply(&mut cap_mgr)?;
            // Identity switch after custom policy (caps may already be restricted)
            Self::apply_process_identity_to_current_process(
                &self.config.process_identity,
                self.config.user_ns_config.is_some(),
            )?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                format!("capability policy applied from {:?}", policy_path),
            );
        } else {
            let overlay_rootfs_caps = [Capability::CAP_DAC_OVERRIDE, Capability::CAP_FOWNER];
            let overlay_rootfs_mode = self.config.rootfs_mode == RootfsMode::Overlay;

            // Phase 1: drop bounding set while CAP_SETPCAP is still effective
            if overlay_rootfs_mode {
                cap_mgr.drop_bounding_set_except(&overlay_rootfs_caps)?;
            } else {
                cap_mgr.drop_bounding_set()?;
            }

            // Identity switch: setgroups/setgid/setuid while CAP_SETUID/CAP_SETGID
            // are still in the effective set. For non-root target UIDs, the kernel
            // auto-clears permitted/effective after setuid().
            Self::apply_process_identity_to_current_process(
                &self.config.process_identity,
                self.config.user_ns_config.is_some(),
            )?;

            // Phase 2: explicitly clear any remaining caps (handles root-stays-root
            // case where kernel doesn't auto-clear).
            if overlay_rootfs_mode {
                cap_mgr.finalize_drop_except(&overlay_rootfs_caps)?;
            } else {
                cap_mgr.finalize_drop()?;
            }

            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                if overlay_rootfs_mode {
                    "capabilities dropped except CAP_DAC_OVERRIDE and CAP_FOWNER required for overlay rootfs copy-up"
                } else {
                    "all capabilities dropped including bounding set"
                },
            );
        }
        sec_state = sec_state.transition(SecurityState::CapabilitiesDropped)?;

        // 12b. RLIMIT backstop: defense-in-depth against fork bombs and fd exhaustion.
        // Must be applied BEFORE seccomp, since SYS_setrlimit is not in the allowlist.
        // SEC-05: In production mode, RLIMIT failures are fatal – a container
        // without resource limits is a privilege escalation vector.
        {
            let is_production = self.config.service_mode == ServiceMode::Production;

            if let Some(nproc_limit) = self.config.limits.pids_max {
                let rlim_nproc = libc::rlimit {
                    rlim_cur: nproc_limit,
                    rlim_max: nproc_limit,
                };
                // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
                if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc) } != 0 {
                    let err = std::io::Error::last_os_error();
                    if is_production {
                        return Err(NucleusError::SeccompError(format!(
                            "Failed to set RLIMIT_NPROC to {} in production mode: {}",
                            nproc_limit, err
                        )));
                    }
                    warn!("Failed to set RLIMIT_NPROC to {}: {}", nproc_limit, err);
                }
            }

            let rlim_nofile = libc::rlimit {
                rlim_cur: 1024,
                rlim_max: 1024,
            };
            // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim_nofile) } != 0 {
                let err = std::io::Error::last_os_error();
                if is_production {
                    return Err(NucleusError::SeccompError(format!(
                        "Failed to set RLIMIT_NOFILE to 1024 in production mode: {}",
                        err
                    )));
                }
                warn!("Failed to set RLIMIT_NOFILE to 1024: {}", err);
            }

            // RLIMIT_MEMLOCK: prevent container from pinning excessive physical
            // memory via mlock(). Default 64KB matches unprivileged default, but
            // in a user namespace the container appears as UID 0 and may have a
            // higher inherited limit. Configurable via --memlock for io_uring etc.
            let memlock_limit: u64 = self.config.limits.memlock_bytes.unwrap_or(64 * 1024);
            let rlim_memlock = libc::rlimit {
                rlim_cur: memlock_limit,
                rlim_max: memlock_limit,
            };
            // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim_memlock) } != 0 {
                let err = std::io::Error::last_os_error();
                if is_production {
                    return Err(NucleusError::SeccompError(format!(
                        "Failed to set RLIMIT_MEMLOCK to {} in production mode: {}",
                        memlock_limit, err
                    )));
                }
                warn!("Failed to set RLIMIT_MEMLOCK to {}: {}", memlock_limit, err);
            }
        }

        // 12c. Verify that namespace-creating capabilities are truly gone before
        // installing seccomp. Seccomp denies unfilterable clone3 and filters
        // clone namespace flags; capability dropping remains an independent guard.
        CapabilityManager::verify_no_namespace_caps(
            self.config.service_mode == ServiceMode::Production,
        )?;

        // 13. Apply seccomp filter (trace, profile-from-file, or built-in allowlist)
        // Security: CapabilitiesDropped -> SeccompApplied
        use crate::container::config::SeccompMode;
        let mut seccomp_mgr = SeccompManager::new();
        let allow_network = !matches!(self.config.network, NetworkMode::None);
        let seccomp_applied = match self.config.seccomp_mode {
            SeccompMode::Trace => {
                audit(
                    &self.config.id,
                    &self.config.name,
                    AuditEventType::SeccompApplied,
                    "seccomp trace mode: allow-all + LOG",
                );
                seccomp_mgr.apply_trace_filter()?
            }
            SeccompMode::Enforce => {
                if let Some(ref profile_path) = self.config.seccomp_profile {
                    audit(
                        &self.config.id,
                        &self.config.name,
                        AuditEventType::SeccompProfileLoaded,
                        format!("path={:?}", profile_path),
                    );
                    seccomp_mgr.apply_profile_from_file(
                        profile_path,
                        self.config.seccomp_profile_sha256.as_deref(),
                        self.config.seccomp_log_denied,
                    )?
                } else {
                    seccomp_mgr.apply_filter_for_network_mode(
                        allow_network,
                        allow_degraded_security,
                        self.config.seccomp_log_denied,
                        &self.config.seccomp_allow_syscalls,
                    )?
                }
            }
        };
        if seccomp_applied {
            sec_state = sec_state.transition(SecurityState::SeccompApplied)?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::SeccompApplied,
                format!("network={}", allow_network),
            );
        } else if !allow_degraded_security {
            return Err(NucleusError::SeccompError(
                "Seccomp filter is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Seccomp not enforced; container is running with degraded hardening");
        }

        // 14. Apply Landlock policy (from policy file or default hardcoded rules)
        let landlock_applied = if let Some(ref policy_path) = self.config.landlock_policy {
            let policy: crate::security::LandlockPolicy = crate::security::load_toml_policy(
                policy_path,
                self.config.landlock_policy_sha256.as_deref(),
            )?;
            // H4: Reject write+execute on same path in production
            if self.config.service_mode == ServiceMode::Production {
                policy.validate_production()?;
            }
            policy.apply(allow_degraded_security)?
        } else {
            let mut landlock_mgr = LandlockManager::new();
            landlock_mgr.assert_minimum_abi(self.config.service_mode == ServiceMode::Production)?;
            landlock_mgr.set_workspace_access(
                self.config.workspace.is_read_only(),
                self.config.workspace.allow_execute,
            );
            landlock_mgr.add_rw_path(&self.config.home.to_string_lossy());
            if self.config.rootfs_mode == RootfsMode::Overlay {
                landlock_mgr.add_rw_exec_path("/");
            }
            // Register volume mount destinations so Landlock permits access to them
            for provider_config in &self.config.provider_configs {
                let provider_dest = crate::filesystem::normalize_provider_config_destination(
                    &self.config.home,
                    &provider_config.dest,
                )?;
                if provider_config.read_only {
                    landlock_mgr.add_ro_path(&provider_dest.to_string_lossy());
                } else {
                    landlock_mgr.add_rw_path(&provider_dest.to_string_lossy());
                }
            }
            for vol in &self.config.volumes {
                if vol.read_only {
                    landlock_mgr.add_ro_path(&vol.dest.to_string_lossy());
                } else {
                    landlock_mgr.add_rw_path(&vol.dest.to_string_lossy());
                }
            }
            landlock_mgr.apply_container_policy_with_mode(allow_degraded_security)?
        };
        if seccomp_applied && landlock_applied {
            sec_state = sec_state.transition(SecurityState::LandlockApplied)?;
            if self.config.seccomp_mode == SeccompMode::Trace {
                warn!("Security state NOT locked: seccomp in trace mode (allow-all)");
            } else {
                sec_state = sec_state.transition(SecurityState::Locked)?;
            }
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::LandlockApplied,
                if self.config.rootfs_mode == RootfsMode::Overlay
                    && self.config.seccomp_mode == SeccompMode::Trace
                {
                    "landlock applied with overlay rootfs trade-off: / is granted rwx; seccomp trace mode means security state is not locked"
                        .to_string()
                } else if self.config.rootfs_mode == RootfsMode::Overlay {
                    "landlock applied with overlay rootfs trade-off: / is granted rwx so rootfs writes can copy up"
                        .to_string()
                } else if self.config.seccomp_mode == SeccompMode::Trace {
                    "landlock applied, but seccomp in trace mode – not locked".to_string()
                } else {
                    "security state locked: all hardening layers active".to_string()
                },
            );
        } else if !allow_degraded_security {
            return Err(NucleusError::LandlockError(
                "Landlock policy is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Security state not locked; one or more hardening controls are inactive");
        }
        debug!("Security state: {:?}", sec_state);

        // 14c. Block on exec FIFO until start() opens it for reading.
        // This implements the OCI two-phase create/start: all container setup
        // is complete, but the user process doesn't exec until explicitly started.
        if let Some(ref fifo_path) = exec_fifo {
            debug!("Waiting on exec FIFO {:?} for start signal", fifo_path);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(fifo_path)
                .map_err(|e| {
                    NucleusError::ExecError(format!("Failed to open exec FIFO for writing: {}", e))
                })?;
            std::io::Write::write_all(&mut &file, &[0u8]).map_err(|e| {
                NucleusError::ExecError(format!("Failed to write exec FIFO sync byte: {}", e))
            })?;
            drop(file);
            debug!("Exec FIFO released, proceeding to exec");
        }

        // 14d. Run startContainer hooks (after start signal, before user process exec)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.start_container.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Running,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.start_container, &hook_state, "startContainer")?;
            }
        }

        if let Some(slave) = native_console_slave {
            NativePty::configure_child_terminal(slave)?;
        }

        // 15. In production mode with PID namespace, run as a mini-init (PID 1)
        // that reaps zombies and forwards signals, rather than exec-ing directly.
        if self.config.service_mode == ServiceMode::Production && self.config.namespaces.pid {
            return self.run_as_init();
        }

        // 15b. Agent mode: exec target process directly
        self.exec_command()?;

        // Should never reach here
        Ok(())
    }

    /// Forward selected signals to child process using sigwait (no async signal handlers).
    ///
    /// Returns a stop flag and join handle. Set the flag to `true` and join
    /// the handle to cleanly shut down the forwarding thread.
    pub(super) fn setup_signal_forwarding_static(
        child: Pid,
    ) -> Result<(Arc<AtomicBool>, JoinHandle<()>)> {
        let mut set = SigSet::empty();
        for signal in [
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGHUP,
            Signal::SIGQUIT,
            Signal::SIGUSR1,
            Signal::SIGUSR2,
            Signal::SIGWINCH,
        ] {
            set.add(signal);
        }

        let unblock_set = set;
        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&unblock_set), None).map_err(|e| {
            NucleusError::ExecError(format!("Failed to block forwarded signals: {}", e))
        })?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let handle = std::thread::Builder::new()
            .name("sig-forward".to_string())
            .spawn(move || {
                // The thread owns unblock_set and uses it for sigwait.
                loop {
                    if let Ok(signal) = unblock_set.wait() {
                        // Check the stop flag *after* waking so that the
                        // wake-up signal (SIGUSR1) is not forwarded to the
                        // child during shutdown.
                        if stop_clone.load(Ordering::Acquire) {
                            break;
                        }
                        let _ = kill(child, signal);
                    }
                }
            })
            .map_err(|e| {
                // Restore the signal mask so the caller isn't left with
                // signals permanently blocked.
                let mut restore = SigSet::empty();
                for signal in [
                    Signal::SIGTERM,
                    Signal::SIGINT,
                    Signal::SIGHUP,
                    Signal::SIGQUIT,
                    Signal::SIGUSR1,
                    Signal::SIGUSR2,
                    Signal::SIGWINCH,
                ] {
                    restore.add(signal);
                }
                let _ = pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&restore), None);
                NucleusError::ExecError(format!("Failed to spawn signal thread: {}", e))
            })?;

        info!("Signal forwarding configured");
        Ok((stop, handle))
    }

    /// Wait for child process to exit
    pub(super) fn wait_for_child_static(child: Pid) -> Result<i32> {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => {
                    return Ok(code);
                }
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    info!("Child killed by signal: {:?}", signal);
                    return Ok(128 + signal as i32);
                }
                Err(nix::errno::Errno::EINTR) => {
                    continue;
                }
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed to wait for child: {}",
                        e
                    )));
                }
                _ => {
                    continue;
                }
            }
        }
    }

    fn wait_for_namespace_ready(ready_read: &OwnedFd, child: Pid) -> Result<u32> {
        let mut pid_buf = [0u8; 4];
        loop {
            match read(ready_read, &mut pid_buf) {
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(4) => return Ok(u32::from_ne_bytes(pid_buf)),
                Ok(0) => {
                    return Err(NucleusError::ExecError(format!(
                        "Child {} exited before namespace initialization",
                        child
                    )))
                }
                Ok(_) => {
                    return Err(NucleusError::ExecError(
                        "Invalid namespace sync payload from child".to_string(),
                    ))
                }
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed waiting for child namespace setup: {}",
                        e
                    )))
                }
            }
        }
    }

    fn notify_namespace_ready(fd: &OwnedFd, pid: u32) -> Result<()> {
        let payload = pid.to_ne_bytes();
        let mut written = 0;
        while written < payload.len() {
            let n = write(fd, &payload[written..]).map_err(|e| {
                NucleusError::ExecError(format!("Failed to notify namespace readiness: {}", e))
            })?;
            if n == 0 {
                return Err(NucleusError::ExecError(
                    "Failed to notify namespace readiness: short write".to_string(),
                ));
            }
            written += n;
        }
        Ok(())
    }

    fn send_sync_byte(fd: &OwnedFd, error_context: &str) -> Result<()> {
        let mut written = 0;
        let payload = [1u8];
        while written < payload.len() {
            let n = write(fd, &payload[written..])
                .map_err(|e| NucleusError::ExecError(format!("{}: {}", error_context, e)))?;
            if n == 0 {
                return Err(NucleusError::ExecError(format!(
                    "{}: short write",
                    error_context
                )));
            }
            written += n;
        }
        Ok(())
    }

    fn wait_for_sync_byte(fd: &OwnedFd, eof_context: &str, error_context: &str) -> Result<()> {
        let mut payload = [0u8; 1];
        loop {
            match read(fd, &mut payload) {
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(1) => return Ok(()),
                Ok(0) => return Err(NucleusError::ExecError(eof_context.to_string())),
                Ok(_) => {
                    return Err(NucleusError::ExecError(format!(
                        "{}: invalid sync payload",
                        error_context
                    )))
                }
                Err(e) => return Err(NucleusError::ExecError(format!("{}: {}", error_context, e))),
            }
        }
    }

    fn become_userns_root_for_setup() -> Result<()> {
        setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)).map_err(|e| {
            NucleusError::NamespaceError(format!(
                "Failed to become gid 0 inside mapped user namespace: {}",
                e
            ))
        })?;
        setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).map_err(|e| {
            NucleusError::NamespaceError(format!(
                "Failed to become uid 0 inside mapped user namespace: {}",
                e
            ))
        })?;
        Self::restore_gvisor_handoff_capabilities()?;
        debug!("Switched setup process to uid/gid 0 inside mapped user namespace");
        Ok(())
    }

    fn gvisor_handoff_capabilities() -> CapsHashSet {
        [
            Capability::CAP_CHOWN,
            Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_FOWNER,
            Capability::CAP_FSETID,
            Capability::CAP_SYS_CHROOT,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SETUID,
            Capability::CAP_SETGID,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_SETPCAP,
        ]
        .into_iter()
        .collect()
    }

    fn restore_gvisor_handoff_capabilities() -> Result<()> {
        let caps = Self::gvisor_handoff_capabilities();
        let permitted = caps::read(None, CapSet::Permitted).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to read gVisor handoff permitted capabilities: {}",
                e
            ))
        })?;
        let missing: Vec<_> = caps.difference(&permitted).copied().collect();
        if !missing.is_empty() {
            return Err(NucleusError::CapabilityError(format!(
                "Missing gVisor handoff permitted capabilities after entering mapped user namespace: {:?}",
                missing
            )));
        }
        let extra_permitted: Vec<_> = permitted.difference(&caps).copied().collect();
        let bounding = caps::read(None, CapSet::Bounding).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to read gVisor handoff bounding capabilities: {}",
                e
            ))
        })?;
        let extra_bounding: Vec<_> = bounding.difference(&caps).copied().collect();
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to clear gVisor handoff ambient capabilities: {}",
                e
            ))
        })?;
        // The caps crate preserves the other base sets during each capset.
        // Lower effective before removing permitted extras so the kernel never
        // sees effective bits outside the new permitted set.
        caps::set(None, CapSet::Effective, &caps).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to set gVisor handoff effective capabilities: {}",
                e
            ))
        })?;
        caps::set(None, CapSet::Inheritable, &caps).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to set gVisor handoff inheritable capabilities: {}",
                e
            ))
        })?;
        for cap in &extra_bounding {
            caps::drop(None, CapSet::Bounding, *cap).map_err(|e| {
                NucleusError::CapabilityError(format!(
                    "Failed to drop extra gVisor handoff bounding capability {cap:?}: {e}"
                ))
            })?;
        }
        for cap in &extra_permitted {
            caps::drop(None, CapSet::Permitted, *cap).map_err(|e| {
                NucleusError::CapabilityError(format!(
                    "Failed to drop extra gVisor handoff permitted capability {cap:?}: {e}"
                ))
            })?;
        }
        caps::set(None, CapSet::Ambient, &caps).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to set gVisor handoff ambient capabilities: {}",
                e
            ))
        })?;
        debug!(
            ?caps,
            ?extra_permitted,
            ?extra_bounding,
            "Restored gVisor handoff capabilities inside mapped user namespace"
        );
        Ok(())
    }

    fn prepare_gvisor_handoff_namespace(
        &self,
        userns_request_pipe: Option<&OwnedFd>,
        userns_ack_pipe: Option<&OwnedFd>,
    ) -> Result<bool> {
        let mut precreated_userns = false;
        if self.config.user_ns_config.is_some() && !Uid::effective().is_root() {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).map_err(|e| {
                NucleusError::NamespaceError(format!(
                    "Failed to unshare gVisor handoff user namespace: {}",
                    e
                ))
            })?;

            let request_fd = userns_request_pipe.ok_or_else(|| {
                NucleusError::ExecError(
                    "Missing user namespace request pipe in gVisor handoff child".to_string(),
                )
            })?;
            let ack_fd = userns_ack_pipe.ok_or_else(|| {
                NucleusError::ExecError(
                    "Missing user namespace acknowledgement pipe in gVisor handoff child"
                        .to_string(),
                )
            })?;

            Self::send_sync_byte(
                request_fd,
                "Failed to request gVisor handoff user namespace mappings from parent",
            )?;
            Self::wait_for_sync_byte(
                ack_fd,
                "Parent closed user namespace ack pipe before gVisor handoff mappings were written",
                "Failed waiting for parent to finish gVisor handoff user namespace mappings",
            )?;
            Self::become_userns_root_for_setup()?;
            precreated_userns = true;
        }

        if matches!(self.config.network, NetworkMode::Bridge(_)) {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).map_err(|e| {
                NucleusError::NamespaceError(format!(
                    "Failed to unshare gVisor bridge network namespace: {}",
                    e
                ))
            })?;
        }
        Ok(precreated_userns)
    }

    fn wait_for_pid_namespace_child(child: Pid) -> i32 {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => return code,
                Ok(WaitStatus::Signaled(_, signal, _)) => return 128 + signal as i32,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return 1,
                _ => continue,
            }
        }
    }
}

impl CreatedContainer {
    fn emit_control_event(&self, event: ContainerControlEvent) {
        if let Some(sink) = &self.event_sink {
            if let Err(e) = sink.emit(&event) {
                warn!("Failed to emit control event: {}", e);
            }
        }
    }

    fn collect_resource_stats(
        cgroup_path: Option<&str>,
    ) -> (Option<ResourceStats>, Option<String>) {
        match cgroup_path {
            Some(path) => match ResourceStats::from_cgroup(path) {
                Ok(stats) => (Some(stats), None),
                Err(e) => (None, Some(e.to_string())),
            },
            None => (None, None),
        }
    }

    /// Start phase: release the child via the exec FIFO, transition to Running,
    /// then wait for the child to exit with full lifecycle management.
    pub fn start(mut self) -> Result<i32> {
        let config = &self.config;
        let _enter = self._lifecycle_span.enter();

        // Open the exec FIFO for reading – this unblocks the child's
        // blocking open-for-write, allowing it to proceed to exec.
        if let Some(exec_fifo_path) = &self.exec_fifo_path {
            let file = std::fs::File::open(exec_fifo_path).map_err(|e| {
                NucleusError::ExecError(format!("Failed to open exec FIFO for reading: {}", e))
            })?;
            let mut buf = [0u8; 1];
            let read = std::io::Read::read(&mut &file, &mut buf).map_err(|e| {
                NucleusError::ExecError(format!("Failed to read exec FIFO sync byte: {}", e))
            })?;
            if read != 1 {
                return Err(NucleusError::ExecError(
                    "Exec FIFO closed before start signal was delivered".to_string(),
                ));
            }
            let _ = std::fs::remove_file(exec_fifo_path);
        }

        // Transition: Created -> Running
        let target_pid = self.state.pid;
        let child = self.child;
        self.state.status = OciStatus::Running;
        self.state_mgr.save_state(&self.state)?;
        self.emit_control_event(ContainerControlEvent::started(
            config,
            target_pid,
            self.state.cgroup_path.clone(),
        ));

        let (sig_stop, sig_handle) =
            Container::setup_signal_forwarding_static(Pid::from_raw(target_pid as i32))?;

        // Guard ensures signal thread is stopped on any exit path (including early ? returns).
        let mut sig_guard = SignalThreadGuard {
            stop: Some(sig_stop),
            handle: Some(sig_handle),
        };

        let mut console_relay = if config.terminal && config.console_socket.is_none() {
            self.native_console_master
                .take()
                .map(NativeConsoleRelay::start)
                .transpose()?
        } else {
            None
        };

        // Run readiness probe before declaring service ready
        if let Some(ref probe) = config.readiness_probe {
            let notify_socket = if config.sd_notify {
                std::env::var("NOTIFY_SOCKET").ok()
            } else {
                None
            };
            Container::run_readiness_probe(
                target_pid,
                &config.name,
                probe,
                config.user_ns_config.is_some(),
                config.use_gvisor,
                &config.process_identity,
                notify_socket.as_deref(),
            )?;
        }

        // Start health check thread if configured
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let health_handle = if let Some(ref hc) = config.health_check {
            if !hc.command.is_empty() {
                let hc = hc.clone();
                let pid = target_pid;
                let container_name = config.name.clone();
                let rootless = config.user_ns_config.is_some();
                let using_gvisor = config.use_gvisor;
                let process_identity = config.process_identity.clone();
                let cancel = cancel_flag.clone();
                Some(std::thread::spawn(move || {
                    Container::health_check_loop(
                        pid,
                        &container_name,
                        rootless,
                        using_gvisor,
                        &hc,
                        &process_identity,
                        &cancel,
                    );
                }))
            } else {
                None
            }
        } else {
            None
        };

        // Guard ensures health check thread is cancelled on any exit path.
        let mut health_guard = HealthThreadGuard {
            cancel: Some(cancel_flag),
            handle: health_handle,
        };

        // Run poststart hooks (after user process started, in parent)
        if let Some(ref hooks) = config.hooks {
            if !hooks.poststart.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: config.id.clone(),
                    status: OciStatus::Running,
                    pid: target_pid,
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.poststart, &hook_state, "poststart")?;
            }
        }

        let mut child_waited = false;
        let mut run_result: Result<i32> = (|| {
            let exit_code = Container::wait_for_child_static(child)?;

            // Transition: Running -> Stopped
            self.state.status = OciStatus::Stopped;
            let _ = self.state_mgr.save_state(&self.state);

            child_waited = true;
            Ok(exit_code)
        })();

        // Explicitly stop threads (guards would do this on drop too, but
        // explicit teardown keeps ordering visible).
        if let Some(relay) = console_relay.as_mut() {
            relay.stop();
        }
        health_guard.stop();
        sig_guard.stop();

        // Run poststop hooks (best-effort)
        if let Some(ref hooks) = config.hooks {
            if !hooks.poststop.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: config.id.clone(),
                    status: OciStatus::Stopped,
                    pid: 0,
                    bundle: String::new(),
                };
                OciHooks::run_hooks_best_effort(&hooks.poststop, &hook_state, "poststop");
            }
        }

        let cgroup_path_for_summary = self.state.cgroup_path.clone();
        let (resource_stats, resource_stats_error) =
            Self::collect_resource_stats(cgroup_path_for_summary.as_deref());
        let mut cleanup_errors = Vec::new();

        let workspace_synced = match Container::sync_workspace_copy_in_out(config) {
            Ok(()) => true,
            Err(e) => {
                let msg = format!("workspace sync failed: {}", e);
                warn!("{}", msg);
                cleanup_errors.push(msg);
                if run_result.is_ok() {
                    run_result = Err(e);
                }
                false
            }
        };
        if workspace_synced {
            Container::cleanup_workspace_staging(config);
        }

        if let Some(net) = self.network_driver.take() {
            if let Err(e) = net.cleanup() {
                let msg = format!("network cleanup failed: {}", e);
                warn!("{}", msg);
                cleanup_errors.push(msg);
            }
        }

        if !child_waited {
            let _ = kill(child, Signal::SIGKILL);
            let _ = waitpid(child, None);
        }

        if let Some(reader) = self.trace_reader.take() {
            reader.stop_and_flush();
        }

        if let Some(logger) = self.deny_logger.take() {
            logger.stop();
        }

        if let Some(cgroup) = self.cgroup_opt.take() {
            if let Err(e) = cgroup.cleanup() {
                let msg = format!("cgroup cleanup failed: {}", e);
                warn!("{}", msg);
                cleanup_errors.push(msg);
            }
        }

        if config.use_gvisor {
            if let Err(e) = Container::cleanup_gvisor_artifacts(&config.id) {
                let msg = format!("gVisor artifact cleanup failed for {}: {}", config.id, e);
                warn!("{}", msg);
                cleanup_errors.push(msg);
            }
        }

        if let Err(e) = self.state_mgr.delete_state(&config.id) {
            let msg = format!("state cleanup failed for {}: {}", config.id, e);
            warn!("{}", msg);
            cleanup_errors.push(msg);
        }

        let exit_status_event = match &run_result {
            Ok(exit_code) => ExitStatusEvent::code(*exit_code),
            Err(e) => ExitStatusEvent::error(e.to_string()),
        };
        self.emit_control_event(ContainerControlEvent::summary(
            config,
            target_pid,
            cgroup_path_for_summary,
            exit_status_event,
            resource_stats,
            resource_stats_error,
            CleanupEvent::from_errors(cleanup_errors),
        ));

        match run_result {
            Ok(exit_code) => {
                audit(
                    &config.id,
                    &config.name,
                    AuditEventType::ContainerStop,
                    format!("exit_code={}", exit_code),
                );
                info!(
                    "Container {} ({}) exited with code {}",
                    config.name, config.id, exit_code
                );
                Ok(exit_code)
            }
            Err(e) => {
                audit_error(
                    &config.id,
                    &config.name,
                    AuditEventType::ContainerStop,
                    format!("error={}", e),
                );
                Err(e)
            }
        }
    }
}

/// RAII guard that stops the signal-forwarding thread on drop.
struct SignalThreadGuard {
    stop: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl SignalThreadGuard {
    fn stop(&mut self) {
        if let Some(flag) = self.stop.take() {
            flag.store(true, Ordering::Release);
            if let Some(handle) = self.handle.as_ref() {
                super::signals::wake_sigwait_thread(handle, Signal::SIGUSR1);
            }
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SignalThreadGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// RAII guard that cancels the health-check thread on drop.
struct HealthThreadGuard {
    cancel: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl HealthThreadGuard {
    fn stop(&mut self) {
        if let Some(flag) = self.cancel.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HealthThreadGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::KernelLockdownMode;
    use crate::network::NetworkMode;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvLock {
        _guard: MutexGuard<'static, ()>,
    }

    impl EnvLock {
        fn acquire() -> Self {
            Self {
                _guard: ENV_LOCK.lock().unwrap(),
            }
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn extract_fn_body<'a>(source: &'a str, fn_signature: &str) -> &'a str {
        let fn_start = source
            .find(fn_signature)
            .unwrap_or_else(|| panic!("function '{}' not found in source", fn_signature));
        let after = &source[fn_start..];
        let open = after
            .find('{')
            .unwrap_or_else(|| panic!("no opening brace found for '{}'", fn_signature));
        let mut depth = 0u32;
        let mut end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        &after[..end]
    }

    #[test]
    fn test_container_config() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!config.id.is_empty());
        assert_eq!(config.command, vec!["/bin/sh"]);
        assert!(config.use_gvisor);
    }

    #[test]
    fn test_run_uses_immediate_start_path_with_parent_setup_gate() {
        let source = include_str!("runtime.rs");
        let fn_start = source.find("pub fn run(&self) -> Result<i32>").unwrap();
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
        let run_body = &after[..fn_end];
        assert!(
            run_body.contains("create_internal(false)"),
            "run() must bypass deferred exec FIFO startup to avoid cross-root deadlocks"
        );
        assert!(
            !run_body.contains("self.create()?.start()"),
            "run() must not route through create()+start()"
        );

        let create_body = extract_fn_body(source, "fn create_internal");
        assert!(
            create_body.contains("parent_setup_write"),
            "immediate run() must still use a parent setup gate before child setup proceeds"
        );
    }

    #[test]
    fn test_container_config_with_name() {
        let config =
            ContainerConfig::try_new(Some("mycontainer".to_string()), vec!["/bin/sh".to_string()])
                .unwrap();
        assert_eq!(config.name, "mycontainer");
        assert!(!config.id.is_empty());
        assert_ne!(config.id, config.name);
    }

    #[test]
    fn test_allow_degraded_security_requires_explicit_config() {
        let strict = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!Container::allow_degraded_security(&strict));

        let relaxed = strict.clone().with_allow_degraded_security(true);
        assert!(Container::allow_degraded_security(&relaxed));
    }

    #[test]
    fn test_env_var_cannot_force_degraded_security_without_explicit_opt_in() {
        let prev = std::env::var_os("NUCLEUS_ALLOW_DEGRADED_SECURITY");
        std::env::set_var("NUCLEUS_ALLOW_DEGRADED_SECURITY", "1");

        let strict = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!Container::allow_degraded_security(&strict));

        let explicit = strict.with_allow_degraded_security(true);
        assert!(Container::allow_degraded_security(&explicit));

        match prev {
            Some(v) => std::env::set_var("NUCLEUS_ALLOW_DEGRADED_SECURITY", v),
            None => std::env::remove_var("NUCLEUS_ALLOW_DEGRADED_SECURITY"),
        }
    }

    #[test]
    fn test_host_network_requires_explicit_opt_in() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_network(NetworkMode::Host)
            .with_allow_host_network(false);
        let err = Container::apply_network_mode_guards(&mut config, true).unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
    }

    #[test]
    fn test_host_network_opt_in_disables_net_namespace() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(!config.namespaces.net);
    }

    #[test]
    fn test_host_network_with_gvisor_requires_gvisor_host_mode() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true);
        let err = Container::apply_network_mode_guards(&mut config, true).unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
        assert!(err.to_string().contains("gvisor-host"));
    }

    #[test]
    fn test_gvisor_host_requires_explicit_opt_in() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(false);
        let err = Container::apply_network_mode_guards(&mut config, true).unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
        assert!(err.to_string().contains("--allow-host-network"));
    }

    #[test]
    fn test_gvisor_host_preserves_namespace_config_for_oci_setup() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::GVisorHost)
            .with_allow_host_network(true);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(config.namespaces.net);
    }

    #[test]
    fn test_non_host_network_does_not_require_host_opt_in() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::None)
            .with_allow_host_network(false);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(config.namespaces.net);
    }

    #[test]
    fn test_credential_broker_auto_nat_rejects_rootless_userspace_resolution() {
        let broker =
            crate::network::CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let mut config = ContainerConfig::try_new(None, vec!["/bin/true".to_string()])
            .unwrap()
            .with_network(NetworkMode::Bridge(crate::network::BridgeConfig::default()))
            .with_credential_broker(broker.clone())
            .with_egress_policy(broker.egress_policy())
            .with_rootless();

        let err = Container::validate_credential_broker_resolved_nat(&config, false).unwrap_err();
        assert!(err.to_string().contains("auto resolves to userspace"));

        config.user_ns_config = None;
        config.namespaces.user = false;
        assert!(Container::validate_credential_broker_resolved_nat(&config, true).is_ok());
    }

    #[test]
    fn test_parse_kernel_lockdown_mode() {
        assert_eq!(
            Container::parse_active_lockdown_mode("none [integrity] confidentiality"),
            Some(KernelLockdownMode::Integrity)
        );
        assert_eq!(
            Container::parse_active_lockdown_mode("none integrity [confidentiality]"),
            Some(KernelLockdownMode::Confidentiality)
        );
        assert_eq!(
            Container::parse_active_lockdown_mode("[none] integrity"),
            None
        );
    }

    #[test]
    fn test_stage_gvisor_secret_files_rewrites_sources_under_stage_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source-secret");
        std::fs::write(&source, "supersecret").unwrap();

        let staged = Container::stage_gvisor_secret_files(
            &temp.path().join("stage"),
            &[crate::container::SecretMount {
                source: source.clone(),
                dest: std::path::PathBuf::from("/etc/app/secret.txt"),
                mode: 0o400,
            }],
            &crate::container::ProcessIdentity::root(),
        )
        .unwrap();

        assert_eq!(staged.len(), 1);
        assert!(staged[0].source.starts_with(temp.path().join("stage")));
        assert_eq!(
            std::fs::read_to_string(&staged[0].source).unwrap(),
            "supersecret"
        );
    }

    #[test]
    fn test_stage_gvisor_secret_files_rejects_symlink_source() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source-secret");
        let link = temp.path().join("source-link");
        std::fs::write(&source, "supersecret").unwrap();
        symlink(&source, &link).unwrap();

        let err = Container::stage_gvisor_secret_files(
            &temp.path().join("stage"),
            &[crate::container::SecretMount {
                source: link,
                dest: std::path::PathBuf::from("/etc/app/secret.txt"),
                mode: 0o400,
            }],
            &crate::container::ProcessIdentity::root(),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("O_NOFOLLOW"),
            "gVisor secret staging must reject symlink sources"
        );
    }

    #[test]
    fn test_native_runtime_uses_inmemory_secrets_for_all_modes() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        assert!(
            fn_body.contains("mount_secrets_inmemory("),
            "setup_and_exec must use in-memory secret mounting"
        );
        assert!(
            !fn_body.contains("mount_secrets(&"),
            "setup_and_exec must not bind-mount secrets from the host"
        );
    }

    #[test]
    fn test_overlay_rootfs_registers_writable_landlock_root() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        assert!(
            fn_body.contains("self.config.rootfs_mode == RootfsMode::Overlay")
                && fn_body.contains("landlock_mgr.add_rw_exec_path(\"/\")"),
            "overlay rootfs mode must permit writes through the default Landlock policy"
        );
    }

    #[test]
    fn test_overlay_rootfs_keeps_only_write_caps() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        assert!(
            fn_body.contains(
                "let overlay_rootfs_caps = [Capability::CAP_DAC_OVERRIDE, Capability::CAP_FOWNER]"
            ) && fn_body.contains("cap_mgr.drop_bounding_set_except(&overlay_rootfs_caps)")
                && fn_body.contains("cap_mgr.finalize_drop_except(&overlay_rootfs_caps)"),
            "overlay rootfs mode must keep only DAC_OVERRIDE/FOWNER through the cap drop"
        );
    }

    #[test]
    fn test_native_production_procfs_mount_is_not_rootless_best_effort() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");

        assert!(
            fn_body.contains(
                "let production_mode = self.config.service_mode == ServiceMode::Production;"
            ),
            "setup_and_exec must derive an explicit production-mode guard for procfs hardening"
        );
        assert!(
            fn_body.contains("let procfs_best_effort = is_rootless && !production_mode;"),
            "rootless best-effort procfs fallback must be disabled in production mode"
        );
        assert!(
            fn_body.contains(
                "mount_procfs(\n            &proc_path,\n            procfs_best_effort,"
            ),
            "mount_procfs must receive the production-aware best-effort flag"
        );
    }

    #[test]
    fn test_gvisor_uses_inmemory_secret_staging_for_all_modes() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("with_inmemory_secret_mounts"),
            "gVisor setup must use the tmpfs-backed secret staging path"
        );
        assert!(
            !fn_body.contains("with_secret_mounts"),
            "gVisor setup must not bind-mount host secret paths"
        );
    }

    #[test]
    fn test_gvisor_precreated_userns_skips_nested_oci_userns() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        let precreated_check = fn_body.find("if precreated_userns").unwrap();
        let remove_oci_userns = fn_body.find("without_user_namespace").unwrap();
        let oci_userns = fn_body.find("with_rootless_user_namespace").unwrap();
        assert!(
            precreated_check < remove_oci_userns && remove_oci_userns < oci_userns,
            "pre-created rootless gVisor userns must remove nested OCI user namespace setup"
        );
    }

    #[test]
    fn test_gvisor_precreated_userns_disables_oci_no_new_privileges() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("if precreated_userns")
                && fn_body.contains("with_no_new_privileges(false)"),
            "pre-created rootless gVisor userns must not pass OCI noNewPrivileges to runsc"
        );
    }

    #[test]
    fn test_gvisor_rootless_passes_runsc_rootless() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("let runsc_rootless = rootless_gvisor"),
            "rootless gVisor must tell runsc to keep rootless supervisor semantics"
        );
    }

    #[test]
    fn test_gvisor_rootless_preserves_configured_platform() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("let platform = self.config.gvisor_platform;")
                && fn_body.contains("platform,"),
            "rootless gVisor must preserve the configured runsc platform"
        );
        assert!(
            !fn_body.contains("GVisorPlatform::Ptrace"),
            "rootless gVisor must not silently rewrite systrap to ptrace"
        );
    }

    #[test]
    fn test_gvisor_precreated_userns_keeps_store_runsc_binary() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("let stage_runsc_binary = false")
                && fn_body.contains("stage_runsc_binary,"),
            "pre-created rootless gVisor userns must keep runsc on its validated store path"
        );
    }

    #[test]
    fn test_gvisor_root_remap_keeps_production_supervisor_exec_policy() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        let helper = extract_fn_body(source, "fn require_gvisor_supervisor_exec_policy");
        let policy = fn_body.find("let require_supervisor_exec_policy").unwrap();
        assert!(
            fn_body[policy..].contains(
                "require_gvisor_supervisor_exec_policy(self.config.service_mode, precreated_userns)"
            ),
            "gVisor setup must use the explicit supervisor policy predicate"
        );
        assert!(
            helper.contains("ServiceMode::Production")
                && helper.contains("!precreated_userns")
                && !helper.contains("rootless_gvisor")
                && !helper.contains("user_ns_config"),
            "root-remapped user namespace config must not disable the production exec policy"
        );
    }

    #[test]
    fn test_gvisor_bridge_rootless_requests_external_userns_mapping() {
        let source = include_str!("runtime.rs");
        let create_body = extract_fn_body(source, "fn create_internal");
        let helper = extract_fn_body(source, "fn gvisor_needs_precreated_userns");
        assert!(
            create_body.contains("let gvisor_needs_precreated_userns"),
            "gVisor bridge rootless setup must request parent-written userns mappings"
        );
        assert!(
            create_body.contains("!config.use_gvisor || gvisor_needs_precreated_userns"),
            "external mapping request must be routed through the gVisor pre-created userns predicate"
        );
        assert!(
            helper.contains("NetworkMode::Bridge(_)"),
            "external mapping request must include gVisor bridge networking"
        );
    }

    #[test]
    fn test_gvisor_host_rootless_requests_external_userns_mapping() {
        let source = include_str!("runtime.rs");
        let helper = extract_fn_body(source, "fn gvisor_needs_precreated_userns");
        assert!(
            helper.contains("NetworkMode::GVisorHost"),
            "gVisor host mode must use the pre-created userns handoff so runsc hostinet starts rootless"
        );
        assert!(
            helper.contains("!host_is_root") && helper.contains("config.user_ns_config.is_some()"),
            "gVisor host handoff must stay scoped to rootless user namespace launches"
        );
    }

    #[test]
    fn test_gvisor_handoff_namespace_creates_userns_before_bridge_netns() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn prepare_gvisor_handoff_namespace");
        let userns = fn_body.find("CLONE_NEWUSER").unwrap();
        let request = fn_body.find("send_sync_byte").unwrap();
        let become_root = fn_body.find("become_userns_root_for_setup").unwrap();
        let bridge_only = fn_body
            .find("if matches!(self.config.network, NetworkMode::Bridge(_))")
            .unwrap();
        let netns = fn_body.find("CLONE_NEWNET").unwrap();
        assert!(
            userns < request
                && request < become_root
                && become_root < bridge_only
                && bridge_only < netns,
            "rootless gVisor handoff must map userns before creating the bridge netns"
        );
        assert!(
            !fn_body.contains("NetworkMode::GVisorHost"),
            "gVisor host handoff must not create an OCI network namespace before runsc hostinet"
        );
    }

    #[test]
    fn test_gvisor_handoff_userns_preserves_caps_for_runsc_exec() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn become_userns_root_for_setup");
        let setuid = fn_body.find("setresuid").unwrap();
        let restore = fn_body.find("restore_gvisor_handoff_capabilities").unwrap();
        assert!(
            setuid < restore,
            "gVisor setup must restore exec-time capabilities after switching to uid 0 in the mapped namespace"
        );
        assert!(
            !fn_body.contains("set_keepcaps"),
            "gVisor setup must let the uid 0 switch grant namespace capabilities instead of preserving the pre-switch empty set"
        );
    }

    #[test]
    fn test_gvisor_handoff_narrows_permitted_caps() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn restore_gvisor_handoff_capabilities");
        let read_permitted = fn_body.find("caps::read(None, CapSet::Permitted)").unwrap();
        let missing_check = fn_body.find("if !missing.is_empty()").unwrap();
        let set_effective = fn_body.find("caps::set(None, CapSet::Effective").unwrap();
        let drop_permitted = fn_body.find("caps::drop(None, CapSet::Permitted").unwrap();
        assert!(
            read_permitted < missing_check && missing_check < set_effective,
            "gVisor handoff must verify existing permitted capabilities"
        );
        assert!(
            fn_body.contains("permitted.difference(&caps)")
                && set_effective < drop_permitted
                && !fn_body.contains("caps::set(None, CapSet::Permitted"),
            "gVisor handoff must drop extra permitted capabilities without trying to raise permitted"
        );
    }

    #[test]
    fn test_gvisor_handoff_narrows_bounding_caps() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn restore_gvisor_handoff_capabilities");
        let set_effective = fn_body.find("caps::set(None, CapSet::Effective").unwrap();
        let drop_bounding = fn_body.find("caps::drop(None, CapSet::Bounding").unwrap();
        let drop_permitted = fn_body.find("caps::drop(None, CapSet::Permitted").unwrap();
        assert!(
            fn_body.contains("caps::read(None, CapSet::Bounding)")
                && fn_body.contains("bounding.difference(&caps)")
                && set_effective < drop_bounding
                && drop_bounding < drop_permitted,
            "gVisor handoff must drop extra bounding capabilities before exec"
        );
    }

    #[test]
    fn test_gvisor_handoff_caps_are_bounded_to_runsc_startup() {
        let caps = Container::gvisor_handoff_capabilities();
        for cap in [
            Capability::CAP_CHOWN,
            Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_FOWNER,
            Capability::CAP_FSETID,
            Capability::CAP_SYS_CHROOT,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SETUID,
            Capability::CAP_SETGID,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_SETPCAP,
        ] {
            assert!(
                caps.contains(&cap),
                "gVisor handoff caps must include {cap:?}"
            );
        }
        assert_eq!(
            caps.len(),
            11,
            "gVisor handoff caps must stay aligned with the frontend systemd bounding set"
        );
        assert!(
            !caps.contains(&Capability::CAP_NET_ADMIN) && !caps.contains(&Capability::CAP_MKNOD),
            "gVisor handoff must not grow into broader host-style privilege"
        );
    }

    #[test]
    fn test_native_fork_sites_assert_single_threaded() {
        let runtime_source = include_str!("runtime.rs");
        let create_body = extract_fn_body(runtime_source, "fn create_internal");
        assert!(
            create_body.contains("assert_single_threaded_for_fork(\"container create fork\")"),
            "create_internal must assert single-threaded before fork"
        );

        let setup_body = extract_fn_body(runtime_source, "fn setup_and_exec");
        assert!(
            setup_body.contains("assert_single_threaded_for_fork(\"PID namespace init fork\")"),
            "PID namespace setup must assert single-threaded before fork"
        );

        let exec_source = include_str!("exec.rs");
        let init_body = extract_fn_body(exec_source, "fn run_as_init");
        assert!(
            init_body.contains("assert_single_threaded_for_fork(\"init supervisor fork\")"),
            "run_as_init must assert single-threaded before fork"
        );
    }

    #[test]
    fn test_parent_setup_gate_released_after_network_policy() {
        let source = include_str!("runtime.rs");
        let create_body = extract_fn_body(source, "fn create_internal");

        let cgroup_attach = create_body.find("cgroup.attach_process").unwrap();
        let deny_logger = create_body.find("maybe_start_seccomp_deny_logger").unwrap();
        let bridge_setup = create_body.find("BridgeDriver::setup_with_id").unwrap();
        let egress_policy = create_body.find("net.apply_egress_policy").unwrap();
        let broker_probe = create_body.find("probe_credential_broker").unwrap();
        let release = create_body
            .find("Failed to notify child that parent setup is complete")
            .unwrap();
        let created = create_body.find("Ok(CreatedContainer").unwrap();

        assert!(
            cgroup_attach < bridge_setup,
            "parent setup gate must not release before cgroup attachment"
        );
        assert!(
            cgroup_attach < deny_logger && deny_logger < bridge_setup,
            "seccomp deny logger must start after cgroup attachment and before workload release"
        );
        assert!(
            create_body.contains("cgroup_opt.as_ref().map(|cgroup| cgroup.path())"),
            "seccomp deny logger must receive the container cgroup scope"
        );
        assert!(
            bridge_setup < egress_policy && egress_policy < broker_probe && broker_probe < release,
            "parent setup gate must not release before bridge, egress policy, and broker probe setup"
        );
        assert!(
            release < created,
            "create_internal must release the child only after all fallible parent setup succeeds"
        );
        assert!(
            !create_body.contains("cgroup attachment is complete"),
            "child setup gate must not be released immediately after cgroup attachment"
        );
    }

    #[test]
    fn test_child_waits_for_parent_setup_before_exec_paths() {
        let source = include_str!("runtime.rs");
        let setup_body = extract_fn_body(source, "fn setup_and_exec");

        let gvisor_wait = setup_body
            .find("Parent closed setup pipe before signalling gVisor child")
            .unwrap();
        let gvisor_exec = setup_body.find("setup_and_exec_gvisor").unwrap();
        assert!(
            gvisor_wait < gvisor_exec,
            "gVisor path must wait for parent setup before execing runsc"
        );

        let pid1_wait = setup_body
            .find("Parent closed setup pipe before signalling PID 1 child")
            .unwrap();
        let namespace_enter = setup_body.find("namespace_mgr.enter()?").unwrap();
        assert!(
            pid1_wait < namespace_enter,
            "PID namespace child must wait for parent setup before container setup continues"
        );

        let direct_wait = setup_body
            .find("Parent closed setup pipe before signalling container child")
            .unwrap();
        assert!(
            direct_wait < namespace_enter,
            "non-PID namespace child must wait for parent setup before container setup continues"
        );
    }

    #[test]
    fn test_parent_setup_failure_kills_reported_target_pid() {
        let source = include_str!("runtime.rs");
        let create_body = extract_fn_body(source, "fn create_internal");

        let record_target = create_body
            .find("target_pid_for_cleanup = Some(target_pid)")
            .unwrap();
        let kill_target = create_body
            .find("kill(Pid::from_raw(target_pid as i32), Signal::SIGKILL)")
            .unwrap();
        let kill_intermediate = create_body.find("kill(child, Signal::SIGKILL)").unwrap();

        assert!(
            record_target < kill_target,
            "parent setup cleanup must remember the reported target PID"
        );
        assert!(
            kill_target < kill_intermediate,
            "cleanup must kill the target PID before reaping the intermediate fork"
        );
    }

    #[test]
    fn test_run_as_init_keeps_identity_drop_in_workload_child_path() {
        let source = include_str!("exec.rs");
        let fn_body = extract_fn_body(source, "fn run_as_init");
        assert!(
            !fn_body.contains("Self::apply_process_identity_to_current_process("),
            "run_as_init must not drop identity before the supervisor fork"
        );
        assert!(
            fn_body.contains("self.exec_command()?"),
            "workload child must still route through exec_command for identity application"
        );
    }

    #[test]
    fn test_run_as_init_parent_closes_nonstdio_fds() {
        let runtime_source = include_str!("runtime.rs");
        let close_body = extract_fn_body(runtime_source, "fn close_nonstdio_fds");
        assert!(
            close_body.contains("libc::SYS_close_range, 3u32, u32::MAX, 0u32")
                && close_body.contains("libc::close(fd)"),
            "close_nonstdio_fds must immediately close descriptors, not only mark them CLOEXEC"
        );
        assert!(
            !close_body.contains("CLOSE_RANGE_CLOEXEC")
                && !close_body.contains("FD_CLOEXEC")
                && !close_body.contains("F_SETFD"),
            "PID 1 supervisor cleanup must not rely on close-on-exec"
        );

        let exec_source = include_str!("exec.rs");
        let init_body = extract_fn_body(exec_source, "fn run_as_init");
        let parent = init_body.find("ForkResult::Parent").unwrap();
        let close = init_body.find("Self::close_nonstdio_fds()").unwrap();
        let signal_setup = init_body.find("let mut sigset = SigSet::empty()").unwrap();
        let child = init_body.find("ForkResult::Child").unwrap();
        assert!(
            parent < close && close < signal_setup && close < child,
            "run_as_init must close inherited FDs in the non-execing PID 1 parent before supervisor work"
        );
    }

    #[test]
    fn test_signal_thread_shutdown_uses_thread_directed_wakeup() {
        let runtime_source = include_str!("runtime.rs");
        let exec_source = include_str!("exec.rs");
        let signal_helper_source = include_str!("signals.rs");
        let process_directed_wakeup = ["kill(Pid::this()", ", Signal::SIGUSR1)"].concat();

        assert!(
            !runtime_source.contains(&process_directed_wakeup),
            "CreatedContainer signal-thread shutdown must not send process-directed SIGUSR1"
        );
        assert!(
            !exec_source.contains(&process_directed_wakeup),
            "init supervisor signal-thread shutdown must not send process-directed SIGUSR1"
        );
        assert!(
            signal_helper_source.contains("libc::pthread_kill"),
            "signal-thread shutdown must wake the sigwait owner with a thread-directed signal"
        );
    }

    #[test]
    fn test_cleanup_gvisor_artifacts_removes_artifact_dir() {
        let _env_lock = EnvLock::acquire();
        let temp = tempfile::TempDir::new().unwrap();
        let _artifact_base = EnvVarGuard::set(
            "NUCLEUS_GVISOR_ARTIFACT_BASE",
            temp.path().join("gvisor-artifacts"),
        );
        let artifact_dir = Container::gvisor_artifact_dir("cleanup-test");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("config.json"), "{}").unwrap();

        Container::cleanup_gvisor_artifacts("cleanup-test").unwrap();
        assert!(!artifact_dir.exists());
    }

    #[test]
    fn test_gvisor_artifact_base_prefers_xdg_runtime_dir() {
        let _env_lock = EnvLock::acquire();
        let temp = tempfile::TempDir::new().unwrap();
        let _artifact_override = EnvVarGuard::remove("NUCLEUS_GVISOR_ARTIFACT_BASE");
        let _runtime = EnvVarGuard::set("XDG_RUNTIME_DIR", temp.path());

        assert_eq!(
            Container::gvisor_artifact_dir("xdg-test"),
            temp.path().join("nucleus-gvisor").join("xdg-test")
        );
    }

    #[test]
    fn test_health_check_loop_supports_cancellation() {
        // BUG-18: health_check_loop must accept an AtomicBool cancel flag
        // and check it between iterations for prompt shutdown.
        // Function lives in health.rs after the runtime split.
        let source = include_str!("health.rs");
        let fn_start = source.find("fn health_check_loop").unwrap();
        let fn_body = &source[fn_start..fn_start + 2500];
        assert!(
            fn_body.contains("AtomicBool") && fn_body.contains("cancel"),
            "health_check_loop must accept an AtomicBool cancellation flag"
        );
        // Must also check cancellation during sleep
        assert!(
            fn_body.contains("cancellable_sleep") || fn_body.contains("cancel.load"),
            "health_check_loop must check cancellation during sleep intervals"
        );
    }

    #[test]
    fn test_runtime_probes_do_not_spawn_host_nsenter() {
        // Both functions live in health.rs after the runtime split.
        let source = include_str!("health.rs");

        let readiness_start = source.find("fn run_readiness_probe").unwrap();
        let readiness_body = &source[readiness_start..readiness_start + 2500];
        assert!(
            !readiness_body.contains("Command::new(&nsenter_bin)"),
            "readiness probes must not execute via host nsenter"
        );

        let health_start = source.find("fn health_check_loop").unwrap();
        let health_body = &source[health_start..health_start + 2200];
        assert!(
            !health_body.contains("Command::new(&nsenter_bin)"),
            "health checks must not execute via host nsenter"
        );
    }

    #[test]
    fn test_oci_mount_strip_prefix_no_expect() {
        // BUG-08: prepare_oci_mountpoints must not use expect() - use ? instead
        // Function lives in gvisor_setup.rs after the runtime split.
        let source = include_str!("gvisor_setup.rs");
        let fn_start = source.find("fn prepare_oci_mountpoints").unwrap();
        let fn_body = &source[fn_start..fn_start + 600];
        assert!(
            !fn_body.contains(".expect("),
            "prepare_oci_mountpoints must not use expect() – return Err instead"
        );
    }

    #[test]
    fn test_notify_namespace_ready_validates_write_length() {
        // BUG-02: notify_namespace_ready must validate that all bytes were written
        let source = include_str!("runtime.rs");
        let fn_start = source.find("fn notify_namespace_ready").unwrap();
        let fn_body = &source[fn_start..fn_start + 500];
        // Must check the return value of write() for partial writes
        assert!(
            fn_body.contains("written")
                || fn_body.contains("4")
                || fn_body.contains("payload.len()"),
            "notify_namespace_ready must validate complete write of all 4 bytes"
        );
    }

    #[test]
    fn test_rlimit_failures_fatal_in_production() {
        // SEC-05: RLIMIT failures must be fatal in production mode
        let source = include_str!("runtime.rs");
        let rlimit_start = source.find("12b. RLIMIT backstop").unwrap();
        let rlimit_section = &source[rlimit_start..rlimit_start + 2000];
        assert!(
            rlimit_section.contains("is_production") && rlimit_section.contains("return Err"),
            "RLIMIT failures must return Err in production mode"
        );
    }

    #[test]
    fn test_tcp_readiness_probe_uses_portable_check() {
        // BUG-14: TCP readiness probe must not use /dev/tcp (bash-only)
        // Function lives in health.rs after the runtime split.
        let source = include_str!("health.rs");
        let probe_fn = source.find("TcpPort(port)").unwrap();
        let probe_body = &source[probe_fn..probe_fn + 500];
        assert!(
            !probe_body.contains("/dev/tcp"),
            "TCP readiness probe must not use /dev/tcp (bash-specific, fails on dash/ash)"
        );
    }
}
