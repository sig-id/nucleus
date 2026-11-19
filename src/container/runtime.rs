use crate::audit::{audit, audit_error, AuditEventType};
use crate::container::{
    ContainerConfig, ContainerState, ContainerStateManager, ContainerStateParams, OciStatus,
    RootfsMode, ServiceMode, WorkspaceMode,
};
use crate::error::{NucleusError, Result, StateTransition};
use crate::filesystem::{
    audit_mounts, bind_mount_host_paths, bind_mount_rootfs, copy_workspace_in, create_minimal_fs,
    device_node_spec, mount_home_tmpfs, mount_procfs, mount_provider_configs,
    mount_secrets_inmemory, mount_volumes, mount_workspace, open_overlay_dirs,
    overlay_mount_rootfs_pinned, resolve_gpu_devices, snapshot_context_dir, switch_root,
    sync_workspace_out, validate_production_rootfs_path, verify_context_manifest,
    verify_rootfs_attestation, DeviceNodeSpec, FilesystemState, GpuDeviceSet, LazyContextPopulator,
    TmpfsMount,
};
use crate::isolation::{NamespaceManager, UserNamespaceConfig, UserNamespaceMapper};
use crate::network::{BridgeDriver, BridgeNetwork, NatBackend, NetworkMode};
use crate::resources::{Cgroup, ResourceStats};
use crate::security::{
    CapabilityManager, CapabilitySets, GVisorRuntime, LandlockManager, NativeLandlock,
    NativeSeccomp, OciContainerState, OciHooks, SeccompDenyLogger, SeccompTraceReader,
    SecurityState,
};
use crate::telemetry::{
    CleanupEvent, ContainerControlEvent, EventSink, ExitStatusEvent, NativeSecurityOutcome,
};
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
use super::supervisor_link::{die_with_supervisor, Lifeline, ReapedTree};

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
    outcome_reader: Option<OwnedFd>,
    mapped_gvisor_base: Option<PathBuf>,
    _landlock_handoff: Option<crate::security::landlock_handoff::LandlockHandoff>,
    /// Relays broker connections; dropping it stops and joins its threads.
    broker_forwarder: Option<crate::network::broker_forwarder::BrokerForwarder>,
    pub(super) native_console_master: Option<OwnedFd>,
    pub(super) event_sink: Option<EventSink>,
    pub(super) _lifecycle_span: tracing::Span,
    /// Open for as long as the supervisor lives; see `supervisor_link`.
    _lifeline: OwnedFd,
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

    /// Stage a verified layer with the same namespace mapping used for execution.
    pub fn run_image(mut self, image: crate::image::VerifiedImage) -> Result<i32> {
        let is_root = Uid::effective().is_root();
        self.config.namespaces.user = true;
        Self::configure_user_namespace(
            &mut self.config,
            is_root,
            UserNamespaceConfig::root_remapped,
        )?;
        let manager = ContainerStateManager::new_with_root(self.config.state_root.clone())?;
        let path = manager.rootfs_overlay_dir_path(&self.config.id)?;
        // The state manager returns a validated filename beneath its state root.
        let overlay = Builder::new()
            .prefix(path.file_name().expect("overlay filename"))
            .rand_bytes(0)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(path.parent().expect("overlay state directory"))?;
        let upper = overlay.path().join("upper");
        let work = overlay.path().join("work");
        std::fs::create_dir(&upper)?;
        std::fs::create_dir(&work)?;
        if is_root {
            let map = self
                .config
                .user_ns_config
                .as_ref()
                .expect("image namespace configured");
            let ([uid], [gid]) = (map.uid_mappings.as_slice(), map.gid_mappings.as_slice()) else {
                return Err(NucleusError::ConfigError(
                    "Root image staging requires one UID and GID range".into(),
                ));
            };
            image.copy_remapped_diff_to_upper(&upper, uid, gid)?;
            chown(
                &work,
                Some(Uid::from_raw(uid.host_id)),
                Some(Gid::from_raw(gid.host_id)),
            )?;
            std::fs::set_permissions(overlay.path(), std::fs::Permissions::from_mode(0o711))?;
        } else {
            image.copy_diff_to_upper(&upper)?;
        }
        drop(image);
        self.config = self.config.with_rootfs_overlay(upper, work);
        self.run()
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
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", std::process::id())) {
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

        if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", std::process::id())) {
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
        let thread_count = std::fs::read_to_string(format!("/proc/{}/status", std::process::id()))
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

    fn gvisor_needs_mount_staging(config: &ContainerConfig) -> bool {
        (config.workspace.host_path.is_some()
            && config.workspace.mode != super::WorkspaceMode::CopyInOut)
            || !config.provider_configs.is_empty()
            || !config.secrets.is_empty()
            || config
                .volumes
                .iter()
                .any(|v| matches!(v.source, super::VolumeSource::Bind { .. }))
            || config
                .rootfs_path
                .as_deref()
                .is_some_and(|p| !crate::filesystem::is_immediate_nix_store_object_path(p))
    }

    fn gvisor_needs_precreated_userns(config: &ContainerConfig, host_is_root: bool) -> bool {
        config.use_gvisor
            && config.user_ns_config.is_some()
            && ((host_is_root && config.service_mode == ServiceMode::Agent)
                || (!host_is_root && Self::gvisor_needs_mount_staging(config))
                || (!host_is_root
                    && matches!(
                        config.network,
                        NetworkMode::Bridge(_) | NetworkMode::GVisorHost
                    )))
    }

    /// Host device nodes the gVisor supervisor must be allowed to open, for
    /// the cgroup device allowlist installed on GPU launches.
    ///
    /// The allowlist is deny-by-default and applies to the runsc process that
    /// the parent attaches to the container cgroup before acknowledging
    /// setup, so without these entries a KVM-backend sandbox could never open
    /// `/dev/kvm` to start. The workload inside the sandbox still cannot reach
    /// these host devices.
    fn gvisor_supervisor_device_specs(config: &ContainerConfig) -> Vec<DeviceNodeSpec> {
        if !config.use_gvisor {
            return Vec::new();
        }
        config
            .gvisor_platform
            .supervisor_host_devices()
            .iter()
            .filter_map(|path| device_node_spec(Path::new(path)))
            .collect()
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
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&base)?;
        let directory = std::fs::File::open(&base)?;
        nix::unistd::fchown(
            &directory,
            Some(Uid::from_raw(host_uid)),
            Some(Gid::from_raw(host_gid)),
        )?;

        // Prepare explicit bundles before handing off to the mapped identity.
        if config.use_gvisor {
            if let Some(bundle_dir) = config.bundle_dir.as_deref() {
                Self::prepare_mapped_bundle_dir(bundle_dir, host_uid, host_gid)?;
            }
        }

        Ok(Some(base))
    }

    /// Prepare an explicit `--bundle` directory for the mapped gVisor
    /// supervisor.
    ///
    /// Root-launched agent handoffs demote the fork child to the mapped
    /// supervisor (the host identity of container ID 0) before
    /// `OciBundle::create` runs against the explicit bundle path. Create the
    /// directory while still host root and transfer it to the supervisor so
    /// previously working explicit bundles keep working.
    fn prepare_mapped_bundle_dir(path: &Path, host_uid: u32, host_gid: u32) -> Result<()> {
        let path = std::env::current_dir()?.join(path);
        let parent = path
            .parent()
            .ok_or_else(|| NucleusError::FilesystemError("Invalid bundle path".into()))?;
        // trusted_directory creates missing ancestors as 0700 root-owned,
        // which the mapped supervisor could never traverse. Widen exactly the
        // components created here to search-only; pre-existing directories
        // keep their ownership and mode untouched.
        let created_ancestors = Self::missing_ancestors(parent);
        crate::filesystem::trusted_directory(parent, true)?;
        for created in &created_ancestors {
            std::fs::set_permissions(created, std::fs::Permissions::from_mode(0o711)).map_err(
                |e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to grant traversal on created bundle parent {:?}: {}",
                        created, e
                    ))
                },
            )?;
        }
        let (dir, _) = crate::oci::open_empty_bundle(&path)?;
        nix::unistd::fchown(
            &dir,
            Some(Uid::from_raw(host_uid)),
            Some(Gid::from_raw(host_gid)),
        )?;
        Ok(())
    }

    /// Ancestor directories of `path` that do not exist yet.
    ///
    /// Used to widen exactly the components a trusted-directory creation
    /// adds, so the mapped supervisor can traverse them without changing the
    /// mode of pre-existing user directories.
    fn missing_ancestors(path: &Path) -> Vec<PathBuf> {
        path.ancestors()
            .filter(|p| !p.as_os_str().is_empty() && !p.exists())
            .map(Path::to_path_buf)
            .collect()
    }

    fn ensure_runtime_parent_dir(path: &std::path::Path) -> Result<()> {
        crate::filesystem::trusted_directory(path, true)?;
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
    ) -> Result<()> {
        if config.workspace.mode != WorkspaceMode::CopyInOut {
            return Ok(());
        }

        let source = config.workspace.host_path.clone().ok_or_else(|| {
            NucleusError::ConfigError(
                "--workspace-mode copy-in-out requires --workspace".to_string(),
            )
        })?;
        // A mapped workload may write its runtime base. Keep the parent of a
        // privileged copy operation under host-root ownership throughout setup.
        let parent = if host_is_root {
            let parent = PathBuf::from("/run/nucleus/workspaces");
            Self::ensure_runtime_parent_dir(&parent)?;
            parent
        } else {
            let parent = runtime_base_override
                .map(Path::to_path_buf)
                .unwrap_or_else(|| {
                    dirs::runtime_dir()
                        .map(|d| d.join("nucleus"))
                        .unwrap_or_else(std::env::temp_dir)
                });
            std::fs::create_dir_all(&parent)?;
            parent
        };

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

        if host_is_root {
            let (uid, gid) = Self::host_workload_ids(config)?;
            Self::chown_tree_no_symlinks(&staging, uid, gid)?;
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

        // Give the workload access only after the subtree is ready.
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to chown workspace staging path {:?} to {}:{}: {}",
                path, uid, gid, e
            ))
        })?;

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

    fn host_workload_ids(config: &ContainerConfig) -> Result<(u32, u32)> {
        let identity = &config.process_identity;
        let Some(mapping) = &config.user_ns_config else {
            return Ok((identity.uid, identity.gid));
        };
        Ok((
            Self::mapped_host_id_for_container_id(
                &mapping.uid_mappings,
                identity.uid,
                "uid mappings",
            )?,
            Self::mapped_host_id_for_container_id(
                &mapping.gid_mappings,
                identity.gid,
                "gid mappings",
            )?,
        ))
    }

    fn configure_user_namespace(
        config: &mut ContainerConfig,
        host_is_root: bool,
        allocate: impl FnOnce(&str) -> Result<UserNamespaceConfig>,
    ) -> Result<()> {
        if config.user_ns_config.is_none() {
            let identity = &config.process_identity;
            if !host_is_root {
                let workload_uid = (identity.uid != 0).then_some(identity.uid);
                config.user_ns_config =
                    Some(UserNamespaceConfig::for_unprivileged_rootless(workload_uid));
            } else if config.namespaces.user
                || config.service_mode.requires_user_namespace_mapping()
                || identity.uid == 0
                || identity.gid == 0
                || identity.additional_gids.contains(&0)
            {
                info!("Remapping workload IDs in a user namespace");
                config.user_ns_config = Some(allocate(&config.id)?);
                config.allocated_root_remap = true;
            }
        }
        if let Some(mapping) = &config.user_ns_config {
            for entry in mapping.uid_mappings.iter().chain(&mapping.gid_mappings) {
                entry.validate(false)?;
            }
            config.namespaces.user = true;
        }
        Ok(())
    }

    fn native_landlock_policy(
        config: &ContainerConfig,
        gpu_device_set: Option<&GpuDeviceSet>,
    ) -> Result<NativeLandlock> {
        if let Some(ref policy_path) = config.landlock_policy {
            let policy: crate::security::LandlockPolicy = crate::security::load_toml_policy(
                policy_path,
                config.landlock_policy_sha256.as_deref(),
            )?;
            // H4: Reject write+execute on same path in production
            if config.service_mode == ServiceMode::Production {
                policy.validate_production()?;
            }
            Ok(NativeLandlock::Custom(policy))
        } else {
            let mut landlock_mgr = LandlockManager::new();
            landlock_mgr.assert_minimum_abi(config.service_mode == ServiceMode::Production)?;
            landlock_mgr.set_workspace_access(
                config.workspace.is_read_only(),
                config.workspace.allow_execute,
            );
            landlock_mgr.add_rw_path(&config.home.to_string_lossy());
            // Register volume mount destinations so Landlock permits access to them
            for provider_config in &config.provider_configs {
                let provider_dest = crate::filesystem::normalize_provider_config_destination(
                    &config.home,
                    &provider_config.dest,
                )?;
                if provider_config.read_only {
                    landlock_mgr.add_ro_path(&provider_dest.to_string_lossy());
                } else {
                    landlock_mgr.add_rw_path(&provider_dest.to_string_lossy());
                }
            }
            for vol in &config.volumes {
                if vol.read_only {
                    landlock_mgr.add_ro_path(&vol.dest.to_string_lossy());
                } else {
                    landlock_mgr.add_rw_path(&vol.dest.to_string_lossy());
                }
            }
            // GPU device nodes must be reachable (read+write) by the workload.
            // Driver support files are read-only inputs.
            if let Some(set) = gpu_device_set {
                for node in &set.nodes {
                    landlock_mgr.add_gpu_device(&node.to_string_lossy());
                }
            }
            Ok(NativeLandlock::Default(landlock_mgr))
        }
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

        if !self.config.use_gvisor && !self.config.namespaces.mnt {
            return Err(NucleusError::ConfigError(
                "Native workloads require a private mount namespace".into(),
            ));
        }
        let is_root = nix::unistd::Uid::effective().is_root();
        let mut config = self.config.clone();
        Self::configure_user_namespace(&mut config, is_root, UserNamespaceConfig::root_remapped)?;

        if matches!(config.network, NetworkMode::Bridge(_)) && config.egress_policy.is_none() {
            config.egress_policy = Some(crate::network::EgressPolicy::deny_all());
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
        if config.verify_rootfs_attestation {
            let root = config.rootfs_path.as_ref().ok_or_else(|| {
                NucleusError::ConfigError("Rootfs attestation requires an explicit rootfs".into())
            })?;
            config.rootfs_path = Some(verify_rootfs_attestation(root)?);
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

        // Use the parent's discovery result for both the filter and the child.
        let gpu_device_set = if let Some(gpu_config) = &config.gpu {
            let devices = resolve_gpu_devices(gpu_config)?;
            if devices.is_none() {
                warn!("--gpu requested but no GPU devices were discovered; continuing without GPU");
                config.gpu = None;
            }
            devices
        } else {
            None
        };

        // Compile once in the host filesystem before the parent and workload diverge.
        let native_seccomp = (!config.use_gvisor)
            .then(|| NativeSeccomp::from_config(&config))
            .transpose()?;

        let native_landlock = (!config.use_gvisor)
            .then(|| Self::native_landlock_policy(&config, gpu_device_set.as_ref()))
            .transpose()?;

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
            Some(tempfile::TempPath::try_from_path(exec_fifo)?)
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
                         cgroup creation failed: {}. Without root, run Nucleus in a \
                         systemd unit with Delegate= or set NUCLEUS_CGROUP_ROOT to a \
                         cgroup delegated to this user",
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
                             enforced – cgroup creation requires root or a delegated cgroup \
                             subtree ({})",
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

        let device_filter =
            gpu_device_set
                .as_ref()
                .map(|set| crate::container::SavedDeviceFilter {
                    gpu: set.device_specs(),
                    supervisor: Self::gvisor_supervisor_device_specs(&config),
                    include_tty: config.terminal,
                });
        if let Some(filter) = &device_filter {
            if let Some(cgroup) = &cgroup_opt {
                // The deny-by-default filter also governs the runsc supervisor,
                // which the parent attaches to this cgroup before the sandbox
                // starts. Allow the selected platform backend's required host
                // devices (e.g. /dev/kvm for KVM) so the sandbox can boot; the
                // workload inside the sandbox still cannot reach them.
                cgroup.install_gpu_device_allowlist(
                    &filter.gpu,
                    &filter.supervisor,
                    filter.include_tty,
                    config.allow_degraded_security,
                )?;
            } else if config.allow_degraded_security {
                warn!("Continuing without GPU cgroup device allowlist: no container cgroup");
            } else {
                return Err(NucleusError::CgroupError(
                    "GPU passthrough requires a container cgroup for the device allowlist".into(),
                ));
            }
        }

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
        Self::prepare_workspace_staging(&mut config, runtime_base_override.as_deref(), is_root)?;

        let event_sink = self.event_sink.clone();
        let outcome_pipe = (event_sink.is_some() && !config.use_gvisor)
            .then(pipe)
            .transpose()?;
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
        let landlock_channel = (!config.use_gvisor)
            .then(std::os::unix::net::UnixStream::pair)
            .transpose()?;
        // The child hands the broker proxy listener to this process.
        let broker_channel = config
            .broker_proxy_listen
            .map(|_| std::os::unix::net::UnixStream::pair())
            .transpose()?;
        Self::assert_single_threaded_for_fork("container create fork")?;
        // The container must not outlive this process, however it ends.
        let lifeline = Lifeline::new()?;
        if let Some(cgroup) = &cgroup_opt {
            // Under gVisor the reaper also removes the runsc state and bundle
            // directory, which the orderly teardown would otherwise remove.
            let gvisor_state = if !config.use_gvisor {
                None
            } else if let Some(base) = runtime_base_override
                .as_deref()
                .filter(|_| is_root && gvisor_needs_precreated_userns)
            {
                Some(base.to_path_buf())
            } else {
                GVisorRuntime::prepare_artifact_base()?;
                Some(GVisorRuntime::artifact_dir(&config.id)?)
            };
            let state = gvisor_state.as_deref().and_then(|dir| {
                Some(ReapedTree {
                    parent: dir.parent()?,
                    name: dir.file_name()?,
                })
            });
            if let Err(e) = lifeline.spawn_cgroup_reaper(cgroup.path(), state) {
                if config.service_mode.requires_cgroup_enforcement() {
                    return Err(e);
                }
                warn!("Container cgroup will not be reaped if the supervisor is killed: {e}");
            }
        }
        // From the fork onward the container lifecycle owns the FIFO. Setup
        // failures before this point (including GPU enforcement) remove it.
        let exec_fifo = exec_fifo
            .map(tempfile::TempPath::keep)
            .transpose()
            .map_err(std::io::Error::from)?;
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
                let lifeline = lifeline.hold();
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

                    // Dropped with the container, or here if setup fails.
                    let broker_forwarder = match (broker_channel, config.broker_socket.as_ref()) {
                        (Some((parent_end, child_end)), Some(broker)) => {
                            drop(child_end);
                            let listener = crate::network::broker_forwarder::receive(&parent_end)?;
                            Some(crate::network::broker_forwarder::BrokerForwarder::spawn(
                                listener, broker,
                            )?)
                        }
                        _ => None,
                    };

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
                    state.allocated_root_remap = config.allocated_root_remap;
                    state.user_ns_config = config.user_ns_config.clone();
                    state.pids_max = config.limits.pids_max;
                    state.native_seccomp = native_seccomp;
                    let landlock_handoff = if let Some((parent, child_end)) = landlock_channel {
                        drop(child_end);
                        let path = state_mgr
                            .exec_fifo_path(&config.id)?
                            .with_extension("landlock");
                        let handoff = crate::security::landlock_handoff::LandlockHandoff::start(
                            &path, parent,
                        )?;
                        state.landlock_socket = Some(path.canonicalize()?);
                        Some(handoff)
                    } else {
                        None
                    };
                    state.gpu_device_filter = device_filter;
                    state.environment = config.environment.iter().cloned().collect();
                    state.workdir = config.workdir.display().to_string();
                    state.config_hash = config.config_hash;
                    state.topology_name = config.topology_name.clone();
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

                    let trace_reader = Self::maybe_start_seccomp_trace_reader(
                        &config,
                        target_pid,
                        cgroup_opt.as_ref().map(|cgroup| cgroup.path()),
                    )?;
                    let deny_logger = Self::maybe_start_seccomp_deny_logger(
                        &config,
                        target_pid,
                        cgroup_opt.as_ref().map(|cgroup| cgroup.path()),
                    )?;

                    if let NetworkMode::Bridge(ref bridge_config) = config.network {
                        // The direct child creates the network/user namespaces before
                        // forking PID 1. Its PID cannot be reused before we reap it.
                        // Pin its descriptors even when the workload is a grandchild.
                        let namespace_owner = child.as_raw() as u32;
                        let net = BridgeDriver::setup_with_id_and_broker(
                            namespace_owner,
                            bridge_config,
                            &config.id,
                            is_root,
                            config.user_ns_config.is_some(),
                            config.credential_broker.as_ref(),
                        )?;
                        net.apply_egress_policy(
                            namespace_owner,
                            config
                                .egress_policy
                                .as_ref()
                                .expect("bridge policy initialized before fork"),
                            config.user_ns_config.is_some(),
                        )?;
                        if let Some(ref broker) = config.credential_broker {
                            Self::probe_credential_broker(broker)?;
                        }
                        network_driver = Some(net);
                    }

                    Self::send_sync_byte(
                        &parent_setup_write,
                        "Failed to notify child that parent setup is complete",
                    )?;

                    info!(
                        "Container {} created (child pid {}), waiting for start",
                        config.id, target_pid
                    );

                    let mapped_gvisor_base =
                        runtime_base_override.filter(|_| is_root && gvisor_needs_precreated_userns);
                    Ok(CreatedContainer {
                        outcome_reader: outcome_pipe.map(|(reader, _)| reader),
                        _landlock_handoff: landlock_handoff,
                        broker_forwarder,
                        mapped_gvisor_base,
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
                        _lifeline: lifeline,
                    })
                };

                parent_setup().inspect_err(|_| {
                    if let Some(target_pid) = target_pid_for_cleanup {
                        let _ = kill(Pid::from_raw(target_pid as i32), Signal::SIGKILL);
                    }
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                })
            }
            ForkResult::Child => {
                lifeline.adopt_in_child();
                if let Err(e) = die_with_supervisor() {
                    error!("Container setup failed: {}", e);
                    std::process::exit(1);
                }
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
                    gpu_device_set.as_ref(),
                    native_seccomp.as_ref(),
                    native_landlock.as_ref(),
                    landlock_channel.map(|(_, child_end)| child_end),
                    broker_channel.map(|(_, child_end)| child_end),
                    outcome_pipe.map(|(_, writer)| writer),
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
    #[allow(clippy::too_many_arguments)]
    fn setup_and_exec(
        &self,
        gpu_device_set: Option<&GpuDeviceSet>,
        native_seccomp: Option<&NativeSeccomp>,
        native_landlock: Option<&NativeLandlock>,
        landlock_channel: Option<std::os::unix::net::UnixStream>,
        broker_channel: Option<std::os::unix::net::UnixStream>,
        outcome_writer: Option<OwnedFd>,
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

        // Supplementary groups survive creation of a user namespace, even
        // when their host IDs are absent from gid_map.
        if is_rootless && Uid::effective().is_root() {
            nix::unistd::setgroups(&[])?;
        }

        // Hand off root-launched agents to runsc as mapped root. Unprivileged
        // bridge and hostinet launches also need the pre-created user namespace.
        if self.config.use_gvisor {
            let mapped_base = runtime_base_override
                .as_deref()
                .filter(|_| Uid::effective().is_root());
            let artifact_base = match mapped_base {
                Some(base) => base.to_owned(),
                None => GVisorRuntime::prepare_artifact_base()?,
            };
            let runsc_debug_dir = GVisorRuntime::prepare_runsc_debug_dir()?;
            let mut handoff_bundle: Option<std::fs::File> = None;
            if mapped_base.is_none() {
                if let Some(bundle) = &self.config.bundle_dir {
                    let path = std::env::current_dir()?.join(bundle);
                    let parent = path.parent().ok_or_else(|| {
                        NucleusError::FilesystemError("Invalid bundle path".into())
                    })?;
                    crate::filesystem::trusted_directory(parent, true)?;
                    // keep-id handoffs demote the setup process to container
                    // ID 0 while the caller's files keep their original host
                    // identity, so the bundle ownership check inside
                    // OciBundle::create would reject the launching user's own
                    // directory. Validate the empty bundle now, while the
                    // effective UID still matches its owner, and transfer it
                    // to the mapped supervisor right after the handoff.
                    if Self::gvisor_needs_precreated_userns(
                        &self.config,
                        Uid::effective().is_root(),
                    ) {
                        let (dir, _) = crate::oci::open_empty_bundle(&path)?;
                        handoff_bundle = Some(dir);
                    }
                }
            }
            let gvisor_precreated_userns = self.prepare_gvisor_handoff_namespace(
                userns_request_pipe.as_ref(),
                userns_ack_pipe.as_ref(),
            )?;
            // Entering the handoff namespace changed credentials, which
            // clears the parent-death signal.
            die_with_supervisor()?;
            if let (Some(dir), true) = (handoff_bundle, gvisor_precreated_userns) {
                // Namespace-relative chown to container ID 0: the mapped
                // supervisor owns the bundle for the upcoming create.
                nix::unistd::fchown(&dir, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))?;
            };

            if mapped_base.is_some() || Self::gvisor_needs_mount_staging(&self.config) {
                // Staged bind mounts must be private to this launch.
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
                nix::mount::mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                    None::<&str>,
                )?;
            }
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
            return self.setup_and_exec_gvisor(
                artifact_base,
                runsc_debug_dir,
                gvisor_precreated_userns,
                gpu_device_set,
            );
        }

        let workload_caps = self
            .config
            .caps_policy
            .as_ref()
            .map(|path| {
                let policy: crate::security::CapsPolicy = crate::security::load_toml_policy(
                    path,
                    self.config.caps_policy_sha256.as_deref(),
                )?;
                policy.resolve_sets()
            })
            .transpose()?;

        let prepared_dev = if is_rootless && Uid::effective().is_root() {
            let (uid, gid) = Self::host_workload_ids(&self.config)?;
            Some(crate::filesystem::prepare_mapped_dev(
                self.config.terminal,
                gpu_device_set,
                uid,
                gid,
            )?)
        } else {
            None
        };

        // createRuntime hooks resolve in the runtime namespace; verify them under
        // the host credentials before the user namespace hides host owners.
        let create_runtime_hooks = match self.config.hooks.as_ref() {
            Some(hooks) => OciHooks::prepare_hooks(&hooks.create_runtime, "createRuntime")?,
            None => Vec::new(),
        };

        // 1. Create namespaces in child and optionally configure user mapping.
        let mut namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());
        // unshare translates the current directory into the new mount namespace.
        // Reach the per-image directory while privileged, then open its children
        // on that namespace's mounts (overlayfs rejects foreign mount fds).
        let mut original_cwd = None;
        if let Some(overlay) = self.config.rootfs_overlay.as_ref() {
            if let Some(parent) = overlay
                .upperdir
                .parent()
                .filter(|p| Some(*p) == overlay.workdir.parent() && !p.as_os_str().is_empty())
            {
                original_cwd = Some(std::fs::File::open(".")?);
                nix::unistd::chdir(parent)?;
            }
        }
        namespace_mgr.unshare_namespaces()?;
        if self.config.broker_socket.is_some() {
            // The in-container forwarder listens on loopback, which a new
            // network namespace leaves down. Raise it while this process
            // still holds CAP_NET_ADMIN over the namespace it just created.
            crate::network::netlink::set_link_up("lo")?;
            if let (Some(addr), Some(channel)) =
                (self.config.broker_proxy_listen, broker_channel.as_ref())
            {
                crate::network::broker_forwarder::bind_and_send(addr, channel)?;
            }
        }
        drop(broker_channel);
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
            Self::become_userns_root_for_setup(None, workload_caps.as_ref())?;
            // The identity switch cleared the parent-death signal.
            die_with_supervisor()?;
        }

        let overlay_dirs = self
            .config
            .rootfs_overlay
            .as_ref()
            .map(|overlay| {
                if let Some(cwd) = original_cwd.as_ref() {
                    let upper = overlay.upperdir.file_name().ok_or_else(|| {
                        NucleusError::FilesystemError("Missing upper directory name".into())
                    })?;
                    let work = overlay.workdir.file_name().ok_or_else(|| {
                        NucleusError::FilesystemError("Missing work directory name".into())
                    })?;
                    let dirs = open_overlay_dirs(Path::new(upper), Path::new(work))?;
                    nix::unistd::fchdir(cwd)?;
                    Ok(dirs)
                } else {
                    open_overlay_dirs(&overlay.upperdir, &overlay.workdir)
                }
            })
            .transpose()?;
        drop(original_cwd);

        // CLONE_NEWPID only applies to children created after unshare().
        // Create a child that will become PID 1 in the new namespace and exec the workload.
        if self.config.namespaces.pid {
            Self::assert_single_threaded_for_fork("PID namespace init fork")?;
            match unsafe { fork() }? {
                ForkResult::Parent { child } => {
                    if let Some(fd) = ready_pipe {
                        Self::notify_namespace_ready(&fd, child.as_raw() as u32)?;
                    }
                    drop(outcome_writer);
                    std::process::exit(Self::wait_for_pid_namespace_child(child));
                }
                ForkResult::Child => {
                    // PID 1 follows the intermediate process, which in turn
                    // follows the supervisor.
                    die_with_supervisor()?;
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
            let (upper, work) = overlay_dirs.ok_or_else(|| {
                NucleusError::FilesystemError(
                    "rootfs overlay mode missing prepared upper/work dirs".to_string(),
                )
            })?;
            overlay_mount_rootfs_pinned(&container_root, rootfs_path, &upper, &work)?;
            true
        } else {
            false
        };

        // 4. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 5. Create device nodes and standard tmpfs mounts under /dev
        let dev_path = container_root.join("dev");
        let dev_target = crate::filesystem::mount_target(&container_root, Path::new("dev"), true)?;
        if let Some(prepared_dev) = &prepared_dev {
            nix::mount::mount(
                Some(prepared_dev),
                &crate::filesystem::fd_path(&dev_target),
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )?;
        } else {
            nix::mount::mount(
                Some("tmpfs"),
                &crate::filesystem::fd_path(&dev_target),
                Some("tmpfs"),
                nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC,
                Some("mode=0755,size=1m"),
            )?;
            crate::filesystem::populate_native_dev(
                &dev_path,
                self.config.terminal,
                is_rootless,
                &self.config.process_identity,
            )?;
        }

        // 5a. GPU passthrough: create private device nodes + bind driver support files.
        if let (Some(set), Some(gpu_config)) = (gpu_device_set, &self.config.gpu) {
            if prepared_dev.is_none() {
                crate::filesystem::create_gpu_nodes(
                    &container_root,
                    set,
                    &self.config.process_identity,
                )?;
            }
            if self.config.rootfs_path.is_none() {
                crate::filesystem::mount_gpu_support(&container_root, set, gpu_config)?;
            }
        }

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
            if rootfs_overlay_mounted
                && matches!(
                    self.config.context_mode,
                    crate::filesystem::ContextMode::Copy
                )
            {
                let target =
                    crate::filesystem::mount_target(&container_root, Path::new("context"), true)?;
                nix::mount::mount(
                    Some("tmpfs"),
                    &crate::filesystem::fd_path(&target),
                    Some("tmpfs"),
                    nix::mount::MsFlags::MS_NOSUID
                        | nix::mount::MsFlags::MS_NODEV
                        | nix::mount::MsFlags::MS_NOEXEC,
                    Some("mode=0755,size=1g"),
                )?;
            }
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

        // 7d'. Broker-socket mode: expose the one host socket, unless the
        // supervisor relays to it from a loopback listener instead.
        if let Some(broker) = self
            .config
            .broker_socket
            .as_ref()
            .filter(|_| self.config.mounts_broker_socket())
        {
            broker.mount(&container_root)?;
        }

        // 7e. Write resolv.conf for bridge networking.
        // When rootfs is mounted, /etc is read-only, so we bind-mount a writable
        // resolv.conf over the top (same technique as secrets).
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            let bridge_dns = &bridge_config.dns;
            if self.config.rootfs_path.is_some() {
                BridgeNetwork::bind_mount_resolv_conf(&container_root, bridge_dns)?;
            } else {
                BridgeNetwork::write_resolv_conf(&container_root, bridge_dns)?;
            }
        }

        // 7f. Mount secrets on an in-memory tmpfs in all modes.
        mount_secrets_inmemory(
            &container_root,
            &self.config.secrets,
            &self.config.process_identity,
        )?;

        // 7g. /tmp scratch: writable but never executable, like the sandbox
        // home and /dev/shm. Files here can be neither execve'd nor mapped
        // PROT_EXEC (mprotect included), which closes the last writable and
        // simultaneously executable tmpfs surface. User volumes cannot
        // override /tmp; it is a reserved runtime destination.
        let tmp_target = crate::filesystem::mount_target(&container_root, Path::new("tmp"), true)?;
        nix::mount::mount(
            Some("tmpfs"),
            &crate::filesystem::fd_path(&tmp_target),
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("mode=1777,size=512m"),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to mount noexec /tmp tmpfs: {e}"))
        })?;
        debug!("Mounted noexec tmpfs on /tmp");

        mount_procfs(&container_root.join("proc"), self.config.proc_readonly)?;

        // 9c. Run createRuntime hooks (after namespaces created, before pivot_root)
        if !create_runtime_hooks.is_empty() {
            let hook_state = OciContainerState {
                oci_version: "1.0.2".to_string(),
                id: self.config.id.clone(),
                status: OciStatus::Creating,
                pid: std::process::id(),
                bundle: String::new(),
            };
            OciHooks::run_prepared_hooks(&create_runtime_hooks, &hook_state, "createRuntime")?;
        }

        // 10. Switch root filesystem
        // Filesystem: Populated -> Pivoted
        switch_root(&container_root, self.config.allow_chroot_fallback)?;
        fs_state = fs_state.transition(FilesystemState::Pivoted)?;
        // The tmpfs is now this process's root and the runtime directory's
        // host path no longer resolves. Their drop-time cleanup can do nothing
        // useful, and after seccomp is installed it is fatal: a failed exec
        // would unwind into umount2 and die with SIGSYS instead of reporting
        // the error. The mount namespace dies with this process.
        tmpfs.release();
        let _ = runtime_dir.keep();
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
                OciHooks::run_container_hooks(
                    &hooks.create_container,
                    &hook_state,
                    "createContainer",
                )?;
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
        crate::filesystem::verify_procfs_mount_flags()?;
        let mut cap_mgr = CapabilityManager::new();
        if let Some(sets) = &workload_caps {
            cap_mgr.prepare_sets(sets)?;
            let keep_across_uid_change = Uid::effective().is_root()
                && self.config.process_identity.uid != 0
                && !sets.permitted.is_empty();
            if keep_across_uid_change {
                nix::sys::prctl::set_keepcaps(true)?;
            }
            Self::apply_process_identity_to_current_process(
                &self.config.process_identity,
                self.config.user_ns_config.is_some(),
            )?;
            if keep_across_uid_change {
                nix::sys::prctl::set_keepcaps(false)?;
            }
            cap_mgr.finish_sets(sets)?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                "explicit workload capability sets applied and verified",
            );
        } else {
            // Phase 1: drop bounding set while CAP_SETPCAP is still effective
            cap_mgr.drop_bounding_set()?;

            // Identity switch: setgroups/setgid/setuid while CAP_SETUID/CAP_SETGID
            // are still in the effective set. For non-root target UIDs, the kernel
            // auto-clears permitted/effective after setuid().
            Self::apply_process_identity_to_current_process(
                &self.config.process_identity,
                self.config.user_ns_config.is_some(),
            )?;

            // Phase 2: explicitly clear any remaining caps (handles root-stays-root
            // case where kernel doesn't auto-clear).
            cap_mgr.finalize_drop()?;

            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                "all capabilities dropped including bounding set",
            );
        }
        sec_state = sec_state.transition(SecurityState::CapabilitiesDropped)?;
        // Last credential change before the workload: re-arm the parent-death
        // signal it cleared. The setting survives the exec that follows.
        die_with_supervisor()?;

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

        // Transfer the applied kernel ruleset before seccomp may disable sendmsg.
        let channel = landlock_channel.ok_or_else(|| {
            NucleusError::LandlockError("Missing Landlock handoff channel".into())
        })?;
        let landlock_status = native_landlock
            .ok_or_else(|| NucleusError::LandlockError("Missing launch Landlock policy".into()))?
            .apply(allow_degraded_security, &channel, &self.config)?;
        // The PID-namespace intermediary may still have a dup of this socket.
        channel.shutdown(std::net::Shutdown::Write)?;
        drop(channel);

        // 13. Apply seccomp filter (trace, profile-from-file, or built-in allowlist)
        // Security: CapabilitiesDropped -> SeccompApplied
        use crate::container::config::SeccompMode;
        let allow_network = self.config.allows_ip_sockets();
        if let Some(path) = self
            .config
            .seccomp_profile
            .as_ref()
            .filter(|_| self.config.seccomp_mode == SeccompMode::Enforce)
        {
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::SeccompProfileLoaded,
                format!("path={:?}", path),
            );
        }
        let install = native_seccomp
            .ok_or_else(|| NucleusError::SeccompError("Missing native launch filter".into()))?
            .apply();
        let seccomp_applied = match install {
            Ok(()) => true,
            Err(e)
                if allow_degraded_security
                    && self.config.seccomp_profile.is_none()
                    && self.config.seccomp_mode == SeccompMode::Enforce =>
            {
                warn!(
                    "Failed to install seccomp filter: {} (degraded security)",
                    e
                );
                false
            }
            Err(e) => return Err(e),
        };

        if seccomp_applied {
            sec_state = sec_state.transition(SecurityState::SeccompApplied)?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::SeccompApplied,
                format!(
                    "mode={:?} network={}",
                    self.config.seccomp_mode, allow_network
                ),
            );
        } else if !allow_degraded_security {
            return Err(NucleusError::SeccompError(
                "Seccomp filter is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Seccomp not enforced; container is running with degraded hardening");
        }

        if seccomp_applied && landlock_status == landlock::RulesetStatus::FullyEnforced {
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
                if self.config.seccomp_mode == SeccompMode::Trace {
                    "landlock applied, but seccomp in trace mode - not locked".to_string()
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

        if let Some(writer) = outcome_writer {
            let outcome = NativeSecurityOutcome {
                landlock: match landlock_status {
                    landlock::RulesetStatus::FullyEnforced => "fully_enforced",
                    landlock::RulesetStatus::PartiallyEnforced => "partially_enforced",
                    landlock::RulesetStatus::NotEnforced => "not_enforced",
                }
                .into(),
                capabilities: if workload_caps.is_some() {
                    "policy_applied"
                } else {
                    "drop_all"
                }
                .into(),
                seccomp_applied,
            };
            serde_json::to_writer(std::fs::File::from(writer), &outcome)?;
        }

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
                OciHooks::run_container_hooks(
                    &hooks.start_container,
                    &hook_state,
                    "startContainer",
                )?;
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

    fn become_userns_root_for_setup(
        gvisor_network: Option<&NetworkMode>,
        workload: Option<&CapabilitySets>,
    ) -> Result<()> {
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
        Self::restore_gvisor_handoff_capabilities(gvisor_network, workload)?;
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

    fn restore_gvisor_handoff_capabilities(
        gvisor_network: Option<&NetworkMode>,
        workload: Option<&CapabilitySets>,
    ) -> Result<()> {
        let mut caps = Self::gvisor_handoff_capabilities();
        if matches!(gvisor_network, Some(NetworkMode::Bridge(_))) {
            // Scoped to the new user namespace: runsc moves interface addresses
            // into netstack and opens its AF_PACKET link in the private netns.
            caps.extend([Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW]);
        }
        if matches!(
            gvisor_network,
            Some(NetworkMode::Bridge(_) | NetworkMode::None)
        ) {
            // DirectFS creates a nested identity mapping of UID 0. Linux
            // requires SETFCAP in this parent user namespace to write it.
            caps.insert(Capability::CAP_SETFCAP);
        }
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
        // Native setup retains policy inputs in the upper bounds only. The
        // workload receives its effective and ambient sets after switching IDs.
        let mut permitted_limit = caps.clone();
        let mut bounding_limit = caps.clone();
        if let Some(sets) = workload {
            permitted_limit.extend(&sets.permitted);
            bounding_limit.extend(&sets.bounding);
            bounding_limit.extend(&sets.inheritable);
        }
        let extra_permitted: Vec<_> = permitted.difference(&permitted_limit).copied().collect();
        let bounding = caps::read(None, CapSet::Bounding).map_err(|e| {
            NucleusError::CapabilityError(format!(
                "Failed to read gVisor handoff bounding capabilities: {}",
                e
            ))
        })?;
        let extra_bounding: Vec<_> = bounding.difference(&bounding_limit).copied().collect();
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
        if Self::gvisor_needs_precreated_userns(&self.config, Uid::effective().is_root()) {
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
            Self::become_userns_root_for_setup(Some(&self.config.network), None)?;
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
    fn emit_control_event(
        &self,
        mut event: ContainerControlEvent,
        outcome: Option<&NativeSecurityOutcome>,
    ) {
        event.security.record_native_outcome(outcome);
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
        let (sig_stop, sig_handle) =
            Container::setup_signal_forwarding_static(Pid::from_raw(target_pid as i32))?;

        // Guard ensures signal thread is stopped on any exit path (including early ? returns).
        let mut sig_guard = SignalThreadGuard {
            stop: Some(sig_stop),
            handle: Some(sig_handle),
        };

        let outcome: Option<NativeSecurityOutcome> = self.outcome_reader.take().and_then(|fd| {
            serde_json::from_reader(std::fs::File::from(fd))
                .inspect_err(|err| warn!("Native setup did not report security outcomes: {err}"))
                .ok()
        });
        if outcome.is_some() || config.use_gvisor {
            self.emit_control_event(
                ContainerControlEvent::started(config, target_pid, self.state.cgroup_path.clone()),
                outcome.as_ref(),
            );
        }

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
            Container::run_readiness_probe(&self.state, probe, notify_socket.as_deref())?;
        }

        // Start health check thread if configured
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let health_handle = if let Some(ref hc) = config.health_check {
            if !hc.command.is_empty() {
                let hc = hc.clone();
                let state = self.state.clone();
                let cancel = cancel_flag.clone();
                Some(std::thread::spawn(move || {
                    Container::health_check_loop(&state, &hc, &cancel);
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
        // The workload is gone: stop relaying and release the namespace.
        drop(self.broker_forwarder.take());

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
            let cleanup = if let Some(base) = self.mapped_gvisor_base.as_ref() {
                // Mounts expired with the child. Never resolve a mapped user's mount paths as host root.
                std::fs::remove_dir_all(base).map_err(|e| {
                    NucleusError::FilesystemError(format!("Failed to remove {base:?}: {e}"))
                })
            } else {
                Container::cleanup_gvisor_artifacts(&config.id)
            };
            if let Err(e) = cleanup {
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
        self.emit_control_event(
            ContainerControlEvent::summary(
                config,
                target_pid,
                cgroup_path_for_summary,
                exit_status_event,
                resource_stats,
                resource_stats_error,
                CleanupEvent::from_errors(cleanup_errors),
            ),
            outcome.as_ref(),
        );

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
    fn privileged_agent_remaps_root_even_with_degraded_security() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".into()])
            .unwrap()
            .with_allow_degraded_security(true);
        Container::configure_user_namespace(&mut config, true, |_| {
            let map = crate::isolation::IdMapping::new(0, 700_000, 65_536);
            crate::isolation::UserNamespaceConfig::custom(vec![map.clone()], vec![map])
        })
        .unwrap();
        assert!(config.namespaces.user);
        assert_eq!(
            Container::host_workload_ids(&config).unwrap(),
            (700_000, 700_000)
        );
    }

    #[test]
    fn privileged_agent_preserves_explicit_nonroot_ids() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".into()]).unwrap();
        config.process_identity.uid = 1234;
        config.process_identity.gid = 2345;
        Container::configure_user_namespace(&mut config, true, |_| panic!("unexpected root remap"))
            .unwrap();
        assert!(!config.namespaces.user);
        assert_eq!(Container::host_workload_ids(&config).unwrap(), (1234, 2345));
    }

    #[test]
    fn explicit_namespace_map_cannot_include_host_root() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".into()]).unwrap();
        for (uid, gid) in [(0, 100_000), (100_000, 0)] {
            config.user_ns_config = Some(crate::isolation::UserNamespaceConfig {
                uid_mappings: vec![crate::isolation::IdMapping::new(0, uid, 1)],
                gid_mappings: vec![crate::isolation::IdMapping::new(0, gid, 1)],
            });
            assert!(
                Container::configure_user_namespace(&mut config, true, |_| panic!(
                    "unexpected root remap"
                ))
                .is_err()
            );
        }
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

        config.user_ns_config = Some(crate::isolation::UserNamespaceConfig::rootless());
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
                dest: std::path::PathBuf::from("/app/secret.txt"),
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
                dest: std::path::PathBuf::from("/app/secret.txt"),
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
    fn test_overlay_rootfs_does_not_register_writable_landlock_root() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        assert!(
            !fn_body.contains("landlock_mgr.add_rw_exec_path(\"/\")"),
            "overlay rootfs mode must not grant broad read/write/execute Landlock access to /"
        );
    }

    #[test]
    fn test_overlay_rootfs_drops_all_capabilities() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        assert!(
            fn_body.contains("cap_mgr.drop_bounding_set()?")
                && fn_body.contains("cap_mgr.finalize_drop()?")
                && !fn_body.contains("drop_bounding_set_except")
                && !fn_body.contains("finalize_drop_except"),
            "overlay rootfs mode must use the default drop-all capability path"
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
    fn test_gvisor_rootless_flag_respects_netstack() {
        let source = include_str!("gvisor_setup.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec_gvisor_oci");
        assert!(
            fn_body.contains("gvisor_net != GVisorNetworkMode::Sandbox")
                && fn_body.contains("precreated_userns || self.config.user_ns_config.is_none()"),
            "runsc accepts its rootless flag only for none and host networking"
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
            fn_body.contains("permitted.difference(&permitted_limit)")
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
                && fn_body.contains("bounding.difference(&bounding_limit)")
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
        let artifact_dir = GVisorRuntime::artifact_dir("cleanup-test").unwrap();
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("config.json"), "{}").unwrap();

        Container::cleanup_gvisor_artifacts("cleanup-test").unwrap();
        assert!(!artifact_dir.exists());
    }

    #[test]
    #[ignore = "requires host root to exercise uid ownership checks"]
    fn host_root_rejects_foreign_bundle_and_artifact_paths() {
        assert!(Uid::effective().is_root());
        let _lock = EnvLock::acquire();
        let temp = tempfile::tempdir().unwrap();
        let foreign = temp.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        let uid = Uid::from_raw(65534);
        chown(&foreign, Some(uid), None).unwrap();
        let _xdg = EnvVarGuard::set("XDG_RUNTIME_DIR", &foreign);
        let _override = EnvVarGuard::remove("NUCLEUS_GVISOR_ARTIFACT_BASE");
        assert_eq!(
            GVisorRuntime::gvisor_artifact_base().unwrap(),
            Path::new("/run/nucleus-gvisor")
        );
        let base = foreign.join("artifacts");
        let _override = EnvVarGuard::set("NUCLEUS_GVISOR_ARTIFACT_BASE", &base);
        assert!(GVisorRuntime::prepare_artifact_base().is_err());
        assert!(!base.exists());
        assert!(Container::prepare_mapped_bundle_dir(&foreign, 100000, 100000).is_err());
        assert!(
            Container::prepare_mapped_bundle_dir(&foreign.join("bundle"), 100000, 100000).is_err()
        );
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&foreign).unwrap().uid(), uid.as_raw());
    }

    #[test]
    fn test_gvisor_artifact_base_uses_xdg_only_for_unprivileged_hosts() {
        let _env_lock = EnvLock::acquire();
        let temp = tempfile::TempDir::new().unwrap();
        let _artifact_override = EnvVarGuard::remove("NUCLEUS_GVISOR_ARTIFACT_BASE");
        let _runtime = EnvVarGuard::set("XDG_RUNTIME_DIR", temp.path());

        assert_eq!(
            GVisorRuntime::gvisor_artifact_base().unwrap(),
            if Uid::effective().is_root() && !crate::isolation::in_nontrivial_userns() {
                PathBuf::from("/run/nucleus-gvisor")
            } else {
                temp.path().join("nucleus-gvisor")
            }
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
    #[test]
    fn test_mapped_runtime_base_prepares_explicit_bundle_dir() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn prepare_runtime_base_override");
        assert!(
            fn_body.contains("prepare_mapped_bundle_dir"),
            "root remap handoff must prepare explicit --bundle directories for the mapped supervisor"
        );
    }

    #[test]
    fn test_prepare_mapped_bundle_dir_creates_and_transfers_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("explicit-bundle");
        // chown to the current identity keeps the test rootless-capable.
        let uid = Uid::effective();
        let gid = Gid::effective();

        Container::prepare_mapped_bundle_dir(&bundle, uid.as_raw(), gid.as_raw()).unwrap();
        assert!(bundle.is_dir());

        // Repeated launches must be idempotent.
        Container::prepare_mapped_bundle_dir(&bundle, uid.as_raw(), gid.as_raw()).unwrap();

        // Symlinked bundle paths are refused before any ownership change.
        let target = temp.path().join("real-target");
        std::fs::create_dir(&target).unwrap();
        let link = temp.path().join("bundle-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = Container::prepare_mapped_bundle_dir(&link, uid.as_raw(), gid.as_raw())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Failed to open bundle directory safely"));
    }
    #[test]
    fn test_gvisor_mount_staging_precreates_userns_in_all_service_modes() {
        // Unprivileged strict/production launches with bind mounts need mount
        // staging, whose CLONE_NEWNS requires CAP_SYS_ADMIN inside a
        // pre-created user namespace. Regression: the staging arm of the
        // predicate was once restricted to ServiceMode::Agent, which made
        // StrictAgent/Production launches with NetworkMode::None exit EPERM
        // at unshare before runsc could start.
        for mode in [
            ServiceMode::Agent,
            ServiceMode::StrictAgent,
            ServiceMode::Production,
        ] {
            let config = ContainerConfig::try_new(None, vec!["/bin/sh".into()])
                .unwrap()
                .with_gvisor(true)
                .with_user_namespace(crate::isolation::UserNamespaceConfig::rootless())
                .with_service_mode(mode)
                .with_workspace(
                    crate::container::WorkspaceConfig::default()
                        .with_host_path(std::path::PathBuf::from("/tmp/ws")),
                );
            assert!(
                Container::gvisor_needs_precreated_userns(&config, false),
                "unprivileged {mode:?} gVisor launch with a bind workspace must pre-create the user namespace"
            );
        }

        // Without staging needs and without bridge/host networking, the
        // handoff stays opt-in: runsc creates its own user namespace.
        let plain = ContainerConfig::try_new(None, vec!["/bin/sh".into()])
            .unwrap()
            .with_gvisor(true)
            .with_user_namespace(crate::isolation::UserNamespaceConfig::rootless())
            .with_service_mode(ServiceMode::StrictAgent);
        assert!(!Container::gvisor_needs_precreated_userns(&plain, false));
    }
    #[test]
    fn test_prepare_mapped_bundle_dir_grants_traversal_on_created_parents() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("deep/nested/parents/explicit-bundle");
        let uid = Uid::effective();
        let gid = Gid::effective();
        use std::os::unix::fs::PermissionsExt;

        Container::prepare_mapped_bundle_dir(&bundle, uid.as_raw(), gid.as_raw()).unwrap();

        // Every ancestor created by the preparation must be traversable by
        // the mapped supervisor (search-only), not just root.
        for created in [temp.path().join("deep"), temp.path().join("deep/nested")] {
            let mode = std::fs::metadata(created).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o711, "created ancestor must grant traversal");
        }
        // The bundle itself stays owner-only.
        let mode = std::fs::metadata(&bundle).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn test_prepare_mapped_bundle_dir_preserves_existing_parent_modes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("pre-existing");
        std::fs::create_dir(&parent).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        let bundle = parent.join("explicit-bundle");
        let uid = Uid::effective();
        let gid = Gid::effective();

        Container::prepare_mapped_bundle_dir(&bundle, uid.as_raw(), gid.as_raw()).unwrap();

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "pre-existing parent mode must be untouched");
    }

    #[test]
    fn test_missing_ancestors_lists_only_absent_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let missing = Container::missing_ancestors(&existing.join("a/b"));
        assert_eq!(
            missing,
            vec![existing.join("a/b"), existing.join("a")],
            "ancestors are reported deepest-first, excluding existing prefixes"
        );
    }

    #[test]
    fn test_native_hooks_are_verified_outside_the_container_user_namespace() {
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        let prepare = fn_body.find("OciHooks::prepare_hooks").unwrap();
        let unshare = fn_body.find("namespace_mgr.unshare_namespaces()").unwrap();
        assert!(prepare < unshare);
        assert!(fn_body.contains("run_prepared_hooks(&create_runtime_hooks"));
        assert!(!fn_body.contains("OciHooks::run_hooks("));
        assert_eq!(fn_body.matches("OciHooks::run_container_hooks(").count(), 2);
    }

    #[test]
    fn test_runsc_debug_dir_is_prepared_before_userns_handoff() {
        // Inside the handoff namespace host-root-owned ancestors such as /var
        // stat as unmapped, so the trust check must run before it.
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        let prepare = fn_body.find("prepare_runsc_debug_dir").unwrap();
        let handoff = fn_body.find("prepare_gvisor_handoff_namespace").unwrap();
        assert!(prepare < handoff);

        let setup = include_str!("gvisor_setup.rs");
        let gvisor_body = extract_fn_body(setup, "fn setup_and_exec_gvisor");
        assert!(gvisor_body.contains("with_prepared_debug_dir(runsc_debug_dir)"));
    }

    #[test]
    fn test_keepid_handoff_transfers_caller_owned_bundle() {
        // Structural regression: the child must validate the explicit bundle
        // while still the launching user and transfer it to container ID 0
        // right after the user namespace handoff.
        let source = include_str!("runtime.rs");
        let fn_body = extract_fn_body(source, "fn setup_and_exec");
        let validate = fn_body.find("open_empty_bundle").unwrap();
        let handoff = fn_body.find("prepare_gvisor_handoff_namespace").unwrap();
        let transfer = fn_body.find("nix::unistd::fchown").unwrap();
        assert!(
            validate < handoff && handoff < transfer,
            "keep-id launches must validate the caller-owned bundle before the handoff and transfer it after"
        );
        let segment = &fn_body[handoff..transfer];
        assert!(
            segment.contains("gvisor_precreated_userns"),
            "the bundle transfer must be gated on the completed user namespace handoff"
        );
    }
}
