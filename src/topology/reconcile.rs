//! Reconciliation engine: diff running vs desired state and apply changes.
//!
//! Implements the core reconciliation loop that:
//! 1. Diffs running containers against the desired topology
//! 2. Stops containers whose config hash changed
//! 3. Starts new/changed containers in dependency order
//! 4. Leaves unchanged containers running

use crate::container::{ContainerLifecycle, ContainerStateManager, ProcessIdentity};
use crate::error::{NucleusError, Result};
use crate::isolation::{NamespaceCommandRunner, NamespaceProbe};
use crate::topology::config::{
    parse_service_volume_mount, parse_volume_owner, ServiceDef, TopologyConfig, VolumeDef,
};
use crate::topology::dag::DependencyGraph;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Reconciliation action for a single service.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileAction {
    /// Service is running with correct config – no action needed.
    NoChange,
    /// Service needs to be started (new or previously stopped).
    Start,
    /// Service config changed – stop then restart.
    Restart,
    /// Service is running but not in desired state – stop it.
    Stop,
}

/// The result of diffing desired vs running state.
#[derive(Debug)]
pub struct ReconcilePlan {
    /// Actions to take, in dependency order.
    pub actions: Vec<(String, ReconcileAction)>,
    /// Startup order from the DAG.
    pub startup_order: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostStartWait {
    Started,
    Healthy,
}

struct ServiceRunCommand {
    args: Vec<String>,
    secrets_file: Option<File>,
}

impl ServiceRunCommand {
    fn prepare_secret_fd_for_spawn(&self) -> Result<Option<FdCloexecGuard<'_>>> {
        self.secrets_file
            .as_ref()
            .map(prepare_inherited_fd)
            .transpose()
    }
}

struct FdCloexecGuard<'a> {
    file: &'a File,
    original_flags: FdFlag,
}

impl Drop for FdCloexecGuard<'_> {
    fn drop(&mut self) {
        let _ = fcntl(self.file, FcntlArg::F_SETFD(self.original_flags));
    }
}

fn prepare_inherited_fd(file: &File) -> Result<FdCloexecGuard<'_>> {
    let flags = fcntl(file, FcntlArg::F_GETFD).map_err(|e| {
        NucleusError::ExecError(format!(
            "Failed to inspect inherited secrets fd {}: {}",
            file.as_raw_fd(),
            e
        ))
    })?;
    let original_flags = FdFlag::from_bits_truncate(flags);
    let inherited_flags = original_flags & !FdFlag::FD_CLOEXEC;
    fcntl(file, FcntlArg::F_SETFD(inherited_flags)).map_err(|e| {
        NucleusError::ExecError(format!(
            "Failed to prepare inherited secrets fd {}: {}",
            file.as_raw_fd(),
            e
        ))
    })?;

    Ok(FdCloexecGuard {
        file,
        original_flags,
    })
}

fn path_component_cstring(component: &std::ffi::OsStr, path: &Path) -> Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| {
        NucleusError::ConfigError(format!(
            "Persistent volume path contains NUL byte: {:?}",
            path
        ))
    })
}

fn open_root_dir_nofollow() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to open filesystem root for persistent volume setup: {}",
                e
            ))
        })
}

fn mkdirat_child(parent: &File, name: &CString, mode: libc::mode_t, path: &Path) -> Result<()> {
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) };
    if rc == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(NucleusError::ConfigError(format!(
            "Failed to create persistent volume directory component under {:?}: {}",
            path, err
        )))
    }
}

fn openat_dir_nofollow(parent: &File, name: &CString, path: &Path) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };

    if fd < 0 {
        Err(NucleusError::ConfigError(format!(
            "Failed to open persistent volume directory component under {:?} without following symlinks: {}",
            path,
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn create_persistent_volume_dir_all_nofollow(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Persistent volume path must be absolute: {:?}",
            path
        )));
    }

    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name.to_os_string())),
            Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(Err(NucleusError::ConfigError(
                format!("Persistent volume path is not normalized: {:?}", path),
            ))),
        })
        .collect::<Result<Vec<_>>>()?;

    if components.is_empty() {
        return Err(NucleusError::ConfigError(
            "Persistent volume path must not be the filesystem root".to_string(),
        ));
    }

    let mut dir = open_root_dir_nofollow()?;
    let final_index = components.len() - 1;
    for (index, component) in components.iter().enumerate() {
        let name = path_component_cstring(component, path)?;
        let mode = if index == final_index { 0o700 } else { 0o755 };
        mkdirat_child(&dir, &name, mode, path)?;
        dir = openat_dir_nofollow(&dir, &name, path)?;
    }

    Ok(dir)
}

fn fchown_persistent_volume(dir: &File, owner: &str, volume_name: &str, path: &Path) -> Result<()> {
    let (uid, gid) = parse_volume_owner(owner)?;
    let rc = unsafe { libc::fchown(dir.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(NucleusError::ConfigError(format!(
            "Failed to set owner {} on persistent volume '{}' at {:?}: {}",
            owner,
            volume_name,
            path,
            std::io::Error::last_os_error()
        )))
    }
}

/// Diff the desired topology against running containers.
///
/// Returns a plan of actions to reconcile the two states.
pub fn plan_reconcile(
    config: &TopologyConfig,
    state_mgr: &ContainerStateManager,
) -> Result<ReconcilePlan> {
    let graph = DependencyGraph::resolve(config)?;
    let running_states = state_mgr.list_running().unwrap_or_default();

    // Build a map of running containers by name prefix
    let mut running_by_name: BTreeMap<String, Option<u64>> = BTreeMap::new();
    for state in &running_states {
        // Topology containers are named "topology-service" (e.g., "myapp-postgres")
        if state.name.starts_with(&format!("{}-", config.name)) {
            let service_name = state
                .name
                .strip_prefix(&format!("{}-", config.name))
                .unwrap_or(&state.name)
                .to_string();

            running_by_name.insert(service_name, state.config_hash);
        }
    }

    let mut actions = Vec::new();

    // Process in startup order
    for service_name in &graph.startup_order {
        let desired_hash = config.service_config_hash(service_name).unwrap_or(0);

        if let Some(&running_hash) = running_by_name.get(service_name) {
            if running_hash == Some(desired_hash) {
                actions.push((service_name.clone(), ReconcileAction::NoChange));
            } else {
                actions.push((service_name.clone(), ReconcileAction::Restart));
            }
        } else {
            actions.push((service_name.clone(), ReconcileAction::Start));
        }
    }

    // Find services that are running but not in desired state
    for running_name in running_by_name.keys() {
        if !config.services.contains_key(running_name) {
            actions.push((running_name.clone(), ReconcileAction::Stop));
        }
    }

    Ok(ReconcilePlan {
        actions,
        startup_order: graph.startup_order.clone(),
    })
}

/// Execute a reconciliation plan.
///
/// Stops changed/removed services in reverse dependency order,
/// then starts new/changed services in dependency order.
pub fn execute_reconcile(
    config: &TopologyConfig,
    plan: &ReconcilePlan,
    state_mgr: &ContainerStateManager,
    stop_timeout: u64,
    state_root: Option<&std::path::Path>,
) -> Result<()> {
    let graph = DependencyGraph::resolve(config)?;

    // Phase 1: Stop services that need stopping (in reverse dependency order)
    let shutdown_order = graph.shutdown_order();
    for service_name in &shutdown_order {
        let action = plan.actions.iter().find(|(n, _)| n == service_name);
        match action {
            Some((_, ReconcileAction::Restart)) | Some((_, ReconcileAction::Stop)) => {
                let container_name = format!("{}-{}", config.name, service_name);
                info!("Stopping service: {}", container_name);
                match state_mgr.resolve_container(&container_name) {
                    Ok(state) => {
                        if let Err(e) = ContainerLifecycle::stop(&state, stop_timeout) {
                            warn!("Failed to stop {}: {} (continuing)", container_name, e);
                        }
                    }
                    Err(_) => {
                        // Container not found – already stopped
                    }
                }
            }
            _ => {}
        }
    }

    // Phase 1b: Stop removed services that are NOT in shutdown_order.
    // shutdown_order only contains services from the desired topology, so
    // services that were removed from config won't appear there at all.
    for (service_name, action) in &plan.actions {
        if *action != ReconcileAction::Stop {
            continue;
        }
        // Already handled above if it happened to be in shutdown_order
        if shutdown_order.contains(service_name) {
            continue;
        }
        let container_name = format!("{}-{}", config.name, service_name);
        info!("Stopping removed service: {}", container_name);
        match state_mgr.resolve_container(&container_name) {
            Ok(state) => {
                if let Err(e) = ContainerLifecycle::stop(&state, stop_timeout) {
                    warn!("Failed to stop {}: {} (continuing)", container_name, e);
                }
            }
            Err(_) => {
                // Container not found – already stopped
            }
        }
    }

    // Phase 2: Start services that need starting (in dependency order)
    for service_name in &plan.startup_order {
        let action = plan.actions.iter().find(|(n, _)| n == service_name);
        match action {
            Some((_, ReconcileAction::Start)) | Some((_, ReconcileAction::Restart)) => {
                let svc = config.services.get(service_name).ok_or_else(|| {
                    NucleusError::ConfigError(format!(
                        "Service '{}' not found in topology",
                        service_name
                    ))
                })?;
                let container_name = format!("{}-{}", config.name, service_name);
                info!(
                    "Starting service: {} (rootfs={}, memory={})",
                    container_name, svc.rootfs, svc.memory
                );
                let desired_hash = config.service_config_hash(service_name).ok_or_else(|| {
                    NucleusError::ConfigError(format!(
                        "Service '{}' missing config hash",
                        service_name
                    ))
                })?;
                let run_command = build_service_run_command(
                    config,
                    service_name,
                    svc,
                    &container_name,
                    desired_hash,
                    state_root,
                )?;

                // Spawn the container as a background process
                // Fail hard if current_exe() fails instead of falling back to
                // PATH search. A PATH-resolved binary could be a malicious replacement.
                let nucleus_bin = std::env::current_exe().map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to resolve nucleus binary path via /proc/self/exe: {}. \
                         Refusing to fall back to PATH search for security.",
                        e
                    ))
                })?;

                let spawn_result = {
                    let _secrets_fd_guard = run_command.prepare_secret_fd_for_spawn()?;
                    Command::new(&nucleus_bin)
                        .args(&run_command.args[1..]) // skip "nucleus" since we're using current_exe
                        .stdin(Stdio::null())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .spawn()
                };
                match spawn_result {
                    Ok(child) => {
                        info!("Started service {} (PID {})", container_name, child.id());
                    }
                    Err(e) => {
                        return Err(NucleusError::ExecError(format!(
                            "Failed to start service {}: {}",
                            container_name, e
                        )));
                    }
                }
                drop(run_command);
                wait_for_started(state_mgr, &container_name, Duration::from_secs(10))?;
                if post_start_wait(&graph, service_name) == PostStartWait::Healthy {
                    wait_for_healthy(state_mgr, &container_name, service_name, svc)?;
                }
            }
            _ => {
                info!("Service {} unchanged, skipping", service_name);
            }
        }
    }

    Ok(())
}

fn prepare_persistent_volume(volume_name: &str, volume_def: &VolumeDef) -> Result<PathBuf> {
    let path = PathBuf::from(volume_def.path.as_ref().ok_or_else(|| {
        NucleusError::ConfigError(format!(
            "Persistent volume '{}' must define path",
            volume_name
        ))
    })?);

    if !path.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Persistent volume '{}' path must be absolute: {:?}",
            volume_name, path
        )));
    }

    let normalized = crate::filesystem::validate_bind_mount_source_policy(&path)?;
    let volume_dir = create_persistent_volume_dir_all_nofollow(&normalized)?;

    let canonical = fs::canonicalize(&normalized).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to canonicalize persistent volume '{}' at {:?}: {}",
            volume_name, normalized, e
        ))
    })?;
    crate::filesystem::validate_bind_mount_source(&canonical)?;

    if let Some(owner) = &volume_def.owner {
        fchown_persistent_volume(&volume_dir, owner, volume_name, &canonical)?;
    }

    Ok(canonical)
}

fn build_service_run_command(
    config: &TopologyConfig,
    service_name: &str,
    svc: &ServiceDef,
    container_name: &str,
    desired_hash: u64,
    state_root: Option<&std::path::Path>,
) -> Result<ServiceRunCommand> {
    let mut args = vec!["nucleus".to_string()];
    let mut secrets_file = None;

    // Propagate --root so the child uses the same state directory
    if let Some(root) = state_root {
        args.push("--root".to_string());
        args.push(root.to_string_lossy().to_string());
    }

    args.extend([
        "create".to_string(),
        "--service-mode".to_string(),
        "production".to_string(),
        "--quiet-id".to_string(),
        "--topology-config-hash".to_string(),
        desired_hash.to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--rootfs".to_string(),
        svc.rootfs.clone(),
        "--memory".to_string(),
        svc.memory.clone(),
        "--cpus".to_string(),
        svc.cpus.to_string(),
        "--pids".to_string(),
        svc.pids.to_string(),
        "--network".to_string(),
        if svc.networks.is_empty() {
            "none".to_string()
        } else {
            "bridge".to_string()
        },
    ]);

    for dns in &svc.dns {
        args.push("--dns".to_string());
        args.push(dns.clone());
    }

    if !svc.networks.is_empty() {
        args.push("--nat-backend".to_string());
        args.push(svc.nat_backend.as_str().to_string());
    }

    for cidr in &svc.egress_allow {
        args.push("--egress-allow".to_string());
        args.push(cidr.clone());
    }

    for domain in &svc.egress_domains {
        args.push("--egress-domain".to_string());
        args.push(domain.clone());
    }

    for port in &svc.egress_tcp_ports {
        args.push("--egress-tcp-port".to_string());
        args.push(port.to_string());
    }

    for port in &svc.egress_udp_ports {
        args.push("--egress-udp-port".to_string());
        args.push(port.to_string());
    }

    if let Some(endpoint) = &svc.credential_broker {
        args.push("--credential-broker".to_string());
        args.push(endpoint.clone());
        if svc.credential_broker_no_proxy_env {
            args.push("--credential-broker-no-proxy-env".to_string());
        }
    }

    for pf in &svc.port_forwards {
        args.push("-p".to_string());
        args.push(pf.clone());
    }

    for spec in &svc.volumes {
        let mount = parse_service_volume_mount(spec)?;
        let volume_def = config.volumes.get(&mount.volume).ok_or_else(|| {
            NucleusError::ConfigError(format!(
                "Service '{}' references unknown volume '{}'",
                service_name, mount.volume
            ))
        })?;
        match volume_def.volume_type.as_str() {
            "persistent" => {
                let host_path = prepare_persistent_volume(&mount.volume, volume_def)?;
                args.push("--volume".to_string());
                args.push(format!(
                    "{}:{}:{}",
                    host_path.to_string_lossy(),
                    mount.dest.to_string_lossy(),
                    if mount.read_only { "ro" } else { "rw" }
                ));
            }
            "ephemeral" => {
                args.push("--tmpfs".to_string());
                let mut spec = mount.dest.to_string_lossy().to_string();
                if let Some(size) = &volume_def.size {
                    spec.push(':');
                    spec.push_str(size);
                }
                if mount.read_only {
                    spec.push(':');
                    spec.push_str("ro");
                }
                args.push(spec);
            }
            other => {
                return Err(NucleusError::ConfigError(format!(
                    "Volume '{}' for service '{}' has unsupported type '{}'",
                    mount.volume, service_name, other
                )));
            }
        }
    }

    if !svc.secrets.is_empty() {
        let file = write_secrets_fd(container_name, &svc.secrets)?;
        args.push("--secrets-fd".to_string());
        args.push(file.as_raw_fd().to_string());
        secrets_file = Some(file);
    }

    for (key, value) in &svc.environment {
        args.push("-e".to_string());
        args.push(format!("{}={}", key, value));
    }

    if let Some(user) = &svc.user {
        args.push("--user".to_string());
        args.push(user.clone());
    }

    if let Some(group) = &svc.group {
        args.push("--group".to_string());
        args.push(group.clone());
    }

    for group in &svc.additional_groups {
        args.push("--additional-group".to_string());
        args.push(group.clone());
    }

    if let Some(ref hc) = svc.health_check {
        args.push("--health-cmd".to_string());
        args.push(hc.clone());
        args.push("--health-interval".to_string());
        args.push(svc.health_interval.to_string());
    }

    if svc.runtime == "gvisor" {
        args.push("--runtime".to_string());
        args.push("gvisor".to_string());
    }

    args.push("--sd-notify".to_string());
    args.push("--".to_string());
    args.extend(svc.command.clone());
    Ok(ServiceRunCommand { args, secrets_file })
}

fn write_secrets_fd(container_name: &str, secrets: &[String]) -> Result<File> {
    let mut file = tempfile::tempfile().map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to create anonymous secrets file for {}: {}",
            container_name, e
        ))
    })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to secure anonymous secrets file for {}: {}",
                container_name, e
            ))
        })?;

    serde_json::to_writer(&mut file, secrets).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to write anonymous secrets file for {}: {}",
            container_name, e
        ))
    })?;
    file.write_all(b"\n").map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to terminate anonymous secrets file for {}: {}",
            container_name, e
        ))
    })?;
    file.flush().map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to flush anonymous secrets file for {}: {}",
            container_name, e
        ))
    })?;
    file.rewind().map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to rewind anonymous secrets file for {}: {}",
            container_name, e
        ))
    })?;

    Ok(file)
}

fn post_start_wait(graph: &DependencyGraph, service_name: &str) -> PostStartWait {
    for dependent in graph.dependents.get(service_name).into_iter().flatten() {
        if let Some(edges) = graph.edges.get(dependent) {
            if edges
                .iter()
                .any(|edge| edge.service == service_name && edge.condition == "healthy")
            {
                return PostStartWait::Healthy;
            }
        }
    }
    PostStartWait::Started
}

fn wait_for_started(
    state_mgr: &ContainerStateManager,
    container_name: &str,
    timeout: Duration,
) -> Result<u32> {
    let start = Instant::now();
    loop {
        match state_mgr.resolve_container(container_name) {
            Ok(state) if state.is_running() => return Ok(state.pid),
            Ok(_) | Err(_) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                return Err(NucleusError::ExecError(format!(
                    "Service {} did not enter running state within {:?}",
                    container_name, timeout
                )));
            }
            Err(e) => {
                return Err(NucleusError::ExecError(format!(
                    "Service {} failed to register state within {:?}: {}",
                    container_name, timeout, e
                )));
            }
        }
    }
}

fn wait_for_healthy(
    state_mgr: &ContainerStateManager,
    container_name: &str,
    service_name: &str,
    svc: &ServiceDef,
) -> Result<()> {
    let health_cmd = svc.health_check.as_ref().ok_or_else(|| {
        NucleusError::ConfigError(format!(
            "Service '{}' must define health_check to satisfy healthy dependencies",
            service_name
        ))
    })?;

    let timeout_secs = (svc.health_interval.saturating_mul(3))
        .saturating_add(10)
        .max(20);
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();

    loop {
        let state = state_mgr.resolve_container(container_name)?;
        if !state.is_running() {
            return Err(NucleusError::ExecError(format!(
                "Service {} exited before becoming healthy",
                container_name
            )));
        }

        if health_check_passes(
            state.pid,
            state.rootless,
            state.using_gvisor,
            &ProcessIdentity {
                uid: state.process_uid,
                gid: state.process_gid,
                additional_gids: state.additional_gids.clone(),
            },
            health_cmd,
        )? {
            info!("Service {} is healthy", container_name);
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(NucleusError::ExecError(format!(
                "Service {} did not become healthy within {:?}",
                container_name, timeout
            )));
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Characters that are safe in shell commands passed to `sh -c`.
/// Only allow these characters – everything else is rejected.
const SAFE_HEALTH_CHECK_CHARS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', ' ', '-', '_', '.', '/', ':', '@', '=', '?',
];

/// Validate that a health check command contains only safe characters.
/// Uses an allowlist approach – only alphanumeric, spaces, and a few
/// safe punctuation marks are permitted.
fn validate_health_check_command(command: &str) -> Result<()> {
    if command.is_empty() {
        return Err(NucleusError::ConfigError(
            "Health check command must not be empty".to_string(),
        ));
    }
    for ch in command.chars() {
        if !SAFE_HEALTH_CHECK_CHARS.contains(&ch) {
            return Err(NucleusError::ConfigError(format!(
                "Health check command contains unsafe character '{}' (code point U+{:04X}): {}",
                ch.escape_default(),
                ch as u32,
                command
            )));
        }
    }
    Ok(())
}

fn health_check_passes(
    pid: u32,
    rootless: bool,
    using_gvisor: bool,
    process_identity: &ProcessIdentity,
    command: &str,
) -> Result<bool> {
    validate_health_check_command(command)?;

    NamespaceCommandRunner::run(
        pid,
        rootless,
        using_gvisor,
        NamespaceProbe::Exec(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            command.to_string(),
        ]),
        Some(process_identity),
        Some(Duration::from_secs(5)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerState, ContainerStateParams};
    use std::os::unix::fs::symlink;

    #[test]
    fn test_plan_new_topology() {
        let toml = r#"
name = "test"

[services.db]
rootfs = "/nix/store/db"
command = ["postgres"]
memory = "1G"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"

[[services.web.depends_on]]
service = "db"
condition = "healthy"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let state_mgr = ContainerStateManager::with_state_dir(temp.path().join("nucleus")).unwrap();
        let plan = plan_reconcile(&config, &state_mgr).unwrap();

        // Both services should be Start since nothing is running
        assert_eq!(plan.actions.len(), 2);
        assert!(plan
            .actions
            .iter()
            .all(|(_, a)| *a == ReconcileAction::Start));
        // db should be before web in startup order
        assert_eq!(plan.startup_order[0], "db");
        assert_eq!(plan.startup_order[1], "web");
    }

    #[test]
    fn test_plan_matching_running_hash_is_no_change() {
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let state_mgr = ContainerStateManager::with_state_dir(temp.path().join("nucleus")).unwrap();
        let mut state = ContainerState::new(ContainerStateParams {
            id: "abc123".to_string(),
            name: "test-web".to_string(),
            pid: std::process::id(),
            command: vec!["/bin/web".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        state.config_hash = config.service_config_hash("web");
        state_mgr.save_state(&state).unwrap();

        let plan = plan_reconcile(&config, &state_mgr).unwrap();
        assert_eq!(
            plan.actions,
            vec![("web".to_string(), ReconcileAction::NoChange)]
        );
    }

    #[test]
    fn test_post_start_wait_marks_healthy_dependencies() {
        let toml = r#"
name = "test"

[services.db]
rootfs = "/nix/store/db"
command = ["postgres"]
memory = "1G"
health_check = "pg_isready"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"

[[services.web.depends_on]]
service = "db"
condition = "healthy"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let graph = DependencyGraph::resolve(&config).unwrap();

        assert_eq!(post_start_wait(&graph, "db"), PostStartWait::Healthy);
        assert_eq!(post_start_wait(&graph, "web"), PostStartWait::Started);
    }

    #[test]
    fn test_build_service_run_args_include_topology_hash() {
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
credential_broker = "10.0.42.1:8080"
credential_broker_no_proxy_env = true
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let svc = config.services.get("web").unwrap();
        let run_command =
            build_service_run_command(&config, "web", svc, "test-web", 42, None).unwrap();
        let args = run_command.args;

        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--topology-config-hash" && pair[1] == "42" }));
        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--credential-broker" && pair[1] == "10.0.42.1:8080" }));
        assert!(args
            .iter()
            .any(|arg| { arg == "--credential-broker-no-proxy-env" }));
        assert!(args.iter().any(|arg| arg == "--quiet-id"));
    }

    #[test]
    fn test_build_service_run_args_include_bind_and_tmpfs_volumes() {
        let persistent_dir = tempfile::TempDir::new().unwrap();
        let persistent_path = persistent_dir.path().join("db-data");
        let toml = format!(
            r#"
name = "test"

[volumes.db-data]
volume_type = "persistent"
path = "{}"

[volumes.cache]
volume_type = "ephemeral"
size = "64M"

[services.db]
rootfs = "/nix/store/db"
command = ["postgres"]
memory = "1G"
volumes = [
  "db-data:/var/lib/postgresql/data",
  "cache:/var/cache/postgresql:ro"
]
"#,
            persistent_path.display()
        );
        let config = TopologyConfig::from_toml(&toml).unwrap();
        let svc = config.services.get("db").unwrap();
        let run_command =
            build_service_run_command(&config, "db", svc, "test-db", 7, None).unwrap();
        let args = run_command.args;

        assert!(
            persistent_path.exists(),
            "persistent volume path must be created"
        );
        assert!(args.windows(2).any(|pair| {
            pair[0] == "--volume"
                && pair[1].contains(":/var/lib/postgresql/data:rw")
                && pair[1].starts_with(persistent_path.to_string_lossy().as_ref())
        }));
        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--tmpfs" && pair[1] == "/var/cache/postgresql:64M:ro" }));
    }

    #[test]
    fn test_build_service_run_command_passes_topology_secrets_by_fd() {
        let secret_dir = tempfile::TempDir::new().unwrap();
        let secret_path = secret_dir.path().join("cloud-provider-token");
        let secret_spec = format!(
            "{}:/run/secrets/cloud_api_key",
            secret_path.to_string_lossy()
        );
        let toml = format!(
            r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
secrets = ["{}"]
"#,
            secret_spec
        );
        let config = TopologyConfig::from_toml(&toml).unwrap();
        let svc = config.services.get("web").unwrap();
        let run_command =
            build_service_run_command(&config, "web", svc, "test-web", 42, None).unwrap();

        assert!(run_command.secrets_file.is_some());
        assert!(!run_command.args.iter().any(|arg| arg == "--secret"));
        assert!(!run_command.args.iter().any(|arg| arg == &secret_spec));
        assert!(!run_command
            .args
            .iter()
            .any(|arg| arg.contains("cloud-provider-token")
                || arg.contains("/run/secrets/cloud_api_key")));
        assert!(run_command.args.windows(2).any(|pair| {
            pair[0] == "--secrets-fd"
                && pair[1]
                    == run_command
                        .secrets_file
                        .as_ref()
                        .unwrap()
                        .as_raw_fd()
                        .to_string()
        }));
    }

    #[test]
    fn test_prepare_persistent_volume_rejects_symlink_parent() {
        let temp = tempfile::TempDir::new().unwrap();
        let victim = temp.path().join("victim");
        let link = temp.path().join("link");
        std::fs::create_dir(&victim).unwrap();
        symlink(&victim, &link).unwrap();

        let volume = VolumeDef {
            volume_type: "persistent".to_string(),
            path: Some(link.join("data").to_string_lossy().to_string()),
            owner: None,
            size: None,
        };

        let err = prepare_persistent_volume("data", &volume).unwrap_err();
        assert!(
            err.to_string().contains("without following symlinks"),
            "unexpected error: {err}"
        );
        assert!(
            !victim.join("data").exists(),
            "persistent volume setup must not create directories through symlink parents"
        );
    }

    #[test]
    fn test_prepare_persistent_volume_rejects_final_symlink() {
        let temp = tempfile::TempDir::new().unwrap();
        let victim = temp.path().join("victim");
        let link = temp.path().join("volume");
        std::fs::create_dir(&victim).unwrap();
        symlink(&victim, &link).unwrap();

        let volume = VolumeDef {
            volume_type: "persistent".to_string(),
            path: Some(link.to_string_lossy().to_string()),
            owner: None,
            size: None,
        };

        let err = prepare_persistent_volume("data", &volume).unwrap_err();
        assert!(
            err.to_string().contains("without following symlinks"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_build_service_run_args_include_nat_backend_for_bridge_services() {
        let toml = r#"
name = "test"

[networks.internal]
subnet = "10.42.0.0/24"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
networks = ["internal"]
nat_backend = "userspace"
egress_udp_ports = [53]
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let svc = config.services.get("web").unwrap();
        let run_command =
            build_service_run_command(&config, "web", svc, "test-web", 42, None).unwrap();
        let args = run_command.args;

        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--nat-backend" && pair[1] == "userspace"));
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--egress-udp-port" && pair[1] == "53"));
    }

    #[test]
    fn test_build_service_run_args_omit_nat_backend_for_network_none_services() {
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let svc = config.services.get("web").unwrap();
        let run_command =
            build_service_run_command(&config, "web", svc, "test-web", 42, None).unwrap();
        let args = run_command.args;

        assert!(!args.iter().any(|arg| arg == "--nat-backend"));
    }

    #[test]
    fn test_topology_reconcile_does_not_forward_oci_hooks() {
        let source = include_str!("reconcile.rs");
        let fn_body = extract_fn_body(source, "fn build_service_run_command");
        assert!(
            !fn_body.contains("\"--hooks\"") && !fn_body.contains("nucleus-hooks-"),
            "topology reconciliation must not forward OCI hooks from service config"
        );
    }

    #[test]
    fn test_health_check_rejects_shell_metacharacters() {
        // H-4: health check commands must only contain allowlisted characters
        assert!(validate_health_check_command("pg_isready").is_ok());
        assert!(validate_health_check_command("curl -f http://localhost:8080/health").is_ok());

        // Semicolon injection – not in allowlist
        assert!(validate_health_check_command("pg_isready; rm -rf /").is_err());
        // Pipe – not in allowlist
        assert!(validate_health_check_command("echo test | sh").is_err());
        // Command substitution – not in allowlist
        assert!(validate_health_check_command("$(cat /etc/shadow)").is_err());
        // Backtick – not in allowlist
        assert!(validate_health_check_command("`cat /etc/shadow`").is_err());
        // Dollar sign – not in allowlist
        assert!(validate_health_check_command("$HOME").is_err());
        // Background ampersand – not in allowlist
        assert!(validate_health_check_command("malware &").is_err());
        // Empty
        assert!(validate_health_check_command("").is_err());
        // Newline – not in allowlist
        assert!(validate_health_check_command("test\ngood").is_err());
    }

    /// Extract the body of a function from source text by brace-matching,
    /// avoiding fragile hardcoded character-window offsets (SEC-MED-03).
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
    fn test_topology_health_checks_do_not_spawn_host_nsenter() {
        let source = include_str!("reconcile.rs");
        let fn_body = extract_fn_body(source, "fn health_check_passes");
        assert!(
            !fn_body.contains("Command::new(resolve_nsenter())"),
            "topology health checks must not execute via host nsenter"
        );
    }

    #[test]
    fn test_plan_stop_for_removed_services() {
        // BUG-01: Services removed from topology must get ReconcileAction::Stop
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let state_mgr = ContainerStateManager::with_state_dir(temp.path().join("nucleus")).unwrap();

        // Simulate a previously-running service "db" that is no longer in config
        let state = ContainerState::new(ContainerStateParams {
            id: "old-db-id".to_string(),
            name: "test-db".to_string(),
            pid: std::process::id(), // use our own PID so is_running() returns true
            command: vec!["postgres".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });
        state_mgr.save_state(&state).unwrap();

        let plan = plan_reconcile(&config, &state_mgr).unwrap();

        // The plan must include a Stop action for "db"
        let stop_actions: Vec<_> = plan
            .actions
            .iter()
            .filter(|(_, a)| *a == ReconcileAction::Stop)
            .collect();
        assert!(
            !stop_actions.is_empty(),
            "removed services must have Stop action"
        );
        assert_eq!(stop_actions[0].0, "db");
    }
}
