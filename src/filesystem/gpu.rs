//! GPU passthrough device discovery and filesystem binding.
//!
//! This module resolves which host GPU device nodes (and the minimal driver
//! support files they require) should be exposed to a container, and performs
//! the bind mounts that expose them. The cgroup device allowlist and seccomp
//! relaxation live in [`crate::resources::cgroup`] and [`crate::security`]
//! respectively; this module only owns the *which devices* and *mount them*
//! concerns.
//!
//! See `spec/gpu-passthrough.md` for the full design.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::container::{GpuPassthroughConfig, GpuVendor, ProcessIdentity};
use crate::error::{NucleusError, Result};

/// NVIDIA device-node glob patterns (regex-free) scanned under the host `/dev`.
const NVIDIA_DEVICE_NAMES: &[&str] = &[
    "nvidiactl",
    "nvidia-uvm",
    "nvidia-uvm-tools",
];

/// Directory holding NVIDIA capability device nodes on newer drivers.
const NVIDIA_CAPS_DIR: &str = "nvidia-caps";

/// A resolved set of host GPU device nodes plus the vendor flags needed by the
/// rest of the runtime (env vars, support-file selection).
#[derive(Debug, Clone, Default)]
pub struct GpuDeviceSet {
    /// Canonical host device node paths to bind into the container `/dev`.
    pub nodes: Vec<PathBuf>,
    pub nvidia: bool,
    pub amd: bool,
    pub intel: bool,
}

impl GpuDeviceSet {
    /// Number of devices that will be exposed.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether any GPU device was resolved.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Major/minor/device-kind for every node, for the cgroup device BPF.
    ///
    /// Nodes that cannot be stat'd are skipped (with a debug log); the cgroup
    /// allowlist is best-effort and the filesystem layer remains the primary
    /// gate.
    pub fn device_specs(&self) -> Vec<DeviceNodeSpec> {
        self.node_specs_with_paths().iter().map(|(_, s)| *s).collect()
    }

    /// Each node paired with its host path, for OCI device entries and the
    /// cgroup device BPF.
    pub fn node_specs_with_paths(&self) -> Vec<(PathBuf, DeviceNodeSpec)> {
        let mut out = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            match fs::metadata(node) {
                Ok(meta) => {
                    let rdev = meta.rdev();
                    out.push((
                        node.clone(),
                        DeviceNodeSpec {
                            is_block: meta.file_type().is_block_device(),
                            major: major_of(rdev),
                            minor: minor_of(rdev),
                        },
                    ));
                }
                Err(e) => debug!("cannot stat GPU device {:?}: {}", node, e),
            }
        }
        out
    }
}

/// A single device node's identity for the cgroup device allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNodeSpec {
    pub is_block: bool,
    pub major: u32,
    pub minor: u32,
}

/// Extract the major number from a `st_rdev` value (Linux `MAJOR` macro).
pub fn major_of(rdev: u64) -> u32 {
    // MAJOR(dev) = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)
    (((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xfffff000)) as u32
}

/// Extract the minor number from a `st_rdev` value (Linux `MINOR` macro).
pub fn minor_of(rdev: u64) -> u32 {
    // MINOR(dev) = (dev & 0xff) | ((dev >> 12) & 0xfff00)
    ((rdev & 0xff) | ((rdev >> 12) & 0xfff00)) as u32
}

/// Resolve the GPU device set for a configuration.
///
/// When `config.devices` is non-empty, those explicit host paths are validated
/// and used verbatim (deduplicated, sorted). Otherwise the host `/dev` is
/// scanned according to `config.vendor`.
///
/// Returns `Ok(None)` when no GPU devices are present and none were requested
/// explicitly — callers decide whether that is an error.
pub fn resolve_gpu_devices(config: &GpuPassthroughConfig) -> Result<Option<GpuDeviceSet>> {
    if !config.devices.is_empty() {
        return resolve_explicit(&config.devices, config.vendor);
    }
    discover_gpu_at(Path::new("/dev"), config.vendor)
}

/// Resolve an explicitly-provided device list.
fn resolve_explicit(devices: &[PathBuf], vendor: GpuVendor) -> Result<Option<GpuDeviceSet>> {
    let mut canonical: Vec<PathBuf> = Vec::with_capacity(devices.len());
    for dev in devices {
        canonical.push(validate_host_device(dev)?);
    }
    Ok(build_explicit_set(&canonical, vendor))
}

/// Build a [`GpuDeviceSet`] from already-validated canonical device paths.
///
/// Separated from [`resolve_explicit`] so the dedup/sort/classify logic is
/// unit-testable without real device nodes (which require root to create).
pub(crate) fn build_explicit_set(canonical: &[PathBuf], vendor: GpuVendor) -> Option<GpuDeviceSet> {
    let mut set = GpuDeviceSet::default();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for dev in canonical {
        if !seen.insert(dev.clone()) {
            debug!("ignoring duplicate GPU device {:?}", dev);
            continue;
        }
        classify_into(dev, vendor, &mut set);
        set.nodes.push(dev.clone());
    }
    set.nodes.sort();
    if set.nodes.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// Validate that `path` is an existing, non-symlink device node on the host.
fn validate_host_device(path: &Path) -> Result<PathBuf> {
    // Reject obvious traversal before canonicalizing.
    let canonical = fs::canonicalize(path).map_err(|e| {
        NucleusError::ConfigError(format!(
            "GPU device '{}' does not exist or cannot be resolved: {}",
            path.display(),
            e
        ))
    })?;
    let meta = fs::symlink_metadata(&canonical)
        .map_err(|e| NucleusError::ConfigError(format!("Failed to stat GPU device '{}': {}", canonical.display(), e)))?;
    if meta.file_type().is_symlink() {
        return Err(NucleusError::ConfigError(format!(
            "GPU device '{}' must not be a symlink",
            canonical.display()
        )));
    }
    if !meta.file_type().is_char_device() && !meta.file_type().is_block_device() {
        return Err(NucleusError::ConfigError(format!(
            "GPU device '{}' is not a device node",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// Discover GPU device nodes under `dev_root` (normally `/dev`).
///
/// Exposed separately from [`resolve_gpu_devices`] so it can be unit-tested
/// against a temporary `/dev` tree without root.
pub fn discover_gpu_at(dev_root: &Path, vendor: GpuVendor) -> Result<Option<GpuDeviceSet>> {
    discover_gpu_with(dev_root, vendor, is_char_device)
}

/// Discovery core with an injectable device validator.
///
/// The validator lets tests scan a tempdir of regular files; production paths
/// pass [`is_char_device`].
pub(crate) fn discover_gpu_with(
    dev_root: &Path,
    vendor: GpuVendor,
    is_dev: impl Fn(&Path) -> bool,
) -> Result<Option<GpuDeviceSet>> {
    let mut set = GpuDeviceSet::default();

    if vendor.includes_nvidia() {
        collect_nvidia(dev_root, vendor, &mut set, &is_dev)?;
    }
    if vendor.includes_amd() {
        collect_amd(dev_root, vendor, &mut set, &is_dev);
    }
    if vendor.includes_intel() {
        collect_intel(dev_root, vendor, &mut set, &is_dev);
    }

    if set.nodes.is_empty() {
        return Ok(None);
    }

    // Dedup (render nodes are shared between AMD/Intel) and sort for determinism.
    let mut deduped: Vec<PathBuf> = set.nodes.into_iter().collect::<HashSet<_>>().into_iter().collect();
    deduped.sort();
    set.nodes = deduped;
    Ok(Some(set))
}

fn collect_nvidia(
    dev_root: &Path,
    vendor: GpuVendor,
    set: &mut GpuDeviceSet,
    is_dev: &impl Fn(&Path) -> bool,
) -> Result<()> {
    // /dev/nvidia[0-9]+
    let mut found = false;
    if let Ok(entries) = fs::read_dir(dev_root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("nvidia") {
                if !rest.is_empty()
                    && rest.chars().all(|c| c.is_ascii_digit())
                    && is_dev(&entry.path())
                {
                    push_existing(dev_root, &name, set, is_dev);
                    found = true;
                }
            }
        }
    }

    for fixed in NVIDIA_DEVICE_NAMES {
        push_existing(dev_root, fixed, set, is_dev);
    }

    // /dev/nvidia-caps/* (capability device nodes on newer drivers).
    let caps = dev_root.join(NVIDIA_CAPS_DIR);
    if caps.is_dir() {
        if let Ok(entries) = fs::read_dir(&caps) {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_dev(&path) {
                    if let Ok(canonical) = fs::canonicalize(&path) {
                        set.nodes.push(canonical);
                    }
                }
            }
        }
    }

    set.nvidia = vendor.includes_nvidia()
        && (found
            || set
                .nodes
                .iter()
                .any(|p| p.file_name().map(|f| f.to_string_lossy().starts_with("nvidia")).unwrap_or(false)));
    Ok(())
}

fn collect_amd(dev_root: &Path, vendor: GpuVendor, set: &mut GpuDeviceSet, is_dev: &impl Fn(&Path) -> bool) {
    let had_before = set.nodes.len();
    push_existing(dev_root, "kfd", set, is_dev);
    collect_render_nodes(dev_root, set, is_dev);
    if set.nodes.len() > had_before {
        set.amd = vendor.includes_amd();
    }
}

fn collect_intel(dev_root: &Path, vendor: GpuVendor, set: &mut GpuDeviceSet, is_dev: &impl Fn(&Path) -> bool) {
    let had_before = set.nodes.len();
    collect_render_nodes(dev_root, set, is_dev);
    // /dev/dri/card[0-9]+ are the kernel KMS nodes; bind them so Mesa/DRI works.
    if let Ok(entries) = fs::read_dir(dev_root.join("dri")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("card") {
                if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                    push_under_dir(&dev_root.join("dri"), &name, set, is_dev);
                }
            }
        }
    }
    if set.nodes.len() > had_before {
        set.intel = vendor.includes_intel();
    }
}

/// Collect `/dev/dri/renderD[0-9]+` (V3D/AMD/Intel render nodes).
fn collect_render_nodes(dev_root: &Path, set: &mut GpuDeviceSet, is_dev: &impl Fn(&Path) -> bool) {
    let dri = dev_root.join("dri");
    if let Ok(entries) = fs::read_dir(&dri) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("renderD") {
                if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                    push_under_dir(&dri, &name, set, is_dev);
                }
            }
        }
    }
}

fn push_existing(dev_root: &Path, name: &str, set: &mut GpuDeviceSet, is_dev: &impl Fn(&Path) -> bool) {
    let path = dev_root.join(name);
    if is_dev(&path) {
        if let Ok(canonical) = fs::canonicalize(&path) {
            set.nodes.push(canonical);
        }
    }
}

fn push_under_dir(dir: &Path, name: &str, set: &mut GpuDeviceSet, is_dev: &impl Fn(&Path) -> bool) {
    let path = dir.join(name);
    if is_dev(&path) {
        if let Ok(canonical) = fs::canonicalize(&path) {
            set.nodes.push(canonical);
        }
    }
}

fn is_char_device(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false)
}

/// Classify an explicit device into vendor flags by its canonical name.
fn classify_into(path: &Path, _vendor: GpuVendor, set: &mut GpuDeviceSet) {
    let name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    if name.starts_with("nvidia") {
        set.nvidia = true;
    } else if name == "kfd" {
        set.amd = true;
    } else if name.starts_with("renderD") || name.starts_with("card") {
        // Ambiguous between AMD/Intel; mark both so env/support logic is permissive.
        set.amd = true;
        set.intel = true;
    }
}

/// Candidate host support files for the resolved vendor set.
///
/// Only paths that actually exist on the host are returned, so callers can
/// bind them unconditionally and simply skip missing ones.
pub fn support_paths(set: &GpuDeviceSet, bind_driver_libs: bool) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if set.nvidia {
        let proc_driver = Path::new("/proc/driver/nvidia");
        if proc_driver.is_dir() {
            paths.push(proc_driver.to_path_buf());
        }
        if bind_driver_libs {
            // NVIDIA driver userspace libraries and the CUDA toolkit, in the
            // standard Debian/Ubuntu and runfile locations. Bound read-only.
            for lib_dir in [
                "/usr/lib/x86_64-linux-gnu",
                "/usr/lib64",
                "/opt/nvidia",
                "/usr/local/cuda",
            ] {
                let dir = Path::new(lib_dir);
                if dir.is_dir() && dir_contains_nvidia_libs(dir) {
                    paths.push(dir.to_path_buf());
                }
            }
            // Vulkan/ICD manifest JSON so the container's loader finds the host driver.
            for icd in [
                "/etc/vulkan/icd.d",
                "/usr/share/vulkan/icd.d",
                "/etc/glvnd/egl_vendor.d",
                "/usr/share/glvnd/egl_vendor.d",
            ] {
                let dir = Path::new(icd);
                if dir.is_dir() && dir_contains_json(dir) {
                    paths.push(dir.to_path_buf());
                }
            }
        }
    }

    if set.amd && bind_driver_libs {
        for dir in ["/opt/rocm", "/opt/amdgpu"] {
            let d = Path::new(dir);
            if d.is_dir() {
                paths.push(d.to_path_buf());
            }
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

fn dir_contains_nvidia_libs(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("libnvidia") || name.starts_with("libcuda") {
            return true;
        }
    }
    false
}

fn dir_contains_json(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten()
        .any(|e| e.file_name().to_string_lossy().ends_with(".json"))
}

/// Result of binding GPU devices into a container root.
#[derive(Debug, Clone, Default)]
pub struct GpuMountResult {
    /// Device nodes bound (host -> container-relative under /dev).
    pub bound_devices: Vec<(PathBuf, PathBuf)>,
    /// Support files/dirs bound.
    pub bound_support: Vec<PathBuf>,
    /// Whether the bind was performed read-only for support files.
    pub nvidia: bool,
    pub amd: bool,
    pub intel: bool,
}

/// Bind-mount the resolved GPU devices and support files into `root`.
///
/// Device nodes are bound under `root/dev/...` preserving their host path so
/// libraries that hardcode `/dev/nvidia0` continue to work. Each node is
/// chown'd to the workload identity so a non-root workload can open it, and
/// left mode 0660.
///
/// This runs in the child after `create_dev_nodes` and before `pivot_root`.
pub fn mount_gpu_passthrough(
    root: &Path,
    set: &GpuDeviceSet,
    config: &GpuPassthroughConfig,
    identity: &ProcessIdentity,
) -> Result<GpuMountResult> {
    use nix::mount::{mount, MsFlags};
    use nix::unistd::{chown, Gid, Uid};

    let mut result = GpuMountResult {
        nvidia: set.nvidia,
        amd: set.amd,
        intel: set.intel,
        ..Default::default()
    };

    let dev_path = root.join("dev");
    std::fs::create_dir_all(&dev_path).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to create container /dev: {}", e))
    })?;

    let bind_flags = MsFlags::MS_BIND | MsFlags::MS_REC;

    for host_node in &set.nodes {
        // Mirror the host path under the container /dev.
        let rel = host_node
            .strip_prefix("/")
            .unwrap_or(host_node.as_path());
        let target = dev_path.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create device parent dir {:?}: {}",
                    parent, e
                ))
            })?;
        }

        // Create a placeholder node so the bind mount has a mountpoint. Use
        // mknod of a char device (best effort; rootful path).
        let _ = create_placeholder_char_node(&target);

        mount(
            Some(host_node),
            &target,
            None::<&str>,
            bind_flags,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind GPU device {:?} -> {:?}: {}",
                host_node, target, e
            ))
        })?;

        // Make the node usable by the (possibly non-root) workload identity.
        let gid = if identity.gid != 0 {
            Some(Gid::from_raw(identity.gid))
        } else {
            None
        };
        let uid = if identity.uid != 0 {
            Some(Uid::from_raw(identity.uid))
        } else {
            None
        };
        let _ = chown(&target, uid, gid);
        let _ = std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o660),
        );

        result
            .bound_devices
            .push((host_node.clone(), target.strip_prefix(root).unwrap_or(&target).to_path_buf()));
        info!("Bound GPU device {:?} -> /dev/{}", host_node, rel.display());
    }

    // Driver support files (NVIDIA /proc, lib dirs, ICD JSON; ROCm /opt/rocm).
    for support in support_paths(set, config.bind_driver_libraries) {
        let rel = support.strip_prefix("/").unwrap_or(support.as_path());
        let target = root.join(rel);
        if let Some(parent) = target.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if support.is_dir() {
            let _ = std::fs::create_dir_all(&target);
        } else {
            // Create a placeholder regular file so the bind has a mountpoint.
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&target);
        }

        mount(
            Some(&support),
            &target,
            None::<&str>,
            bind_flags,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind GPU support {:?} -> {:?}: {}",
                support, target, e
            ))
        })?;

        // Remount read-only: device drivers and ICD manifests are read-only inputs.
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            bind_flags | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| {
            // Read-only remount is best-effort: some NVIDIA proc files are
            // writable by the driver; warn but keep the rw bind.
            warn!(
                "Failed to remount GPU support {:?} read-only: {} (leaving rw)",
                target, e
            );
            NucleusError::FilesystemError(format!("read-only remount failed: {}", e))
        })
        .ok();

        result
            .bound_support
            .push(target.strip_prefix(root).unwrap_or(&target).to_path_buf());
        debug!("Bound GPU support {:?}", support);
    }

    Ok(result)
}

fn create_placeholder_char_node(target: &Path) -> Result<()> {
    use nix::sys::stat::{makedev, mknod, Mode, SFlag};
    let dev = makedev(0, 0);
    match mknod(target, SFlag::S_IFCHR, Mode::from_bits_truncate(0o600), dev) {
        Ok(_) => Ok(()),
        Err(nix::Error::EEXIST) => Ok(()),
        Err(e) => {
            debug!("placeholder mknod for {:?} failed (continuing): {}", target, e);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
