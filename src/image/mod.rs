use crate::container::{ContainerState, RootfsMode};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    is_immediate_nix_store_object_path, read_rootfs_attestation, DirectoryManifest,
    ROOTFS_ATTESTATION_FILE, ROOTFS_STORE_PATHS_FILE,
};
use crate::resources::Cgroup;
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

pub const IMAGE_SCHEMA_VERSION: u32 = 2;
pub const IMAGE_MANIFEST_FILE: &str = "manifest.json";
pub const IMAGE_SIGNATURE_FILE: &str = "image.sig";
pub const IMAGE_ROOTFS_ATTESTATION_FILE: &str = "rootfs.sha256";
pub const IMAGE_STORE_PATHS_FILE: &str = "store-paths";
pub const IMAGE_DIFF_DIR: &str = "diff";
const IMAGE_HMAC_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NucleusImageManifest {
    pub schema_version: u32,
    pub image_id: String,
    pub created_at: u64,
    pub nucleus_version: String,
    pub base: ImageBase,
    pub diff: Option<ImageDiff>,
    pub config: ImageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageBase {
    pub rootfs_path: String,
    pub store_paths: Vec<String>,
    pub attestation: DirectoryManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageDiff {
    pub path: String,
    pub manifest: BTreeMap<String, String>,
    pub deleted_paths: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageConfig {
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub workdir: String,
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct ImageCommitOptions {
    pub freeze: bool,
}

impl NucleusImageManifest {
    pub fn new(base: ImageBase, diff: Option<ImageDiff>, config: ImageConfig) -> Result<Self> {
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut manifest = Self {
            schema_version: IMAGE_SCHEMA_VERSION,
            image_id: String::new(),
            created_at,
            nucleus_version: env!("CARGO_PKG_VERSION").to_string(),
            base,
            diff,
            config,
        };
        manifest.image_id = manifest.compute_image_id()?;
        Ok(manifest)
    }

    pub fn compute_image_id(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.image_id.clear();
        let canonical = serde_json::to_vec(&unsigned)?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }

    pub fn validate_identity(&self) -> Result<()> {
        if self.schema_version != IMAGE_SCHEMA_VERSION {
            return Err(image_error(format!(
                "Unsupported image schema version {}",
                self.schema_version
            )));
        }
        let expected = self.compute_image_id()?;
        if self.image_id != expected {
            return Err(image_error(format!(
                "Image manifest digest mismatch: expected {}, got {}",
                expected, self.image_id
            )));
        }
        Ok(())
    }

    pub fn save(&self, image_dir: &Path) -> Result<()> {
        atomic_write_json(image_dir, IMAGE_MANIFEST_FILE, self)
    }

    pub fn load(image_dir: &Path) -> Result<Self> {
        let path = image_dir.join(IMAGE_MANIFEST_FILE);
        let json = read_file_nofollow_bytes(&path)
            .map_err(|e| image_error(format!("Failed to read image manifest {:?}: {}", path, e)))?;
        let manifest: Self = serde_json::from_slice(&json)?;
        manifest.validate_identity()?;
        Ok(manifest)
    }
}

impl ImageBase {
    pub fn from_rootfs(rootfs_path: &Path) -> Result<Self> {
        let rootfs_path = fs::canonicalize(rootfs_path).map_err(|e| {
            image_error(format!(
                "Failed to canonicalize rootfs path {:?}: {}",
                rootfs_path, e
            ))
        })?;
        let store_paths = read_store_paths(&rootfs_path)?;
        let attestation = read_rootfs_attestation(&rootfs_path)?;
        Ok(Self {
            rootfs_path: rootfs_path.display().to_string(),
            store_paths,
            attestation,
        })
    }
}

impl ImageConfig {
    pub fn from_state(state: &ContainerState) -> Self {
        Self {
            command: state.command.clone(),
            env: state.environment.clone(),
            workdir: state.workdir.clone(),
            uid: state.process_uid,
            gid: state.process_gid,
            additional_gids: state.additional_gids.clone(),
        }
    }
}

pub fn commit_container_image(
    state: &ContainerState,
    output_dir: &Path,
    options: &ImageCommitOptions,
) -> Result<NucleusImageManifest> {
    if state.rootfs_mode != RootfsMode::Overlay {
        return Err(image_error(format!(
            "Container {} was launched with rootfs_mode={:?}; image commit requires overlay",
            state.id, state.rootfs_mode
        )));
    }

    let rootfs_path = state.rootfs_path.as_deref().ok_or_else(|| {
        image_error(format!(
            "Container {} has no recorded rootfs path; cannot commit image",
            state.id
        ))
    })?;
    let upperdir = state.rootfs_upperdir.as_deref().ok_or_else(|| {
        image_error(format!(
            "Container {} has no recorded overlay upperdir; cannot commit image",
            state.id
        ))
    })?;
    let upperdir = PathBuf::from(upperdir);
    ensure_real_directory(&upperdir, "overlay upperdir")?;

    let _freeze_guard = if options.freeze {
        let cgroup_path = state.cgroup_path.as_deref().ok_or_else(|| {
            image_error(format!(
                "Container {} has no recorded cgroup path; cannot freeze for image commit",
                state.id
            ))
        })?;
        Some(Cgroup::freeze_existing(Path::new(cgroup_path))?)
    } else {
        None
    };

    prepare_image_dir(output_dir)?;
    let diff_dir = output_dir.join(IMAGE_DIFF_DIR);
    prepare_empty_dir(&diff_dir, "image diff directory")?;

    let base = ImageBase::from_rootfs(Path::new(rootfs_path))?;
    copy_base_sidecars(Path::new(rootfs_path), output_dir)?;
    let diff = export_diff(&upperdir, &diff_dir)?;
    let config = ImageConfig::from_state(state);
    let manifest = NucleusImageManifest::new(base, Some(diff), config)?;
    manifest.save(output_dir)?;
    write_image_hmac(output_dir)?;
    Ok(manifest)
}

pub fn load_image(image_dir: &Path) -> Result<NucleusImageManifest> {
    let sig_path = image_dir.join(IMAGE_SIGNATURE_FILE);
    if sig_path.exists() {
        verify_image_hmac(image_dir)?;
    } else if !is_immediate_nix_store_object_path(image_dir) {
        return Err(image_error(format!(
            "Image signature {:?} is missing outside the Nix store",
            sig_path
        )));
    }
    NucleusImageManifest::load(image_dir)
}

pub fn copy_image_diff_to_upper(image_dir: &Path, upperdir: &Path) -> Result<()> {
    let manifest = load_image(image_dir)?;
    let Some(diff) = manifest.diff else {
        return Ok(());
    };
    let diff_dir = image_dir.join(diff.path);
    ensure_real_directory(&diff_dir, "image diff directory")?;
    ensure_real_directory(upperdir, "target overlay upperdir")?;
    copy_tree(
        &diff_dir,
        &diff_dir,
        upperdir,
        &mut BTreeMap::new(),
        &mut Vec::new(),
    )?;
    replay_deleted_paths(upperdir, &diff.deleted_paths)?;
    Ok(())
}

fn replay_deleted_paths(upperdir: &Path, deleted_paths: &[String]) -> Result<()> {
    for deleted in deleted_paths {
        let dest = upperdir.join(validate_manifest_relative_path(deleted)?);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                image_error(format!(
                    "Failed to create whiteout parent {:?}: {}",
                    parent, e
                ))
            })?;
        }
        if dest.exists() {
            return Err(image_error(format!(
                "Cannot replay deletion whiteout over existing path {:?}",
                dest
            )));
        }
        mknod(
            &dest,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0),
            makedev(0, 0),
        )
        .map_err(|e| {
            image_error(format!(
                "Failed to replay deletion whiteout {:?}: {}",
                dest, e
            ))
        })?;
    }
    Ok(())
}

fn export_diff(upperdir: &Path, diff_dir: &Path) -> Result<ImageDiff> {
    let mut manifest = BTreeMap::new();
    let mut deleted_paths = Vec::new();
    copy_tree(
        upperdir,
        upperdir,
        diff_dir,
        &mut manifest,
        &mut deleted_paths,
    )?;
    let digest = digest_diff_manifest(&manifest, &deleted_paths)?;
    Ok(ImageDiff {
        path: IMAGE_DIFF_DIR.to_string(),
        manifest,
        deleted_paths,
        digest,
    })
}

fn copy_tree(
    root: &Path,
    current: &Path,
    dest_root: &Path,
    manifest: &mut BTreeMap<String, String>,
    deleted_paths: &mut Vec<String>,
) -> Result<()> {
    let mut entries = fs::read_dir(current)
        .map_err(|e| {
            image_error(format!(
                "Failed to read diff directory {:?}: {}",
                current, e
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| image_error(format!("Failed to enumerate diff directory: {}", e)))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let rel = relative_path(root, &path)?;
        if should_skip_runtime_diff_path(&rel) {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| image_error(format!("Failed to stat diff path {:?}: {}", path, e)))?;
        let dest = dest_root.join(&rel);
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|e| image_error(format!("Failed to read symlink {:?}: {}", path, e)))?;
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    image_error(format!("Failed to create diff parent {:?}: {}", parent, e))
                })?;
            }
            std::os::unix::fs::symlink(&target, &dest).map_err(|e| {
                image_error(format!(
                    "Failed to copy symlink {:?} -> {:?}: {}",
                    path, dest, e
                ))
            })?;
            preserve_path_metadata(&path, &dest, &metadata, false)?;
            manifest.insert(rel, format!("symlink:{}", target.display()));
        } else if metadata.is_dir() {
            fs::create_dir_all(&dest).map_err(|e| {
                image_error(format!("Failed to create diff directory {:?}: {}", dest, e))
            })?;
            copy_tree(root, &path, dest_root, manifest, deleted_paths)?;
            preserve_path_metadata(&path, &dest, &metadata, true)?;
        } else if metadata.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    image_error(format!("Failed to create diff parent {:?}: {}", parent, e))
                })?;
            }
            fs::copy(&path, &dest).map_err(|e| {
                image_error(format!(
                    "Failed to copy diff file {:?} -> {:?}: {}",
                    path, dest, e
                ))
            })?;
            preserve_path_metadata(&path, &dest, &metadata, true)?;
            manifest.insert(rel, hash_file(&path)?);
        } else if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
            deleted_paths.push(rel);
        } else {
            return Err(image_error(format!(
                "Image diff contains unsupported special file {:?}",
                path
            )));
        }
    }

    Ok(())
}

fn preserve_path_metadata(
    source: &Path,
    dest: &Path,
    metadata: &fs::Metadata,
    follow: bool,
) -> Result<()> {
    set_owner(dest, metadata.uid(), metadata.gid(), follow)?;
    if follow {
        fs::set_permissions(
            dest,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )
        .map_err(|e| image_error(format!("Failed to set metadata mode for {:?}: {}", dest, e)))?;
    }
    copy_xattrs(source, dest, follow)?;
    set_timestamps(dest, metadata, follow)
}

fn set_owner(path: &Path, uid: u32, gid: u32, follow: bool) -> Result<()> {
    let path_c = path_cstring(path)?;
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let rc = unsafe {
        libc::fchownat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            uid as libc::uid_t,
            gid as libc::gid_t,
            flags,
        )
    };
    if rc != 0 {
        return Err(image_error(format!(
            "Failed to preserve owner {}:{} for {:?}: {}",
            uid,
            gid,
            path,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_timestamps(path: &Path, metadata: &fs::Metadata, follow: bool) -> Result<()> {
    let path_c = path_cstring(path)?;
    let times = [
        libc::timespec {
            tv_sec: metadata.atime() as libc::time_t,
            tv_nsec: metadata.atime_nsec() as libc::c_long,
        },
        libc::timespec {
            tv_sec: metadata.mtime() as libc::time_t,
            tv_nsec: metadata.mtime_nsec() as libc::c_long,
        },
    ];
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), flags) };
    if rc != 0 {
        return Err(image_error(format!(
            "Failed to preserve timestamps for {:?}: {}",
            path,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn copy_xattrs(source: &Path, dest: &Path, follow: bool) -> Result<()> {
    for name in list_xattrs(source, follow)? {
        if let Some(value) = get_xattr(source, &name, follow)? {
            set_xattr(dest, &name, &value, follow)?;
        }
    }
    Ok(())
}

fn list_xattrs(path: &Path, follow: bool) -> Result<Vec<Vec<u8>>> {
    let path_c = path_cstring(path)?;
    let size = unsafe {
        if follow {
            libc::listxattr(path_c.as_ptr(), std::ptr::null_mut(), 0)
        } else {
            libc::llistxattr(path_c.as_ptr(), std::ptr::null_mut(), 0)
        }
    };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if is_xattr_unsupported(&err) {
            return Ok(Vec::new());
        }
        return Err(image_error(format!(
            "Failed to list xattrs for {:?}: {}",
            path, err
        )));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; size as usize];
    let read = unsafe {
        if follow {
            libc::listxattr(
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        } else {
            libc::llistxattr(
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        }
    };
    if read < 0 {
        return Err(image_error(format!(
            "Failed to read xattr list for {:?}: {}",
            path,
            std::io::Error::last_os_error()
        )));
    }
    buf.truncate(read as usize);
    Ok(buf
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_vec())
        .collect())
}

fn get_xattr(path: &Path, name: &[u8], follow: bool) -> Result<Option<Vec<u8>>> {
    let path_c = path_cstring(path)?;
    let name_c = bytes_cstring(name, "xattr name")?;
    let size = unsafe {
        if follow {
            libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0)
        } else {
            libc::lgetxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0)
        }
    };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENODATA) || is_xattr_unsupported(&err) {
            return Ok(None);
        }
        return Err(image_error(format!(
            "Failed to get xattr {:?} for {:?}: {}",
            String::from_utf8_lossy(name),
            path,
            err
        )));
    }
    let mut value = vec![0u8; size as usize];
    let read = unsafe {
        if follow {
            libc::getxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        } else {
            libc::lgetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_mut_ptr() as *mut libc::c_void,
                value.len(),
            )
        }
    };
    if read < 0 {
        return Err(image_error(format!(
            "Failed to read xattr {:?} for {:?}: {}",
            String::from_utf8_lossy(name),
            path,
            std::io::Error::last_os_error()
        )));
    }
    value.truncate(read as usize);
    Ok(Some(value))
}

fn set_xattr(path: &Path, name: &[u8], value: &[u8], follow: bool) -> Result<()> {
    let path_c = path_cstring(path)?;
    let name_c = bytes_cstring(name, "xattr name")?;
    let rc = unsafe {
        if follow {
            libc::setxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        } else {
            libc::lsetxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        }
    };
    if rc != 0 {
        return Err(image_error(format!(
            "Failed to preserve xattr {:?} for {:?}: {}",
            String::from_utf8_lossy(name),
            path,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn is_xattr_unsupported(err: &std::io::Error) -> bool {
    let raw = err.raw_os_error();
    raw == Some(libc::ENOTSUP) || raw == Some(libc::EOPNOTSUPP)
}

fn copy_base_sidecars(rootfs_path: &Path, output_dir: &Path) -> Result<()> {
    copy_sidecar(
        &rootfs_path.join(ROOTFS_ATTESTATION_FILE),
        &output_dir.join(IMAGE_ROOTFS_ATTESTATION_FILE),
    )?;
    copy_sidecar(
        &rootfs_path.join(ROOTFS_STORE_PATHS_FILE),
        &output_dir.join(IMAGE_STORE_PATHS_FILE),
    )
}

fn copy_sidecar(source: &Path, dest: &Path) -> Result<()> {
    let content = read_file_nofollow_bytes(source)
        .map_err(|e| image_error(format!("Failed to read sidecar {:?}: {}", source, e)))?;
    atomic_write_bytes(dest, &content, 0o600)
}

fn read_store_paths(rootfs_path: &Path) -> Result<Vec<String>> {
    let path = rootfs_path.join(ROOTFS_STORE_PATHS_FILE);
    let content = read_file_nofollow_bytes(&path)
        .map_err(|e| image_error(format!("Failed to read store paths {:?}: {}", path, e)))?;
    let content = String::from_utf8(content)
        .map_err(|e| image_error(format!("Store paths {:?} are not UTF-8: {}", path, e)))?;
    let mut paths = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_immediate_nix_store_object_path(Path::new(trimmed)) {
            return Err(image_error(format!(
                "Invalid store path on line {} in {:?}: {}",
                line_no + 1,
                path,
                trimmed
            )));
        }
        paths.push(trimmed.to_string());
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn digest_diff_manifest(
    manifest: &BTreeMap<String, String>,
    deleted_paths: &[String],
) -> Result<String> {
    let canonical = serde_json::to_vec(&(manifest, deleted_paths))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn should_skip_runtime_diff_path(rel: &str) -> bool {
    first_component(rel)
        .map(|component| matches!(component, "dev" | "proc" | "sys"))
        .unwrap_or(false)
        || rel == ".old_root"
        || rel.starts_with(".old_root/")
        || rel == "run/secrets"
        || rel.starts_with("run/secrets/")
}

fn first_component(path: &str) -> Option<&str> {
    path.split('/')
        .next()
        .filter(|component| !component.is_empty())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|e| image_error(format!("Failed to compute relative diff path: {}", e)))?;
    path_to_string(rel)
}

fn path_to_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| {
                    image_error(format!("Image path component is not UTF-8: {:?}", part))
                })?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(image_error(format!(
                    "Invalid relative image path component in {:?}",
                    path
                )));
            }
        }
    }
    Ok(parts.join("/"))
}

fn path_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| image_error(format!("Path {:?} contains an interior NUL", path)))
}

fn bytes_cstring(bytes: &[u8], label: &str) -> Result<CString> {
    CString::new(bytes).map_err(|_| {
        image_error(format!(
            "{} {:?} contains an interior NUL",
            label,
            String::from_utf8_lossy(bytes)
        ))
    })
}

fn validate_manifest_relative_path(path: &str) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(image_error(
            "Image manifest path cannot be empty".to_string(),
        ));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(image_error(format!(
            "Image manifest path must be relative: {:?}",
            path
        )));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(image_error(format!(
                    "Invalid image manifest path component in {:?}",
                    path
                )));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(image_error(
            "Image manifest path cannot be empty".to_string(),
        ));
    }
    Ok(normalized)
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| image_error(format!("Failed to open file {:?}: {}", path, e)))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|e| image_error(format!("Failed to read file {:?}: {}", path, e)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn prepare_image_dir(path: &Path) -> Result<()> {
    reject_symlink_path(path, "image directory")?;
    if path.exists() {
        if !path.is_dir() {
            return Err(image_error(format!(
                "Image output {:?} is not a directory",
                path
            )));
        }
    } else {
        fs::create_dir_all(path)
            .map_err(|e| image_error(format!("Failed to create image dir {:?}: {}", path, e)))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| image_error(format!("Failed to secure image dir {:?}: {}", path, e)))
}

fn prepare_empty_dir(path: &Path, label: &str) -> Result<()> {
    reject_symlink_path(path, label)?;
    if path.exists() {
        if !path.is_dir() {
            return Err(image_error(format!(
                "{} {:?} is not a directory",
                label, path
            )));
        }
        for entry in fs::read_dir(path)
            .map_err(|e| image_error(format!("Failed to read {} {:?}: {}", label, path, e)))?
        {
            let entry = entry.map_err(|e| {
                image_error(format!("Failed to enumerate {} {:?}: {}", label, path, e))
            })?;
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(|e| {
                image_error(format!(
                    "Failed to stat {} entry {:?}: {}",
                    label, entry_path, e
                ))
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::remove_dir_all(&entry_path).map_err(|e| {
                    image_error(format!(
                        "Failed to remove stale dir {:?}: {}",
                        entry_path, e
                    ))
                })?;
            } else {
                fs::remove_file(&entry_path).map_err(|e| {
                    image_error(format!(
                        "Failed to remove stale file {:?}: {}",
                        entry_path, e
                    ))
                })?;
            }
        }
    } else {
        fs::create_dir(path)
            .map_err(|e| image_error(format!("Failed to create {} {:?}: {}", label, path, e)))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| image_error(format!("Failed to secure {} {:?}: {}", label, path, e)))
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    reject_symlink_path(path, label)?;
    let metadata = fs::metadata(path)
        .map_err(|e| image_error(format!("Failed to stat {} {:?}: {}", label, path, e)))?;
    if !metadata.is_dir() {
        return Err(image_error(format!(
            "{} {:?} is not a directory",
            label, path
        )));
    }
    Ok(())
}

fn atomic_write_json<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<()> {
    let json = serde_json::to_vec_pretty(value)?;
    atomic_write_bytes(&dir.join(name), &json, 0o600)
}

fn atomic_write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| image_error(format!("Path {:?} has no parent", path)))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| image_error(format!("Path {:?} has no file name", path)))?;
    let tmp_path = parent.join(format!("{}.tmp", file_name.to_string_lossy()));
    match fs::symlink_metadata(&tmp_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(image_error(format!(
                "Refusing symlink temp image file {:?}",
                tmp_path
            )));
        }
        Ok(_) => fs::remove_file(&tmp_path).map_err(|e| {
            image_error(format!("Failed to remove temp file {:?}: {}", tmp_path, e))
        })?,
        Err(_) => {}
    }

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| image_error(format!("Failed to open temp file {:?}: {}", tmp_path, e)))?;
    file.write_all(bytes)
        .map_err(|e| image_error(format!("Failed to write temp file {:?}: {}", tmp_path, e)))?;
    file.sync_all()
        .map_err(|e| image_error(format!("Failed to sync temp file {:?}: {}", tmp_path, e)))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        image_error(format!(
            "Failed to atomically replace image file {:?}: {}",
            path, e
        ))
    })
}

fn write_image_hmac(dir: &Path) -> Result<()> {
    let key = load_or_create_image_hmac_key()?;
    let digest = compute_image_hmac(dir, &key)?;
    atomic_write_bytes(&dir.join(IMAGE_SIGNATURE_FILE), digest.as_bytes(), 0o600)
}

fn verify_image_hmac(dir: &Path) -> Result<()> {
    let sig_path = dir.join(IMAGE_SIGNATURE_FILE);
    let expected = read_file_nofollow_bytes(&sig_path).map_err(|e| {
        image_error(format!(
            "Failed to read image signature {:?}: {}",
            sig_path, e
        ))
    })?;
    let expected = std::str::from_utf8(&expected)
        .map_err(|e| image_error(format!("Image signature is not UTF-8: {}", e)))?
        .trim()
        .to_string();
    if expected.is_empty() {
        return Err(image_error("Image signature is empty".to_string()));
    }
    let key = load_or_create_image_hmac_key()?;
    let actual = compute_image_hmac(dir, &key)?;
    if expected != actual {
        return Err(image_error(format!(
            "Image integrity verification failed: HMAC mismatch (expected {}, got {})",
            expected, actual
        )));
    }
    Ok(())
}

fn compute_image_hmac(dir: &Path, key: &[u8]) -> Result<String> {
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
    update_image_hmac_inner(&mut inner, dir, dir)?;
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    Ok(hex::encode(outer.finalize()))
}

fn update_image_hmac_inner(hasher: &mut Sha256, root: &Path, dir: &Path) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .map_err(|e| image_error(format!("Failed to read image directory {:?}: {}", dir, e)))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| image_error(format!("Failed to enumerate image directory: {}", e)))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|e| image_error(format!("Failed to compute image relative path: {}", e)))?;
        if relative == Path::new(IMAGE_SIGNATURE_FILE) {
            continue;
        }
        let relative = path_to_string(relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| image_error(format!("Failed to stat image path {:?}: {}", path, e)))?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|e| image_error(format!("Failed to read symlink {:?}: {}", path, e)))?;
            hasher.update(b"L\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            update_metadata_hmac(hasher, &path, &metadata, false)?;
            hasher.update(target.as_os_str().as_encoded_bytes());
            hasher.update(b"\0");
        } else if metadata.is_dir() {
            hasher.update(b"D\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            update_metadata_hmac(hasher, &path, &metadata, true)?;
            update_image_hmac_inner(hasher, root, &path)?;
        } else if metadata.is_file() {
            hasher.update(b"F\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            update_metadata_hmac(hasher, &path, &metadata, true)?;
            hasher.update(metadata.len().to_le_bytes());
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .map_err(|e| image_error(format!("Failed to open image file {:?}: {}", path, e)))?;
            let mut buf = [0u8; 8192];
            loop {
                let read = file.read(&mut buf).map_err(|e| {
                    image_error(format!("Failed to read image file {:?}: {}", path, e))
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
            }
        } else {
            return Err(image_error(format!(
                "Image integrity scan rejects special file {:?}",
                path
            )));
        }
    }
    Ok(())
}

fn update_metadata_hmac(
    hasher: &mut Sha256,
    path: &Path,
    metadata: &fs::Metadata,
    follow: bool,
) -> Result<()> {
    hasher.update(metadata.uid().to_le_bytes());
    hasher.update(metadata.gid().to_le_bytes());
    hasher.update(metadata.permissions().mode().to_le_bytes());
    hasher.update(metadata.mtime().to_le_bytes());
    hasher.update(metadata.mtime_nsec().to_le_bytes());

    let mut xattrs = Vec::new();
    for name in list_xattrs(path, follow)? {
        if let Some(value) = get_xattr(path, &name, follow)? {
            xattrs.push((name, value));
        }
    }
    xattrs.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (name, value) in xattrs {
        hasher.update(b"X\0");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(&name);
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(&value);
    }

    Ok(())
}

fn image_hmac_key_path() -> PathBuf {
    if let Some(path) = std::env::var_os("NUCLEUS_IMAGE_HMAC_KEY_FILE").filter(|p| !p.is_empty()) {
        return PathBuf::from(path);
    }
    if Uid::effective().is_root() {
        PathBuf::from("/var/lib/nucleus/image-hmac.key")
    } else {
        dirs::data_local_dir()
            .map(|dir| dir.join("nucleus/image-hmac.key"))
            .or_else(|| dirs::home_dir().map(|dir| dir.join(".nucleus/image-hmac.key")))
            .unwrap_or_else(|| PathBuf::from("/tmp/nucleus-image-hmac.key"))
    }
}

fn load_or_create_image_hmac_key() -> Result<Vec<u8>> {
    let key_path = image_hmac_key_path();
    let parent = key_path
        .parent()
        .ok_or_else(|| image_error(format!("Image HMAC key path {:?} has no parent", key_path)))?;
    ensure_secure_key_parent_dir(parent)?;
    reject_symlink_path(&key_path, "image HMAC key file")?;

    if key_path.exists() {
        let metadata = fs::metadata(&key_path)
            .map_err(|e| image_error(format!("Failed to stat image HMAC key: {}", e)))?;
        let mode = metadata.permissions().mode() & 0o777;
        let owner = metadata.uid();
        let euid = Uid::effective().as_raw();
        if owner != euid {
            return Err(image_error(format!(
                "Image HMAC key {:?} is owned by uid {} (expected {})",
                key_path, owner, euid
            )));
        }
        if mode & 0o077 != 0 {
            return Err(image_error(format!(
                "Image HMAC key {:?} has insecure mode {:o}; expected owner-only access",
                key_path, mode
            )));
        }
        let key = read_file_nofollow_bytes(&key_path)
            .map_err(|e| image_error(format!("Failed to read image HMAC key: {}", e)))?;
        if key.len() < IMAGE_HMAC_KEY_SIZE {
            return Err(image_error(format!(
                "Image HMAC key {:?} is too short ({} bytes)",
                key_path,
                key.len()
            )));
        }
        return Ok(key);
    }

    let mut key = vec![0u8; IMAGE_HMAC_KEY_SIZE];
    fill_secure_random(&mut key)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&key_path)
        .map_err(|e| {
            image_error(format!(
                "Failed to create image HMAC key {:?}: {}",
                key_path, e
            ))
        })?;
    file.write_all(&key).map_err(|e| {
        image_error(format!(
            "Failed to write image HMAC key {:?}: {}",
            key_path, e
        ))
    })?;
    file.sync_all().map_err(|e| {
        image_error(format!(
            "Failed to sync image HMAC key {:?}: {}",
            key_path, e
        ))
    })?;
    Ok(key)
}

fn ensure_secure_key_parent_dir(path: &Path) -> Result<()> {
    reject_symlink_path(path, "image HMAC key directory")?;
    if path.exists() {
        let metadata = fs::metadata(path)
            .map_err(|e| image_error(format!("Failed to stat image HMAC key dir: {}", e)))?;
        if !metadata.is_dir() {
            return Err(image_error(format!(
                "Image HMAC key directory {:?} is not a directory",
                path
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        let owner = metadata.uid();
        let euid = Uid::effective().as_raw();
        if owner != euid {
            return Err(image_error(format!(
                "Image HMAC key directory {:?} is owned by uid {} (expected {})",
                path, owner, euid
            )));
        }
        if mode & 0o077 != 0 {
            return Err(image_error(format!(
                "Image HMAC key directory {:?} has insecure mode {:o}; expected owner-only access",
                path, mode
            )));
        }
        return Ok(());
    }
    fs::create_dir_all(path)
        .map_err(|e| image_error(format!("Failed to create image HMAC key dir: {}", e)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| image_error(format!("Failed to secure image HMAC key dir: {}", e)))
}

fn fill_secure_random(buf: &mut [u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")
        .map_err(|e| image_error(format!("Failed to open /dev/urandom: {}", e)))?;
    let metadata = file
        .metadata()
        .map_err(|e| image_error(format!("Failed to stat /dev/urandom: {}", e)))?;
    if !metadata.file_type().is_char_device() {
        return Err(image_error(
            "/dev/urandom is not a character device".to_string(),
        ));
    }
    file.read_exact(buf)
        .map_err(|e| image_error(format!("Failed to read /dev/urandom: {}", e)))
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

fn reject_symlink_path(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(image_error(format!(
            "Refusing symlink {} {:?}",
            label, path
        ))),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn image_error(message: String) -> NucleusError {
    NucleusError::ConfigError(format!("Image error: {}", message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerState, ContainerStateParams};
    use std::ffi::OsString;
    use std::os::unix::fs::symlink;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    fn image_key_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ImageKeyEnvGuard {
        previous: Option<OsString>,
    }

    impl ImageKeyEnvGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::var_os("NUCLEUS_IMAGE_HMAC_KEY_FILE");
            std::env::set_var("NUCLEUS_IMAGE_HMAC_KEY_FILE", path);
            Self { previous }
        }
    }

    impl Drop for ImageKeyEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var("NUCLEUS_IMAGE_HMAC_KEY_FILE", value),
                None => std::env::remove_var("NUCLEUS_IMAGE_HMAC_KEY_FILE"),
            }
        }
    }

    fn sample_rootfs(dir: &Path) -> PathBuf {
        let rootfs = dir.join("rootfs");
        fs::create_dir(&rootfs).unwrap();
        fs::create_dir(rootfs.join("bin")).unwrap();
        fs::write(rootfs.join("bin/app"), "app").unwrap();
        fs::write(
            rootfs.join(ROOTFS_ATTESTATION_FILE),
            format!("{}\tbin/app\n", hash_file(&rootfs.join("bin/app")).unwrap()),
        )
        .unwrap();
        fs::write(
            rootfs.join(ROOTFS_STORE_PATHS_FILE),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-coreutils\n",
        )
        .unwrap();
        rootfs
    }

    fn sample_state(rootfs: &Path, upper: &Path) -> ContainerState {
        let mut state = ContainerState::new(ContainerStateParams {
            id: "abc123def456".to_string(),
            name: "worker".to_string(),
            pid: 123,
            command: vec!["/bin/app".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 1000,
            process_gid: 1000,
            additional_gids: vec![27],
        });
        state
            .environment
            .insert("APP_ENV".to_string(), "snapshot".to_string());
        state.workdir = "/srv/app".to_string();
        state.rootfs_path = Some(rootfs.display().to_string());
        state.rootfs_mode = RootfsMode::Overlay;
        state.rootfs_upperdir = Some(upper.display().to_string());
        state.rootfs_workdir = Some(upper.parent().unwrap().join("work").display().to_string());
        state
    }

    #[test]
    fn test_manifest_image_id_roundtrips() {
        let base = ImageBase {
            rootfs_path: "/nix/store/rootfs".to_string(),
            store_paths: Vec::new(),
            attestation: DirectoryManifest::new(),
        };
        let config = ImageConfig {
            command: vec!["/bin/true".to_string()],
            env: BTreeMap::new(),
            workdir: "/workspace".to_string(),
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
        };
        let manifest = NucleusImageManifest::new(base, None, config).unwrap();
        assert_eq!(manifest.compute_image_id().unwrap(), manifest.image_id);
        manifest.validate_identity().unwrap();
    }

    #[test]
    fn test_manifest_detects_tampered_image_id() {
        let base = ImageBase {
            rootfs_path: "/nix/store/rootfs".to_string(),
            store_paths: Vec::new(),
            attestation: DirectoryManifest::new(),
        };
        let config = ImageConfig {
            command: vec!["/bin/true".to_string()],
            env: BTreeMap::new(),
            workdir: "/workspace".to_string(),
            uid: 0,
            gid: 0,
            additional_gids: Vec::new(),
        };
        let mut manifest = NucleusImageManifest::new(base, None, config).unwrap();
        manifest.config.command = vec!["/bin/false".to_string()];
        assert!(manifest.validate_identity().is_err());
    }

    #[test]
    fn test_commit_rejects_non_overlay_state() {
        let temp = TempDir::new().unwrap();
        let rootfs = sample_rootfs(temp.path());
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        let mut state = sample_state(&rootfs, &upper);
        state.rootfs_mode = RootfsMode::Bind;

        let err = commit_container_image(
            &state,
            &temp.path().join("image"),
            &ImageCommitOptions::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires overlay"));
    }

    #[test]
    fn test_commit_writes_and_verifies_cold_thin_image() {
        let _lock = image_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = ImageKeyEnvGuard::set(&key_dir.join("image.key"));

        let rootfs = sample_rootfs(temp.path());
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        fs::create_dir(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/config"), "changed").unwrap();
        fs::set_permissions(upper.join("etc/config"), fs::Permissions::from_mode(0o754)).unwrap();
        let xattr_supported = set_xattr(
            &upper.join("etc/config"),
            b"user.nucleus.test",
            b"preserved",
            true,
        )
        .is_ok();
        fs::create_dir(upper.join("dev")).unwrap();
        fs::write(upper.join("dev/runtime-node"), "skip").unwrap();
        symlink("config", upper.join("etc/config-link")).unwrap();

        let image_dir = temp.path().join("image");
        let manifest = commit_container_image(
            &sample_state(&rootfs, &upper),
            &image_dir,
            &ImageCommitOptions::default(),
        )
        .unwrap();

        assert_eq!(manifest.schema_version, IMAGE_SCHEMA_VERSION);
        assert_eq!(manifest.config.env["APP_ENV"], "snapshot");
        assert_eq!(manifest.config.workdir, "/srv/app");
        assert!(image_dir.join(IMAGE_MANIFEST_FILE).exists());
        assert!(image_dir.join(IMAGE_SIGNATURE_FILE).exists());
        assert!(image_dir.join(IMAGE_ROOTFS_ATTESTATION_FILE).exists());
        assert!(image_dir.join(IMAGE_STORE_PATHS_FILE).exists());
        assert!(image_dir.join("diff/etc/config").exists());
        assert!(!image_dir.join("diff/dev/runtime-node").exists());
        let source_meta = fs::symlink_metadata(upper.join("etc/config")).unwrap();
        let copied_meta = fs::symlink_metadata(image_dir.join("diff/etc/config")).unwrap();
        assert_eq!(
            copied_meta.permissions().mode() & 0o7777,
            source_meta.permissions().mode() & 0o7777
        );
        assert_eq!(copied_meta.uid(), source_meta.uid());
        assert_eq!(copied_meta.gid(), source_meta.gid());
        assert_eq!(copied_meta.mtime(), source_meta.mtime());
        assert_eq!(copied_meta.mtime_nsec(), source_meta.mtime_nsec());
        if xattr_supported {
            assert_eq!(
                get_xattr(
                    &image_dir.join("diff/etc/config"),
                    b"user.nucleus.test",
                    true
                )
                .unwrap()
                .as_deref(),
                Some(&b"preserved"[..])
            );
        }

        let loaded = load_image(&image_dir).unwrap();
        assert_eq!(loaded.image_id, manifest.image_id);
        assert!(loaded
            .diff
            .unwrap()
            .manifest
            .contains_key("etc/config-link"));
    }

    #[test]
    fn test_image_hmac_detects_tampering() {
        let _lock = image_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = ImageKeyEnvGuard::set(&key_dir.join("image.key"));

        let rootfs = sample_rootfs(temp.path());
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        fs::write(upper.join("file"), "one").unwrap();
        let image_dir = temp.path().join("image");
        commit_container_image(
            &sample_state(&rootfs, &upper),
            &image_dir,
            &ImageCommitOptions::default(),
        )
        .unwrap();

        fs::write(image_dir.join("diff/file"), "two").unwrap();
        let err = load_image(&image_dir).unwrap_err();
        assert!(err.to_string().contains("HMAC mismatch"));
    }

    #[test]
    fn test_image_hmac_detects_metadata_tampering() {
        let _lock = image_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = ImageKeyEnvGuard::set(&key_dir.join("image.key"));

        let rootfs = sample_rootfs(temp.path());
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        fs::write(upper.join("file"), "one").unwrap();
        let image_dir = temp.path().join("image");
        commit_container_image(
            &sample_state(&rootfs, &upper),
            &image_dir,
            &ImageCommitOptions::default(),
        )
        .unwrap();

        fs::set_permissions(
            image_dir.join("diff/file"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let err = load_image(&image_dir).unwrap_err();
        assert!(err.to_string().contains("HMAC mismatch"));
    }

    #[test]
    fn test_whiteout_replay_rejects_manifest_path_escape() {
        let temp = TempDir::new().unwrap();
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();

        let err = replay_deleted_paths(&upper, &["../escape".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Invalid image manifest path"));
    }

    // Cross-cutting regression: a credential-brokered sandbox must not bake
    // its broker endpoint or per-container identity env into a committed image
    // manifest. Those values are host/container specific; baking them in would
    // make the image non-portable and would leak per-container tokens. The
    // contract is that `config.environment` is the capture surface for image
    // commit, while `config.derived_environment` carries launch-derived values
    // that reach the workload but stay out of committed artifacts.
    #[test]
    fn test_image_commit_excludes_credential_broker_derived_env() {
        use crate::container::ContainerConfig;
        use crate::network::{BridgeConfig, CredentialBrokerConfig, NatBackend, NetworkMode};

        let broker =
            CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let mut config = ContainerConfig::try_new_with_id(
            Some("0123456789abcdef0123456789abcdef".to_string()),
            None,
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_network(NetworkMode::Bridge(
            BridgeConfig::default().with_nat_backend(NatBackend::Kernel),
        ))
        // User env is the capture surface; it must round-trip into the image.
        .with_env("APP_PORT".to_string(), "8080".to_string())
        // `with_credential_broker` already routes identity env through
        // `derived_environment`. Mimic the CLI's broker-proxy-env step here
        // to assert the same derived path is used for proxy env.
        .with_credential_broker(broker.clone())
        .with_egress_policy(broker.egress_policy());
        for (key, value) in broker.proxy_environment() {
            config = config.with_derived_env(key, value);
        }

        // Sanity: user env stays clean of every broker-derived var.
        let broker_keys = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NUCLEUS_CONTAINER_ID",
            "NUCLEUS_CREDENTIAL_BROKER_TOKEN",
        ];
        for key in broker_keys {
            assert!(
                !config.environment.iter().any(|(k, _)| k == key),
                "broker-derived env `{key}` leaked into user environment"
            );
        }
        // And the broker vars land in derived env where they belong.
        assert!(config
            .derived_environment
            .iter()
            .any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(config
            .derived_environment
            .iter()
            .any(|(k, _)| k == "NUCLEUS_CONTAINER_ID"));
        assert!(config
            .derived_environment
            .iter()
            .any(|(k, _)| k == "NUCLEUS_CREDENTIAL_BROKER_TOKEN"));

        // Mirror what the runtime captures into ContainerState. Only user env
        // is captured; derived env is intentionally dropped here.
        let mut state = ContainerState::new(ContainerStateParams {
            id: config.id.clone(),
            name: config.name.clone(),
            pid: 123,
            command: config.command.clone(),
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: config.process_identity.uid,
            process_gid: config.process_identity.gid,
            additional_gids: config.process_identity.additional_gids.clone(),
        });
        state.environment = config.environment.iter().cloned().collect();
        state.workdir = config.workdir.display().to_string();

        let temp = TempDir::new().unwrap();
        let rootfs = sample_rootfs(temp.path());
        let upper = temp.path().join("upper");
        fs::create_dir(&upper).unwrap();
        state.rootfs_path = Some(rootfs.display().to_string());
        state.rootfs_mode = RootfsMode::Overlay;
        state.rootfs_upperdir = Some(upper.display().to_string());
        state.rootfs_workdir = Some(upper.parent().unwrap().join("work").display().to_string());

        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        // User env survives the round trip.
        assert_eq!(
            manifest.config.env.get("APP_PORT").map(String::as_str),
            Some("8080"),
            "user-supplied env must survive image commit"
        );
        // Broker-derived env must not.
        for key in broker_keys {
            assert!(
                !manifest.config.env.contains_key(key),
                "broker-derived env `{key}` was baked into the committed image"
            );
        }
    }
}
