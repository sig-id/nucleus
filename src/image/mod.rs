use crate::container::{ContainerState, RootfsMode};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    is_immediate_nix_store_object_path, read_rootfs_attestation, DirectoryManifest,
    ROOTFS_ATTESTATION_FILE, ROOTFS_STORE_PATHS_FILE,
};
use crate::isolation::{IdMapping, UserNamespaceConfig};
use crate::resources::Cgroup;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nix::fcntl::{open, openat, readlinkat, OFlag};
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
pub const IMAGE_SIGNING_KEY_ENV: &str = "NUCLEUS_IMAGE_SIGNING_KEY_FILE";
pub const IMAGE_VERIFY_KEY_ENV: &str = "NUCLEUS_IMAGE_VERIFY_KEY_FILE";

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
    /// Host ownership recorded in the signed layer belongs to this namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_user_namespace: Option<UserNamespaceConfig>,
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
        if self
            .diff
            .as_ref()
            .is_some_and(|diff| diff.path != IMAGE_DIFF_DIR)
        {
            return Err(image_error(
                "Image diff must use the image-local diff directory".into(),
            ));
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
    // Pin the entire source path before touching the output. A symlink in any
    // component of a recorded upperdir is invalid, including its ancestors.
    let cwd = open(".", OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())?;
    let upperdir = nix::fcntl::openat2(
        &cwd,
        &upperdir,
        nix::fcntl::OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?;

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

    let output = std::env::current_dir()?.join(output_dir);
    let parent = output
        .parent()
        .ok_or_else(|| image_error("Invalid image output path".into()))?;
    let parent = crate::filesystem::trusted_directory(parent, true)?;
    let source = fs::read_link(crate::filesystem::fd_path(&upperdir))?;
    if parent.starts_with(&source) || source.starts_with(&output) {
        return Err(image_error(
            "Image output and overlay upperdir must be disjoint".into(),
        ));
    }
    match fs::symlink_metadata(&output) {
        Ok(meta)
            if !meta.is_dir()
                || meta.uid() != Uid::effective().as_raw()
                || meta.mode() & 0o022 != 0 =>
        {
            return Err(image_error(format!("Untrusted image output {output:?}")));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => (),
    }
    // Keep partially copied workload-owned files inaccessible and publish the
    // completed signature and tree together.
    let staging = tempfile::Builder::new()
        .prefix(".nucleus-commit-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    let output_dir = staging.path();
    let diff_dir = output_dir.join(IMAGE_DIFF_DIR);
    fs::create_dir(&diff_dir)?;

    let base = ImageBase::from_rootfs(Path::new(rootfs_path))?;
    copy_base_sidecars(Path::new(rootfs_path), output_dir)?;
    let mut diff = export_diff(&upperdir, &diff_dir)?;
    diff.source_user_namespace = state.user_ns_config.clone().or_else(|| {
        // Unshifted overlays already carry container IDs. Record their identity
        // mapping explicitly to distinguish them from legacy root-remapped layers.
        (!state.rootless).then(|| {
            let ids = IdMapping::new(0, 0, 65_536);
            UserNamespaceConfig {
                uid_mappings: vec![ids.clone()],
                gid_mappings: vec![ids],
            }
        })
    });
    let config = ImageConfig::from_state(state);
    let manifest = NucleusImageManifest::new(base, Some(diff), config)?;
    manifest.save(output_dir)?;
    sign_image(output_dir)?;
    match fs::rename(output_dir, &output) {
        Ok(()) => {
            let _ = staging.keep();
        }
        Err(e)
            if e.raw_os_error() == Some(libc::ENOTEMPTY)
                || e.raw_os_error() == Some(libc::EEXIST) =>
        {
            // Updating an existing package must not discard unrelated files.
            let meta = fs::symlink_metadata(&output)?;
            if !meta.is_dir() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o077 != 0
            {
                return Err(image_error(format!(
                    "Untrusted existing image output {output:?}"
                )));
            }
            NucleusImageManifest::load(&output)?;
            for entry in fs::read_dir(&output)? {
                let name = entry?.file_name();
                if !matches!(
                    name.to_str(),
                    Some(
                        IMAGE_MANIFEST_FILE
                            | IMAGE_SIGNATURE_FILE
                            | IMAGE_DIFF_DIR
                            | IMAGE_STORE_PATHS_FILE
                            | IMAGE_ROOTFS_ATTESTATION_FILE
                    )
                ) {
                    return Err(image_error(format!(
                        "Unexpected entry {name:?} in existing image output"
                    )));
                }
            }
            nix::fcntl::renameat2(
                &cwd,
                output_dir,
                &cwd,
                &output,
                nix::fcntl::RenameFlags::RENAME_EXCHANGE,
            )?;
            // The temporary directory now owns the previous package.
        }
        Err(e) => return Err(e.into()),
    }
    Ok(manifest)
}

/// A private copy of a signed package ties verification and import to the
/// same bytes. Immutable, base-only Nix image packages can be read in place.
pub struct VerifiedImage {
    pub manifest: NucleusImageManifest,
    snapshot: Option<tempfile::TempDir>,
}

impl VerifiedImage {
    pub fn open(image_dir: &Path) -> Result<Self> {
        ensure_real_directory(image_dir, "image directory")?;
        let signed = match fs::symlink_metadata(image_dir.join(IMAGE_SIGNATURE_FILE)) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if signed {
            let snapshot = tempfile::Builder::new()
                .prefix("nucleus-image-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(crate::filesystem::trusted_directory(
                    &std::env::temp_dir(),
                    false,
                )?)?;
            if snapshot
                .path()
                .canonicalize()?
                .starts_with(image_dir.canonicalize()?)
            {
                return Err(image_error(
                    "Image includes the snapshot staging directory".into(),
                ));
            }
            copy_image_tree(image_dir, snapshot.path(), None)?;
            verify_image_signature(snapshot.path())?;
            let manifest = NucleusImageManifest::load(snapshot.path())?;
            return Ok(Self {
                manifest,
                snapshot: Some(snapshot),
            });
        }
        if !is_immediate_nix_store_object_path(image_dir)
            || fs::canonicalize(image_dir)? != image_dir
        {
            return Err(image_error(
                "Image signature is missing outside the Nix store".into(),
            ));
        }
        let manifest = NucleusImageManifest::load(image_dir)?;
        if manifest.diff.is_some() {
            return Err(image_error(
                "Images with a writable layer require an image signature".into(),
            ));
        }
        Ok(Self {
            manifest,
            snapshot: None,
        })
    }

    /// Import into a private staging directory. Only copied layer
    /// entries carry source ownership. Replayed whiteouts and the new upperdir
    /// start as host root and belong to container root.
    pub fn copy_remapped_diff_to_upper(
        &self,
        upperdir: &Path,
        uid: &IdMapping,
        gid: &IdMapping,
    ) -> Result<()> {
        ensure_real_directory(upperdir, "target overlay upperdir")?;
        if fs::read_dir(upperdir)?.next().is_some() {
            return Err(image_error(
                "Image import requires an empty overlay upperdir".into(),
            ));
        }
        let source = self
            .manifest
            .diff
            .as_ref()
            .and_then(|diff| diff.source_user_namespace.as_ref());
        self.copy_diff_to_upper(upperdir)?;
        for entry in fs::read_dir(upperdir)? {
            remap_imported_layer(&entry?.path(), source, uid, gid)?;
        }
        set_owner(
            upperdir,
            imported_host_id(0, None, uid)?,
            imported_host_id(0, None, gid)?,
            false,
        )
    }

    pub fn copy_diff_to_upper(&self, upperdir: &Path) -> Result<()> {
        let Some(diff) = &self.manifest.diff else {
            return Ok(());
        };
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| image_error("Missing signed image snapshot".into()))?;
        let diff_dir = snapshot.path().join(IMAGE_DIFF_DIR);
        ensure_real_directory(&diff_dir, "image diff directory")?;
        ensure_real_directory(upperdir, "target overlay upperdir")?;
        if fs::read_dir(upperdir)?.next().is_some() {
            return Err(image_error(
                "Image import requires an empty overlay upperdir".into(),
            ));
        }
        let mut imported = LayerEntries::default();
        copy_image_tree(&diff_dir, upperdir, Some(&mut imported))?;
        replay_deleted_paths(upperdir, &diff.deleted_paths)
    }
}

pub fn load_image(image_dir: &Path) -> Result<NucleusImageManifest> {
    Ok(VerifiedImage::open(image_dir)?.manifest)
}

pub fn copy_image_diff_to_upper(image_dir: &Path, upperdir: &Path) -> Result<()> {
    VerifiedImage::open(image_dir)?.copy_diff_to_upper(upperdir)
}

// Older signed layers contain either container-relative IDs or host IDs from
// the previous fixed root mapping. Never leave a foreign host owner in an upperdir.
fn imported_host_id(id: u32, source: Option<&[IdMapping]>, target: &IdMapping) -> Result<u32> {
    let container_id = match source {
        Some(maps) => maps.iter().find_map(|m| {
            let offset = id.checked_sub(m.host_id)?;
            if offset >= m.count {
                return None;
            }
            m.container_id.checked_add(offset)
        }),
        None if (100_000..165_536).contains(&id) => Some(id - 100_000),
        None => Some(id),
    };
    container_id
        .and_then(|id| target.host_id_for(id))
        .ok_or_else(|| image_error(format!("Image owner {id} is outside the namespace mapping")))
}

/// Translate container-relative ownership in a privately staged image layer.
pub fn remap_layer_ownership(root: &Path, uid_map: &IdMapping, gid_map: &IdMapping) -> Result<()> {
    remap_imported_layer(root, None, uid_map, gid_map)
}

fn remap_imported_layer(
    root: &Path,
    source: Option<&UserNamespaceConfig>,
    uid_map: &IdMapping,
    gid_map: &IdMapping,
) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to stat imported layer path {:?}: {}",
            root, e
        ))
    })?;
    if metadata.is_dir() {
        for entry in fs::read_dir(root).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to read imported layer dir {:?}: {}",
                root, e
            ))
        })? {
            let entry = entry.map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to read imported layer entry in {:?}: {}",
                    root, e
                ))
            })?;
            remap_imported_layer(&entry.path(), source, uid_map, gid_map)?;
        }
    }

    use std::os::unix::fs::MetadataExt;
    let uid = metadata.uid();
    let gid = metadata.gid();
    let source = if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
        None
    } else {
        source
    };
    let new_uid = imported_host_id(uid, source.map(|s| s.uid_mappings.as_slice()), uid_map)?;
    let new_gid = imported_host_id(gid, source.map(|s| s.gid_mappings.as_slice()), gid_map)?;
    if new_uid != uid || new_gid != gid {
        set_owner(root, new_uid, new_gid, false)?;
    }
    Ok(())
}

fn replay_deleted_paths(upperdir: &Path, deleted_paths: &[String]) -> Result<()> {
    for deleted in deleted_paths {
        let relative = validate_manifest_relative_path(deleted)?;
        let parent = crate::filesystem::mount_target(
            upperdir,
            relative.parent().expect("validated relative entry"),
            true,
        )?;
        let dest = crate::filesystem::fd_path(&parent)
            .join(relative.file_name().expect("validated relative entry"));
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

fn export_diff(upperdir: &std::os::fd::OwnedFd, diff_dir: &Path) -> Result<ImageDiff> {
    let mut entries = LayerEntries::default();
    copy_image_dir(upperdir, Path::new(""), diff_dir, Some(&mut entries))?;
    let digest = digest_diff_manifest(&entries.manifest, &entries.deleted_paths)?;
    Ok(ImageDiff {
        source_user_namespace: None,
        path: IMAGE_DIFF_DIR.to_string(),
        manifest: entries.manifest,
        deleted_paths: entries.deleted_paths,
        digest,
    })
}

#[derive(Default)]
struct LayerEntries {
    manifest: BTreeMap<String, String>,
    deleted_paths: Vec<String>,
}

fn copy_image_tree(source: &Path, dest: &Path, layer: Option<&mut LayerEntries>) -> Result<()> {
    let dir = open(
        source,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    copy_image_dir(&dir, Path::new(""), dest, layer)
}

fn copy_image_dir(
    dir: &std::os::fd::OwnedFd,
    prefix: &Path,
    dest_root: &Path,
    mut layer: Option<&mut LayerEntries>,
) -> Result<()> {
    let base = crate::filesystem::fd_path(dir);
    let mut entries = fs::read_dir(&base)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let relative = prefix.join(&name);
        let rel = path_to_string(&relative)?;
        if layer.is_some() && should_skip_runtime_diff_path(&rel) {
            continue;
        }
        // Hold every source inode across stat/read/copy. A running container
        // can rename entries while an unfrozen image commit is in progress.
        let fd = openat(
            dir,
            name.as_os_str(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let source = crate::filesystem::fd_path(&fd);
        let metadata = fs::metadata(&source)?;
        let dest = dest_root.join(&relative);
        if metadata.file_type().is_symlink() {
            let target = readlinkat(&fd, "")?;
            let target = Path::new(std::ffi::OsStr::from_bytes(target.as_bytes()));
            std::os::unix::fs::symlink(target, &dest)?;
            // l*xattr operations on a symlink use the pinned parent and never follow the leaf.
            preserve_path_metadata(&entry.path(), &dest, &metadata, false)?;
            if let Some(entries) = layer.as_deref_mut() {
                entries
                    .manifest
                    .insert(rel, format!("symlink:{}", target.display()));
            }
        } else if metadata.is_dir() {
            fs::create_dir(&dest)?;
            copy_image_dir(&fd, &relative, dest_root, layer.as_deref_mut())?;
            preserve_path_metadata(&source, &dest, &metadata, true)?;
        } else if metadata.is_file() {
            let mut input = fs::File::open(&source)?;
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&dest)?;
            std::io::copy(&mut input, &mut output)?;
            if let Some(entries) = layer.as_deref_mut() {
                entries.manifest.insert(rel, hash_file(&dest)?);
            }
            preserve_path_metadata(&source, &dest, &metadata, true)?;
        } else if let Some(entries) = layer
            .as_deref_mut()
            .filter(|_| metadata.file_type().is_char_device() && metadata.rdev() == 0)
        {
            entries.deleted_paths.push(rel);
        } else {
            return Err(image_error(format!(
                "Image contains unsupported special file {relative:?}"
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

fn sign_image(dir: &Path) -> Result<()> {
    let path = signing_key_path()?;
    let parent = crate::filesystem::trusted_directory(
        path.parent()
            .expect("validated signing key path has a filename"),
        true,
    )?;
    if parent.starts_with(dir.canonicalize()?) {
        return Err(image_error(
            "Signing key must be stored outside the image".into(),
        ));
    }
    if !path.try_exists()? {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        fill_secure_random(seed.as_mut())?;
        install_key(&path, &seed)?;
    }
    let seed = zeroize::Zeroizing::new(read_key(&path, true)?);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_path = path.with_added_extension("pub");
    install_key(&public_path, signing_key.verifying_key().as_bytes())?;
    if read_key(&public_path, false)? != signing_key.verifying_key().to_bytes() {
        return Err(image_error(format!(
            "Verification key {public_path:?} does not match signing key"
        )));
    }
    let signature = signing_key.sign(&image_digest(dir)?);
    let encoded = format!("ed25519-v1:{}\n", hex::encode(signature.to_bytes()));
    atomic_write_bytes(&dir.join(IMAGE_SIGNATURE_FILE), encoded.as_bytes(), 0o600)
}

fn verify_image_signature(dir: &Path) -> Result<()> {
    let bytes = read_file_nofollow_bytes(&dir.join(IMAGE_SIGNATURE_FILE))?;
    let encoded = std::str::from_utf8(&bytes).ok().and_then(|s| s.trim_end().strip_prefix("ed25519-v1:"))
        .ok_or_else(|| image_error("Expected an Ed25519 image signature. Recommit legacy HMAC images with a signing key.".into()))?;
    let mut sig = [0u8; 64];
    hex::decode_to_slice(encoded, &mut sig)
        .map_err(|_| image_error("Invalid Ed25519 image signature".into()))?;
    let public_path = match std::env::var_os(IMAGE_VERIFY_KEY_ENV) {
        Some(path) => std::env::current_dir()?.join(path),
        None => signing_key_path()?.with_added_extension("pub"),
    };
    crate::filesystem::trusted_directory(
        public_path
            .parent()
            .ok_or_else(|| image_error("Invalid verification key path".into()))?,
        false,
    )?;
    let verifier = VerifyingKey::from_bytes(&read_key(&public_path, false)?)
        .map_err(|_| image_error("Invalid Ed25519 verification key".into()))?;
    verifier
        .verify_strict(&image_digest(dir)?, &Signature::from_bytes(&sig))
        .map_err(|_| image_error("Image integrity verification failed: signature mismatch".into()))
}

fn image_digest(dir: &Path) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"nucleus-image-ed25519-v1\0");
    update_image_digest(&mut hash, dir, dir)?;
    Ok(hash.finalize().into())
}

fn update_image_digest(hasher: &mut Sha256, root: &Path, dir: &Path) -> Result<()> {
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
            update_metadata_digest(hasher, &path, &metadata, false)?;
            hasher.update(target.as_os_str().as_encoded_bytes());
            hasher.update(b"\0");
        } else if metadata.is_dir() {
            hasher.update(b"D\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            update_metadata_digest(hasher, &path, &metadata, true)?;
            update_image_digest(hasher, root, &path)?;
        } else if metadata.is_file() {
            hasher.update(b"F\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            update_metadata_digest(hasher, &path, &metadata, true)?;
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

fn update_metadata_digest(
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
    hasher.update((xattrs.len() as u64).to_le_bytes());
    for (name, value) in xattrs {
        hasher.update(b"X\0");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(&name);
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(&value);
    }

    Ok(())
}

fn signing_key_path() -> Result<PathBuf> {
    let path = if let Some(path) = std::env::var_os(IMAGE_SIGNING_KEY_ENV) {
        std::env::current_dir()?.join(path)
    } else if std::env::var_os("NUCLEUS_IMAGE_HMAC_KEY_FILE").is_some() {
        return Err(image_error(
            "Replace NUCLEUS_IMAGE_HMAC_KEY_FILE with an Ed25519 signing or verification key"
                .into(),
        ));
    } else if Uid::effective().is_root() {
        PathBuf::from("/var/lib/nucleus/image-ed25519.key")
    } else {
        dirs::data_local_dir()
            .ok_or_else(|| {
                image_error(
                    "Set NUCLEUS_IMAGE_SIGNING_KEY_FILE or NUCLEUS_IMAGE_VERIFY_KEY_FILE".into(),
                )
            })?
            .join("nucleus/image-ed25519.key")
    };
    if path.file_name().is_none() {
        return Err(image_error(format!("Invalid signing key path {path:?}")));
    }
    Ok(path)
}

// Publish a complete key atomically. Concurrent first-time signers all read
// the winning seed before deriving the companion public key.
fn install_key(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    if path.try_exists()? {
        return Ok(());
    }
    let mut file = tempfile::NamedTempFile::new_in(
        path.parent()
            .expect("validated signing key path has a filename"),
    )?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.error.into()),
    }
}

fn read_key(path: &Path, private: bool) -> Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| image_error(format!("Cannot open image key {path:?}: {e}")))?;
    let meta = file.metadata()?;
    let euid = Uid::effective().as_raw();
    if !meta.is_file()
        || meta.len() != 32
        || (meta.uid() != euid && (private || meta.uid() != 0))
        || meta.mode() & (if private { 0o077 } else { 0o022 }) != 0
    {
        return Err(image_error(format!(
            "Invalid image key ownership, permissions or format at {path:?}"
        )));
    }
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
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
        name: &'static str,
        previous: Option<OsString>,
    }

    impl ImageKeyEnvGuard {
        fn set(name: &'static str, path: &Path) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, path);
            Self { name, previous }
        }
    }

    impl Drop for ImageKeyEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
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
    fn rejects_nonlocal_diff_even_with_a_matching_manifest_digest() {
        let tmp = TempDir::new().unwrap();
        let root = sample_rootfs(tmp.path());
        let base = ImageBase::from_rootfs(&root).unwrap();
        let cfg = ImageConfig::from_state(&sample_state(&root, tmp.path()));
        for path in ["/outside", "../sibling", "diff/child"] {
            let diff = ImageDiff {
                source_user_namespace: None,
                path: path.into(),
                digest: String::new(),
                manifest: BTreeMap::new(),
                deleted_paths: Vec::new(),
            };
            let manifest =
                NucleusImageManifest::new(base.clone(), Some(diff), cfg.clone()).unwrap();
            assert!(manifest.validate_identity().is_err());
        }
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
        let _guard = ImageKeyEnvGuard::set(IMAGE_SIGNING_KEY_ENV, &key_dir.join("image.key"));

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
        let mut state = sample_state(&rootfs, &upper);
        let map = UserNamespaceConfig::rootless();
        state.user_ns_config = Some(map.clone());
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

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

        let verified = VerifiedImage::open(&image_dir).unwrap();
        fs::write(
            image_dir.join("diff/etc/config"),
            "modified after verification",
        )
        .unwrap();
        let imported = temp.path().join("imported");
        fs::create_dir(&imported).unwrap();
        assert_eq!(
            verified
                .manifest
                .diff
                .as_ref()
                .unwrap()
                .source_user_namespace
                .as_ref(),
            Some(&map)
        );
        verified
            .copy_remapped_diff_to_upper(&imported, &map.uid_mappings[0], &map.gid_mappings[0])
            .unwrap();
        assert_eq!(fs::read(imported.join("etc/config")).unwrap(), b"changed");
        let loaded = verified.manifest;
        assert_eq!(loaded.image_id, manifest.image_id);
        assert!(loaded
            .diff
            .unwrap()
            .manifest
            .contains_key("etc/config-link"));
    }

    #[test]
    fn test_image_signature_detects_tampering() {
        let _lock = image_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = ImageKeyEnvGuard::set(IMAGE_SIGNING_KEY_ENV, &key_dir.join("image.key"));

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

        // A verifier gets only the independently provisioned public key.
        let verifier = temp.path().join("verifier");
        fs::create_dir(&verifier).unwrap();
        fs::copy(key_dir.join("image.key.pub"), verifier.join("trusted.pub")).unwrap();
        fs::remove_dir_all(&key_dir).unwrap();
        let _public = ImageKeyEnvGuard::set(IMAGE_VERIFY_KEY_ENV, &verifier.join("trusted.pub"));
        assert!(load_image(&image_dir).is_ok());
        assert!(!key_dir.exists());
        let good_key = fs::read(verifier.join("trusted.pub")).unwrap();
        let other = SigningKey::from_bytes(&[37; 32]).verifying_key();
        fs::write(verifier.join("trusted.pub"), other.as_bytes()).unwrap();
        assert!(load_image(&image_dir)
            .unwrap_err()
            .to_string()
            .contains("signature mismatch"));
        fs::write(verifier.join("trusted.pub"), good_key).unwrap();

        fs::write(image_dir.join("diff/file"), "two").unwrap();
        let err = load_image(&image_dir).unwrap_err();
        assert!(err.to_string().contains("signature mismatch"));
        fs::write(image_dir.join(IMAGE_SIGNATURE_FILE), "0".repeat(64)).unwrap();
        assert!(load_image(&image_dir)
            .unwrap_err()
            .to_string()
            .contains("legacy HMAC"));
    }

    #[test]
    fn commit_rejects_an_upperdir_with_a_symlinked_parent() {
        let temp = TempDir::new().unwrap();
        let rootfs = sample_rootfs(temp.path());
        fs::create_dir_all(temp.path().join("overlay/upper")).unwrap();
        symlink("overlay", temp.path().join("alias")).unwrap();
        let output = temp.path().join("image");
        let state = sample_state(&rootfs, &temp.path().join("alias/upper"));
        assert!(commit_container_image(&state, &output, &ImageCommitOptions::default()).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn test_image_signature_detects_metadata_tampering() {
        let _lock = image_key_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let key_dir = temp.path().join("keys");
        fs::create_dir(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _guard = ImageKeyEnvGuard::set(IMAGE_SIGNING_KEY_ENV, &key_dir.join("image.key"));

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
        assert!(err.to_string().contains("signature mismatch"));
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

        let _lock = image_key_env_lock().lock().unwrap();
        let key_temp = TempDir::new().unwrap();
        fs::set_permissions(key_temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _guard =
            ImageKeyEnvGuard::set(IMAGE_SIGNING_KEY_ENV, &key_temp.path().join("image.key"));

        let broker = CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
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
    #[test]
    fn import_rebases_previous_and_legacy_mappings_without_leaving_foreign_owners() {
        let target = IdMapping::new(0, 700_000, 65_536);
        let source = [IdMapping::new(0, 900_000, 65_536)];
        assert_eq!(
            imported_host_id(900_999, Some(&source), &target).unwrap(),
            700_999
        );
        assert_eq!(imported_host_id(100_999, None, &target).unwrap(), 700_999);
        assert_eq!(imported_host_id(999, None, &target).unwrap(), 700_999);
        assert!(imported_host_id(999, Some(&source), &target).is_err());
        assert!(imported_host_id(900_999, None, &target).is_err());
    }

    #[test]
    fn remap_layer_ownership_preserves_identity_mapping() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("upper");
        std::fs::create_dir(&root).unwrap();
        let data = root.join("data");
        std::fs::write(&data, b"x").unwrap();
        let link = root.join("link");
        symlink(&data, &link).unwrap();

        // The current identity maps to itself; nothing else is mapped.
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let uid_map = crate::isolation::IdMapping::new(uid, uid, 1);
        let gid_map = crate::isolation::IdMapping::new(gid, gid, 1);

        remap_layer_ownership(&root, &uid_map, &gid_map).unwrap();

        assert_eq!(std::fs::symlink_metadata(&data).unwrap().uid(), uid);
        assert_eq!(
            std::fs::symlink_metadata(&link).unwrap().uid(),
            uid,
            "symlink owners must not be followed or changed"
        );
    }

    #[test]
    #[ignore = "requires root with CAP_CHOWN; remaps foreign owners in a disposable tree"]
    fn remap_layer_ownership_translates_foreign_service_owners() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("upper");
        std::fs::create_dir(&root).unwrap();
        // A committed layer from a non-remapped container: service uid/gid 1000.
        let service_dir = root.join("service");
        std::fs::create_dir(&service_dir).unwrap();
        std::fs::set_permissions(&service_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        nix::unistd::chown(
            &service_dir,
            Some(nix::unistd::Uid::from_raw(1000)),
            Some(nix::unistd::Gid::from_raw(1000)),
        )
        .unwrap();
        let file = service_dir.join("state");
        std::fs::write(&file, b"x").unwrap();
        nix::unistd::chown(
            &file,
            Some(nix::unistd::Uid::from_raw(1000)),
            Some(nix::unistd::Gid::from_raw(1000)),
        )
        .unwrap();

        let mapping = IdMapping::new(0, 700_000, 65_536);
        remap_layer_ownership(&root, &mapping, &mapping).unwrap();

        assert_eq!(std::fs::metadata(&service_dir).unwrap().uid(), 701_000);
        assert_eq!(std::fs::metadata(&service_dir).unwrap().gid(), 701_000);
        assert_eq!(std::fs::metadata(&file).unwrap().uid(), 701_000);
    }
}
