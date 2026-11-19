use crate::error::{NucleusError, Result};
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use tracing::{debug, warn};

const MAX_WORKSPACE_DEPTH: u32 = 256;

const DENIED_WORKSPACE_SOURCES_EXACT: &[&str] = &["/", "/home", "/tmp"];

const DENIED_WORKSPACE_SOURCE_PREFIXES: &[&str] = &[
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/var/log",
    "/var/run",
    "/var/lib",
    "/var/spool",
    "/nix/var",
];

fn normalize_workspace_source_for_policy(source: &Path) -> Result<PathBuf> {
    if !source.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Workspace source must be absolute: {:?}",
            source
        )));
    }

    let mut normalized = PathBuf::from("/");
    for component in source.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
                if normalized.as_os_str().is_empty() {
                    normalized.push("/");
                }
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported workspace source prefix: {:?}",
                    source
                )));
            }
        }
    }

    Ok(normalized)
}

fn reject_denied_workspace_source(source: &Path) -> Result<()> {
    for denied in DENIED_WORKSPACE_SOURCES_EXACT {
        if source == Path::new(denied) {
            return Err(NucleusError::ConfigError(format!(
                "Workspace source '{}' is a sensitive host path and cannot be mounted",
                source.display()
            )));
        }
    }

    for denied in DENIED_WORKSPACE_SOURCE_PREFIXES {
        let denied_path = Path::new(denied);
        if denied_path.starts_with(source) || source.starts_with(denied_path) {
            return Err(NucleusError::ConfigError(format!(
                "Workspace source '{}' is under sensitive host path '{}' and cannot be mounted",
                source.display(),
                denied
            )));
        }
    }

    Ok(())
}

/// Validate a workspace source and return its canonical host path.
///
/// Workspaces intentionally allow ordinary user project directories such as
/// `/home/alice/src/app`; the broader `--volume` denylist is stricter because
/// generic bind mounts do not carry the same first-class workspace contract.
pub fn validate_workspace_host_path(source: &Path) -> Result<PathBuf> {
    let fd = pin_workspace_source(source)?;
    Ok(fs::read_link(super::fd_path(&fd))?)
}

pub(crate) fn pin_workspace_source(source: &Path) -> Result<std::os::fd::OwnedFd> {
    reject_denied_workspace_source(&normalize_workspace_source_for_policy(source)?)?;
    let fd = nix::fcntl::open(
        source,
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?;
    reject_denied_workspace_source(&fs::read_link(super::fd_path(&fd))?)?;
    Ok(fd)
}

/// Copy a host workspace into a private staging directory.
///
/// The host source is pinned with an `O_PATH` descriptor and every child is
/// opened relative to that pin (`openat` + `O_NOFOLLOW`), so a concurrent
/// writer on the host cannot swap a name between the metadata check and the
/// copy: the copied bytes always come from the pinned inode.
pub fn copy_workspace_in(source: &Path, staging: &Path) -> Result<()> {
    let pinned = pin_workspace_source(source)?;
    fs::create_dir_all(staging).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create workspace staging directory {:?}: {}",
            staging, e
        ))
    })?;
    copy_tree_contents(&pinned, staging, 0)
}

/// Mirror the staged workspace back to the host source after workload exit.
///
/// The host destination is pinned; directory creation, file publication and
/// stale-entry removal all operate relative to pinned directory descriptors,
/// never on re-resolved host paths.
pub fn sync_workspace_out(staging: &Path, destination: &Path) -> Result<()> {
    let pinned = pin_workspace_source(destination)?;
    if !staging.is_dir() {
        return Err(NucleusError::FilesystemError(format!(
            "Workspace staging path is not a directory: {}",
            staging.display()
        )));
    }

    remove_stale_entries(staging, &pinned, 0)?;
    sync_tree_to_fd(staging, &pinned, 0)
}

/// List the entry names of a pinned directory, depth-limited.
fn workspace_entry_names(
    dir: &std::os::fd::OwnedFd,
    depth: u32,
) -> Result<Vec<std::ffi::OsString>> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded",
            MAX_WORKSPACE_DEPTH
        )));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(super::fd_path(dir)).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read pinned workspace directory: {}", e))
    })? {
        names.push(
            entry
                .map_err(|e| {
                    NucleusError::FilesystemError(format!("Failed to read workspace entry: {}", e))
                })?
                .file_name(),
        );
    }
    Ok(names)
}

/// Copy the pinned source directory into `destination` (a trusted staging
/// path). Children are pinned one by one; symlinks are recreated, special
/// files are skipped and set-id bits are stripped.
fn copy_tree_contents(source: &OwnedFd, destination: &Path, depth: u32) -> Result<()> {
    for name in workspace_entry_names(source, depth)? {
        let child = super::pinned_child(source, &name)?;
        let kind = super::pinned_kind(&child)?;
        let dst = destination.join(&name);
        if kind == nix::sys::stat::SFlag::S_IFDIR {
            prepare_staging_dir(&dst)?;
            copy_tree_contents(&child, &dst, depth + 1)?;
            let mode = nix::sys::stat::fstat(&child)?.st_mode;
            fs::set_permissions(&dst, fs::Permissions::from_mode(mode & 0o1777)).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions on workspace directory {:?}: {}",
                    dst, e
                ))
            })?;
        } else if kind == nix::sys::stat::SFlag::S_IFREG {
            copy_pinned_file(&child, &dst)?;
        } else if kind == nix::sys::stat::SFlag::S_IFLNK {
            // Read the link target relative to the pinned parent, then
            // recreate it; the copy never follows the host-side link.
            let target =
                nix::fcntl::readlinkat(source, std::path::Path::new(&name)).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to read workspace symlink {:?}: {}",
                        name, e
                    ))
                })?;
            remove_existing_path(&dst)?;
            symlink(&target, &dst).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create workspace symlink {:?} -> {:?}: {}",
                    dst, target, e
                ))
            })?;
        } else {
            debug!("Skipping special workspace file {:?}", name);
        }
    }
    Ok(())
}

/// Ensure the staging path is a real directory, replacing anything else.
fn prepare_staging_dir(dst: &Path) -> Result<()> {
    match fs::symlink_metadata(dst) {
        Ok(existing) if existing.is_dir() && !existing.file_type().is_symlink() => {}
        Ok(_) => remove_existing_path(dst)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(NucleusError::FilesystemError(format!(
                "Failed to stat workspace destination {:?}: {}",
                dst, e
            )))
        }
    }
    fs::create_dir_all(dst).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create workspace directory {:?}: {}",
            dst, e
        ))
    })
}

/// Stream a pinned regular file into a fresh private inode next to `dst`,
/// then publish it under the sanitized mode.
fn copy_pinned_file(src: &OwnedFd, dst: &Path) -> Result<()> {
    // Re-open the pin (not the mutable name) for reading. Opening the
    // procfs descriptor link resolves exactly the pinned inode, and the
    // kernel refuses to re-open a pin whose original open disallowed it;
    // O_NOFOLLOW is deliberately absent because the procfs link itself is a
    // symlink.
    let mut from = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(super::fd_path(src))?;
    let metadata = from.metadata()?;
    if !metadata.is_file() {
        return Err(NucleusError::FilesystemError(format!(
            "Workspace entry is no longer a regular file: {:?}",
            super::fd_path(src)
        )));
    }
    stream_file(&mut from, metadata.permissions().mode(), dst)
}

fn stream_file(from: &mut fs::File, raw_mode: u32, dst: &Path) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(dst.parent().expect("workspace entry has a parent"))?;
    std::io::copy(from, &mut file)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(raw_mode & 0o1777))?;
    if fs::symlink_metadata(dst).is_ok_and(|existing| existing.is_dir()) {
        fs::remove_dir_all(dst)?;
    }
    file.persist(dst).map_err(|e| e.error)?;
    Ok(())
}

/// Mirror the trusted staging tree into the pinned host destination.
fn sync_tree_to_fd(source: &Path, destination: &OwnedFd, depth: u32) -> Result<()> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded",
            MAX_WORKSPACE_DEPTH
        )));
    }
    for entry in fs::read_dir(source).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to read workspace staging directory {:?}: {}",
            source, e
        ))
    })? {
        let entry =
            entry.map_err(|e| NucleusError::FilesystemError(format!("Workspace stage: {e}")))?;
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to stat staged entry: {e}"))
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let dst_dir = ensure_destination_dir(destination, &name)?;
            sync_tree_to_fd(&entry.path(), &dst_dir, depth + 1)?;
            fs::set_permissions(
                super::fd_path(&dst_dir),
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o1777),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions on workspace directory: {}",
                    e
                ))
            })?;
        } else if metadata.is_file() {
            let mut from = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(entry.path())?;
            publish_file(&mut from, metadata.permissions().mode(), destination, &name)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to read staged symlink {:?}: {}",
                    entry.path(),
                    e
                ))
            })?;
            clear_destination_entry(destination, &name)?;
            nix::unistd::symlinkat(&target, destination, Path::new(&name)).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create workspace symlink {:?} -> {:?}: {}",
                    name, target, e
                ))
            })?;
        } else {
            debug!("Skipping special staged workspace file {:?}", name);
        }
    }
    Ok(())
}

/// Create (or reuse a real) directory `name` under the pinned destination.
///
/// A non-directory occupying the name is removed first; a symlink is never
/// followed, so the copy cannot be redirected through a swapped link.
fn ensure_destination_dir(parent: &OwnedFd, name: &std::ffi::OsStr) -> Result<OwnedFd> {
    let mkdir = || {
        // nix 0.32 does not wrap mkdirat; call it directly. Both arguments
        // are an integer and a path relative to the pinned parent.
        let c_name = match std::ffi::CString::new(name.as_encoded_bytes()) {
            Ok(c_name) => c_name,
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "Invalid workspace name: {e}"
                )))
            }
        };
        let result = unsafe {
            libc::mkdirat(
                std::os::fd::AsRawFd::as_raw_fd(parent),
                c_name.as_ptr(),
                0o700,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    match mkdir() {
        Ok(()) => super::pinned_child(parent, name),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = super::pinned_child(parent, name)?;
            if super::pinned_kind(&existing)? == nix::sys::stat::SFlag::S_IFDIR {
                return Ok(existing);
            }
            remove_pinned_entry(parent, name)?;
            mkdir().map_err(|e| {
                NucleusError::FilesystemError(format!("Failed to create workspace directory: {e}"))
            })?;
            super::pinned_child(parent, name)
        }
        Err(e) => Err(NucleusError::FilesystemError(format!(
            "Failed to create workspace directory: {e}"
        ))),
    }
}

/// Publish a file under `name` in the pinned destination directory.
///
/// The content streams into a private temporary inode inside the pinned
/// directory and is renamed into place; a directory occupying the name is
/// removed through its own pin, never by re-resolving the host path.
fn publish_file(
    from: &mut fs::File,
    raw_mode: u32,
    destination: &OwnedFd,
    name: &std::ffi::OsStr,
) -> Result<()> {
    let dir_path = super::fd_path(destination);
    let dst = dir_path.join(name);
    let mut file = tempfile::NamedTempFile::new_in(&dir_path)?;
    std::io::copy(from, &mut file)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(raw_mode & 0o1777))?;
    if let Err(persist_error) = file.persist(&dst) {
        // A directory at the destination blocks the rename; clear it through
        // the pin and retry once. A vanished entry means nothing blocks the
        // retry either.
        clear_destination_entry(destination, name)?;
        persist_error.file.persist(&dst).map_err(|e| e.error)?;
    }
    Ok(())
}

/// Remove `name` below the pinned `parent` if it exists, whatever it is.
fn clear_destination_entry(parent: &OwnedFd, name: &std::ffi::OsStr) -> Result<()> {
    match super::pinned_child(parent, name) {
        Ok(_) => remove_pinned_entry(parent, name),
        Err(e) if e.to_string().contains("No such file") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Clear `name` below the pinned `parent` directory, whatever it is.
///
/// Directories are emptied relative to their own pin and then removed with
/// `unlinkat(AT_REMOVEDIR)` under the pinned parent. `std::fs::remove_dir_all`
/// must not be pointed at the pin path: it opens the top-level path with
/// `O_NOFOLLOW`, which rejects the procfs descriptor link itself (EPERM), so
/// deleting a directory would abort the whole synchronization.
fn remove_pinned_entry(parent: &OwnedFd, name: &std::ffi::OsStr) -> Result<()> {
    let child = super::pinned_child(parent, name)?;
    if super::pinned_kind(&child)? == nix::sys::stat::SFlag::S_IFDIR {
        remove_pinned_tree(&child, 0)?;
        nix::unistd::unlinkat(
            parent,
            Path::new(name),
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remove workspace directory {:?}: {}",
                name, e
            ))
        })
    } else {
        nix::unistd::unlinkat(
            parent,
            Path::new(name),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remove workspace entry {:?}: {}",
                name, e
            ))
        })
    }
}

/// Empty a pinned directory tree bottom-up, removing every entry relative to
/// its pinned parent so a concurrent writer cannot redirect a removal.
fn remove_pinned_tree(dir: &OwnedFd, depth: u32) -> Result<()> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded",
            MAX_WORKSPACE_DEPTH
        )));
    }
    for name in workspace_entry_names(dir, depth)? {
        let child = super::pinned_child(dir, &name)?;
        let is_dir = super::pinned_kind(&child)? == nix::sys::stat::SFlag::S_IFDIR;
        if is_dir {
            remove_pinned_tree(&child, depth + 1)?;
        }
        let flag = if is_dir {
            nix::unistd::UnlinkatFlags::RemoveDir
        } else {
            nix::unistd::UnlinkatFlags::NoRemoveDir
        };
        nix::unistd::unlinkat(dir, Path::new(&name), flag).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remove workspace entry {:?}: {}",
                name, e
            ))
        })?;
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to remove existing workspace directory {:?}: {}",
                    path, e
                ))
            })
        }
        Ok(_) => fs::remove_file(path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remove existing workspace file {:?}: {}",
                path, e
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NucleusError::FilesystemError(format!(
            "Failed to stat existing workspace path {:?}: {}",
            path, e
        ))),
    }
}

/// Remove host destination entries that no longer exist in staging.
///
/// The destination walk is anchored on pinned directory descriptors, so a
/// concurrent host writer cannot redirect a removal through a swapped
/// symlink; the staging side is trusted and read by path.
fn remove_stale_entries(source: &Path, destination: &OwnedFd, depth: u32) -> Result<()> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded",
            MAX_WORKSPACE_DEPTH
        )));
    }

    for name in workspace_entry_names(destination, depth)? {
        let src_path = source.join(&name);
        let Ok(src_meta) = fs::symlink_metadata(&src_path) else {
            warn!("Removing workspace path absent from stage: {:?}", name);
            remove_pinned_entry(destination, &name)?;
            continue;
        };

        if src_meta.is_dir() && !src_meta.file_type().is_symlink() {
            let child = super::pinned_child(destination, &name)?;
            if super::pinned_kind(&child)? == nix::sys::stat::SFlag::S_IFDIR {
                remove_stale_entries(&src_path, &child, depth + 1)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_copy_in_out_roundtrip_updates_and_deletes() {
        let host = tempfile::TempDir::new().unwrap();
        let stage = tempfile::TempDir::new().unwrap();

        fs::write(host.path().join("keep.txt"), "old").unwrap();
        fs::write(host.path().join("delete.txt"), "gone").unwrap();

        copy_workspace_in(host.path(), stage.path()).unwrap();
        fs::write(stage.path().join("keep.txt"), "new").unwrap();
        fs::write(stage.path().join("created.txt"), "created").unwrap();
        fs::remove_file(stage.path().join("delete.txt")).unwrap();

        sync_workspace_out(stage.path(), host.path()).unwrap();

        assert_eq!(
            fs::read_to_string(host.path().join("keep.txt")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(host.path().join("created.txt")).unwrap(),
            "created"
        );
        assert!(!host.path().join("delete.txt").exists());
    }

    #[test]
    fn workspace_copy_strips_setid_from_files_and_directories() {
        let host = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let modes = [(0o4751, 0o751), (0o2640, 0o640), (0o6755, 0o755)];
        let check = |root: &Path| {
            assert_eq!(
                fs::metadata(root.join("sub")).unwrap().permissions().mode() & 0o7777,
                0o1750
            );
            for (i, (_, want)) in modes.iter().enumerate() {
                let path = root.join("sub").join(i.to_string());
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                    *want
                );
            }
        };
        let set_modes = |root: &Path| {
            let dir = root.join("sub");
            fs::create_dir_all(&dir).unwrap();
            for (i, (mode, _)) in modes.iter().enumerate() {
                let path = dir.join(i.to_string());
                fs::write(&path, b"workspace fixture").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(*mode)).unwrap();
            }
            fs::set_permissions(dir, fs::Permissions::from_mode(0o7750)).unwrap();
        };
        set_modes(host.path());
        copy_workspace_in(host.path(), stage.path()).unwrap();
        check(stage.path());
        set_modes(stage.path());
        sync_workspace_out(stage.path(), host.path()).unwrap();
        check(host.path());
    }

    #[test]
    fn test_workspace_sync_removes_deleted_directories() {
        // Regression (review finding): removing a deleted directory through
        // the pin must succeed — std::fs::remove_dir_all on /proc/self/fd/N
        // fails with EPERM, which used to abort the whole sync.
        let host = tempfile::TempDir::new().unwrap();
        let stage = tempfile::TempDir::new().unwrap();

        fs::create_dir_all(host.path().join("build").join("nested")).unwrap();
        fs::write(host.path().join("build").join("nested").join("bin"), b"x").unwrap();
        fs::write(host.path().join("build").join("lib"), b"y").unwrap();
        fs::write(host.path().join("keep.txt"), b"keep").unwrap();

        copy_workspace_in(host.path(), stage.path()).unwrap();
        fs::remove_dir_all(stage.path().join("build")).unwrap();

        sync_workspace_out(stage.path(), host.path()).unwrap();

        assert!(!host.path().join("build").exists());
        assert!(host.path().join("keep.txt").is_file());
    }

    #[test]
    fn test_workspace_sync_replaces_directory_with_file_and_symlink() {
        // A directory occupied by a stale entry must be cleared through the
        // pins when staging publishes a file or a symlink under the same name.
        let host = tempfile::TempDir::new().unwrap();
        let stage = tempfile::TempDir::new().unwrap();

        fs::create_dir_all(host.path().join("as_file").join("inner")).unwrap();
        fs::write(host.path().join("as_file").join("inner").join("f"), b"old").unwrap();
        fs::create_dir_all(host.path().join("as_link")).unwrap();
        fs::write(host.path().join("as_link").join("f"), b"old").unwrap();

        copy_workspace_in(host.path(), stage.path()).unwrap();
        fs::remove_dir_all(stage.path().join("as_file")).unwrap();
        fs::write(stage.path().join("as_file"), b"now a file").unwrap();
        fs::remove_dir_all(stage.path().join("as_link")).unwrap();
        symlink(Path::new("as_file"), stage.path().join("as_link")).unwrap();

        sync_workspace_out(stage.path(), host.path()).unwrap();

        assert_eq!(
            fs::read_to_string(host.path().join("as_file")).unwrap(),
            "now a file"
        );
        assert!(host
            .path()
            .join("as_link")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn test_workspace_validation_rejects_sensitive_sources() {
        let err = validate_workspace_host_path(Path::new("/proc")).unwrap_err();
        assert!(err.to_string().contains("sensitive host path"));
    }
}
