use crate::error::{NucleusError, Result};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use tracing::{debug, warn};

const MAX_WORKSPACE_DEPTH: u32 = 256;

const DENIED_WORKSPACE_SOURCES_EXACT: &[&str] = &["/"];

const DENIED_WORKSPACE_SOURCE_PREFIXES: &[&str] = &[
    "/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys", "/var/log", "/var/run",
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
        if source == denied_path || source.starts_with(denied_path) {
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
    let normalized = normalize_workspace_source_for_policy(source)?;
    reject_denied_workspace_source(&normalized)?;

    let canonical = fs::canonicalize(source).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve workspace source {:?}: {}",
            source, e
        ))
    })?;
    reject_denied_workspace_source(&canonical)?;
    if !canonical.is_dir() {
        return Err(NucleusError::ConfigError(format!(
            "Workspace source must be a directory: {}",
            canonical.display()
        )));
    }

    Ok(canonical)
}

/// Copy a host workspace into a private staging directory.
pub fn copy_workspace_in(source: &Path, staging: &Path) -> Result<()> {
    let source = validate_workspace_host_path(source)?;
    fs::create_dir_all(staging).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create workspace staging directory {:?}: {}",
            staging, e
        ))
    })?;
    copy_tree_contents(&source, staging)
}

/// Mirror the staged workspace back to the host source after workload exit.
pub fn sync_workspace_out(staging: &Path, destination: &Path) -> Result<()> {
    let destination = validate_workspace_host_path(destination)?;
    if !staging.is_dir() {
        return Err(NucleusError::FilesystemError(format!(
            "Workspace staging path is not a directory: {}",
            staging.display()
        )));
    }

    remove_stale_entries(staging, &destination, 0)?;
    copy_tree_contents(staging, &destination)
}

fn copy_tree_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in read_workspace_entries(source, 0)? {
        let (src_path, name, metadata) = entry;
        copy_entry(&src_path, &destination.join(name), &metadata, 1)?;
    }
    Ok(())
}

fn read_workspace_entries(
    dir: &Path,
    depth: u32,
) -> Result<Vec<(PathBuf, std::ffi::OsString, fs::Metadata)>> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded at {:?}",
            MAX_WORKSPACE_DEPTH, dir
        )));
    }

    let entries = fs::read_dir(dir).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read workspace dir {:?}: {}", dir, e))
    })?;

    let mut result = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to read workspace entry in {:?}: {}",
                dir, e
            ))
        })?;
        let src_path = entry.path();
        let metadata = fs::symlink_metadata(&src_path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat workspace entry {:?}: {}",
                src_path, e
            ))
        })?;
        result.push((src_path, entry.file_name(), metadata));
    }
    Ok(result)
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

fn copy_entry(src: &Path, dst: &Path, metadata: &fs::Metadata, depth: u32) -> Result<()> {
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
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
        })?;
        for entry in read_workspace_entries(src, depth)? {
            let (child_src, name, child_metadata) = entry;
            copy_entry(&child_src, &dst.join(name), &child_metadata, depth + 1)?;
        }
        fs::set_permissions(
            dst,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to set permissions on workspace directory {:?}: {}",
                dst, e
            ))
        })?;
    } else if metadata.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create workspace file parent {:?}: {}",
                    parent, e
                ))
            })?;
        }
        remove_existing_path(dst)?;
        fs::copy(src, dst).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to copy workspace file {:?} to {:?}: {}",
                src, dst, e
            ))
        })?;
        fs::set_permissions(
            dst,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to set permissions on workspace file {:?}: {}",
                dst, e
            ))
        })?;
    } else if metadata.file_type().is_symlink() {
        let target = fs::read_link(src).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to read workspace symlink {:?}: {}",
                src, e
            ))
        })?;
        remove_existing_path(dst)?;
        symlink(&target, dst).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create workspace symlink {:?} -> {:?}: {}",
                dst, target, e
            ))
        })?;
    } else {
        debug!("Skipping special workspace file {:?}", src);
    }

    Ok(())
}

fn remove_stale_entries(source: &Path, destination: &Path, depth: u32) -> Result<()> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(NucleusError::FilesystemError(format!(
            "Maximum workspace directory depth ({}) exceeded at {:?}",
            MAX_WORKSPACE_DEPTH, destination
        )));
    }

    let entries = fs::read_dir(destination).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to read workspace destination {:?}: {}",
            destination, e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to read workspace destination entry in {:?}: {}",
                destination, e
            ))
        })?;
        let name = entry.file_name();
        let dst_path = entry.path();
        let src_path = source.join(&name);
        if fs::symlink_metadata(&src_path).is_err() {
            warn!("Removing workspace path absent from stage: {:?}", dst_path);
            remove_existing_path(&dst_path)?;
            continue;
        }

        let src_meta = fs::symlink_metadata(&src_path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat staged workspace path {:?}: {}",
                src_path, e
            ))
        })?;
        let dst_meta = fs::symlink_metadata(&dst_path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat destination workspace path {:?}: {}",
                dst_path, e
            ))
        })?;
        if src_meta.is_dir()
            && !src_meta.file_type().is_symlink()
            && dst_meta.is_dir()
            && !dst_meta.file_type().is_symlink()
        {
            remove_stale_entries(&src_path, &dst_path, depth + 1)?;
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
    fn test_workspace_validation_rejects_sensitive_sources() {
        let err = validate_workspace_host_path(Path::new("/proc")).unwrap_err();
        assert!(err.to_string().contains("sensitive host path"));
    }
}
