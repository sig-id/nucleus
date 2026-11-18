//! Pathnames passed to another process must stay under directories whose
//! entries other users cannot replace. Check each parent before using a child.
use crate::error::{NucleusError, Result};
use nix::unistd::Uid;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

pub(crate) fn trusted_directory(path: &Path, create: bool) -> Result<PathBuf> {
    let path = std::env::current_dir()?.join(path);
    let mut current = PathBuf::from("/");
    let uid = Uid::effective().as_raw();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => current.push(name),
            _ => {
                return Err(NucleusError::FilesystemError(format!(
                    "Invalid directory path {path:?}"
                )))
            }
        }
        let meta = match fs::symlink_metadata(&current) {
            Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                match DirBuilder::new().mode(0o700).create(&current) {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e.into()),
                }
                fs::symlink_metadata(&current)?
            }
            result => result?,
        };
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != uid)
            || (meta.mode() & 0o022 != 0 && meta.mode() & libc::S_ISVTX == 0)
        {
            return Err(NucleusError::FilesystemError(format!(
                "Untrusted directory {current:?} (uid {}, mode {:o})",
                meta.uid(),
                meta.mode() & 0o7777
            )));
        }
    }
    Ok(current)
}
