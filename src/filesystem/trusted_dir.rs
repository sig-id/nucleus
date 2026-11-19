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
        if meta.is_dir() && owner_unmapped(meta.uid()) {
            return Err(NucleusError::FilesystemError(format!(
                "Cannot verify directory {current:?}: its owner is not mapped into this \
                 user namespace; check it before entering the namespace"
            )));
        }
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

/// Owners outside the current user namespace stat as the overflow UID, so their
/// identity (and whether they are root) cannot be checked from inside it.
pub(crate) fn owner_unmapped(uid: u32) -> bool {
    let overflow_uid = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(65534);
    uid == overflow_uid && !in_initial_user_namespace()
}

fn in_initial_user_namespace() -> bool {
    fs::read_to_string("/proc/self/uid_map")
        .map(|map| map.split_whitespace().eq(["0", "0", "4294967295"]))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_namespace_reports_ownership_not_unmapped_owner() {
        if !in_initial_user_namespace() {
            return;
        }
        assert!(!owner_unmapped(65534));
        assert!(!owner_unmapped(0));
    }

    #[test]
    fn unmapped_owner_inside_user_namespace_fails_closed_with_cause() {
        let dir = tempfile::tempdir().unwrap();
        // unshare(CLONE_NEWUSER) requires a single-threaded caller.
        match unsafe { nix::unistd::fork().unwrap() } {
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0)
            ),
            nix::unistd::ForkResult::Child => {
                let result = std::panic::catch_unwind(|| {
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).unwrap();
                    // No ID map is written, so every existing owner is unmapped.
                    let err = trusted_directory(dir.path(), false)
                        .unwrap_err()
                        .to_string();
                    assert!(err.contains("not mapped into this user namespace"), "{err}");
                    let err = trusted_directory(&dir.path().join("new"), true)
                        .unwrap_err()
                        .to_string();
                    assert!(err.contains("not mapped into this user namespace"), "{err}");
                    assert!(!dir.path().join("new").exists());
                });
                unsafe { libc::_exit(i32::from(result.is_err())) };
            }
        }
    }
}
