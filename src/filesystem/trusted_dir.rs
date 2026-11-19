//! Pathnames passed to another process must stay under directories whose
//! entries other users cannot replace. Check each parent before using a child.
use crate::error::{NucleusError, Result};
use nix::unistd::Uid;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

pub(crate) fn trusted_directory(path: &Path, create: bool) -> Result<PathBuf> {
    trusted_directory_with(path, create, false)
}

/// For paths resolved inside a container's user namespace: owners outside the
/// namespace cannot be impersonated by anything in it, so they are trusted too.
/// See [`owner_outside_namespace`] for when an owner provably is outside.
pub(crate) fn trusted_container_directory(path: &Path) -> Result<PathBuf> {
    trusted_directory_with(path, false, true)
}

fn trusted_directory_with(path: &Path, create: bool, allow_unmapped: bool) -> Result<PathBuf> {
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
        let unmapped = owner_unmapped(meta.uid());
        let outside = allow_unmapped && owner_outside_namespace(meta.uid());
        if meta.is_dir() && unmapped && !outside {
            return Err(NucleusError::FilesystemError(format!(
                "Cannot verify directory {current:?}: its owner is not mapped into this \
                 user namespace; check it before entering the namespace"
            )));
        }
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != uid && !outside)
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
    uid == overflow_uid() && !in_initial_user_namespace()
}

/// Whether `uid` can only be an owner outside the current user namespace.
///
/// An unmapped owner stats as the overflow UID. So does a file owned by the
/// overflow UID itself when the namespace maps that ID, as every 65,536-ID
/// mapping does; that owner can act inside the namespace. The two cannot be
/// told apart from here, so only a namespace that leaves the overflow UID
/// unmapped proves the owner is outside.
pub(crate) fn owner_outside_namespace(uid: u32) -> bool {
    owner_unmapped(uid)
        && fs::read_to_string("/proc/self/uid_map")
            .is_ok_and(|map| !uid_map_covers(&map, overflow_uid()))
}

fn overflow_uid() -> u32 {
    fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(65534)
}

/// Whether a `uid_map` maps the in-namespace ID `id`. Unparsable input counts
/// as mapped, which keeps the caller fail-closed.
fn uid_map_covers(map: &str, id: u32) -> bool {
    map.lines().any(|line| {
        let mut fields = line.split_whitespace().map(str::parse::<u64>);
        match (fields.next(), fields.next(), fields.next()) {
            (Some(Ok(inside)), Some(Ok(_)), Some(Ok(count))) => {
                (inside..inside.saturating_add(count)).contains(&u64::from(id))
            }
            _ => true,
        }
    })
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
    fn uid_map_coverage_follows_the_inside_id_range() {
        assert!(!uid_map_covers("         0       1000          1\n", 65534));
        assert!(uid_map_covers("0 100000 65536\n", 65534));
        assert!(!uid_map_covers("0 100000 65534\n", 65534));
        assert!(uid_map_covers("0 1000 1\n65534 1001 1\n", 65534));
        assert!(!uid_map_covers("", 65534));
        // Anything unreadable is treated as mapped.
        assert!(uid_map_covers("garbage\n", 65534));
    }

    /// Run `check` in a child whose user namespace maps one ID, `inside`, to
    /// the calling user.
    fn in_user_namespace_mapping(inside: u32, check: impl FnOnce()) {
        let uid = Uid::current();
        // unshare(CLONE_NEWUSER) requires a single-threaded caller.
        match unsafe { nix::unistd::fork().unwrap() } {
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0)
            ),
            nix::unistd::ForkResult::Child => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER).unwrap();
                    fs::write("/proc/self/uid_map", format!("{inside} {uid} 1")).unwrap();
                    check();
                }));
                unsafe { libc::_exit(i32::from(result.is_err())) };
            }
        }
    }

    #[test]
    fn overflow_owner_is_outside_only_when_the_namespace_cannot_hold_it() {
        let overflow = overflow_uid();
        // Only ID 0 is mapped: an overflow-UID owner must be a host user.
        in_user_namespace_mapping(0, move || {
            assert!(owner_unmapped(overflow));
            assert!(owner_outside_namespace(overflow));
            assert!(!owner_outside_namespace(0));
        });
        // The overflow UID is a real user here, so the same stat result may
        // be a file that user controls.
        in_user_namespace_mapping(overflow, move || {
            assert!(owner_unmapped(overflow));
            assert!(!owner_outside_namespace(overflow));
        });
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
