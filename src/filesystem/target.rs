//! Descriptor-relative preparation of mountpoints inside an untrusted image.
use crate::error::{NucleusError, Result};
use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{fstat, mkdirat, Mode, SFlag};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Walk one component at a time. Never truncate an existing mountpoint or
/// follow image symlinks, including during directory creation.
pub(crate) fn mount_target(root: &Path, relative: &Path, directory: bool) -> Result<OwnedFd> {
    let dir_flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut parent = open(root, dir_flags, Mode::empty())?;
    let mut components = relative.components().peekable();
    if components.peek().is_none() {
        if directory {
            return Ok(parent);
        }
        return Err(NucleusError::FilesystemError(
            "Empty file mountpoint".into(),
        ));
    }
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(NucleusError::FilesystemError(format!(
                "Invalid mountpoint {relative:?}"
            )));
        };
        let is_dir = directory || components.peek().is_some();
        let flags = if is_dir {
            dir_flags
        } else {
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
        };
        parent = match openat(&parent, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                let created = if is_dir {
                    mkdirat(&parent, name, Mode::from_bits_truncate(0o755))
                } else {
                    openat(
                        &parent,
                        name,
                        OFlag::O_WRONLY
                            | OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                    )
                    .map(drop)
                };
                match created {
                    Ok(()) | Err(Errno::EEXIST) => (),
                    Err(e) => return Err(e.into()),
                }
                openat(&parent, name, flags, Mode::empty())?
            }
            Err(e) => return Err(e.into()),
        };
        if !is_dir && SFlag::from_bits_truncate(fstat(&parent)?.st_mode) != SFlag::S_IFREG {
            return Err(NucleusError::FilesystemError(format!(
                "Expected regular file mountpoint {relative:?}"
            )));
        }
    }
    Ok(parent)
}

pub(crate) fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Restrict a detached clone of the source before attaching it to the pinned
/// target. attr_clr stays zero so source or descendant restrictions survive.
pub(crate) fn bind_tree(
    source: &Path,
    target: &OwnedFd,
    recursive: bool,
    attrs: u64,
) -> Result<()> {
    let src = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| NucleusError::FilesystemError("NUL in bind source".into()))?;
    let rec = if recursive { libc::AT_RECURSIVE } else { 0 };
    // SAFETY: src is terminated and open_tree returns a fresh mount fd.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | rec as u32,
        )
    };
    if raw == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    let tree = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let mut attr: libc::mount_attr = unsafe { std::mem::zeroed() };
    attr.attr_set = attrs;
    // SAFETY: both fds are live, the empty paths are terminated, and attr is initialized.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | rec,
            &attr,
            std::mem::size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(NucleusError::FilesystemError(format!(
            "Cannot restrict bind from {source:?}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) const READ_ONLY: u64 =
    libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn image_targets_reject_links_and_preserve_existing_file_contents() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("parent")).unwrap();
        assert!(mount_target(root.path(), Path::new("parent/new"), false).is_err());
        assert!(!outside.path().join("new").exists());
        let data = outside.path().join("fixture");
        fs::write(&data, "untouched").unwrap();
        symlink(&data, root.path().join("leaf")).unwrap();
        assert!(mount_target(root.path(), Path::new("leaf"), false).is_err());
        mount_target(outside.path(), Path::new("fixture"), false).unwrap();
        assert_eq!(fs::read(&data).unwrap(), b"untouched");
    }

    #[test]
    #[ignore = "requires a private mount namespace and CAP_SYS_ADMIN"]
    fn recursive_bind_restricts_nested_mounts() {
        use nix::mount::{mount, MsFlags};
        // Run in a fork child to avoid modifying the test runner's mount namespace.
        match unsafe { nix::unistd::fork().unwrap() } {
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0)
            ),
            nix::unistd::ForkResult::Child => {
                let result = std::panic::catch_unwind(|| {
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
                    mount(
                        None::<&str>,
                        "/",
                        None::<&str>,
                        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                        None::<&str>,
                    )
                    .unwrap();
                    let tmp = tempfile::tempdir().unwrap();
                    let nested = tmp.path().join("src/nested");
                    fs::create_dir_all(&nested).unwrap();
                    mount(
                        Some("tmpfs"),
                        &nested,
                        Some("tmpfs"),
                        MsFlags::empty(),
                        None::<&str>,
                    )
                    .unwrap();
                    let target = mount_target(tmp.path(), Path::new("target"), true).unwrap();
                    bind_tree(
                        &tmp.path().join("src"),
                        &target,
                        true,
                        READ_ONLY | libc::MOUNT_ATTR_NOEXEC,
                    )
                    .unwrap();
                    for path in ["target", "target/nested"] {
                        let flags = nix::sys::statvfs::statvfs(&tmp.path().join(path))
                            .unwrap()
                            .flags();
                        use nix::sys::statvfs::FsFlags;
                        assert!(flags.contains(
                            FsFlags::ST_RDONLY
                                | FsFlags::ST_NOSUID
                                | FsFlags::ST_NODEV
                                | FsFlags::ST_NOEXEC
                        ));
                        assert_eq!(
                            fs::write(tmp.path().join(path).join("fixture"), "text")
                                .unwrap_err()
                                .raw_os_error(),
                            Some(libc::EROFS)
                        );
                    }
                    fs::write(nested.join("source"), "writable").unwrap();
                    nix::mount::umount(tmp.path().join("target/nested").as_path()).unwrap();
                    nix::mount::umount(tmp.path().join("target").as_path()).unwrap();
                    nix::mount::umount(&nested).unwrap();
                });
                unsafe { libc::_exit(i32::from(result.is_err())) }
            }
        }
    }
}
