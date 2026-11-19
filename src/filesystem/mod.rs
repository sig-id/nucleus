mod attestation;
mod context;
mod gpu;
mod lazy;
mod mount;
mod state;
mod target;
mod tmpfs;
mod trusted_dir;
pub(crate) use target::*;
pub(crate) use trusted_dir::{owner_unmapped, trusted_directory};
mod workspace;

/// Open `name` below `dir` as an `O_PATH` pin, refusing to follow a symlink
/// at the final component.
///
/// The returned descriptor refers to exactly the inode that existed at open
/// time, so a concurrent writer that swaps the name afterwards cannot
/// redirect the caller: every later access goes through the pin (re-opened
/// via `/proc/self/fd/N`) instead of the mutable name. Check-then-use by
/// path is what workspace and context copies must never do against a
/// directory another uid can write.
pub(crate) fn pinned_child(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> crate::error::Result<std::os::fd::OwnedFd> {
    let path = std::path::PathBuf::from(std::ffi::OsString::from(name));
    nix::fcntl::openat(
        dir,
        &path,
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|e| {
        crate::error::NucleusError::FilesystemError(format!(
            "Failed to pin {:?} below pinned directory: {e}",
            name
        ))
    })
}

/// File type of a pinned descriptor, immune to name swaps after pinning.
pub(crate) fn pinned_kind(
    fd: &std::os::fd::OwnedFd,
) -> crate::error::Result<nix::sys::stat::SFlag> {
    let mode = nix::sys::stat::fstat(fd)
        .map_err(|e| {
            crate::error::NucleusError::FilesystemError(format!("Failed to stat pinned entry: {e}"))
        })?
        .st_mode;
    Ok(nix::sys::stat::SFlag::from_bits_truncate(mode))
}

pub use attestation::*;
pub use context::*;
pub use gpu::*;
pub use lazy::*;
pub use mount::*;
pub use state::*;
pub use tmpfs::*;
pub use workspace::*;
