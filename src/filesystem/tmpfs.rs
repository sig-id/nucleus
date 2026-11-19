use crate::error::{NucleusError, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// tmpfs mount manager
pub struct TmpfsMount {
    path: PathBuf,
    size_bytes: Option<u64>,
    mounted: bool,
}

impl TmpfsMount {
    /// Create new tmpfs mount configuration
    pub fn new<P: AsRef<Path>>(path: P, size_bytes: Option<u64>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            size_bytes,
            mounted: false,
        }
    }

    /// Mount the tmpfs filesystem
    ///
    /// This implements the transition: unmounted -> mounted
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            debug!("tmpfs already mounted at {:?}, skipping", self.path);
            return Ok(());
        }

        info!("Mounting tmpfs at {:?}", self.path);

        // Create mount point if it doesn't exist
        if !self.path.exists() {
            std::fs::create_dir_all(&self.path).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create mount point {:?}: {}",
                    self.path, e
                ))
            })?;
        }

        // Build mount options
        let mut options = String::new();
        if let Some(size) = self.size_bytes {
            options = format!("size={}", size);
        }

        let options_cstr = if options.is_empty() {
            None
        } else {
            Some(options.as_str())
        };

        // Mount tmpfs with nosuid, nodev for security
        // Note: MS_NOEXEC is omitted so user binaries in /context/ can execute.
        // Execution control is provided by seccomp + capability drop + Landlock.
        let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

        mount(
            Some("tmpfs"),
            &self.path,
            Some("tmpfs"),
            flags,
            options_cstr,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to mount tmpfs at {:?}: {}",
                self.path, e
            ))
        })?;

        self.mounted = true;
        info!("Successfully mounted tmpfs at {:?}", self.path);

        Ok(())
    }

    /// Unmount the tmpfs filesystem
    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted {
            debug!("tmpfs not mounted at {:?}, skipping", self.path);
            return Ok(());
        }

        info!("Unmounting tmpfs at {:?}", self.path);

        umount2(&self.path, MntFlags::MNT_DETACH).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to unmount tmpfs at {:?}: {}",
                self.path, e
            ))
        })?;

        self.mounted = false;
        info!("Successfully unmounted tmpfs at {:?}", self.path);

        Ok(())
    }

    /// Stop owning the mount: dropping it no longer unmounts.
    ///
    /// Once the mount has become the root of a private mount namespace,
    /// it lives exactly as long as that namespace and its path no longer
    /// resolves, so there is nothing for this guard to clean up.
    pub fn release(mut self) {
        self.mounted = false;
    }

    /// Get mount path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if mounted
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }
}

impl Drop for TmpfsMount {
    fn drop(&mut self) {
        if self.mounted {
            let _ = self.unmount();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_mount_is_not_unmounted_on_drop() {
        let mut tmpfs = TmpfsMount::new(Path::new("/nonexistent/nucleus-tmpfs"), None);
        tmpfs.mounted = true;
        tmpfs.release();
    }

    #[test]
    fn test_tmpfs_mount_new() {
        let mount = TmpfsMount::new("/tmp/test", Some(1024 * 1024));
        assert!(!mount.is_mounted());
        assert_eq!(mount.path(), Path::new("/tmp/test"));
    }

    // Note: Testing actual mounting requires root privileges
    // These are tested in integration tests
}
