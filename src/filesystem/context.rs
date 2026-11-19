use crate::error::{NucleusError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Context populator - copies files from source to destination
pub struct ContextPopulator {
    source: PathBuf,
    dest: PathBuf,
}

impl ContextPopulator {
    pub fn new<P: AsRef<Path>, Q: AsRef<Path>>(source: P, dest: Q) -> Self {
        Self {
            source: source.as_ref().to_path_buf(),
            dest: dest.as_ref().to_path_buf(),
        }
    }

    /// Populate the destination with files from source
    ///
    /// This implements the transition: mounted -> populated
    pub fn populate(&self) -> Result<()> {
        info!(
            "Populating context from {:?} to {:?}",
            self.source, self.dest
        );

        Self::validate_source(&self.source)?;

        // Pin the source directory: the copy below resolves every child
        // relative to this descriptor (openat + O_NOFOLLOW), never by
        // re-resolving host paths a concurrent writer can swap.
        let pinned = nix::fcntl::open(
            &self.source,
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|e| {
            NucleusError::ContextError(format!(
                "Failed to pin context source {:?}: {}",
                self.source, e
            ))
        })?;

        // Create destination if it doesn't exist
        if !self.dest.exists() {
            fs::create_dir_all(&self.dest).map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to create destination {:?}: {}",
                    self.dest, e
                ))
            })?;
        }

        // Walk source tree and copy (depth-limited to prevent stack overflow)
        Self::copy_recursive_fd(&pinned, &self.dest, 0)?;

        info!("Successfully populated context");

        Ok(())
    }

    /// Validate a source tree without copying it.
    ///
    /// Used by bind-mount mode so the host tree gets the same preflight checks
    /// as copy mode.
    pub fn validate_source_tree(&self) -> Result<()> {
        Self::validate_source(&self.source)?;
        Self::validate_dir(&self.source, 0)
    }

    /// Validate the tree under a pinned source directory.
    ///
    /// Bind mounts must validate and then mount the same inode: callers pin
    /// the source once, validate through the pin and bind the pin, so a
    /// concurrent writer cannot swap the directory between the checks and
    /// the mount.
    pub fn validate_pinned_tree(dir: &std::os::fd::OwnedFd) -> Result<()> {
        Self::validate_dir(&super::fd_path(dir), 0)
    }

    /// Validate that a source path exists and is a directory.
    fn validate_source(source: &Path) -> Result<()> {
        if !source.exists() {
            return Err(NucleusError::ContextError(format!(
                "Source directory does not exist: {:?}",
                source
            )));
        }

        if !source.is_dir() {
            return Err(NucleusError::ContextError(format!(
                "Source is not a directory: {:?}",
                source
            )));
        }

        Ok(())
    }

    /// Maximum directory recursion depth to prevent stack overflow
    const MAX_RECURSION_DEPTH: u32 = 128;

    /// Read directory entries, filtering out excluded names.
    ///
    /// Shared between `copy_recursive` and `validate_recursive` to avoid
    /// duplicating depth checks, read_dir error handling, and exclusion logic.
    fn filtered_entries(
        dir: &Path,
        depth: u32,
    ) -> Result<Vec<(PathBuf, std::ffi::OsString, fs::Metadata)>> {
        if depth > Self::MAX_RECURSION_DEPTH {
            return Err(NucleusError::ContextError(format!(
                "Maximum directory depth ({}) exceeded at {:?}",
                Self::MAX_RECURSION_DEPTH,
                dir
            )));
        }

        let entries = fs::read_dir(dir).map_err(|e| {
            NucleusError::ContextError(format!("Failed to read directory {:?}: {}", dir, e))
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                NucleusError::ContextError(format!("Failed to read entry in {:?}: {}", dir, e))
            })?;

            let file_name = entry.file_name();
            if Self::should_exclude_name(&file_name) {
                debug!("Skipping excluded file: {:?}", file_name);
                continue;
            }

            let src_path = entry.path();
            let metadata = fs::symlink_metadata(&src_path).map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to get metadata for {:?}: {}",
                    src_path, e
                ))
            })?;

            result.push((src_path, file_name, metadata));
        }

        Ok(result)
    }

    /// Recursively copy directory contents from a pinned source directory.
    ///
    /// Every child is pinned with `openat` + `O_NOFOLLOW` before use, so a
    /// concurrent writer on the host source cannot swap a name between the
    /// type check and the copy. Files are streamed from the pin into a fresh
    /// private inode and published with an atomic rename; symlinks and
    /// special files are skipped.
    fn copy_recursive_fd(src: &std::os::fd::OwnedFd, dst: &Path, depth: u32) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if depth > Self::MAX_RECURSION_DEPTH {
            return Err(NucleusError::ContextError(format!(
                "Maximum directory depth ({}) exceeded at {:?}",
                Self::MAX_RECURSION_DEPTH,
                super::fd_path(src)
            )));
        }
        for name in Self::pinned_entry_names(src, depth)? {
            let child = super::pinned_child(src, &name)?;
            let kind = super::pinned_kind(&child)?;
            let dst_path = dst.join(&name);

            if kind == nix::sys::stat::SFlag::S_IFDIR {
                fs::create_dir_all(&dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to create directory {:?}: {}",
                        dst_path, e
                    ))
                })?;
                Self::copy_recursive_fd(&child, &dst_path, depth + 1)?;
            } else if kind == nix::sys::stat::SFlag::S_IFREG {
                // Re-open the pinned inode through its procfs descriptor
                // link: resolution lands on exactly the pinned file, so no
                // O_NOFOLLOW is needed (the link itself is a symlink).
                let mut from = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(super::fd_path(&child))
                    .map_err(|e| {
                        NucleusError::ContextError(format!(
                            "Failed to open context file {:?}: {}",
                            name, e
                        ))
                    })?;
                let metadata = from
                    .metadata()
                    .map_err(|e| NucleusError::ContextError(format!("Context stat: {e}")))?;
                if !metadata.is_file() {
                    warn!("Skipping non-regular context file {:?}", name);
                    continue;
                }
                let mut file = tempfile::NamedTempFile::new_in(dst).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to create temp file in {:?}: {}",
                        dst, e
                    ))
                })?;
                std::io::copy(&mut from, &mut file)
                    .map_err(|e| NucleusError::ContextError(format!("Context copy: {e}")))?;
                file.as_file()
                    .set_permissions(fs::Permissions::from_mode(
                        metadata.permissions().mode() & 0o7777,
                    ))
                    .map_err(|e| NucleusError::ContextError(format!("Context chmod: {e}")))?;
                file.persist(&dst_path).map_err(|e| {
                    NucleusError::ContextError(format!("Context publish: {}", e.error))
                })?;
            } else if kind == nix::sys::stat::SFlag::S_IFLNK {
                // Skip symlinks entirely to prevent link-based escapes or host path leakage.
                warn!("Skipping symlink in context: {:?}", name);
            } else {
                debug!("Skipping special context file {:?}", name);
            }
        }

        Ok(())
    }

    /// Entry names of a pinned directory, excluding filtered names.
    fn pinned_entry_names(
        dir: &std::os::fd::OwnedFd,
        depth: u32,
    ) -> Result<Vec<std::ffi::OsString>> {
        if depth > Self::MAX_RECURSION_DEPTH {
            return Err(NucleusError::ContextError(format!(
                "Maximum directory depth ({}) exceeded",
                Self::MAX_RECURSION_DEPTH
            )));
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(super::fd_path(dir))
            .map_err(|e| NucleusError::ContextError(format!("Failed to read directory: {}", e)))?
        {
            let entry = entry
                .map_err(|e| NucleusError::ContextError(format!("Failed to read entry: {e}")))?;
            let name = entry.file_name();
            if Self::should_exclude_name(&name) {
                debug!("Skipping excluded file: {:?}", name);
                continue;
            }
            names.push(name);
        }
        Ok(names)
    }

    fn validate_dir(src: &Path, depth: u32) -> Result<()> {
        for (src_path, _file_name, metadata) in Self::filtered_entries(src, depth)? {
            if metadata.is_symlink() {
                return Err(NucleusError::ContextError(format!(
                    "Bind-mounted contexts may not contain symlinks: {:?}",
                    src_path
                )));
            }

            if metadata.is_dir() {
                Self::validate_dir(&src_path, depth + 1)?;
            } else if !metadata.is_file() {
                return Err(NucleusError::ContextError(format!(
                    "Bind-mounted contexts may not contain special files: {:?}",
                    src_path
                )));
            }
        }

        Ok(())
    }

    /// Check if a file should be excluded from copying
    pub(crate) fn should_exclude_name(name: &std::ffi::OsStr) -> bool {
        let name_str = name.to_string_lossy();
        let lower = name_str.to_lowercase();

        // Exact matches (case-insensitive for .git to cover .Git/.GIT variants):
        if lower == ".git" {
            return true;
        }

        // Exact matches: build artifacts, caches, sensitive directories
        if matches!(
            name_str.as_ref(),
            "target"
                | "node_modules"
                | ".DS_Store"
                | "__pycache__"
                | ".svn"
                | ".env"
                | ".ssh"
                | ".gnupg"
                | ".aws"
                | ".azure"
                | ".gcloud"
                | ".config/gcloud"
                | ".docker"
                | ".netrc"
                | ".kube"
                | ".helm"
        ) {
            return true;
        }

        // Prefix patterns: .env.* files (e.g., .env.local, .env.production)
        if name_str.starts_with(".env.") {
            return true;
        }

        // Suffix patterns: editor swap files
        if name_str.ends_with(".swp") || name_str.ends_with(".swo") {
            return true;
        }

        // Suffix patterns: crypto material
        if name_str.ends_with(".pem")
            || name_str.ends_with(".key")
            || name_str.ends_with(".p12")
            || name_str.ends_with(".crt")
            || name_str.ends_with(".pfx")
            || name_str.ends_with(".jks")
        {
            return true;
        }

        // Contains patterns (case-insensitive): secrets and credentials
        if lower.contains("credential")
            || lower.contains("secret")
            || lower.contains("private_key")
            || lower.contains("kubeconfig")
        {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_exclude_exact_matches() {
        // Original exact matches
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".git"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "target"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "node_modules"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".DS_Store"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "__pycache__"
        )));

        // New exact matches
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".svn"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".ssh"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".gnupg"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".aws"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".docker"
        )));

        // L-2: expanded exclusion list
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".azure"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".gcloud"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".netrc"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".kube"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".helm"
        )));
    }

    #[test]
    fn test_should_exclude_env_variants() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.local"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.production"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.development"
        )));
    }

    #[test]
    fn test_should_exclude_editor_swap() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "file.swp"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "file.swo"
        )));
    }

    #[test]
    fn test_should_exclude_crypto_material() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "server.pem"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "private.key"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "cert.p12"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "ca.crt"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "keystore.pfx"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "app.jks"
        )));
    }

    #[test]
    fn test_should_exclude_secrets_patterns() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "credentials.json"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "my_secret.txt"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "private_key.pem"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "AWS_CREDENTIALS"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "app-secret-config.yaml"
        )));

        // L-2: kubeconfig pattern
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "kubeconfig"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "my-kubeconfig.yaml"
        )));
    }

    #[test]
    fn test_should_not_exclude_legitimate_files() {
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("src")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("README.md")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("main.rs")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("Cargo.toml")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("my_file.rs")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("config.yaml")
        ));
    }
}
