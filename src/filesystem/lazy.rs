use crate::error::{NucleusError, Result};
use crate::filesystem::ContextPopulator;
use std::path::Path;
use tracing::info;

/// Context population mode
#[derive(Debug, Clone, Default, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum ContextMode {
    /// Traditional copy (default, backward compatible)
    #[default]
    #[serde(rename = "copy")]
    Copy,
    /// Bind mount for zero-copy, instant access
    #[value(name = "bind")]
    #[serde(rename = "bind", alias = "bind-mount")]
    BindMount,
}

/// Lazy context populator that supports both copy and bind mount modes
pub struct LazyContextPopulator;

impl LazyContextPopulator {
    /// Populate context using the specified mode
    ///
    /// For BindMount mode, the bind mount must happen before pivot_root
    /// since the source is on the host filesystem.
    pub fn populate(mode: &ContextMode, source: &Path, dest: &Path) -> Result<()> {
        match mode {
            ContextMode::Copy => {
                let populator = ContextPopulator::new(source, dest);
                populator.populate()
            }
            ContextMode::BindMount => Self::bind_mount_context(source, dest),
        }
    }

    /// Bind mount source directory to destination (read-only)
    fn bind_mount_context(source: &Path, dest: &Path) -> Result<()> {
        ContextPopulator::new(source, dest).validate_source_tree()?;

        info!(
            "Bind mounting context: {:?} -> {:?} (read-only)",
            source, dest
        );

        let parent = dest
            .parent()
            .ok_or_else(|| NucleusError::ContextError("Missing context parent".into()))?;
        let target = super::mount_target(
            parent,
            Path::new(
                dest.file_name()
                    .ok_or_else(|| NucleusError::ContextError("Missing context name".into()))?,
            ),
            true,
        )?;
        super::bind_tree(
            source,
            &target,
            true,
            super::READ_ONLY | libc::MOUNT_ATTR_NOEXEC,
        )?;
        info!("Context bind mounted successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use tempfile::TempDir;

    #[test]
    fn test_context_mode_default() {
        let mode = ContextMode::Copy;
        assert!(matches!(mode, ContextMode::Copy));
    }

    #[test]
    fn test_bind_mount_nonexistent_source() {
        let result = LazyContextPopulator::bind_mount_context(
            Path::new("/nonexistent/path"),
            Path::new("/tmp/dest"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_bind_mount_context_rejects_special_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let dst = temp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();

        let fifo_path = src.join("agent.fifo");
        mkfifo(&fifo_path, Mode::from_bits_truncate(0o600)).unwrap();

        let err = LazyContextPopulator::bind_mount_context(&src, &dst).unwrap_err();
        assert!(
            err.to_string().contains("special file"),
            "bind-mounted contexts must reject host special files"
        );
    }
}
