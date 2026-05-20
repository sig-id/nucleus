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

        // Ensure destination exists
        std::fs::create_dir_all(dest).map_err(|e| {
            NucleusError::ContextError(format!("Failed to create destination {:?}: {}", dest, e))
        })?;

        info!(
            "Bind mounting context: {:?} -> {:?} (read-only)",
            source, dest
        );

        // Initial bind mount
        nix::mount::mount(
            Some(source),
            dest,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::ContextError(format!(
                "Failed to bind mount {:?} -> {:?}: {}",
                source, dest, e
            ))
        })?;

        // Remount read-only
        nix::mount::mount(
            None::<&str>,
            dest,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_REC
                | nix::mount::MsFlags::MS_RDONLY
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::ContextError(format!("Failed to remount {:?} read-only: {}", dest, e))
        })?;

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

    #[test]
    fn test_bind_mount_context_remount_adds_hardening_flags() {
        // Verify bind_mount_context applies hardening mount flags.
        // Uses brace-matched extraction instead of scanning to EOF (SEC-MED-03).
        let source = include_str!("lazy.rs");
        let fn_start = source.find("fn bind_mount_context").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let fn_body = &after[..fn_end];
        assert!(
            fn_body.contains("MS_NOSUID"),
            "bind_mount_context must set MS_NOSUID"
        );
        assert!(
            fn_body.contains("MS_NODEV"),
            "bind_mount_context must set MS_NODEV"
        );
        assert!(
            fn_body.contains("MS_NOEXEC"),
            "bind_mount_context must set MS_NOEXEC"
        );
    }
}
