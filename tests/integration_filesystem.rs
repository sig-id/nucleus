/// Integration tests for filesystem operations
///
/// Tests context population (file copying with exclusion rules),
/// context modes, tmpfs state, and filesystem state machine transitions.
#[cfg(test)]
mod tests {
    use nucleus::filesystem::{ContextMode, ContextPopulator, FilesystemState, TmpfsMount};
    use nucleus::StateTransition;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    #[ignore = "requires host root, native namespaces and mount privileges"]
    fn root_agent_bind_mount_uses_unprivileged_host_ids() {
        check_root_agent_bind_mount("native");
    }

    #[test]
    #[ignore = "requires host root, gVisor and user namespaces"]
    fn root_gvisor_bind_mount_uses_unprivileged_host_ids() {
        check_root_agent_bind_mount("gvisor");
    }

    fn check_root_agent_bind_mount(runtime: &str) {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::process::Command;

        assert!(nix::unistd::Uid::effective().is_root());
        let workspace = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        fs::set_permissions(workspace.path(), fs::Permissions::from_mode(0o1777)).unwrap();
        let private = workspace.path().join("root-owned");
        fs::write(&private, b"fixture\n").unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_nucleus"))
            .args(["create", "--root"])
            .arg(state.path())
            .args([
                "--runtime",
                runtime,
                "--trust-level",
                "trusted",
                "--network",
                "none",
                "--pids",
                "0",
                "--allow-degraded-security",
                "--workspace",
            ])
            .arg(workspace.path())
            .args([
                "--",
                "/bin/sh",
                "-ec",
                "if read -r line </workspace/root-owned; then exit 1; fi; : </dev/null; : > /workspace/created",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let created = fs::metadata(workspace.path().join("created")).unwrap();
        assert_eq!(created.uid(), created.gid());
        assert!((0x7000_0000..0x7ffe_0000).contains(&created.uid()));
        assert_eq!(created.uid() % 65_536, 0);
    }

    #[test]
    #[ignore = "requires host root, native namespaces and mount privileges"]
    fn native_procfs_exposes_status_but_refuses_descriptor_links() {
        let state = TempDir::new().unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_nucleus"))
            .args(["create", "--root"])
            .arg(state.path())
            .args([
                "--runtime",
                "native",
                "--trust-level",
                "trusted",
                "--network",
                "none",
                "--pids",
                "0",
                "--allow-degraded-security",
                "--",
                "/bin/sh",
                "-ec",
                r#"exec 3</dev/null
                   test -r "/proc/$$/status"
                   test -L "/proc/$$/fd/3"
                   test ! -r "/proc/$$/fd/3"
                   test ! -r /proc/self/fd/3
                   exec 4</bin/sh
                   if "/proc/$$/fd/4" -c true 2>/dev/null; then exit 1; fi
                   /bin/sh -ec 'test -r "/proc/$$/status" && test ! -r "/proc/$$/fd/3"'"#,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // --- ContextPopulator: file copying ---

    #[test]
    fn test_populate_copies_files() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join("hello.txt"), "world").unwrap();
        std::fs::write(src.path().join("main.rs"), "fn main() {}").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert_eq!(
            std::fs::read_to_string(dst.path().join("hello.txt")).unwrap(),
            "world"
        );
        assert_eq!(
            std::fs::read_to_string(dst.path().join("main.rs")).unwrap(),
            "fn main() {}"
        );
    }

    #[test]
    fn test_populate_copies_nested_directories() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::create_dir_all(src.path().join("a/b/c")).unwrap();
        std::fs::write(src.path().join("a/b/c/deep.txt"), "deep").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert_eq!(
            std::fs::read_to_string(dst.path().join("a/b/c/deep.txt")).unwrap(),
            "deep"
        );
    }

    #[test]
    fn test_populate_excludes_git() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::create_dir(src.path().join(".git")).unwrap();
        std::fs::write(src.path().join(".git/config"), "secret").unwrap();
        std::fs::write(src.path().join("code.rs"), "pub fn foo() {}").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert!(!dst.path().join(".git").exists());
        assert!(dst.path().join("code.rs").exists());
    }

    #[test]
    fn test_populate_excludes_sensitive_directories() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        for dir in &[".env", ".ssh", ".gnupg", ".aws", ".docker"] {
            std::fs::create_dir(src.path().join(dir)).unwrap();
            std::fs::write(src.path().join(format!("{}/secret", dir)), "sensitive").unwrap();
        }
        std::fs::write(src.path().join("safe.txt"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        for dir in &[".env", ".ssh", ".gnupg", ".aws", ".docker"] {
            assert!(!dst.path().join(dir).exists(), "{} should be excluded", dir);
        }
        assert!(dst.path().join("safe.txt").exists());
    }

    #[test]
    fn test_populate_excludes_env_variants() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join(".env.local"), "SECRET=x").unwrap();
        std::fs::write(src.path().join(".env.production"), "DB=x").unwrap();
        std::fs::write(src.path().join("config.toml"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert!(!dst.path().join(".env.local").exists());
        assert!(!dst.path().join(".env.production").exists());
        assert!(dst.path().join("config.toml").exists());
    }

    #[test]
    fn test_populate_excludes_crypto_material() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        for ext in &[".pem", ".key", ".p12", ".crt", ".pfx", ".jks"] {
            std::fs::write(src.path().join(format!("cert{}", ext)), "---").unwrap();
        }
        std::fs::write(src.path().join("app.rs"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        for ext in &[".pem", ".key", ".p12", ".crt", ".pfx", ".jks"] {
            assert!(
                !dst.path().join(format!("cert{}", ext)).exists(),
                "*{} should be excluded",
                ext
            );
        }
        assert!(dst.path().join("app.rs").exists());
    }

    #[test]
    fn test_populate_excludes_build_artifacts() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        for dir in &["target", "node_modules", "__pycache__"] {
            std::fs::create_dir(src.path().join(dir)).unwrap();
            std::fs::write(src.path().join(format!("{}/artifact", dir)), "big").unwrap();
        }
        std::fs::write(src.path().join("src.rs"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        for dir in &["target", "node_modules", "__pycache__"] {
            assert!(!dst.path().join(dir).exists(), "{} should be excluded", dir);
        }
    }

    #[test]
    fn test_populate_excludes_editor_swap_files() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join("file.swp"), "swap").unwrap();
        std::fs::write(src.path().join("file.swo"), "swap").unwrap();
        std::fs::write(src.path().join("file.rs"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert!(!dst.path().join("file.swp").exists());
        assert!(!dst.path().join("file.swo").exists());
        assert!(dst.path().join("file.rs").exists());
    }

    #[test]
    fn test_populate_excludes_secrets_by_name_pattern() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join("credentials.json"), "{}").unwrap();
        std::fs::write(src.path().join("my_secret.txt"), "shh").unwrap();
        std::fs::write(src.path().join("private_key.pem"), "---").unwrap();
        std::fs::write(src.path().join("README.md"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert!(!dst.path().join("credentials.json").exists());
        assert!(!dst.path().join("my_secret.txt").exists());
        assert!(!dst.path().join("private_key.pem").exists());
        assert!(dst.path().join("README.md").exists());
    }

    #[test]
    fn test_populate_skips_symlinks() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join("real.txt"), "content").unwrap();
        std::os::unix::fs::symlink(src.path().join("real.txt"), src.path().join("link.txt"))
            .unwrap();

        let populator = ContextPopulator::new(src.path(), dst.path());
        populator.populate().unwrap();

        assert!(dst.path().join("real.txt").exists());
        assert!(
            !dst.path().join("link.txt").exists(),
            "Symlinks should be skipped"
        );
    }

    #[test]
    fn test_populate_nonexistent_source_errors() {
        let dst = TempDir::new().unwrap();
        let populator = ContextPopulator::new("/nonexistent/path", dst.path());
        assert!(populator.populate().is_err());
    }

    #[test]
    fn test_populate_source_is_file_errors() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        let file_path = src.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let populator = ContextPopulator::new(&file_path, dst.path());
        assert!(populator.populate().is_err());
    }

    #[test]
    fn test_populate_creates_destination_if_missing() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        let nested_dst = dst.path().join("a/b/c");

        std::fs::write(src.path().join("file.txt"), "ok").unwrap();

        let populator = ContextPopulator::new(src.path(), &nested_dst);
        populator.populate().unwrap();

        assert!(nested_dst.join("file.txt").exists());
    }

    // --- ContextMode ---

    #[test]
    fn test_context_mode_copy_populates() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        std::fs::write(src.path().join("data.txt"), "hello").unwrap();

        nucleus::filesystem::LazyContextPopulator::populate(
            &ContextMode::Copy,
            src.path(),
            dst.path(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(dst.path().join("data.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_context_mode_bind_mount_nonexistent_source() {
        let dst = TempDir::new().unwrap();
        let result = nucleus::filesystem::LazyContextPopulator::populate(
            &ContextMode::BindMount,
            Path::new("/nonexistent"),
            dst.path(),
        );
        assert!(result.is_err());
    }

    // --- TmpfsMount state ---

    #[test]
    fn test_tmpfs_mount_initial_state() {
        let mount = TmpfsMount::new("/tmp/test-nucleus-tmpfs", Some(64 * 1024 * 1024));
        assert!(!mount.is_mounted());
        assert_eq!(mount.path(), Path::new("/tmp/test-nucleus-tmpfs"));
    }

    #[test]
    fn test_tmpfs_mount_no_size() {
        let mount = TmpfsMount::new("/tmp/test-nucleus-tmpfs-nosiz", None);
        assert!(!mount.is_mounted());
    }

    // --- FilesystemState machine ---

    #[test]
    fn test_filesystem_state_happy_path() {
        let state = FilesystemState::Unmounted;
        let state = state.transition(FilesystemState::Mounted).unwrap();
        let state = state.transition(FilesystemState::Populated).unwrap();
        let state = state.transition(FilesystemState::Pivoted).unwrap();
        let state = state.transition(FilesystemState::UnmountedFinal).unwrap();
        assert!(state.is_terminal());
    }

    #[test]
    fn test_filesystem_state_stuttering_steps() {
        // Each state can transition to itself (stuttering)
        assert!(FilesystemState::Unmounted
            .transition(FilesystemState::Unmounted)
            .is_ok());
        assert!(FilesystemState::Mounted
            .transition(FilesystemState::Mounted)
            .is_ok());
        assert!(FilesystemState::Populated
            .transition(FilesystemState::Populated)
            .is_ok());
        assert!(FilesystemState::Pivoted
            .transition(FilesystemState::Pivoted)
            .is_ok());
        assert!(FilesystemState::UnmountedFinal
            .transition(FilesystemState::UnmountedFinal)
            .is_ok());
    }

    #[test]
    fn test_filesystem_state_cannot_skip() {
        assert!(FilesystemState::Unmounted
            .transition(FilesystemState::Populated)
            .is_err());
        assert!(FilesystemState::Mounted
            .transition(FilesystemState::Pivoted)
            .is_err());
        assert!(FilesystemState::Unmounted
            .transition(FilesystemState::UnmountedFinal)
            .is_err());
    }

    #[test]
    fn test_filesystem_state_cannot_go_backwards() {
        assert!(FilesystemState::Pivoted
            .transition(FilesystemState::Populated)
            .is_err());
        assert!(FilesystemState::UnmountedFinal
            .transition(FilesystemState::Pivoted)
            .is_err());
    }

    #[test]
    fn test_filesystem_state_allows_cleanup_to_unmounted() {
        assert!(FilesystemState::Mounted
            .transition(FilesystemState::Unmounted)
            .is_ok());
        assert!(FilesystemState::Populated
            .transition(FilesystemState::Unmounted)
            .is_ok());
    }

    #[test]
    fn test_filesystem_only_final_is_terminal() {
        assert!(!FilesystemState::Unmounted.is_terminal());
        assert!(!FilesystemState::Mounted.is_terminal());
        assert!(!FilesystemState::Populated.is_terminal());
        assert!(!FilesystemState::Pivoted.is_terminal());
        assert!(FilesystemState::UnmountedFinal.is_terminal());
    }
}
