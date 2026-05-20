/// Integration tests for security modules
///
/// Tests OCI config generation, OCI bundle creation/cleanup,
/// security state machine, and gVisor availability checks.
#[cfg(test)]
mod tests {
    use nucleus::resources::ResourceLimits;
    use nucleus::security::{GVisorRuntime, OciBundle, OciConfig, SecurityState};
    use nucleus::StateTransition;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    // --- OCI Config ---

    #[test]
    fn test_oci_config_defaults() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()));
        assert_eq!(config.oci_version, "1.0.2");
        assert_eq!(config.root.path, "rootfs");
        assert!(config.root.readonly);
        assert_eq!(config.process.args, vec!["/bin/sh"]);
        assert_eq!(config.hostname, Some("test".to_string()));
        assert!(config.process.no_new_privileges);
        assert_eq!(config.process.cwd, "/workspace");
    }

    #[test]
    fn test_oci_config_can_disable_no_new_privileges() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()))
            .with_no_new_privileges(false);
        assert!(!config.process.no_new_privileges);
    }

    #[test]
    fn test_oci_config_no_hostname() {
        let config = OciConfig::new(vec!["/bin/echo".to_string(), "hi".to_string()], None);
        assert!(config.hostname.is_none());
        assert_eq!(config.process.args.len(), 2);
    }

    #[test]
    fn test_oci_config_capabilities_empty_by_default() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let caps = config.process.capabilities.unwrap();
        assert!(caps.bounding.is_empty());
        assert!(caps.effective.is_empty());
        assert!(caps.inheritable.is_empty());
        assert!(caps.permitted.is_empty());
        assert!(caps.ambient.is_empty());
    }

    #[test]
    fn test_oci_config_default_mounts() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let mount_dests: Vec<&str> = config
            .mounts
            .iter()
            .map(|m| m.destination.as_str())
            .collect();
        assert!(mount_dests.contains(&"/proc"));
        assert!(mount_dests.contains(&"/dev"));
        assert!(mount_dests.contains(&"/tmp"));
        assert!(mount_dests.contains(&"/home/agent"));
        assert!(mount_dests.contains(&"/sys"));
    }

    #[test]
    fn test_oci_config_default_namespaces() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let linux = config.linux.unwrap();
        let namespaces = linux.namespaces.unwrap();
        let ns_types: Vec<&str> = namespaces
            .iter()
            .map(|n| n.namespace_type.as_str())
            .collect();
        assert!(ns_types.contains(&"pid"));
        assert!(ns_types.contains(&"network"));
        assert!(ns_types.contains(&"ipc"));
        assert!(ns_types.contains(&"uts"));
        assert!(ns_types.contains(&"mount"));
        assert!(!ns_types.contains(&"user")); // not by default
    }

    #[test]
    fn test_oci_config_masked_paths() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let linux = config.linux.unwrap();
        assert!(linux.masked_paths.contains(&"/proc/kcore".to_string()));
        assert!(linux.masked_paths.contains(&"/proc/keys".to_string()));
        assert!(linux.masked_paths.contains(&"/sys/firmware".to_string()));
    }

    #[test]
    fn test_oci_config_readonly_paths() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let linux = config.linux.unwrap();
        assert!(linux.readonly_paths.contains(&"/proc/sys".to_string()));
        // M14: sysrq-trigger moved from readonly to masked (null-masked)
        assert!(linux
            .masked_paths
            .contains(&"/proc/sysrq-trigger".to_string()));
        assert!(!linux
            .readonly_paths
            .contains(&"/proc/sysrq-trigger".to_string()));
    }

    #[test]
    fn test_oci_config_with_resources() {
        let limits = ResourceLimits::unlimited()
            .with_memory("256M")
            .unwrap()
            .with_cpu_cores(1.5)
            .unwrap()
            .with_pids(100)
            .unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_resources(&limits);
        let resources = config.linux.unwrap().resources.unwrap();

        assert_eq!(resources.memory.unwrap().limit, Some(256 * 1024 * 1024));
        assert_eq!(resources.cpu.as_ref().unwrap().quota, Some(150_000));
        assert_eq!(resources.cpu.as_ref().unwrap().period, Some(100_000));
        assert_eq!(resources.pids.unwrap().limit, 100);
    }

    #[test]
    fn test_oci_config_with_env() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_env(&[("FOO".to_string(), "bar".to_string())]);

        assert!(config.process.env.contains(&"FOO=bar".to_string()));
        // PATH should still be present
        assert!(config.process.env.iter().any(|e| e.starts_with("PATH=")));
    }

    #[test]
    fn test_oci_config_with_user_namespace() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_user_namespace();
        let linux = config.linux.unwrap();
        let namespaces = linux.namespaces.unwrap();
        let ns_types: Vec<&str> = namespaces
            .iter()
            .map(|n| n.namespace_type.as_str())
            .collect();
        assert!(ns_types.contains(&"user"));
    }

    #[test]
    fn test_oci_config_with_rootless_user_namespace_mappings() {
        use nucleus::isolation::UserNamespaceConfig;

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_rootless_user_namespace(&UserNamespaceConfig::rootless());
        let linux = config.linux.unwrap();
        let namespaces = linux.namespaces.unwrap();
        let ns_types: Vec<&str> = namespaces
            .iter()
            .map(|n| n.namespace_type.as_str())
            .collect();

        assert!(ns_types.contains(&"user"));
        assert!(!ns_types.contains(&"network"));
        assert_eq!(linux.uid_mappings.len(), 1);
        assert_eq!(linux.gid_mappings.len(), 1);
        assert_eq!(linux.uid_mappings[0].container_id, 0);
        assert_eq!(linux.uid_mappings[0].size, 1);
        assert_eq!(linux.gid_mappings[0].container_id, 0);
        assert_eq!(linux.gid_mappings[0].size, 1);
    }

    #[test]
    fn test_oci_config_with_cgroup_and_time_namespaces() {
        use nucleus::isolation::NamespaceConfig;

        let namespaces = NamespaceConfig::minimal().with_time_namespace(true);
        let config =
            OciConfig::new(vec!["/bin/sh".to_string()], None).with_namespace_config(&namespaces);
        let linux = config.linux.unwrap();
        let namespaces = linux.namespaces.unwrap();
        let ns_types: Vec<&str> = namespaces
            .iter()
            .map(|n| n.namespace_type.as_str())
            .collect();

        assert!(ns_types.contains(&"cgroup"));
        assert!(ns_types.contains(&"time"));
    }

    #[test]
    fn test_oci_config_with_host_runtime_binds() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_host_runtime_binds();
        let mount_dests: Vec<&str> = config
            .mounts
            .iter()
            .map(|m| m.destination.as_str())
            .collect();

        for path in ["/bin", "/sbin", "/usr", "/lib", "/lib64", "/nix/store"] {
            if std::path::Path::new(path).exists() {
                assert!(
                    mount_dests.contains(&path),
                    "existing host runtime path {} should be bind-mounted",
                    path
                );
            }
        }
    }

    #[test]
    fn test_oci_config_with_context_bind() {
        let temp = TempDir::new().unwrap();
        let config =
            OciConfig::new(vec!["/bin/sh".to_string()], None).with_context_bind(temp.path());
        let context_mount = config.mounts.iter().find(|m| m.destination == "/context");

        assert!(context_mount.is_some());
        let mount = context_mount.unwrap();
        assert_eq!(mount.mount_type, "bind");
        assert!(mount.options.contains(&"ro".to_string()));
    }

    #[test]
    fn test_oci_config_with_secret_mounts() {
        use nucleus::container::SecretMount;
        let secrets = vec![SecretMount {
            source: std::path::PathBuf::from("/run/secrets/db-pass"),
            dest: std::path::PathBuf::from("/secrets/db-pass"),
            mode: 0o400,
        }];

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_secret_mounts(&secrets);

        let secret_mount = config
            .mounts
            .iter()
            .find(|m| m.destination == "/secrets/db-pass");
        assert!(secret_mount.is_some());
        let m = secret_mount.unwrap();
        assert_eq!(m.mount_type, "bind");
        assert!(m.options.contains(&"ro".to_string()));
        assert!(m.options.contains(&"noexec".to_string()));
    }

    #[test]
    fn test_oci_config_with_inmemory_secret_mounts_adds_run_secrets_mount() {
        use nucleus::container::SecretMount;

        let stage_dir = TempDir::new().unwrap();
        let staged = vec![SecretMount {
            source: stage_dir.path().join("etc/tls/cert.pem"),
            dest: std::path::PathBuf::from("/etc/tls/cert.pem"),
            mode: 0o400,
        }];

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None)
            .with_inmemory_secret_mounts(stage_dir.path(), &staged)
            .unwrap();

        assert!(config
            .mounts
            .iter()
            .any(|m| m.destination == "/run/secrets"));
        assert!(config.mounts.iter().any(|m| {
            m.destination == "/etc/tls/cert.pem" && m.source.ends_with("etc/tls/cert.pem")
        }));
    }

    #[test]
    fn test_oci_config_serialization_roundtrip() {
        let config = OciConfig::new(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string(),
            ],
            Some("myhost".to_string()),
        );

        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: OciConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.oci_version, "1.0.2");
        assert_eq!(deserialized.process.args.len(), 3);
        assert_eq!(deserialized.hostname, Some("myhost".to_string()));
    }

    // --- OCI Bundle ---

    #[test]
    fn test_oci_bundle_create_and_cleanup() {
        let temp = TempDir::new().unwrap();
        let bundle_path = temp.path().join("test-bundle");

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let bundle = OciBundle::new(bundle_path.clone(), config);

        bundle.create().unwrap();

        // Verify structure
        assert!(bundle_path.exists());
        assert!(bundle_path.join("rootfs").exists());
        assert!(bundle_path.join("config.json").exists());

        // Verify permissions (0o700)
        let meta = std::fs::metadata(&bundle_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);

        let rootfs_meta = std::fs::metadata(bundle_path.join("rootfs")).unwrap();
        assert_eq!(rootfs_meta.permissions().mode() & 0o777, 0o755);

        let config_meta = std::fs::metadata(bundle_path.join("config.json")).unwrap();
        assert_eq!(config_meta.permissions().mode() & 0o777, 0o600);

        // Verify config.json is valid JSON
        let json_str = std::fs::read_to_string(bundle_path.join("config.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["ociVersion"], "1.0.2");

        // Cleanup
        bundle.cleanup().unwrap();
        assert!(!bundle_path.exists());
    }

    #[test]
    fn test_oci_bundle_rootfs_path() {
        let temp = TempDir::new().unwrap();
        let bundle_path = temp.path().join("b");
        let bundle = OciBundle::new(
            bundle_path.clone(),
            OciConfig::new(vec!["/bin/sh".to_string()], None),
        );
        assert_eq!(bundle.rootfs_path(), bundle_path.join("rootfs"));
        assert_eq!(bundle.bundle_path(), bundle_path.as_path());
    }

    #[test]
    fn test_oci_bundle_cleanup_idempotent() {
        let temp = TempDir::new().unwrap();
        let bundle_path = temp.path().join("b");
        let bundle = OciBundle::new(
            bundle_path,
            OciConfig::new(vec!["/bin/sh".to_string()], None),
        );

        // Cleanup without create should be fine
        bundle.cleanup().unwrap();
        // Double cleanup
        bundle.cleanup().unwrap();
    }

    // --- GVisor availability ---

    #[test]
    fn test_gvisor_availability_check() {
        // This test just verifies the check doesn't panic
        let available = GVisorRuntime::is_available();
        if available {
            let runtime = GVisorRuntime::new();
            assert!(runtime.is_ok());
        } else {
            let runtime = GVisorRuntime::new();
            assert!(runtime.is_err());
        }
    }

    // --- SecurityState machine ---

    #[test]
    fn test_security_state_happy_path() {
        let state = SecurityState::Privileged;
        let state = state
            .transition(SecurityState::CapabilitiesDropped)
            .unwrap();
        let state = state.transition(SecurityState::SeccompApplied).unwrap();
        let state = state.transition(SecurityState::LandlockApplied).unwrap();
        let state = state.transition(SecurityState::Locked).unwrap();
        assert!(state.is_terminal());
    }

    #[test]
    fn test_security_state_cannot_skip() {
        assert!(SecurityState::Privileged
            .transition(SecurityState::SeccompApplied)
            .is_err());
        assert!(SecurityState::Privileged
            .transition(SecurityState::Locked)
            .is_err());
        assert!(SecurityState::CapabilitiesDropped
            .transition(SecurityState::LandlockApplied)
            .is_err());
    }

    #[test]
    fn test_security_state_cannot_go_backwards() {
        assert!(SecurityState::Locked
            .transition(SecurityState::Privileged)
            .is_err());
        assert!(SecurityState::SeccompApplied
            .transition(SecurityState::CapabilitiesDropped)
            .is_err());
        assert!(SecurityState::LandlockApplied
            .transition(SecurityState::SeccompApplied)
            .is_err());
    }

    #[test]
    fn test_security_state_only_locked_is_terminal() {
        assert!(!SecurityState::Privileged.is_terminal());
        assert!(!SecurityState::CapabilitiesDropped.is_terminal());
        assert!(!SecurityState::SeccompApplied.is_terminal());
        assert!(!SecurityState::LandlockApplied.is_terminal());
        assert!(SecurityState::Locked.is_terminal());
    }
}
