/// Integration test for complete container lifecycle
///
/// This test verifies the complete container execution flow matching
/// NucleusVerification_IntegrationTests_ContainerLifecycleTest.tla
///
/// State transitions tested:
/// test_start -> container_created -> container_running -> container_exited -> cleanup_done
#[cfg(test)]
mod tests {
    use nucleus::container::{Container, ContainerConfig, TrustLevel};
    use nucleus::error::NucleusError;
    use nucleus::isolation::NamespaceConfig;
    use nucleus::resources::ResourceLimits;
    use nucleus::security::GVisorRuntime;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_lifecycle_echo() {
        // Create temporary context directory
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let context_path = temp_dir.path().to_path_buf();

        // Create a simple file in context
        std::fs::write(context_path.join("test.txt"), "Hello from nucleus")
            .expect("Failed to write test file");

        // Configure container with minimal resources
        let limits = ResourceLimits::unlimited()
            .with_memory("128M")
            .expect("Failed to set memory")
            .with_cpu_cores(1.0)
            .expect("Failed to set CPU");

        let config = ContainerConfig::try_new(
            Some("test-echo".to_string()),
            vec!["/bin/echo".to_string(), "hello".to_string()],
        )
        .unwrap()
        .with_context(context_path)
        .with_limits(limits)
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        // Run container
        let container = Container::new(config);
        let result = container.run();

        // Verify successful execution
        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Container should exit with code 0");
    }

    #[test]
    fn test_container_config_builder() {
        // Test the configuration builder pattern
        let config = ContainerConfig::try_new(
            Some("test".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
        )
        .unwrap()
        .with_context(PathBuf::from("/tmp/test"))
        .with_namespaces(NamespaceConfig::minimal())
        .with_gvisor(false);

        assert_eq!(config.name, "test");
        assert_eq!(config.command.len(), 3);
        assert!(config.context_dir.is_some());
        assert!(!config.use_gvisor);
    }

    #[test]
    fn test_resource_limits_configuration() {
        // Test resource limit parsing and configuration
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .expect("Failed to set memory")
            .with_cpu_cores(2.0)
            .expect("Failed to set CPU")
            .with_pids(100)
            .expect("Failed to set PIDs");

        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.cpu_quota_us, Some(200_000)); // 2.0 * 100_000
        assert_eq!(limits.pids_max, Some(100));
    }

    #[test]
    fn test_namespace_config_variations() {
        // Test different namespace configurations
        let all = NamespaceConfig::all();
        assert!(all.pid && all.mnt && all.net && all.uts && all.ipc && all.cgroup);
        assert!(!all.time);

        let minimal = NamespaceConfig::minimal();
        assert!(minimal.pid && minimal.mnt && minimal.net && minimal.cgroup);
        // M10: UTS and IPC now enabled in minimal config
        assert!(minimal.uts && minimal.ipc && !minimal.time);
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_with_device_nodes() {
        // Test that device nodes are accessible in container
        let config = ContainerConfig::try_new(
            Some("test-dev".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test -c /dev/null && test -c /dev/zero && test -c /dev/random".to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Device nodes should be accessible");
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_with_hostname() {
        // Test that hostname is set correctly in UTS namespace
        let mut namespaces = NamespaceConfig::minimal();
        namespaces.uts = true; // Enable UTS namespace

        let config = ContainerConfig::try_new(
            Some("test-hostname".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test $(hostname) = 'custom-hostname'".to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(namespaces)
        .with_hostname(Some("custom-hostname".to_string()))
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Hostname should be set correctly");
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_full_isolation() {
        // Test container with all isolation mechanisms enabled
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let context_path = temp_dir.path().to_path_buf();

        // Create test script
        std::fs::write(
            context_path.join("test.sh"),
            "#!/bin/sh\necho 'Testing full isolation'\nexit 0\n",
        )
        .expect("Failed to write test script");

        let limits = ResourceLimits::unlimited()
            .with_memory("256M")
            .expect("Failed to set memory")
            .with_cpu_cores(1.0)
            .expect("Failed to set CPU")
            .with_pids(50)
            .expect("Failed to set PIDs");

        let mut namespaces = NamespaceConfig::all();
        namespaces.uts = true;

        let config = ContainerConfig::try_new(
            Some("test-full".to_string()),
            vec!["/bin/sh".to_string(), "/context/test.sh".to_string()],
        )
        .unwrap()
        .with_context(context_path)
        .with_limits(limits)
        .with_namespaces(namespaces)
        .with_hostname(Some("nucleus-test".to_string()))
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Container should complete successfully");
    }

    #[test]
    fn test_container_with_custom_hostname() {
        // Test hostname configuration
        let config =
            ContainerConfig::try_new(Some("test".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_hostname(Some("custom-host".to_string()));

        assert_eq!(config.hostname, Some("custom-host".to_string()));
    }

    #[test]
    fn test_container_default_hostname() {
        // Test that default hostname is set to container name
        let config = ContainerConfig::try_new(
            Some("my-container".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap();

        assert_eq!(config.hostname, Some("my-container".to_string()));
    }

    #[test]
    fn test_container_rootless_config() {
        let config =
            ContainerConfig::try_new(Some("test".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_rootless();

        assert!(
            config.namespaces.user,
            "User namespace should be enabled in rootless mode"
        );
        assert_eq!(
            config.user_ns_config.is_some(),
            !nix::unistd::Uid::effective().is_root()
        );
    }

    #[test]
    fn test_gvisor_unavailable_returns_error() {
        use nucleus::security::GVisorRuntime;

        if GVisorRuntime::is_available() {
            // runsc is present on this machine; skip
            return;
        }
        let result = GVisorRuntime::new();
        assert!(
            result.is_err(),
            "GVisorRuntime::new() should fail when runsc is not available"
        );
    }

    #[test]
    fn test_resource_stats_parsing() {
        use nucleus::resources::ResourceStats;

        let temp = tempfile::TempDir::new().unwrap();
        let p = temp.path();
        std::fs::write(p.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(p.join("memory.max"), "536870912\n").unwrap();
        std::fs::write(p.join("cpu.stat"), "usage_usec 1000000\nother 0\n").unwrap();
        std::fs::write(p.join("pids.current"), "5\n").unwrap();

        let stats = ResourceStats::from_cgroup(p.to_str().unwrap()).unwrap();
        assert_eq!(stats.memory_usage, 1_048_576);
        assert_eq!(stats.memory_limit, 536_870_912);
        assert_eq!(stats.cpu_usage_ns, 1_000_000_000); // 1_000_000 µs → ns
        assert_eq!(stats.pid_count, 5);
    }

    // --- Seccomp clone-flag integration test ---

    #[test]
    #[ignore] // Requires root privileges
    fn test_seccomp_blocks_clone_newuser() {
        // Verify that seccomp denies CLONE_NEWUSER inside the container.
        // The shell script checks if `unshare -U true` succeeds:
        //   - exit 0 = seccomp correctly blocked it (or unshare not available)
        //   - exit 1 = filter is broken, unshare succeeded
        let config = ContainerConfig::try_new(
            Some("test-seccomp-clone".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "if ! command -v unshare >/dev/null 2>&1; then exit 0; fi; \
                 if unshare -U true 2>/dev/null; then exit 1; else exit 0; fi"
                    .to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(
            exit_code, 0,
            "Seccomp should deny CLONE_NEWUSER (exit 1 means filter is broken)"
        );
    }

    // --- Trust-level tests ---

    #[test]
    fn test_trust_level_default_is_untrusted() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert_eq!(config.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn test_untrusted_workload_rejects_host_network() {
        use nucleus::network::NetworkMode;

        // Untrusted + host network should be rejected before fork (ConfigError)
        let config = ContainerConfig::try_new(
            Some("test-untrusted-host".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Untrusted)
        .with_network(NetworkMode::Host)
        .with_allow_host_network(true)
        .with_namespaces(NamespaceConfig::minimal());

        let container = Container::new(config);
        let result = container.run();
        assert!(result.is_err(), "Untrusted + host network should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, NucleusError::ConfigError(_)),
            "Should be ConfigError, got: {:?}",
            err
        );
    }

    #[test]
    fn test_untrusted_workload_requires_gvisor_or_degraded() {
        if GVisorRuntime::is_available() {
            // gVisor is available: trust-level guard would auto-enable it,
            // so we can't test the rejection path. Skip.
            return;
        }

        let config = ContainerConfig::try_new(
            Some("test-untrusted-no-gvisor".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Untrusted)
        .with_namespaces(NamespaceConfig::minimal());

        let container = Container::new(config);
        let result = container.run();
        assert!(
            result.is_err(),
            "Untrusted without gVisor or degraded should fail"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, NucleusError::ConfigError(_)),
            "Should be ConfigError, got: {:?}",
            err
        );
    }
}
