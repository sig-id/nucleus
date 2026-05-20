/// Integration tests for container configuration
///
/// Tests the ContainerConfig builder, production mode validation,
/// service mode, secrets, environment, health checks, readiness probes,
/// container ID generation, and container state management.
#[cfg(test)]
mod tests {
    use nucleus::container::{
        generate_container_id, ContainerConfig, ContainerState, ContainerStateParams, HealthCheck,
        ReadinessProbe, SecretMount, ServiceMode, TrustLevel,
    };
    use nucleus::filesystem::ContextMode;
    use nucleus::isolation::NamespaceConfig;
    use nucleus::network::NetworkMode;
    use nucleus::resources::ResourceLimits;
    use nucleus::StateTransition;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Existing Nix store directory used for production-mode config validation.
    fn test_rootfs_path() -> PathBuf {
        PathBuf::from("/nix/store")
    }

    // --- Container ID generation ---

    #[test]
    fn test_container_id_is_32_hex_chars() {
        let id = generate_container_id().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_container_id_uniqueness() {
        let ids: HashSet<String> = (0..100).map(|_| generate_container_id().unwrap()).collect();
        assert_eq!(ids.len(), 100, "Generated IDs should be unique");
    }

    // --- ContainerConfig defaults ---

    #[test]
    fn test_config_defaults_are_secure() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();

        assert!(!config.allow_degraded_security);
        assert!(!config.allow_chroot_fallback);
        assert!(!config.allow_host_network);
        assert!(config.proc_readonly);
        assert_eq!(config.trust_level, TrustLevel::Untrusted);
        assert_eq!(config.service_mode, ServiceMode::Agent);
        assert!(matches!(config.network, NetworkMode::None));
        assert!(matches!(config.context_mode, ContextMode::Copy));
        assert!(config.secrets.is_empty());
        assert_eq!(config.home, PathBuf::from("/home/agent"));
        assert!(config.provider_configs.is_empty());
        assert!(config.environment.is_empty());
        assert!(!config.sd_notify);
        assert!(config.use_gvisor);
        assert!(config.rootfs_path.is_none());
        assert!(config.egress_policy.is_none());
        assert!(config.health_check.is_none());
        assert!(config.readiness_probe.is_none());
    }

    #[test]
    fn test_config_name_defaults_to_id() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert_eq!(config.name, config.id);
    }

    #[test]
    fn test_config_custom_name() {
        let config =
            ContainerConfig::try_new(Some("my-app".to_string()), vec!["/bin/sh".to_string()])
                .unwrap();
        assert_eq!(config.name, "my-app");
        assert_ne!(config.id, "my-app"); // ID is always generated
    }

    #[test]
    fn test_config_hostname_defaults_to_name() {
        let config =
            ContainerConfig::try_new(Some("myhost".to_string()), vec!["/bin/sh".to_string()])
                .unwrap();
        assert_eq!(config.hostname, Some("myhost".to_string()));
    }

    // --- Builder pattern ---

    #[test]
    fn test_config_builder_chaining() {
        let config =
            ContainerConfig::try_new(Some("test".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_context(PathBuf::from("/tmp/ctx"))
                .with_limits(
                    ResourceLimits::unlimited()
                        .with_memory("512M")
                        .unwrap()
                        .with_cpu_cores(2.0)
                        .unwrap(),
                )
                .with_namespaces(NamespaceConfig::all())
                .with_hostname(Some("custom".to_string()))
                .with_trust_level(TrustLevel::Trusted)
                .with_network(NetworkMode::Host)
                .with_allow_host_network(true)
                .with_context_mode(ContextMode::BindMount)
                .with_allow_degraded_security(true)
                .with_allow_chroot_fallback(true)
                .with_proc_readonly(false)
                .with_env("FOO".to_string(), "bar".to_string())
                .with_sd_notify(true);

        assert_eq!(config.context_dir, Some(PathBuf::from("/tmp/ctx")));
        assert_eq!(config.limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(config.hostname, Some("custom".to_string()));
        assert_eq!(config.trust_level, TrustLevel::Trusted);
        assert!(matches!(config.network, NetworkMode::Host));
        assert!(config.allow_host_network);
        assert!(matches!(config.context_mode, ContextMode::BindMount));
        assert!(config.allow_degraded_security);
        assert!(config.allow_chroot_fallback);
        assert!(!config.proc_readonly);
        assert_eq!(
            config.environment,
            vec![("FOO".to_string(), "bar".to_string())]
        );
        assert!(config.sd_notify);
    }

    #[test]
    fn test_config_rootless() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_rootless();

        assert!(config.namespaces.user);
        assert!(config.user_ns_config.is_some());
    }

    #[test]
    fn test_config_with_oci_bundle_enables_gvisor() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_oci_bundle();
        assert!(config.use_gvisor);
    }

    // --- Secrets ---

    #[test]
    fn test_config_with_secrets() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_secret(SecretMount {
                source: PathBuf::from("/run/secrets/api-key"),
                dest: PathBuf::from("/secrets/api-key"),
                mode: 0o400,
            })
            .with_secret(SecretMount {
                source: PathBuf::from("/run/secrets/db-pass"),
                dest: PathBuf::from("/secrets/db-pass"),
                mode: 0o400,
            });

        assert_eq!(config.secrets.len(), 2);
        assert_eq!(
            config.secrets[0].source,
            PathBuf::from("/run/secrets/api-key")
        );
        assert_eq!(config.secrets[1].dest, PathBuf::from("/secrets/db-pass"));
    }

    // --- Health check ---

    #[test]
    fn test_health_check_defaults() {
        let hc = HealthCheck::default();
        assert!(hc.command.is_empty());
        assert_eq!(hc.interval, Duration::from_secs(30));
        assert_eq!(hc.retries, 3);
        assert_eq!(hc.start_period, Duration::from_secs(5));
        assert_eq!(hc.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_config_with_health_check() {
        let hc = HealthCheck {
            command: vec![
                "curl".to_string(),
                "-f".to_string(),
                "http://localhost/health".to_string(),
            ],
            interval: Duration::from_secs(10),
            retries: 5,
            start_period: Duration::from_secs(30),
            timeout: Duration::from_secs(3),
        };

        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_health_check(hc);

        assert!(config.health_check.is_some());
        let hc = config.health_check.unwrap();
        assert_eq!(hc.command.len(), 3);
        assert_eq!(hc.retries, 5);
    }

    // --- Readiness probe ---

    #[test]
    fn test_config_with_readiness_probe_exec() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_readiness_probe(ReadinessProbe::Exec {
                command: vec!["pg_isready".to_string()],
            });

        assert!(config.readiness_probe.is_some());
        assert!(matches!(
            config.readiness_probe.unwrap(),
            ReadinessProbe::Exec { .. }
        ));
    }

    #[test]
    fn test_config_with_readiness_probe_tcp() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_readiness_probe(ReadinessProbe::TcpPort(8080));

        assert!(matches!(
            config.readiness_probe.unwrap(),
            ReadinessProbe::TcpPort(8080)
        ));
    }

    #[test]
    fn test_config_with_readiness_probe_sd_notify() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_readiness_probe(ReadinessProbe::SdNotify);

        assert!(matches!(
            config.readiness_probe.unwrap(),
            ReadinessProbe::SdNotify
        ));
    }

    // --- Production mode validation ---

    #[test]
    fn test_production_mode_valid_config() {
        let rootfs = test_rootfs_path();
        if !rootfs.is_dir() {
            return;
        }
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs)
            .with_verify_rootfs_attestation(true)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        assert!(config.validate_production_mode().is_ok());
    }

    #[test]
    fn test_production_mode_requires_rootfs_attestation() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("attestation"));
    }

    #[test]
    fn test_production_mode_rejects_degraded_security() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_allow_degraded_security(true)
            .with_rootfs_path(rootfs)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("degraded"));
    }

    #[test]
    fn test_production_mode_rejects_chroot_fallback() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_allow_chroot_fallback(true)
            .with_rootfs_path(rootfs)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("chroot"));
    }

    #[test]
    fn test_production_mode_rejects_host_network_flag() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_allow_host_network(true)
            .with_rootfs_path(rootfs)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        assert!(config.validate_production_mode().is_err());
    }

    #[test]
    fn test_production_mode_requires_rootfs() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_limits(
                ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("rootfs"));
    }

    #[test]
    fn test_production_mode_requires_memory_limit() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs)
            .with_limits(ResourceLimits::unlimited().with_cpu_cores(1.0).unwrap());

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("memory"));
    }

    #[test]
    fn test_production_mode_requires_cpu_limit() {
        let rootfs = test_rootfs_path();
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(rootfs)
            .with_limits(ResourceLimits::unlimited().with_memory("512M").unwrap());

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("cpus"));
    }

    #[test]
    fn test_agent_mode_skips_production_validation() {
        // Agent mode should always pass validate_production_mode
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::Agent)
            .with_allow_degraded_security(true);

        assert!(config.validate_production_mode().is_ok());
    }

    #[test]
    fn test_strict_agent_mode_does_not_require_production_rootfs() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent);

        assert!(config.validate_strict_agent_mode().is_ok());
        assert!(config.validate_production_mode().is_ok());
        assert!(config.rootfs_path.is_none());
    }

    #[test]
    fn test_strict_agent_mode_rejects_relaxed_security_flags() {
        let degraded = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_allow_degraded_security(true);
        let chroot = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_allow_chroot_fallback(true);

        assert!(degraded.validate_strict_agent_mode().is_err());
        assert!(chroot.validate_strict_agent_mode().is_err());
    }

    #[test]
    fn test_strict_agent_mode_requires_cgroup_control_but_not_memory_cpu() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent);
        let unlimited = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(ServiceMode::StrictAgent)
            .with_limits(ResourceLimits::unlimited());

        assert!(config.validate_strict_agent_mode().is_ok());
        assert!(unlimited.validate_strict_agent_mode().is_err());
    }

    // --- ContainerState ---

    #[test]
    fn test_container_state_uptime() {
        let state = ContainerState::new(ContainerStateParams {
            id: "test".to_string(),
            name: "test".to_string(),
            pid: std::process::id(),
            command: vec!["/bin/sh".to_string()],
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        // Uptime should be very small (just created)
        assert!(state.uptime() < 5);
    }

    #[test]
    fn test_container_state_serialization() {
        let state = ContainerState::new(ContainerStateParams {
            id: "abc123".to_string(),
            name: "myapp".to_string(),
            pid: 12345,
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string(),
            ],
            memory_limit: Some(512 * 1024 * 1024),
            cpu_limit: Some(2000),
            using_gvisor: true,
            rootless: false,
            cgroup_path: Some("/sys/fs/cgroup/nucleus-abc123".to_string()),
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        });

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ContainerState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "abc123");
        assert_eq!(deserialized.name, "myapp");
        assert_eq!(deserialized.pid, 12345);
        assert_eq!(deserialized.command.len(), 3);
        assert_eq!(deserialized.memory_limit, Some(512 * 1024 * 1024));
        assert!(deserialized.using_gvisor);
        assert!(!deserialized.rootless);
    }

    // --- Namespace config ---

    #[test]
    fn test_namespace_all() {
        let ns = NamespaceConfig::all();
        assert!(ns.pid && ns.mnt && ns.net && ns.uts && ns.ipc && ns.cgroup);
        assert!(!ns.user); // user not included in all()
        assert!(!ns.time);
    }

    #[test]
    fn test_namespace_minimal() {
        let ns = NamespaceConfig::minimal();
        assert!(ns.pid && ns.mnt && ns.net && ns.cgroup);
        // M10: UTS and IPC are now enabled in minimal config for security
        assert!(ns.uts && ns.ipc);
        assert!(!ns.user && !ns.time);
    }

    // --- Network state machine ---

    #[test]
    fn test_network_state_happy_path() {
        use nucleus::network::NetworkState;

        let state = NetworkState::Unconfigured;
        let state = state.transition(NetworkState::Configuring).unwrap();
        let state = state.transition(NetworkState::Active).unwrap();
        let state = state.transition(NetworkState::Cleaned).unwrap();
        assert!(state.is_terminal());
    }

    #[test]
    fn test_network_state_cannot_skip() {
        use nucleus::network::NetworkState;

        assert!(NetworkState::Unconfigured
            .transition(NetworkState::Active)
            .is_err());
        assert!(NetworkState::Unconfigured
            .transition(NetworkState::Cleaned)
            .is_err());
    }

    #[test]
    fn test_network_state_cannot_go_backwards() {
        use nucleus::network::NetworkState;

        assert!(NetworkState::Active
            .transition(NetworkState::Configuring)
            .is_err());
        assert!(NetworkState::Cleaned
            .transition(NetworkState::Active)
            .is_err());
    }

    // --- Checkpoint state machine ---

    #[test]
    fn test_checkpoint_state_dump_path() {
        use nucleus::checkpoint::CheckpointState;

        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Dumping));
        assert!(CheckpointState::Dumping.can_transition_to(&CheckpointState::Dumped));
        assert!(!CheckpointState::Dumped.can_transition_to(&CheckpointState::Restoring));
    }

    #[test]
    fn test_checkpoint_state_restore_path() {
        use nucleus::checkpoint::CheckpointState;

        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Restoring));
        assert!(CheckpointState::Restoring.can_transition_to(&CheckpointState::Restored));
        assert!(!CheckpointState::Restored.can_transition_to(&CheckpointState::Dumping));
    }

    #[test]
    fn test_checkpoint_state_invalid_transitions() {
        use nucleus::checkpoint::CheckpointState;

        assert!(!CheckpointState::Dumping.can_transition_to(&CheckpointState::Restoring));
        assert!(!CheckpointState::Restored.can_transition_to(&CheckpointState::None));
        assert!(!CheckpointState::Dumped.can_transition_to(&CheckpointState::None));
    }
}
