/// Integration tests for network configuration and validation
///
/// Tests the network module's configuration validation, bridge config,
/// egress policies, and port forwarding without requiring root privileges.
#[cfg(test)]
mod tests {
    use nucleus::container::{Container, ContainerConfig, TrustLevel};
    use nucleus::error::NucleusError;
    use nucleus::isolation::NamespaceConfig;
    use nucleus::network::{
        BridgeConfig, CredentialBrokerConfig, EgressPolicy, NatBackend, NetworkMode, PortForward,
        Protocol,
    };
    use std::env;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // --- BridgeConfig validation ---

    #[test]
    fn test_bridge_config_default_valid() {
        let config = BridgeConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.bridge_name, "nucleus0");
        assert_eq!(config.subnet, "10.0.42.0/24");
        assert!(config.container_ip.is_none());
        assert!(config.dns.is_empty());
        assert_eq!(config.nat_backend, NatBackend::Auto);
    }

    #[test]
    fn test_bridge_config_with_public_dns() {
        let config = BridgeConfig::default().with_public_dns();
        assert!(config.validate().is_ok());
        assert_eq!(config.dns, vec!["8.8.8.8", "8.8.4.4"]);
    }

    #[test]
    fn test_bridge_config_with_custom_dns() {
        let config =
            BridgeConfig::default().with_dns(vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]);
        assert!(config.validate().is_ok());
        assert_eq!(config.dns.len(), 2);
    }

    #[test]
    fn test_bridge_config_with_nat_backend() {
        let config = BridgeConfig::default().with_nat_backend(NatBackend::Userspace);
        assert_eq!(config.nat_backend, NatBackend::Userspace);
        assert_eq!(
            config.selected_nat_backend(true, false),
            NatBackend::Userspace
        );
        assert_eq!(
            config.selected_nat_backend(false, true),
            NatBackend::Userspace
        );
    }

    #[test]
    fn test_bridge_config_auto_nat_backend_selects_by_privilege() {
        let config = BridgeConfig::default();
        assert_eq!(config.selected_nat_backend(true, false), NatBackend::Kernel);
        assert_eq!(
            config.selected_nat_backend(true, true),
            NatBackend::Userspace
        );
        assert_eq!(
            config.selected_nat_backend(false, true),
            NatBackend::Userspace
        );
    }

    #[test]
    fn test_bridge_config_empty_name_rejected() {
        let config = BridgeConfig {
            bridge_name: String::new(),
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bridge_config_long_name_rejected() {
        let config = BridgeConfig {
            bridge_name: "a".repeat(16), // 16 chars, max is 15
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bridge_config_name_at_limit() {
        let config = BridgeConfig {
            bridge_name: "a".repeat(15), // exactly 15 chars
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_bridge_config_special_chars_in_name_rejected() {
        for bad_name in &["my bridge", "br;rm", "br$(cmd)", "br/0", "br\nnet"] {
            let config = BridgeConfig {
                bridge_name: bad_name.to_string(),
                ..BridgeConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "Bridge name '{}' should be rejected",
                bad_name
            );
        }
    }

    #[test]
    fn test_bridge_config_valid_name_chars() {
        for good_name in &["br0", "my-bridge", "net_1", "ABC123"] {
            let config = BridgeConfig {
                bridge_name: good_name.to_string(),
                ..BridgeConfig::default()
            };
            assert!(
                config.validate().is_ok(),
                "Bridge name '{}' should be valid",
                good_name
            );
        }
    }

    #[test]
    fn test_bridge_config_invalid_subnet_rejected() {
        let cases = vec![
            "not-a-cidr",
            "10.0.0.0",     // missing prefix
            "10.0.0.0/33",  // prefix too large
            "999.0.0.0/24", // invalid octet
            "10.0.0.0/abc", // non-numeric prefix
            "-1.0.0.0/24",  // negative octet
            "10.0.0/24",    // only 3 octets
        ];
        for subnet in cases {
            let config = BridgeConfig {
                subnet: subnet.to_string(),
                ..BridgeConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "Subnet '{}' should be rejected",
                subnet
            );
        }
    }

    #[test]
    fn test_bridge_config_valid_subnets() {
        for subnet in &["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12", "0.0.0.0/0"] {
            let config = BridgeConfig {
                subnet: subnet.to_string(),
                ..BridgeConfig::default()
            };
            assert!(
                config.validate().is_ok(),
                "Subnet '{}' should be valid",
                subnet
            );
        }
    }

    #[test]
    fn test_bridge_config_gateway_and_subnet_membership() {
        let config = BridgeConfig {
            subnet: "10.0.42.0/24".to_string(),
            ..BridgeConfig::default()
        };

        assert_eq!(config.gateway_ipv4().unwrap().to_string(), "10.0.42.1");
        assert!(config.contains_ipv4("10.0.42.1".parse().unwrap()).unwrap());
        assert!(config
            .contains_ipv4("10.0.42.254".parse().unwrap())
            .unwrap());
        assert!(!config.contains_ipv4("8.8.8.8".parse().unwrap()).unwrap());
    }

    #[test]
    fn test_bridge_config_invalid_container_ip() {
        let config = BridgeConfig {
            container_ip: Some("not-an-ip".to_string()),
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bridge_config_invalid_dns_rejected() {
        let config = BridgeConfig {
            dns: vec!["8.8.8.8".to_string(), "badip".to_string()],
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_err());
    }

    // --- PortForward ---

    #[test]
    fn test_port_forward_tcp_default() {
        let pf = PortForward::parse("8080:80").unwrap();
        assert_eq!(pf.host_port, 8080);
        assert_eq!(pf.container_port, 80);
        assert_eq!(pf.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_port_forward_explicit_tcp() {
        let pf = PortForward::parse("3000:3000/tcp").unwrap();
        assert_eq!(pf.host_port, 3000);
        assert_eq!(pf.container_port, 3000);
        assert_eq!(pf.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_port_forward_udp() {
        let pf = PortForward::parse("5353:53/udp").unwrap();
        assert_eq!(pf.host_port, 5353);
        assert_eq!(pf.container_port, 53);
        assert_eq!(pf.protocol, Protocol::Udp);
    }

    #[test]
    fn test_port_forward_invalid_protocol() {
        assert!(PortForward::parse("8080:80/sctp").is_err());
    }

    #[test]
    fn test_port_forward_missing_container_port() {
        assert!(PortForward::parse("8080").is_err());
    }

    #[test]
    fn test_port_forward_non_numeric() {
        assert!(PortForward::parse("http:80").is_err());
        assert!(PortForward::parse("8080:http").is_err());
    }

    #[test]
    fn test_port_forward_overflow() {
        assert!(PortForward::parse("99999:80").is_err());
    }

    // --- EgressPolicy ---

    #[test]
    fn test_egress_deny_all_defaults() {
        let policy = EgressPolicy::deny_all();
        assert!(policy.allowed_cidrs.is_empty());
        assert!(policy.allowed_domains.is_empty());
        assert!(policy.allowed_tcp_ports.is_empty());
        assert!(policy.allowed_udp_ports.is_empty());
        assert!(policy.log_denied);
        assert!(!policy.allow_dns);
    }

    #[test]
    fn test_egress_default_allows_dns_for_allowlists() {
        let policy = EgressPolicy::default();
        assert!(policy.allowed_cidrs.is_empty());
        assert!(policy.allowed_domains.is_empty());
        assert!(policy.allowed_tcp_ports.is_empty());
        assert!(policy.allowed_udp_ports.is_empty());
        assert!(policy.log_denied);
        assert!(policy.allow_dns);
    }

    #[test]
    fn test_egress_policy_builder() {
        let policy = EgressPolicy::default()
            .with_allowed_cidrs(vec!["10.0.0.0/8".to_string()])
            .with_allowed_domains(vec!["api.example.com".to_string()])
            .with_allowed_tcp_ports(vec![443, 80])
            .with_allowed_udp_ports(vec![53]);

        assert_eq!(policy.allowed_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(policy.allowed_domains, vec!["api.example.com"]);
        assert_eq!(policy.allowed_tcp_ports, vec![443, 80]);
        assert_eq!(policy.allowed_udp_ports, vec![53]);
    }

    #[test]
    fn test_credential_broker_endpoint_validation() {
        let broker = CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        assert_eq!(broker.broker_cidr(), "10.0.42.1/32");
        assert_eq!(broker.proxy_url(), "http://10.0.42.1:8080");

        assert!(CredentialBrokerConfig::parse_endpoint("api.example.com:8080").is_err());
        assert!(CredentialBrokerConfig::parse_endpoint("127.0.0.1:8080").is_err());
        assert!(CredentialBrokerConfig::parse_endpoint("0.0.0.0:8080").is_err());
        assert!(CredentialBrokerConfig::parse_endpoint("10.0.42.1:0").is_err());
    }

    #[test]
    fn test_credential_broker_policy_denies_dns_and_allows_only_broker() {
        let broker = CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let policy = broker.egress_policy();

        assert_eq!(policy.allowed_cidrs, vec!["10.0.42.1/32"]);
        assert!(policy.allowed_domains.is_empty());
        assert_eq!(policy.allowed_tcp_ports, vec![8080]);
        assert!(policy.allowed_udp_ports.is_empty());
        assert!(!policy.allow_dns);
        assert!(policy.is_credential_broker_only(&broker));
    }

    #[test]
    #[ignore = "set NUCLEUS_RUN_PRIVILEGED_E2E=1; requires root, kernel bridge networking, iptables, bash, and coreutils timeout"]
    fn test_credential_broker_e2e_allows_only_broker_endpoint() {
        if env::var_os("NUCLEUS_RUN_PRIVILEGED_E2E").is_none() {
            eprintln!("set NUCLEUS_RUN_PRIVILEGED_E2E=1 to run privileged broker e2e");
            return;
        }

        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let broker = CredentialBrokerConfig::parse_endpoint(&format!("10.0.42.1:{port}")).unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nbroker-ok")
                .unwrap();
        });

        let script = format!(
            "exec 3<>/dev/tcp/10.0.42.1/{port}; \
             printf 'GET / HTTP/1.0\\r\\n\\r\\n' >&3; \
             grep -q broker-ok <&3; \
             if timeout 1 bash -c 'exec 4<>/dev/tcp/1.1.1.1/80' 2>/dev/null; then exit 1; fi"
        );
        let config = ContainerConfig::try_new(
            Some("broker-e2e".to_string()),
            vec!["/bin/bash".to_string(), "-ceu".to_string(), script],
        )
        .unwrap()
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Trusted)
        .with_namespaces(NamespaceConfig::all())
        .with_network(NetworkMode::Bridge(
            BridgeConfig::default().with_nat_backend(NatBackend::Kernel),
        ))
        .with_credential_broker(broker.clone())
        .with_egress_policy(broker.egress_policy());

        let exit = Container::new(config).run().unwrap();
        assert_eq!(exit, 0);
        server.join().unwrap();
    }

    // --- CIDR validation ---

    #[test]
    fn test_validate_egress_cidr_valid() {
        assert!(nucleus::network::validate_egress_cidr("10.0.0.0/8").is_ok());
        assert!(nucleus::network::validate_egress_cidr("192.168.0.0/16").is_ok());
    }

    #[test]
    fn test_validate_egress_cidr_invalid() {
        assert!(nucleus::network::validate_egress_cidr("not-cidr").is_err());
        assert!(nucleus::network::validate_egress_cidr("10.0.0.0").is_err());
    }

    #[test]
    fn test_validate_egress_domain_valid() {
        assert!(nucleus::network::validate_egress_domain("api.example.com").is_ok());
        assert!(nucleus::network::validate_egress_domain("api.example.com.").is_ok());
        assert!(nucleus::network::validate_egress_domain("xn--bcher-kva.example").is_ok());
    }

    #[test]
    fn test_validate_egress_domain_invalid() {
        assert!(nucleus::network::validate_egress_domain("").is_err());
        assert!(nucleus::network::validate_egress_domain("localhost").is_err());
        assert!(nucleus::network::validate_egress_domain("*.example.com").is_err());
        assert!(nucleus::network::validate_egress_domain("-api.example.com").is_err());
        assert!(nucleus::network::validate_egress_domain("api.example.com:443").is_err());
        assert!(nucleus::network::validate_egress_domain("192.0.2.1").is_err());
    }

    // --- NetworkMode with ContainerConfig ---

    #[test]
    fn test_container_default_network_is_none() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(matches!(config.network, NetworkMode::None));
    }

    #[test]
    fn test_container_with_bridge_network() {
        let bridge = BridgeConfig::default().with_public_dns();
        let config =
            ContainerConfig::try_new(Some("test-bridge".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_network(NetworkMode::Bridge(bridge));

        assert!(matches!(config.network, NetworkMode::Bridge(_)));
    }

    #[test]
    fn test_container_with_egress_policy() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_egress_policy(EgressPolicy::deny_all().with_allowed_tcp_ports(vec![443]));

        assert!(config.egress_policy.is_some());
        let policy = config.egress_policy.unwrap();
        assert_eq!(policy.allowed_tcp_ports, vec![443]);
    }

    #[test]
    fn test_host_network_requires_opt_in() {
        // Host network without allow_host_network should fail before startup.
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_gvisor(false)
            .with_network(NetworkMode::Host)
            .with_namespaces(NamespaceConfig::minimal());

        let container = nucleus::container::Container::new(config);
        let result = container.run();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
    }

    #[test]
    fn test_production_mode_rejects_host_network() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_service_mode(nucleus::container::ServiceMode::Production)
            .with_network(NetworkMode::Host)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake"))
            .with_limits(
                nucleus::resources::ResourceLimits::unlimited()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(1.0)
                    .unwrap(),
            );

        let err = config.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("host network"));
    }
}
