use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::str::FromStr;

/// Network mode for container
#[derive(Debug, Clone)]
pub enum NetworkMode {
    /// No networking (default, fully isolated)
    None,
    /// Native runtime host network namespace sharing.
    Host,
    /// gVisor hostinet mode; omits the OCI network namespace and passes
    /// `--network host` to runsc.
    GVisorHost,
    /// Bridge network with NAT
    Bridge(BridgeConfig),
}

/// NAT backend for native bridge-style networking.
///
/// `Auto` preserves the historical behavior for privileged callers while
/// enabling a userspace NAT path for rootless/native containers.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum NatBackend {
    /// Select kernel bridge + iptables when privileged, otherwise userspace NAT.
    #[value(name = "auto")]
    Auto,
    /// Require the kernel bridge/veth/iptables backend.
    #[value(name = "kernel")]
    Kernel,
    /// Require the userspace NAT backend.
    #[value(name = "userspace")]
    Userspace,
}

impl NatBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Kernel => "kernel",
            Self::Userspace => "userspace",
        }
    }
}

/// Configuration for bridge networking
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge interface name
    pub bridge_name: String,
    /// Subnet (e.g., "10.0.42.0/24")
    pub subnet: String,
    /// Container IP address (auto-assigned from subnet)
    pub container_ip: Option<String>,
    /// DNS servers
    pub dns: Vec<String>,
    /// Port forwarding rules
    pub port_forwards: Vec<PortForward>,
    /// NAT backend selection for the native runtime.
    pub nat_backend: NatBackend,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            bridge_name: "nucleus0".to_string(),
            subnet: "10.0.42.0/24".to_string(),
            container_ip: None,
            // Empty by default – production services must configure DNS explicitly.
            // Agent mode callers can use BridgeConfig::with_public_dns() for convenience.
            dns: Vec::new(),
            port_forwards: Vec::new(),
            nat_backend: NatBackend::Auto,
        }
    }
}

impl BridgeConfig {
    /// Convenience: populate with public Google DNS resolvers.
    /// Suitable for agent/sandbox workloads, NOT for production services.
    pub fn with_public_dns(mut self) -> Self {
        self.dns = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];
        self
    }

    pub fn with_dns(mut self, servers: Vec<String>) -> Self {
        self.dns = servers;
        self
    }

    pub fn with_nat_backend(mut self, backend: NatBackend) -> Self {
        self.nat_backend = backend;
        self
    }

    pub fn selected_nat_backend(&self, host_is_root: bool, rootless: bool) -> NatBackend {
        match self.nat_backend {
            NatBackend::Auto if host_is_root && !rootless => NatBackend::Kernel,
            NatBackend::Auto => NatBackend::Userspace,
            explicit => explicit,
        }
    }

    pub fn contains_ipv4(&self, ip: Ipv4Addr) -> Result<bool, String> {
        let (network, prefix) = parse_ipv4_cidr(&self.subnet)?;
        Ok(ipv4_in_cidr(ip, network, prefix))
    }

    /// Return the host-side bridge gateway address for this subnet.
    pub fn gateway_ipv4(&self) -> Result<Ipv4Addr, String> {
        let (network, prefix) = parse_ipv4_cidr(&self.subnet)?;
        let network_u32 = u32::from(network) & ipv4_mask(prefix);
        let gateway = if prefix >= 31 {
            network_u32
        } else {
            network_u32
                .checked_add(1)
                .ok_or_else(|| format!("CIDR '{}' overflowed", self.subnet))?
        };
        Ok(Ipv4Addr::from(gateway))
    }

    /// Validate all fields to prevent argument injection into ip/iptables commands.
    pub fn validate(&self) -> crate::error::Result<()> {
        // Bridge name: alphanumeric, dash, underscore; max 15 chars (Linux IFNAMSIZ)
        if self.bridge_name.is_empty() || self.bridge_name.len() > 15 {
            return Err(crate::error::NucleusError::NetworkError(format!(
                "Bridge name must be 1-15 characters, got '{}'",
                self.bridge_name
            )));
        }
        if !self
            .bridge_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(crate::error::NucleusError::NetworkError(format!(
                "Bridge name contains invalid characters (allowed: a-zA-Z0-9_-): '{}'",
                self.bridge_name
            )));
        }

        // Subnet: must be valid IPv4 CIDR
        validate_ipv4_cidr(&self.subnet).map_err(crate::error::NucleusError::NetworkError)?;

        // Container IP (if specified)
        if let Some(ref ip) = self.container_ip {
            validate_ipv4_addr(ip).map_err(crate::error::NucleusError::NetworkError)?;
        }

        // DNS servers
        for dns in &self.dns {
            validate_ipv4_addr(dns).map_err(crate::error::NucleusError::NetworkError)?;
        }

        Ok(())
    }
}

/// Validate that a string is a valid IPv4 address (no leading dashes, proper octets).
fn validate_ipv4_addr(s: &str) -> Result<(), String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("Invalid IPv4 address: '{}'", s));
    }
    for part in &parts {
        if part.is_empty() {
            return Err(format!("Invalid IPv4 address: '{}'", s));
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(format!(
                "Invalid IPv4 address: '{}' – octet '{}' has leading zero",
                s, part
            ));
        }
        match part.parse::<u8>() {
            Ok(_) => {}
            Err(_) => return Err(format!("Invalid IPv4 address: '{}'", s)),
        }
    }
    Ok(())
}

fn parse_ipv4_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR (missing /prefix): '{}'", s))?;
    validate_ipv4_addr(addr)?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IPv4 address: '{}'", addr))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("Invalid CIDR prefix: '{}'", s))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix must be 0-32, got {}", prefix));
    }
    Ok((addr, prefix))
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = ipv4_mask(prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

/// Validate that a string is a valid IPv4 CIDR (e.g., "10.0.42.0/24").
fn validate_ipv4_cidr(s: &str) -> Result<(), String> {
    parse_ipv4_cidr(s).map(|_| ())
}

/// Validate that a string is a valid IPv4 CIDR for egress rules.
pub fn validate_egress_cidr(s: &str) -> Result<(), String> {
    validate_ipv4_cidr(s)
}

/// Validate that a string is an exact DNS name for egress domain rules.
pub fn validate_egress_domain(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("Egress domain cannot be empty".to_string());
    }
    if s.parse::<Ipv4Addr>().is_ok() || s.parse::<Ipv6Addr>().is_ok() {
        return Err(format!(
            "Egress domain '{}' is an IP address; use --egress-allow with a CIDR",
            s
        ));
    }

    let domain = s.strip_suffix('.').unwrap_or(s);
    if domain.is_empty() {
        return Err("Egress domain cannot be only '.'".to_string());
    }
    if domain.len() > 253 {
        return Err(format!("Egress domain '{}' is longer than 253 bytes", s));
    }
    if !domain.contains('.') {
        return Err(format!(
            "Egress domain '{}' must be a fully-qualified name with at least one dot",
            s
        ));
    }

    for label in domain.split('.') {
        if label.is_empty() {
            return Err(format!("Egress domain '{}' contains an empty label", s));
        }
        if label.len() > 63 {
            return Err(format!(
                "Egress domain '{}' contains a label longer than 63 bytes",
                s
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "Egress domain '{}' contains a label starting or ending with '-'",
                s
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("Egress domain '{}' contains invalid characters", s));
        }
    }

    Ok(())
}

/// Egress policy for audited outbound network access.
///
/// When set, iptables OUTPUT chain rules restrict which destinations the
/// container process can connect to. Use [`EgressPolicy::deny_all`] when no
/// outbound connections, including DNS, should be permitted.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Allowed destination CIDRs (e.g., "10.0.0.0/8", "192.168.1.0/24").
    pub allowed_cidrs: Vec<String>,
    /// Allowed exact DNS names. These are resolved to IPv4 /32 rules at startup.
    pub allowed_domains: Vec<String>,
    /// Allowed destination TCP ports. Empty means all ports on allowed CIDRs.
    pub allowed_tcp_ports: Vec<u16>,
    /// Allowed destination UDP ports.
    pub allowed_udp_ports: Vec<u16>,
    /// Whether to log denied egress attempts (rate-limited).
    pub log_denied: bool,
    /// Whether to add implicit DNS (port 53 UDP/TCP) allow rules for configured
    /// resolvers. Defaults to `true` for explicit allowlist usability.
    pub allow_dns: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            allowed_domains: Vec::new(),
            allowed_tcp_ports: Vec::new(),
            allowed_udp_ports: Vec::new(),
            log_denied: true,
            allow_dns: true,
        }
    }
}

impl EgressPolicy {
    /// Create a strict deny-all egress policy, including DNS.
    pub fn deny_all() -> Self {
        Self {
            allow_dns: false,
            ..Self::default()
        }
    }

    /// Allow egress to the given CIDRs on any port.
    pub fn with_allowed_cidrs(mut self, cidrs: Vec<String>) -> Self {
        self.allowed_cidrs = cidrs;
        self
    }

    /// Allow egress to the given exact DNS names.
    pub fn with_allowed_domains(mut self, domains: Vec<String>) -> Self {
        self.allowed_domains = domains;
        self
    }

    pub fn with_allowed_tcp_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_tcp_ports = ports;
        self
    }

    pub fn with_allowed_udp_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_udp_ports = ports;
        self
    }

    /// Create a deny-by-default policy that only permits TCP egress to the
    /// configured host-side credential broker.
    pub fn credential_broker_only(broker: &CredentialBrokerConfig) -> Self {
        Self::deny_all()
            .with_allowed_cidrs(vec![broker.broker_cidr()])
            .with_allowed_tcp_ports(vec![broker.broker_port])
    }

    /// Return true when this policy permits no direct outbound route except
    /// the configured credential broker endpoint.
    pub fn is_credential_broker_only(&self, broker: &CredentialBrokerConfig) -> bool {
        self.allowed_cidrs == vec![broker.broker_cidr()]
            && self.allowed_domains.is_empty()
            && self.allowed_tcp_ports == vec![broker.broker_port]
            && self.allowed_udp_ports.is_empty()
            && !self.allow_dns
    }
}

/// Host-side credential broker endpoint for broker-only egress.
///
/// The broker process runs outside the sandbox and holds the real credential.
/// Nucleus only allows the sandbox to reach this endpoint; the broker is
/// responsible for injecting credentials, constraining upstream destinations,
/// rate limiting, and auditing authenticated requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBrokerConfig {
    /// Host-side bridge IP reachable from the container namespace.
    pub broker_ip: Ipv4Addr,
    /// TCP port where the host-side broker listens.
    pub broker_port: u16,
    /// Whether Nucleus should inject standard proxy environment variables
    /// pointing at the broker. Disable this when using a provider-specific
    /// base URL environment variable instead.
    pub inject_proxy_env: bool,
}

impl CredentialBrokerConfig {
    /// Create a credential broker config from a host-side bridge IP and port.
    pub fn new(broker_ip: Ipv4Addr, broker_port: u16) -> Self {
        Self {
            broker_ip,
            broker_port,
            inject_proxy_env: true,
        }
    }

    /// Parse an endpoint in `IPv4:PORT` form.
    pub fn parse_endpoint(endpoint: &str) -> Result<Self, String> {
        let socket = SocketAddrV4::from_str(endpoint).map_err(|_| {
            format!(
                "Invalid credential broker endpoint '{}', expected IPv4:PORT",
                endpoint
            )
        })?;
        let config = Self::new(*socket.ip(), socket.port());
        config.validate()?;
        Ok(config)
    }

    pub fn with_proxy_env(mut self, inject_proxy_env: bool) -> Self {
        self.inject_proxy_env = inject_proxy_env;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.broker_port == 0 {
            return Err("Credential broker port must be non-zero".to_string());
        }
        if self.broker_ip.is_unspecified() {
            return Err("Credential broker IP must not be 0.0.0.0".to_string());
        }
        if self.broker_ip.is_loopback() {
            return Err(
                "Credential broker IP must be reachable on the bridge, not container loopback"
                    .to_string(),
            );
        }
        if self.broker_ip.is_multicast() || self.broker_ip == Ipv4Addr::BROADCAST {
            return Err("Credential broker IP must be a unicast IPv4 address".to_string());
        }
        Ok(())
    }

    pub fn broker_cidr(&self) -> String {
        format!("{}/32", self.broker_ip)
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.broker_ip, self.broker_port)
    }

    /// Standard proxy variables for HTTP API CLIs that honor proxy settings.
    ///
    /// These values are not secrets; they only point at the broker endpoint.
    pub fn proxy_environment(&self) -> Vec<(String, String)> {
        if !self.inject_proxy_env {
            return Vec::new();
        }

        let url = self.proxy_url();
        ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]
            .into_iter()
            .map(|key| (key.to_string(), url.clone()))
            .collect()
    }

    pub fn egress_policy(&self) -> EgressPolicy {
        EgressPolicy::credential_broker_only(self)
    }
}

/// Network protocol for port forwarding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Port forwarding rule
#[derive(Debug, Clone)]
pub struct PortForward {
    /// Optional host bind IP address. When omitted, match all local addresses.
    pub host_ip: Option<Ipv4Addr>,
    /// Host port
    pub host_port: u16,
    /// Container port
    pub container_port: u16,
    /// Protocol (tcp/udp)
    pub protocol: Protocol,
}

impl PortForward {
    /// Parse a port forward spec like:
    /// - "8080:80"
    /// - "8080:80/udp"
    /// - "127.0.0.1:8080:80"
    /// - "127.0.0.1:8080:80/udp"
    pub fn parse(spec: &str) -> crate::error::Result<Self> {
        let (ports, protocol) = if let Some((p, proto)) = spec.rsplit_once('/') {
            let protocol = match proto {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => {
                    return Err(crate::error::NucleusError::ConfigError(format!(
                        "Invalid protocol '{}', must be tcp or udp",
                        proto
                    )))
                }
            };
            (p, protocol)
        } else {
            (spec, Protocol::Tcp)
        };

        let parts: Vec<&str> = ports.split(':').collect();
        let (host_ip, host_port, container_port) = match parts.as_slice() {
            [host_port, container_port] => (None, *host_port, *container_port),
            [host_ip, host_port, container_port] => {
                validate_ipv4_addr(host_ip).map_err(crate::error::NucleusError::ConfigError)?;
                let host_ip = host_ip.parse::<Ipv4Addr>().map_err(|_| {
                    crate::error::NucleusError::ConfigError(format!(
                        "Invalid host IP address: {}",
                        host_ip
                    ))
                })?;
                (Some(host_ip), *host_port, *container_port)
            }
            _ => {
                return Err(crate::error::NucleusError::ConfigError(format!(
                    "Invalid port forward format '{}', expected HOST:CONTAINER or HOST_IP:HOST:CONTAINER",
                    spec
                )))
            }
        };

        let host_port: u16 = host_port.parse().map_err(|_| {
            crate::error::NucleusError::ConfigError(format!("Invalid host port: {}", host_port))
        })?;
        let container_port: u16 = container_port.parse().map_err(|_| {
            crate::error::NucleusError::ConfigError(format!(
                "Invalid container port: {}",
                container_port
            ))
        })?;

        Ok(Self {
            host_ip,
            host_port,
            container_port,
            protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_forward_parse() {
        let pf = PortForward::parse("8080:80").unwrap();
        assert_eq!(pf.host_ip, None);
        assert_eq!(pf.host_port, 8080);
        assert_eq!(pf.container_port, 80);
        assert_eq!(pf.protocol, Protocol::Tcp);

        let pf = PortForward::parse("5353:53/udp").unwrap();
        assert_eq!(pf.host_ip, None);
        assert_eq!(pf.host_port, 5353);
        assert_eq!(pf.container_port, 53);
        assert_eq!(pf.protocol, Protocol::Udp);

        let pf = PortForward::parse("127.0.0.1:8080:80").unwrap();
        assert_eq!(pf.host_ip, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(pf.host_port, 8080);
        assert_eq!(pf.container_port, 80);
        assert_eq!(pf.protocol, Protocol::Tcp);

        let pf = PortForward::parse("10.0.0.5:5353:53/udp").unwrap();
        assert_eq!(pf.host_ip, Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(pf.host_port, 5353);
        assert_eq!(pf.container_port, 53);
        assert_eq!(pf.protocol, Protocol::Udp);
    }

    #[test]
    fn test_port_forward_parse_invalid() {
        assert!(PortForward::parse("8080").is_err());
        assert!(PortForward::parse("abc:80").is_err());
        assert!(PortForward::parse("8080:abc").is_err());
        assert!(PortForward::parse("127.0.0.1:abc:80").is_err());
        assert!(PortForward::parse("999.0.0.1:8080:80").is_err());
    }

    #[test]
    fn test_validate_ipv4_addr_rejects_leading_zeros() {
        assert!(validate_ipv4_addr("10.0.42.1").is_ok());
        assert!(validate_ipv4_addr("0.0.0.0").is_ok());
        assert!(
            validate_ipv4_addr("010.0.0.1").is_err(),
            "leading zero in first octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.01.0.1").is_err(),
            "leading zero in second octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.0.01.1").is_err(),
            "leading zero in third octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.0.0.01").is_err(),
            "leading zero in fourth octet must be rejected"
        );
    }
}
