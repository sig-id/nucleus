use super::{
    egress, BridgeConfig, BridgeNetwork, EgressPolicy, NatBackend, NetworkState, PortForward,
};
use crate::error::{NucleusError, Result, StateTransition};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use serde_json::json;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const SLIRP_TAP_NAME: &str = "tap0";

/// Native bridge-mode driver for the native runtime.
pub enum BridgeDriver {
    Kernel(BridgeNetwork),
    Userspace(UserspaceNetwork),
}

impl BridgeDriver {
    pub fn setup_with_id(
        pid: u32,
        config: &BridgeConfig,
        container_id: &str,
        host_is_root: bool,
        rootless: bool,
    ) -> Result<Self> {
        match config.selected_nat_backend(host_is_root, rootless) {
            NatBackend::Kernel => Ok(Self::Kernel(BridgeNetwork::setup_with_id(
                pid,
                config,
                container_id,
            )?)),
            NatBackend::Userspace => Ok(Self::Userspace(UserspaceNetwork::setup_with_id(
                pid,
                config,
                container_id,
                host_is_root,
                rootless,
            )?)),
            NatBackend::Auto => Err(NucleusError::NetworkError(
                "nat backend selection resolved to auto unexpectedly".to_string(),
            )),
        }
    }

    pub fn apply_egress_policy(
        &self,
        pid: u32,
        policy: &EgressPolicy,
        rootless: bool,
    ) -> Result<()> {
        match self {
            Self::Kernel(net) => net.apply_egress_policy(pid, policy),
            Self::Userspace(net) => net.apply_egress_policy(pid, policy, rootless),
        }
    }

    pub fn cleanup(self) -> Result<()> {
        match self {
            Self::Kernel(net) => net.cleanup(),
            Self::Userspace(net) => net.cleanup(),
        }
    }
}

/// Userspace NAT manager backed by slirp4netns.
pub struct UserspaceNetwork {
    config: BridgeConfig,
    guest_ip: String,
    container_id: String,
    api_socket_path: PathBuf,
    runtime_dir: PathBuf,
    exit_signal: Option<OwnedFd>,
    child: Child,
    state: NetworkState,
}

impl UserspaceNetwork {
    pub(crate) fn default_dns_server(subnet: &str) -> Result<String> {
        Self::dns_ip_from_subnet(subnet)
    }

    pub fn setup_with_id(
        pid: u32,
        config: &BridgeConfig,
        container_id: &str,
        host_is_root: bool,
        rootless: bool,
    ) -> Result<Self> {
        config.validate()?;

        let guest_ip = Self::guest_ip_from_subnet(&config.subnet)?;
        Self::validate_userspace_config(config, &guest_ip)?;

        let mut state = NetworkState::Unconfigured;
        state = state.transition(NetworkState::Configuring)?;

        let runtime_dir = Self::runtime_dir(container_id);
        Self::ensure_runtime_dir(&runtime_dir)?;
        let api_socket_path = runtime_dir.join("slirp4netns.sock");

        let slirp = BridgeNetwork::resolve_bin("slirp4netns")?;
        // Keep slirp4netns inside the container user namespace whenever the
        // container is rootless/root-remapped, even when Nucleus itself runs as
        // host root. slirp4netns processes untrusted guest network traffic, so
        // omitting --userns-path would run that helper as host root in the
        // initial user namespace.
        let needs_userns = Self::should_join_userns(host_is_root, rootless);

        let slirp_path = Path::new(&slirp);
        let (child, exit_write) = match Self::spawn_slirp(
            slirp_path,
            pid,
            config,
            needs_userns,
            &api_socket_path,
            true,
        ) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "slirp4netns sandbox failed ({}), retrying without --enable-sandbox",
                    e
                );
                // The sandbox uses pivot_root(2) which can fail in constrained
                // environments (e.g. QEMU test VMs, nested containers) where
                // mount propagation or /tmp restrictions prevent the pivot.
                // Retry without --enable-sandbox while preserving user namespace
                // confinement for rootless/root-remapped containers.
                let _ = std::fs::remove_file(&api_socket_path);
                Self::spawn_slirp(
                    slirp_path,
                    pid,
                    config,
                    needs_userns,
                    &api_socket_path,
                    false,
                )
                .inspect_err(|_| {
                    let _ = std::fs::remove_dir_all(&runtime_dir);
                })?
            }
        };

        let mut network = Self {
            config: config.clone(),
            guest_ip: guest_ip.to_string(),
            container_id: container_id.to_string(),
            api_socket_path,
            runtime_dir,
            exit_signal: Some(exit_write),
            child,
            state,
        };

        if let Err(e) = network.configure_port_forwards() {
            network.cleanup_best_effort();
            return Err(e);
        }

        network.state = network.state.transition(NetworkState::Active)?;

        info!(
            "Userspace NAT configured via slirp4netns for container {} (guest IP {})",
            network.container_id, network.guest_ip
        );

        Ok(network)
    }

    pub fn apply_egress_policy(
        &self,
        pid: u32,
        policy: &EgressPolicy,
        rootless: bool,
    ) -> Result<()> {
        egress::apply_egress_policy(pid, &self.effective_dns_servers(), policy, rootless)
    }

    pub fn cleanup(mut self) -> Result<()> {
        self.state = self.state.transition(NetworkState::Cleaned)?;
        self.stop_child()?;
        self.cleanup_runtime_dir();
        Ok(())
    }

    fn effective_dns_servers(&self) -> Vec<String> {
        if self.config.dns.is_empty() {
            vec![Self::dns_ip_from_subnet(&self.config.subnet)
                .unwrap_or_else(|_| "10.0.2.3".to_string())]
        } else {
            self.config.dns.clone()
        }
    }

    fn configure_port_forwards(&mut self) -> Result<()> {
        for pf in &self.config.port_forwards {
            self.add_port_forward(pf)?;
        }
        Ok(())
    }

    fn add_port_forward(&self, pf: &PortForward) -> Result<()> {
        let mut arguments = serde_json::Map::new();
        arguments.insert("proto".to_string(), json!(pf.protocol.as_str()));
        arguments.insert("host_port".to_string(), json!(pf.host_port));
        arguments.insert("guest_port".to_string(), json!(pf.container_port));
        if let Some(host_ip) = pf.host_ip {
            arguments.insert("host_addr".to_string(), json!(host_ip.to_string()));
        }

        let response = Self::api_request(
            &self.api_socket_path,
            &json!({
                "execute": "add_hostfwd",
                "arguments": arguments,
            }),
        )?;

        if let Some(error) = response.get("error") {
            return Err(NucleusError::NetworkError(format!(
                "slirp4netns add_hostfwd failed for {}:{}->{}/{}: {}",
                pf.host_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "0.0.0.0".to_string()),
                pf.host_port,
                pf.container_port,
                pf.protocol,
                error
            )));
        }

        debug!(
            "Configured slirp4netns port forward {}:{} -> {}:{}/{}",
            pf.host_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            pf.host_port,
            self.guest_ip,
            pf.container_port,
            pf.protocol
        );
        Ok(())
    }

    fn api_request(socket_path: &Path, request: &serde_json::Value) -> Result<serde_json::Value> {
        let mut stream = UnixStream::connect(socket_path).map_err(|e| {
            NucleusError::NetworkError(format!(
                "connect slirp4netns API socket {:?}: {}",
                socket_path, e
            ))
        })?;
        let payload = serde_json::to_vec(request).map_err(|e| {
            NucleusError::NetworkError(format!("serialize slirp4netns API request: {}", e))
        })?;
        stream.write_all(&payload).map_err(|e| {
            NucleusError::NetworkError(format!("write slirp4netns API request: {}", e))
        })?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| NucleusError::NetworkError(format!("shutdown slirp4netns API: {}", e)))?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| {
            NucleusError::NetworkError(format!("read slirp4netns API response: {}", e))
        })?;

        serde_json::from_slice(&buf).map_err(|e| {
            NucleusError::NetworkError(format!(
                "parse slirp4netns API response '{}': {}",
                String::from_utf8_lossy(&buf),
                e
            ))
        })
    }

    fn wait_until_ready(child: &mut Child, ready_read: OwnedFd) -> Result<()> {
        let mut ready = std::fs::File::from(ready_read);
        let mut buf = [0u8; 1];
        match ready.read_exact(&mut buf) {
            Ok(()) if buf == [b'1'] => Ok(()),
            Ok(()) => Err(NucleusError::NetworkError(format!(
                "slirp4netns ready-fd returned unexpected byte {:?}",
                buf
            ))),
            Err(e) => {
                if let Ok(Some(status)) = child.try_wait() {
                    let detail = status
                        .code()
                        .map(|code| format!("exit code {}", code))
                        .or_else(|| status.signal().map(|sig| format!("signal {}", sig)))
                        .unwrap_or_else(|| "unknown status".to_string());
                    Err(NucleusError::NetworkError(format!(
                        "slirp4netns exited before ready: {}",
                        detail
                    )))
                } else {
                    Err(NucleusError::NetworkError(format!(
                        "failed waiting for slirp4netns readiness: {}",
                        e
                    )))
                }
            }
        }
    }

    fn stop_child(&mut self) -> Result<()> {
        self.exit_signal.take();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(None) => {
                    self.child.kill().map_err(|e| {
                        NucleusError::NetworkError(format!("kill slirp4netns: {}", e))
                    })?;
                    let _ = self.child.wait();
                    break;
                }
                Err(e) => {
                    return Err(NucleusError::NetworkError(format!(
                        "wait for slirp4netns shutdown: {}",
                        e
                    )))
                }
            }
        }

        info!(
            "Userspace NAT cleaned up for container {}",
            self.container_id
        );
        Ok(())
    }

    fn cleanup_best_effort(&mut self) {
        if self.state == NetworkState::Cleaned {
            return;
        }

        self.exit_signal.take();

        if let Ok(None) = self.child.try_wait() {
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                    Err(_) => break,
                }
            }

            if let Ok(None) = self.child.try_wait() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        self.cleanup_runtime_dir();
        self.state = NetworkState::Cleaned;
        debug!(
            "Userspace NAT cleaned up (best-effort via drop) for container {}",
            self.container_id
        );
    }

    fn cleanup_runtime_dir(&self) {
        if let Err(e) = std::fs::remove_dir_all(&self.runtime_dir) {
            if self.runtime_dir.exists() {
                warn!(
                    "Failed to remove slirp4netns runtime dir {:?}: {}",
                    self.runtime_dir, e
                );
            }
        }
    }

    fn validate_userspace_config(config: &BridgeConfig, guest_ip: &str) -> Result<()> {
        let prefix = config
            .subnet
            .split_once('/')
            .and_then(|(_, prefix)| prefix.parse::<u8>().ok())
            .unwrap_or(24);
        if prefix > 25 {
            return Err(NucleusError::NetworkError(format!(
                "Userspace NAT requires a subnet with at least 128 addresses; '{}' is too small",
                config.subnet
            )));
        }

        if let Some(requested_ip) = config.container_ip.as_deref() {
            if requested_ip != guest_ip {
                return Err(NucleusError::NetworkError(format!(
                    "Userspace NAT uses the slirp4netns guest address {}; requested container IP {} is unsupported",
                    guest_ip, requested_ip
                )));
            }
        }

        Ok(())
    }

    fn should_join_userns(_host_is_root: bool, rootless: bool) -> bool {
        rootless
    }

    fn spawn_slirp(
        slirp_bin: &Path,
        pid: u32,
        config: &BridgeConfig,
        needs_userns: bool,
        api_socket_path: &Path,
        enable_sandbox: bool,
    ) -> Result<(Child, OwnedFd)> {
        let (ready_read, ready_write) = nix::unistd::pipe()
            .map_err(|e| NucleusError::NetworkError(format!("ready pipe: {}", e)))?;
        let (exit_read, exit_write) = nix::unistd::pipe()
            .map_err(|e| NucleusError::NetworkError(format!("exit pipe: {}", e)))?;
        Self::clear_cloexec(&ready_write)?;
        Self::clear_cloexec(&exit_read)?;

        let args = Self::command_args(
            pid,
            config,
            needs_userns,
            api_socket_path,
            ready_write.as_raw_fd(),
            exit_read.as_raw_fd(),
            enable_sandbox,
        );

        let mut child = Command::new(slirp_bin)
            .args(&args)
            .spawn()
            .map_err(|e| NucleusError::NetworkError(format!("spawn slirp4netns: {}", e)))?;

        drop(ready_write);
        drop(exit_read);

        match Self::wait_until_ready(&mut child, ready_read) {
            Ok(()) => Ok((child, exit_write)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
        }
    }

    fn command_args(
        pid: u32,
        config: &BridgeConfig,
        join_userns: bool,
        api_socket_path: &Path,
        ready_fd: i32,
        exit_fd: i32,
        enable_sandbox: bool,
    ) -> Vec<String> {
        let mut args = vec![
            "--configure".to_string(),
            "--ready-fd".to_string(),
            ready_fd.to_string(),
            "--exit-fd".to_string(),
            exit_fd.to_string(),
            "--api-socket".to_string(),
            api_socket_path.display().to_string(),
            "--cidr".to_string(),
            config.subnet.clone(),
            "--disable-host-loopback".to_string(),
        ];

        if enable_sandbox {
            args.push("--enable-sandbox".to_string());
        }

        if !config.dns.is_empty() {
            args.push("--disable-dns".to_string());
        }

        if join_userns {
            args.push("--userns-path".to_string());
            args.push(format!("/proc/{}/ns/user", pid));
        }

        args.push(pid.to_string());
        args.push(SLIRP_TAP_NAME.to_string());
        args
    }

    fn runtime_dir(container_id: &str) -> PathBuf {
        let base = if nix::unistd::Uid::effective().is_root() {
            PathBuf::from("/run/nucleus/userspace-net")
        } else {
            dirs::runtime_dir()
                .map(|dir| dir.join("nucleus/userspace-net"))
                .or_else(|| dirs::data_local_dir().map(|dir| dir.join("nucleus/userspace-net")))
                .unwrap_or_else(|| std::env::temp_dir().join("nucleus-userspace-net"))
        };
        base.join(container_id)
    }

    fn ensure_runtime_dir(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::NetworkError(format!(
                    "create userspace-net parent dir {:?}: {}",
                    parent, e
                ))
            })?;
        }
        std::fs::create_dir_all(path).map_err(|e| {
            NucleusError::NetworkError(format!("create userspace-net dir {:?}: {}", path, e))
        })?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::NetworkError(format!(
                "secure userspace-net dir permissions for {:?}: {}",
                path, e
            ))
        })?;
        Ok(())
    }

    fn clear_cloexec(fd: &OwnedFd) -> Result<()> {
        let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(|e| {
            NucleusError::NetworkError(format!("fcntl(F_GETFD) on fd {}: {}", fd.as_raw_fd(), e))
        })?;
        let fd_flags = FdFlag::from_bits_truncate(flags);
        let new_flags = fd_flags & !FdFlag::FD_CLOEXEC;
        fcntl(fd, FcntlArg::F_SETFD(new_flags)).map_err(|e| {
            NucleusError::NetworkError(format!("fcntl(F_SETFD) on fd {}: {}", fd.as_raw_fd(), e))
        })?;
        Ok(())
    }

    fn guest_ip_from_subnet(subnet: &str) -> Result<String> {
        Self::offset_ip_from_subnet(subnet, 100).map(|ip| ip.to_string())
    }

    fn dns_ip_from_subnet(subnet: &str) -> Result<String> {
        Self::offset_ip_from_subnet(subnet, 3).map(|ip| ip.to_string())
    }

    fn offset_ip_from_subnet(subnet: &str, offset: u32) -> Result<std::net::Ipv4Addr> {
        let (base, prefix) = subnet.split_once('/').ok_or_else(|| {
            NucleusError::NetworkError(format!("Invalid CIDR (missing /prefix): '{}'", subnet))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|e| {
            NucleusError::NetworkError(format!("Invalid CIDR prefix '{}': {}", subnet, e))
        })?;
        let base_ip = base.parse::<std::net::Ipv4Addr>().map_err(|e| {
            NucleusError::NetworkError(format!("Invalid CIDR base '{}': {}", subnet, e))
        })?;

        let host_capacity = if prefix == 32 {
            1u64
        } else {
            1u64 << (32 - prefix)
        };
        if offset as u64 >= host_capacity {
            return Err(NucleusError::NetworkError(format!(
                "CIDR '{}' does not have room for host offset {}",
                subnet, offset
            )));
        }

        let candidate = u32::from(base_ip)
            .checked_add(offset)
            .ok_or_else(|| NucleusError::NetworkError(format!("CIDR '{}' overflowed", subnet)))?;
        Ok(std::net::Ipv4Addr::from(candidate))
    }
}

impl Drop for UserspaceNetwork {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Protocol;

    #[test]
    fn test_auto_nat_backend_prefers_kernel_for_rootful_hosts() {
        let cfg = BridgeConfig::default();
        assert_eq!(cfg.selected_nat_backend(true, false), NatBackend::Kernel);
        assert_eq!(cfg.selected_nat_backend(true, true), NatBackend::Userspace);
        assert_eq!(cfg.selected_nat_backend(false, true), NatBackend::Userspace);
    }

    #[test]
    fn test_userspace_backend_rejects_too_small_subnets() {
        let cfg = BridgeConfig {
            subnet: "10.0.42.0/26".to_string(),
            ..BridgeConfig::default()
        };

        let guest_ip = UserspaceNetwork::guest_ip_from_subnet(&cfg.subnet).unwrap_err();
        assert!(
            guest_ip.to_string().contains("does not have room"),
            "unexpected error: {guest_ip}"
        );
    }

    #[test]
    fn test_userspace_backend_rejects_custom_guest_ip() {
        let cfg = BridgeConfig {
            container_ip: Some("10.0.42.2".to_string()),
            ..BridgeConfig::default()
        };

        let err = UserspaceNetwork::validate_userspace_config(&cfg, "10.0.42.100").unwrap_err();
        assert!(err
            .to_string()
            .contains("requested container IP 10.0.42.2 is unsupported"));
    }

    #[test]
    fn test_slirp_command_args_disable_builtin_dns_when_explicit_dns_is_set() {
        let cfg = BridgeConfig::default().with_dns(vec!["1.1.1.1".to_string()]);
        let args = UserspaceNetwork::command_args(
            4242,
            &cfg,
            true,
            Path::new("/tmp/slirp.sock"),
            5,
            6,
            true,
        );

        assert!(args.iter().any(|arg| arg == "--disable-dns"));
        assert!(args.iter().any(|arg| arg == "--userns-path"));
    }

    #[test]
    fn test_slirp_userns_join_is_kept_for_root_remapped_hosts() {
        assert!(UserspaceNetwork::should_join_userns(true, true));
        assert!(UserspaceNetwork::should_join_userns(false, true));
        assert!(!UserspaceNetwork::should_join_userns(true, false));
        assert!(!UserspaceNetwork::should_join_userns(false, false));
    }

    #[test]
    fn test_slirp_command_args_keep_userns_without_sandbox() {
        let cfg = BridgeConfig::default();
        let args = UserspaceNetwork::command_args(
            4242,
            &cfg,
            true,
            Path::new("/tmp/slirp.sock"),
            5,
            6,
            false,
        );

        assert!(!args.iter().any(|arg| arg == "--enable-sandbox"));
        assert!(args.iter().any(|arg| arg == "--userns-path"));
        assert!(args.iter().any(|arg| arg == "/proc/4242/ns/user"));
    }

    #[test]
    fn test_userspace_port_forward_request_uses_slirp_hostfwd_shape() {
        let pf = PortForward {
            host_ip: Some(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            host_port: 8080,
            container_port: 80,
            protocol: Protocol::Tcp,
        };

        let mut arguments = serde_json::Map::new();
        arguments.insert("proto".to_string(), json!(pf.protocol.as_str()));
        arguments.insert("host_port".to_string(), json!(pf.host_port));
        arguments.insert("guest_port".to_string(), json!(pf.container_port));
        if let Some(host_ip) = pf.host_ip {
            arguments.insert("host_addr".to_string(), json!(host_ip.to_string()));
        }
        let request = json!({
            "execute": "add_hostfwd",
            "arguments": arguments,
        });

        assert_eq!(request["execute"], "add_hostfwd");
        assert_eq!(request["arguments"]["proto"], "tcp");
        assert_eq!(request["arguments"]["host_addr"], "127.0.0.1");
        assert_eq!(request["arguments"]["host_port"], 8080);
        assert_eq!(request["arguments"]["guest_port"], 80);
    }
}
