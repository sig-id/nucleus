use super::netns::Namespaces;
use super::{
    egress, BridgeConfig, BridgeNetwork, EgressPolicy, NatBackend, NetworkState, PortForward,
};
use crate::error::{NucleusError, Result, StateTransition};
use serde_json::json;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tracing::{debug, info};

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
        Self::setup_with_id_and_broker(pid, config, container_id, host_is_root, rootless, None)
    }

    pub(crate) fn setup_with_id_and_broker(
        pid: u32,
        config: &BridgeConfig,
        container_id: &str,
        host_is_root: bool,
        rootless: bool,
        broker: Option<&super::CredentialBrokerConfig>,
    ) -> Result<Self> {
        match config.selected_nat_backend(host_is_root, rootless) {
            NatBackend::Kernel => Ok(Self::Kernel(BridgeNetwork::setup_for(
                pid,
                config,
                container_id,
                broker,
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
        _rootless: bool,
    ) -> Result<()> {
        match self {
            Self::Kernel(net) => net.apply_egress_policy(pid, policy),
            Self::Userspace(net) => net.apply_egress_policy(pid, policy, _rootless),
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
    _runtime_dir: tempfile::TempDir,
    namespaces: std::sync::Arc<Namespaces>,
    firewall: egress::GuestFirewall,
    exit_signal: Option<OwnedFd>,
    child: Child,
    state: NetworkState,
}

impl UserspaceNetwork {
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

        if !rootless {
            return Err(NucleusError::NetworkError(
                "Userspace NAT requires a remapped workload user namespace".into(),
            ));
        }
        let namespaces = std::sync::Arc::new(Namespaces::open(pid, true)?);
        let runtime_dir = Self::runtime_dir(host_is_root)?;
        if host_is_root {
            nix::unistd::chown(
                runtime_dir.path(),
                namespaces.mapped_root.map(nix::unistd::Uid::from_raw),
                None,
            )
            .map_err(|e| {
                NucleusError::NetworkError(format!("assign slirp socket directory: {e}"))
            })?;
        }
        let api_socket_path = runtime_dir.path().join("api.sock");
        let slirp = BridgeNetwork::resolve_bin("slirp4netns")?;
        let (child, exit_write) = Self::spawn_slirp(
            Path::new(&slirp),
            config,
            namespaces.clone(),
            &api_socket_path,
        )?;

        let mut network = Self {
            config: config.clone(),
            guest_ip: guest_ip.to_string(),
            container_id: container_id.to_string(),
            api_socket_path,
            _runtime_dir: runtime_dir,
            namespaces,
            firewall: Default::default(),
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
        _pid: u32,
        policy: &EgressPolicy,
        _rootless: bool,
    ) -> Result<()> {
        self.firewall
            .apply(self.namespaces.clone(), &self.config, policy)
    }

    pub fn cleanup(mut self) -> Result<()> {
        self.state = self.state.transition(NetworkState::Cleaned)?;
        self.stop_child()
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
            Ok(()) if buf == *b"1" => Ok(()),
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

        self.state = NetworkState::Cleaned;
        debug!(
            "Userspace NAT cleaned up (best-effort via drop) for container {}",
            self.container_id
        );
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

    fn spawn_slirp(
        slirp_bin: &Path,
        config: &BridgeConfig,
        ns: std::sync::Arc<Namespaces>,
        api_socket_path: &Path,
    ) -> Result<(Child, OwnedFd)> {
        let (ready_read, ready_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let (exit_read, exit_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let inherited = [
            ready_write.as_raw_fd(),
            exit_read.as_raw_fd(),
            ns.net.as_raw_fd(),
        ];
        let mut command = Command::new(slirp_bin);
        command.env_clear().args([
            "--configure",
            "--enable-sandbox",
            "--enable-seccomp",
            "--disable-host-loopback",
            "--disable-dns",
            "--netns-type=path",
            "--cidr",
            &config.subnet,
            "--ready-fd",
            &inherited[0].to_string(),
            "--exit-fd",
            &inherited[1].to_string(),
        ]);
        if !config.port_forwards.is_empty() {
            command.arg("--api-socket").arg(api_socket_path);
        }
        command
            .arg(format!("/proc/self/fd/{}", inherited[2]))
            .arg(SLIRP_TAP_NAME);
        // Enter the remapped user namespace before exec, including when the
        // launcher is host root. Keep these three descriptors only in this child.
        unsafe {
            command.pre_exec(move || {
                ns.enter_user()?;
                for fd in inherited {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|e| NucleusError::NetworkError(format!("spawn confined slirp4netns: {e}")))?;
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

    fn runtime_dir(root: bool) -> Result<tempfile::TempDir> {
        let base = if root {
            PathBuf::from("/run")
        } else {
            dirs::runtime_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
        };
        let meta = std::fs::symlink_metadata(&base)?;
        let euid = nix::unistd::Uid::effective().as_raw();
        let private = meta.uid() == euid && meta.mode() & 0o022 == 0;
        let sticky_tmp =
            base == Path::new("/tmp") && meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0;
        if !base.is_absolute()
            || base.canonicalize()? != base
            || !meta.is_dir()
            || !(private || sticky_tmp)
        {
            return Err(NucleusError::NetworkError(format!(
                "Untrusted slirp runtime directory {base:?}"
            )));
        }
        for parent in base.ancestors().skip(1) {
            let meta = std::fs::symlink_metadata(parent)?;
            let sticky =
                parent == Path::new("/tmp") && meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0;
            if !meta.is_dir()
                || (meta.uid() != 0 && meta.uid() != euid)
                || (meta.mode() & 0o022 != 0 && !sticky)
            {
                return Err(NucleusError::NetworkError(format!(
                    "Untrusted slirp runtime parent {parent:?}"
                )));
            }
        }
        use std::os::unix::fs::PermissionsExt;
        Ok(tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .prefix("nx-slirp-")
            .tempdir_in(base)?)
    }

    fn guest_ip_from_subnet(subnet: &str) -> Result<String> {
        Self::offset_ip_from_subnet(subnet, 100).map(|ip| ip.to_string())
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
    fn root_without_user_namespace_cannot_start_slirp() {
        assert!(UserspaceNetwork::setup_with_id(
            std::process::id(),
            &BridgeConfig::default(),
            "test",
            true,
            false
        )
        .err()
        .unwrap()
        .to_string()
        .contains("remapped workload user namespace"));
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
