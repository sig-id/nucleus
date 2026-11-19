use super::{egress, firewall, netlink, netns, CredentialBrokerConfig};
use crate::error::{NucleusError, Result, StateTransition};
use crate::network::config::{BridgeConfig, EgressPolicy};
use crate::network::NetworkState;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::fs::OpenOptions;
use std::net::Ipv4Addr;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// Bridge network manager
pub struct BridgeNetwork {
    config: BridgeConfig,
    lease: Lease,
    alloc_dir: PathBuf,
    ip: String,
    ns: Arc<netns::Namespaces>,
    firewall: egress::GuestFirewall,
    broker: Option<CredentialBrokerConfig>,
    state: NetworkState,
}

/// Serialize bridge creation, orphan recovery and deletion within the host netns.
fn lifecycle_lock(dir: &Path) -> Result<File> {
    BridgeNetwork::ensure_alloc_dir(dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(".bridge.lock"))?;
    lock.lock()?;
    Ok(lock)
}

#[derive(Serialize, Deserialize)]
struct Lease {
    id: String,
    bridge: String,
    veth: String,
    peer: String,
}

impl Lease {
    fn staging_bridge(&self) -> String {
        format!("nxb{}", &self.veth[3..])
    }
    fn table(&self) -> String {
        format!("nucleus_{}", self.veth)
    }
    fn path(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.lease", self.veth))
    }

    fn remove(&self, dir: &Path) -> Result<()> {
        if !self.path(dir).try_exists()? {
            return Ok(());
        }
        if netlink::link_exists(&self.veth) {
            let alias = std::fs::read_to_string(format!("/sys/class/net/{}/ifalias", self.veth))?;
            let pair_is_staged = netlink::link_exists(&self.peer)
                && std::fs::read_to_string(format!("/sys/class/net/{}/iflink", self.veth))?
                    == std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.peer))?;
            if alias.trim() != "nucleus-managed-veth"
                && !(alias.trim().is_empty() && pair_is_staged)
            {
                return Err(NucleusError::NetworkError(format!(
                    "Refusing to remove foreign link {}",
                    self.veth
                )));
            }
            netlink::del_link(&self.veth)?;
        }
        let staging = self.staging_bridge();
        if Path::new("/sys/class/net")
            .join(&staging)
            .join("bridge")
            .is_dir()
        {
            netlink::del_link(&staging)?;
        }
        let table = self.table();
        // add is idempotent. Delete both private tables in a single transaction.
        firewall::transact(None, &format!("add table ip {table}\nadd table bridge {table}\ndelete table ip {table}\ndelete table bridge {table}\n"))?;
        BridgeNetwork::release_allocated_ip_in_dir(dir, &self.id);
        let br = Path::new("/sys/class/net").join(&self.bridge);
        if br.join("bridge").exists()
            && std::fs::read_to_string(br.join("ifalias"))?.trim() == "nucleus-managed-bridge"
            && std::fs::read_dir(br.join("brif"))?.next().is_none()
        {
            netlink::del_link(&self.bridge)?;
        }
        std::fs::remove_file(self.path(dir))?;
        Ok(())
    }
}

impl BridgeNetwork {
    fn open_dev_urandom() -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/urandom")
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to open /dev/urandom: {}", e))
            })?;

        let metadata = file.metadata().map_err(|e| {
            NucleusError::NetworkError(format!("Failed to stat /dev/urandom: {}", e))
        })?;
        if !metadata.file_type().is_char_device() {
            return Err(NucleusError::NetworkError(
                "/dev/urandom is not a character device".to_string(),
            ));
        }

        Ok(file)
    }

    /// Set up bridge networking for a container
    ///
    /// Creates bridge, veth pair, assigns IPs, enables NAT.
    /// Must be called from the parent process after fork (needs host netns).
    ///
    /// State transitions: Unconfigured -> Configuring -> Active
    pub fn setup(pid: u32, config: &BridgeConfig) -> Result<Self> {
        Self::setup_with_id(pid, config, &format!("{pid:x}"))
    }

    pub fn setup_with_id(pid: u32, config: &BridgeConfig, id: &str) -> Result<Self> {
        Self::setup_for(pid, config, id, None)
    }

    pub(super) fn setup_for(
        pid: u32,
        config: &BridgeConfig,
        id: &str,
        broker: Option<&CredentialBrokerConfig>,
    ) -> Result<Self> {
        config.validate()?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NucleusError::NetworkError(
                "Invalid network allocation ID".into(),
            ));
        }
        if let Some(broker) = broker {
            broker
                .validate_for_bridge(config)
                .map_err(NucleusError::NetworkError)?;
        }
        let ns = Arc::new(netns::Namespaces::open(pid, false)?);
        let dir = Self::ip_alloc_dir()?;
        let _lock = lifecycle_lock(&dir)?;
        Self::cleanup_orphaned_rules(&dir)?;
        if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
            return Err(NucleusError::NetworkError(
                "Kernel bridge requires host-configured net.ipv4.ip_forward=1".into(),
            ));
        }
        if dir.join(format!("{id}.ip")).exists() {
            return Err(NucleusError::NetworkError(format!(
                "Network allocation {id} already exists"
            )));
        }
        let mut nonce = [0u8; 6];
        std::io::Read::read_exact(&mut Self::open_dev_urandom()?, &mut nonce)?;
        let suffix = hex::encode(nonce);
        let lease = Lease {
            id: id.into(),
            bridge: config.bridge_name.clone(),
            veth: format!("nxv{suffix}"),
            peer: format!("nxp{suffix}"),
        };
        if [&lease.veth, &lease.peer, &lease.staging_bridge()]
            .iter()
            .any(|name| netlink::link_exists(name))
        {
            return Err(NucleusError::NetworkError(
                "Generated interface name already exists".into(),
            ));
        }
        let mut record = tempfile::NamedTempFile::new_in(&dir)?;
        serde_json::to_writer(&mut record, &lease)
            .map_err(|e| NucleusError::NetworkError(e.to_string()))?;
        record
            .persist_noclobber(lease.path(&dir))
            .map_err(|e| e.error)?;
        let setup = || -> Result<String> {
            let ip =
                Self::reserve_ip_in_dir(&dir, id, &config.subnet, config.container_ip.as_deref())?;
            let gateway = config.gateway_ipv4().map_err(NucleusError::NetworkError)?;
            let (_, prefix) = super::config::parse_ipv4_cidr(&config.subnet)
                .map_err(NucleusError::NetworkError)?;
            Self::ensure_bridge_for(&lease, gateway, prefix)?;
            netlink::create_veth(&lease.veth, &lease.peer)?;
            std::fs::write(
                format!("/sys/class/net/{}/ifalias", lease.veth),
                "nucleus-managed-veth",
            )?;
            let mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", lease.peer))?;
            let rules = Self::host_rules(config, &lease, &ip, mac.trim(), broker);
            firewall::transact(None, &rules)?;
            netlink::set_link_master(&lease.veth, &lease.bridge)?;
            netlink::set_link_netns(&lease.peer, &ns.net)?;
            netlink::set_link_up(&lease.veth)?;
            ns.configure(|| {
                netlink::add_addr(
                    &lease.peer,
                    ip.parse().map_err(|e| {
                        NucleusError::NetworkError(format!("invalid allocated IP: {e}"))
                    })?,
                    prefix,
                )?;
                netlink::set_link_up(&lease.peer)?;
                netlink::set_link_up("lo")?;
                netlink::add_default_route(gateway)
            })?;
            Ok(ip)
        };
        let ip = setup().inspect_err(|_| {
            if let Err(cleanup) = lease.remove(&dir) {
                warn!("Bridge rollback: {cleanup}");
            }
        })?;
        Ok(Self {
            ip,
            config: config.clone(),
            lease,
            alloc_dir: dir,
            ns,
            firewall: Default::default(),
            broker: broker.cloned(),
            state: NetworkState::Active,
        })
    }

    fn host_rules(
        config: &BridgeConfig,
        lease: &Lease,
        ip: &str,
        mac: &str,
        broker: Option<&CredentialBrokerConfig>,
    ) -> String {
        let table = lease.table();
        let br = &lease.bridge;
        let veth = &lease.veth;
        let private = br == "nucleus0";
        let mut rules = format!(
            r#"create table bridge {table}
table bridge {table} {{
  chain ingress {{
    type filter hook prerouting priority -300; policy accept;
    iifname "{veth}" ether saddr != {mac} drop
    iifname "{veth}" ether type != {{ ip, arp }} drop
    iifname "{veth}" ip saddr != {ip} drop
    iifname "{veth}" arp saddr ip != {ip} drop
    iifname "{veth}" arp saddr ether != {mac} drop
  }}
"#
        );
        if private {
            rules.push_str(&format!("chain peers {{ type filter hook forward priority -200; policy accept; iifname \"{veth}\" drop; oifname \"{veth}\" drop; }}\n"));
        }
        rules.push_str(&format!("}}\ncreate table ip {table}\ntable ip {table} {{\nchain host_input {{ type filter hook input priority -10; policy accept;\n"));
        let source = format!("iifname \"{br}\" ip saddr {ip}");
        rules.push_str(&Self::input_rules(&source, broker, &[]));
        rules.push_str(&format!("}}\nchain transit {{ type filter hook forward priority -10; policy accept;\n{source} ct direction original ct status dnat drop\n"));
        let target = format!("oifname \"{br}\" ip daddr {ip}");
        if !private {
            rules.push_str(&format!(
                "iifname \"{br}\" {target} ip saddr {} accept\n",
                config.subnet
            ));
        }
        rules.push_str(&format!("{target} ct direction reply ct state established,related accept\n{target} ct status dnat accept\n{target} drop\n}}\n"));
        for hook in ["prerouting", "output"] {
            rules.push_str(&format!(
                "chain nat_{hook} {{ type nat hook {hook} priority dstnat; policy accept;\n"
            ));
            for pf in &config.port_forwards {
                let dest = pf
                    .host_ip
                    .map(|ip| format!("ip daddr {ip} "))
                    .unwrap_or_default();
                rules.push_str(&format!(
                    "fib daddr type local {dest}{} dport {} dnat to {ip}:{}\n",
                    pf.protocol.as_str(),
                    pf.host_port,
                    pf.container_port
                ));
            }
            rules.push_str("}\n");
        }
        rules.push_str(&format!("chain nat_post {{ type nat hook postrouting priority srcnat; policy accept; ip saddr {ip} oifname != \"{br}\" masquerade; }}\n}}\n"));
        rules
    }

    fn input_rules(
        source: &str,
        broker: Option<&CredentialBrokerConfig>,
        dns: &[String],
    ) -> String {
        let mut rules = String::new();
        rules.push_str(&format!(
            "{source} ct direction reply ct state established,related accept\n"
        ));
        if let Some(broker) = broker {
            rules.push_str(&format!(
                "{source} ip daddr {} tcp dport {} accept\n",
                broker.broker_ip, broker.broker_port
            ));
        }
        // The guest firewall separately requires explicit DNS egress.
        for dns in dns {
            rules.push_str(&format!("{source} ip daddr {dns} udp dport 53 accept\n{source} ip daddr {dns} tcp dport 53 accept\n"));
        }
        rules.push_str(&format!("{source} drop\n"));
        rules
    }

    pub fn apply_egress_policy(&self, _pid: u32, policy: &EgressPolicy) -> Result<()> {
        self.firewall.apply(self.ns.clone(), &self.config, policy)?;
        let table = self.lease.table();
        let source = format!("iifname \"{}\" ip saddr {}", self.lease.bridge, self.ip);
        let dns = if policy.allow_dns {
            self.config.dns.as_slice()
        } else {
            &[]
        };
        let input = Self::input_rules(&source, self.broker.as_ref(), dns);
        firewall::transact(None,&format!("flush chain ip {table} host_input\ntable ip {table} {{ chain host_input {{\n{input}}}\n}}\n"))
    }

    pub fn cleanup(mut self) -> Result<()> {
        let dir = &self.alloc_dir;
        let _lock = lifecycle_lock(dir)?;
        self.lease.remove(dir)?;
        self.state = self.state.transition(NetworkState::Cleaned)?;
        Ok(())
    }

    fn cleanup_orphaned_rules(dir: &Path) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("lease") {
                continue;
            }
            let lease: Lease = serde_json::from_reader(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)?,
            )
            .map_err(|e| NucleusError::NetworkError(format!("Invalid bridge lease: {e}")))?;
            if lease.veth.len() != 15
                || !lease.veth.starts_with("nxv")
                || !lease.veth[3..].bytes().all(|b| b.is_ascii_hexdigit())
                || lease.peer != format!("nxp{}", &lease.veth[3..])
                || lease.path(dir) != path
                || lease.id.is_empty()
                || !lease
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(NucleusError::NetworkError(format!(
                    "Invalid bridge lease {path:?}"
                )));
            }
            BridgeConfig {
                bridge_name: lease.bridge.clone(),
                ..Default::default()
            }
            .validate()?;
            // A moved veth survives for the lifetime of the workload netns.
            // If both ends are here, setup stopped before handing off the peer.
            if !netlink::link_exists(&lease.veth) || netlink::link_exists(&lease.peer) {
                lease.remove(dir)?;
            }
        }
        Ok(())
    }

    fn ensure_bridge_for(lease: &Lease, gateway: Ipv4Addr, prefix: u8) -> Result<()> {
        let name = &lease.bridge;
        let dir = Path::new("/sys/class/net").join(name);
        if netlink::link_exists(name) {
            if !dir.join("bridge").is_dir() {
                return Err(NucleusError::NetworkError(format!(
                    "Existing interface {name} is not a bridge"
                )));
            }
            let alias = std::fs::read_to_string(dir.join("ifalias"))?;
            if alias.trim() != "nucleus-managed-bridge" {
                return Err(NucleusError::NetworkError(format!(
                    "Bridge {name} has unexpected ownership marker {alias:?}"
                )));
            }
            if !netlink::has_address(&gateway, Some((name, prefix)))? {
                return Err(NucleusError::NetworkError(format!(
                    "Bridge {name} lacks expected address {gateway}/{prefix}"
                )));
            }
        } else {
            if netlink::is_addr_in_use(&gateway)? {
                return Err(NucleusError::NetworkError(format!(
                    "Bridge gateway {gateway} is already assigned"
                )));
            }
            let staging = lease.staging_bridge();
            netlink::create_bridge(&staging)?;
            std::fs::write(
                format!("/sys/class/net/{staging}/ifalias"),
                "nucleus-managed-bridge",
            )?;
            netlink::add_addr(&staging, gateway, prefix)?;
            netlink::rename_link(&staging, name)?;
        }
        netlink::set_link_up(name)
    }

    /// Allocate a container IP from the subnet using /dev/urandom.
    ///
    /// Checks both host-visible interfaces (via `ip addr`) and IPs assigned to
    /// other Nucleus containers (via state files) to avoid duplicates. Container
    /// IPs inside network namespaces are invisible to `ip addr show` on the host.
    fn allocate_ip_with_reserved(
        subnet: &str,
        reserved: &std::collections::HashSet<String>,
    ) -> Result<String> {
        let (base, prefix) =
            super::config::parse_ipv4_cidr(subnet).map_err(NucleusError::NetworkError)?;
        let usable = !super::config::ipv4_mask(prefix) - 2;
        let mut random = [0u8; 4];
        std::io::Read::read_exact(&mut Self::open_dev_urandom()?, &mut random)?;
        let start = u32::from_ne_bytes(random) % usable;
        for offset in 0..usable {
            let index = (u64::from(start) + u64::from(offset)) % u64::from(usable);
            let candidate = Ipv4Addr::from(u32::from(base) + index as u32 + 2).to_string();
            if reserved.contains(&candidate) {
                continue;
            }
            if !Self::is_ip_in_use(&candidate)? {
                // Lock is released when lock_file is dropped
                return Ok(candidate);
            }
        }

        Err(NucleusError::NetworkError(format!(
            "Failed to allocate free IP in subnet {}",
            subnet
        )))
    }

    fn reserve_ip_in_dir(
        alloc_dir: &std::path::Path,
        container_id: &str,
        subnet: &str,
        requested_ip: Option<&str>,
    ) -> Result<String> {
        let lock_path = alloc_dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to open IP alloc lock: {}", e))
            })?;
        // SAFETY: lock_file is a valid open fd. LOCK_EX is a blocking exclusive
        // lock that is released when the fd is closed (end of scope).
        let lock_ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if lock_ret != 0 {
            return Err(NucleusError::NetworkError(format!(
                "Failed to acquire IP alloc lock: {}",
                std::io::Error::last_os_error()
            )));
        }

        let reserved = Self::collect_reserved_ips_in_dir(alloc_dir);
        let ip = match requested_ip {
            Some(ip) => {
                if reserved.contains(ip) || Self::is_ip_in_use(ip)? {
                    return Err(NucleusError::NetworkError(format!(
                        "Requested container IP {} is already in use",
                        ip
                    )));
                }
                ip.to_string()
            }
            None => Self::allocate_ip_with_reserved(subnet, &reserved)?,
        };

        Self::record_allocated_ip_in_dir(alloc_dir, container_id, &ip)?;
        Ok(ip)
    }

    /// Scan the Nucleus IP allocation directory for IPs already assigned.
    fn collect_reserved_ips_in_dir(
        alloc_dir: &std::path::Path,
    ) -> std::collections::HashSet<String> {
        let mut ips = std::collections::HashSet::new();
        if let Ok(entries) = std::fs::read_dir(alloc_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".ip") {
                        if let Ok(ip) = std::fs::read_to_string(entry.path()) {
                            let ip = ip.trim().to_string();
                            if !ip.is_empty() {
                                ips.insert(ip);
                            }
                        }
                    }
                }
            }
        }
        ips
    }

    /// Persist the allocated IP for this container so other containers can see it.
    fn record_allocated_ip_in_dir(
        alloc_dir: &std::path::Path,
        container_id: &str,
        ip: &str,
    ) -> Result<()> {
        let path = alloc_dir.join(format!("{}.ip", container_id));
        std::fs::write(&path, ip).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to record IP allocation: {}", e))
        })?;
        Ok(())
    }

    fn release_allocated_ip_in_dir(alloc_dir: &std::path::Path, container_id: &str) {
        let path = alloc_dir.join(format!("{}.ip", container_id));
        let _ = std::fs::remove_file(path);
    }

    fn ensure_alloc_dir(dir: &Path) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        // Walk from the trusted root and reject replaceable parent directories.
        // Tests use a private directory created under sticky /tmp.
        let uid = nix::unistd::Uid::effective().as_raw();
        for path in dir.ancestors().collect::<Vec<_>>().into_iter().rev() {
            if !path.try_exists()? {
                match std::fs::DirBuilder::new().mode(0o700).create(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    result => result?,
                }
            }
            let meta = std::fs::symlink_metadata(path)?;
            let sticky_tmp =
                path == Path::new("/tmp") && meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0;
            if !meta.is_dir()
                || (meta.uid() != uid && meta.uid() != 0)
                || (meta.mode() & 0o022 != 0 && !sticky_tmp)
            {
                return Err(NucleusError::NetworkError(format!(
                    "Unsafe network state directory {path:?}"
                )));
            }
        }
        Ok(())
    }

    fn ip_alloc_dir() -> Result<PathBuf> {
        use std::os::unix::fs::MetadataExt;
        let namespace = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
        Ok(Path::new("/run/nucleus/ip-alloc").join(namespace.to_string()))
    }

    /// Resolve a system binary to a validated absolute path.
    ///
    /// Searches known sysadmin paths first while validating ownership and
    /// permissions before use. When running as root, the process PATH is never
    /// consulted because bridge networking invokes privileged helpers and must
    /// not trust an attacker-influenced environment. This also avoids depending
    /// on a separate `which` binary in service managers that set a narrow PATH.
    /// Returns an error if no valid binary is found.
    pub(crate) fn resolve_bin(name: &str) -> Result<String> {
        let search_dirs: &[&str] = match name {
            "nft" => &[
                "/usr/sbin/nft",
                "/sbin/nft",
                "/usr/bin/nft",
                "/run/current-system/sw/bin/nft",
            ],
            "slirp4netns" => &[
                "/usr/bin/slirp4netns",
                "/bin/slirp4netns",
                "/run/current-system/sw/bin/slirp4netns",
            ],
            _ => &[],
        };

        let packaged = match name {
            "nft" => option_env!("NUCLEUS_PACKAGED_NFT"),
            "slirp4netns" => option_env!("NUCLEUS_PACKAGED_SLIRP"),
            _ => None,
        };
        for path in packaged.into_iter().chain(search_dirs.iter().copied()) {
            let p = std::path::Path::new(path);
            if p.exists() {
                Self::validate_network_binary(p, name)?;
                let resolved = std::fs::canonicalize(p).map_err(|e| {
                    NucleusError::NetworkError(format!(
                        "Cannot canonicalize {} at {:?}: {}",
                        name, p, e
                    ))
                })?;
                return Ok(resolved.to_string_lossy().into_owned());
            }
        }

        if nix::unistd::Uid::effective().is_root() {
            return Err(NucleusError::NetworkError(format!(
                "Required binary '{}' not found in trusted system paths",
                name
            )));
        }

        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if candidate.exists() {
                    Self::validate_network_binary(&candidate, name)?;
                    let resolved = std::fs::canonicalize(&candidate).map_err(|e| {
                        NucleusError::NetworkError(format!(
                            "Cannot canonicalize {} at {:?}: {}",
                            name, candidate, e
                        ))
                    })?;
                    return Ok(resolved.to_string_lossy().into_owned());
                }
            }
        }

        Err(NucleusError::NetworkError(format!(
            "Required binary '{}' not found or failed validation",
            name
        )))
    }

    /// Validate a network binary's ownership and permissions.
    /// Rejects binaries that are group/world-writable or not owned by root/euid,
    /// except for immutable Nix store artifacts.
    fn validate_network_binary(path: &std::path::Path, name: &str) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let meta = std::fs::metadata(&resolved)
            .map_err(|e| NucleusError::NetworkError(format!("Cannot stat {}: {}", name, e)))?;
        let mode = meta.mode();
        if mode & 0o111 == 0 {
            return Err(NucleusError::NetworkError(format!(
                "Binary '{}' at {:?} is not executable, refusing to execute",
                name, resolved
            )));
        }
        if mode & 0o022 != 0 {
            return Err(NucleusError::NetworkError(format!(
                "Binary '{}' at {:?} is writable by group/others (mode {:o}), refusing to execute",
                name, resolved, mode
            )));
        }
        let owner = meta.uid();
        let euid = nix::unistd::Uid::effective().as_raw();
        if owner != 0 && owner != euid && !Self::is_trusted_store_network_binary(&resolved, mode) {
            return Err(NucleusError::NetworkError(format!(
                "Binary '{}' at {:?} owned by UID {} (expected root or euid {}), refusing to execute",
                name, resolved, owner, euid
            )));
        }
        Ok(())
    }

    fn is_trusted_store_network_binary(path: &std::path::Path, mode: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        if !path.starts_with("/nix/store") {
            return false;
        }
        if mode & 0o200 != 0 {
            return false;
        }
        if let Some(parent) = path.parent() {
            if let Ok(parent_meta) = std::fs::metadata(parent) {
                return parent_meta.mode() & 0o222 == 0;
            }
        }
        false
    }

    fn is_ip_in_use(ip: &str) -> Result<bool> {
        let addr: Ipv4Addr = ip
            .parse()
            .map_err(|e| NucleusError::NetworkError(format!("invalid IP '{}': {}", ip, e)))?;
        netlink::is_addr_in_use(&addr)
    }

    /// Write resolv.conf inside container (for writable /etc, e.g. agent mode)
    pub fn write_resolv_conf(root: &std::path::Path, dns: &[String]) -> Result<()> {
        let parent = crate::filesystem::mount_target(root, std::path::Path::new("etc"), true)?;
        let parent_path = crate::filesystem::fd_path(&parent);
        let mut temp = tempfile::NamedTempFile::new_in(&parent_path)?;
        for server in dns {
            use std::io::Write;
            writeln!(temp, "nameserver {server}")?;
        }
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        temp.persist(parent_path.join("resolv.conf"))
            .map_err(|e| e.error)?;
        Ok(())
    }

    /// Bind-mount a resolv.conf over a read-only /etc (for production rootfs mode).
    ///
    /// Creates a memfd-backed resolv.conf and bind-mounts it over
    /// /etc/resolv.conf so it works even when the rootfs /etc is read-only.
    /// The memfd is cleaned up when the container exits. Kernels that cannot
    /// clone a memfd's internal shmem mount reject that bind with EINVAL even
    /// for root (verified on Linux 7.3.3 where both `open_tree(OPEN_TREE_CLONE)`
    /// and `mount(2)` `MS_BIND` fail on memfds while regular-file binds work),
    /// so a staging-file bind is used as the fallback instead of failing
    /// container start.
    pub fn bind_mount_resolv_conf(root: &std::path::Path, dns: &[String]) -> Result<()> {
        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();

        // Create a memfd-backed file to avoid leaving staging files on disk
        let memfd_name = std::ffi::CString::new("nucleus-resolv").map_err(|e| {
            NucleusError::NetworkError(format!("Failed to create memfd name: {}", e))
        })?;
        // SAFETY: memfd_name is a valid NUL-terminated CString. memfd_create
        // returns a new fd or -1 on error; we check for error below.
        let raw_fd = unsafe { libc::memfd_create(memfd_name.as_ptr(), 0) };
        if raw_fd < 0 {
            // Fallback to staging file if memfd_create is unavailable
            return Self::bind_mount_resolv_conf_staging(root, dns);
        }
        // SAFETY: raw_fd is a valid, newly-created fd from memfd_create.
        // OwnedFd takes ownership and will close it exactly once on drop,
        // preventing double-close on any error path.
        let memfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };

        // Write content to memfd using File I/O to handle partial writes correctly.
        use std::io::Write as _;
        let mut memfd_file = std::fs::File::from(memfd);
        if memfd_file.write_all(content.as_bytes()).is_err() {
            // memfd_file dropped here, closing the fd automatically
            return Self::bind_mount_resolv_conf_staging(root, dns);
        }
        // Re-extract the OwnedFd for the proc path below
        use std::os::fd::IntoRawFd;
        let memfd = {
            let raw = memfd_file.into_raw_fd();
            // SAFETY: raw is the valid fd we just extracted from the File.
            unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }
        };

        let target =
            crate::filesystem::mount_target(root, std::path::Path::new("etc/resolv.conf"), false)?;
        let memfd_path = format!("/proc/self/fd/{}", memfd.as_raw_fd());
        match crate::filesystem::bind_tree(
            std::path::Path::new(&memfd_path),
            &target,
            false,
            crate::filesystem::READ_ONLY | libc::MOUNT_ATTR_NOEXEC,
        ) {
            Ok(()) => {
                // memfd dropped here – the mount holds a kernel reference to
                // the file, so it survives the fd close.
                info!("Bind-mounted resolv.conf for bridge networking (rootfs mode, memfd)");
                Ok(())
            }
            Err(e) => {
                warn!("memfd resolv.conf bind rejected ({e}); binding staging file instead");
                Self::bind_mount_resolv_conf_staging(root, dns)
            }
        }
    }

    /// Fallback: bind-mount a staging resolv.conf file.
    fn bind_mount_resolv_conf_staging(root: &std::path::Path, dns: &[String]) -> Result<()> {
        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();

        let staging = Self::create_resolv_conf_staging_file(root, content.as_bytes())?;

        let target =
            crate::filesystem::mount_target(root, std::path::Path::new("etc/resolv.conf"), false)?;
        crate::filesystem::bind_tree(
            staging.path(),
            &target,
            false,
            crate::filesystem::READ_ONLY | libc::MOUNT_ATTR_NOEXEC,
        )?;

        // The bind mount holds a reference to the inode. Dropping the temporary
        // file unlinks the staging path so DNS server info is not left on disk.

        info!("Bind-mounted resolv.conf for bridge networking (rootfs mode, staging)");
        Ok(())
    }

    fn create_resolv_conf_staging_file(
        root: &std::path::Path,
        content: &[u8],
    ) -> Result<tempfile::NamedTempFile> {
        use std::io::Write as _;

        let staging_dir = root.parent().ok_or_else(|| {
            NucleusError::NetworkError(format!(
                "Container root {:?} has no parent for resolv.conf staging",
                root
            ))
        })?;

        let mut staging = tempfile::Builder::new()
            .prefix(".resolv.conf.nucleus.")
            .tempfile_in(staging_dir)
            .map_err(|e| {
                NucleusError::NetworkError(format!(
                    "Failed to create temporary resolv.conf staging file under {:?}: {}",
                    staging_dir, e
                ))
            })?;

        staging.as_file_mut().write_all(content).map_err(|e| {
            NucleusError::NetworkError(format!(
                "Failed to write temporary resolv.conf staging file {:?}: {}",
                staging.path(),
                e
            ))
        })?;

        Ok(staging)
    }
}

impl Drop for BridgeNetwork {
    fn drop(&mut self) {
        if self.state != NetworkState::Cleaned {
            let dir = &self.alloc_dir;
            if let Err(e) = lifecycle_lock(dir).and_then(|_lock| self.lease.remove(dir)) {
                warn!("Failed to clean up bridge: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserve_ip_blocks_duplicate_requested_address() {
        let temp = tempfile::tempdir().unwrap();
        BridgeNetwork::record_allocated_ip_in_dir(temp.path(), "one", "10.0.42.2").unwrap();

        let err =
            BridgeNetwork::reserve_ip_in_dir(temp.path(), "two", "10.0.42.0/24", Some("10.0.42.2"))
                .unwrap_err();
        assert!(
            err.to_string().contains("already in use"),
            "second reservation of the same IP must fail"
        );
    }

    #[test]
    fn test_resolv_conf_staging_file_is_outside_container_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("tmp")).unwrap();

        let staging =
            BridgeNetwork::create_resolv_conf_staging_file(&root, b"nameserver 203.0.113.53\n")
                .unwrap();

        assert_eq!(
            std::fs::read_to_string(staging.path()).unwrap(),
            "nameserver 203.0.113.53\n"
        );
        assert!(
            !staging.path().starts_with(&root),
            "staging file must not be created under the container root"
        );
    }

    #[test]
    fn test_bind_mount_resolv_conf_does_not_overwrite_root_tmp_symlink_on_failure() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("tmp")).unwrap();

        let victim = temp.path().join("host_victim_file");
        std::fs::write(&victim, "ORIGINAL_HOST_CONTENT\n").unwrap();
        symlink(&victim, root.join("tmp/.resolv.conf.nucleus")).unwrap();

        let dns = vec!["203.0.113.53".to_string()];
        let result = BridgeNetwork::bind_mount_resolv_conf(&root, &dns);

        assert!(
            result.is_err(),
            "test root intentionally lacks /etc so bind mount setup must fail"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL_HOST_CONTENT\n",
            "resolv.conf setup must not write through attacker-controlled /tmp symlinks"
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN over a private mount namespace (run inside a user namespace or as root)"]
    fn bind_mount_resolv_conf_overlays_read_only_etc() {
        // Run in a fork child with a private mount namespace.
        match unsafe { nix::unistd::fork().unwrap() } {
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0)
            ),
            nix::unistd::ForkResult::Child => {
                let result = std::panic::catch_unwind(|| {
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
                    nix::mount::mount(
                        None::<&str>,
                        "/",
                        None::<&str>,
                        nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                        None::<&str>,
                    )
                    .unwrap();
                    let temp = tempfile::tempdir().unwrap();
                    let root = temp.path().join("rootfs");
                    std::fs::create_dir_all(root.join("etc")).unwrap();
                    // Pre-existing host resolv.conf that the bind must shadow.
                    std::fs::write(root.join("etc/resolv.conf"), "nameserver 192.0.2.99\n")
                        .unwrap();

                    let outcome =
                        BridgeNetwork::bind_mount_resolv_conf(&root, &["203.0.113.53".to_string()]);
                    if let Err(e) = &outcome {
                        eprintln!("bind_mount_resolv_conf error: {e}");
                    }
                    outcome.expect("resolv.conf bind must succeed via memfd or staging fallback");

                    assert_eq!(
                        std::fs::read_to_string(root.join("etc/resolv.conf")).unwrap(),
                        "nameserver 203.0.113.53\n",
                        "bind must shadow the underlying file"
                    );
                    let err = std::fs::write(root.join("etc/resolv.conf"), b"x").unwrap_err();
                    assert_eq!(
                        err.raw_os_error(),
                        Some(libc::EROFS),
                        "bind must be read-only"
                    );
                    let staging = std::fs::read_dir(temp.path())
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .filter(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .starts_with(".resolv.conf.nucleus.")
                        })
                        .count();
                    assert_eq!(staging, 0, "no staging leftovers may remain on disk");
                });
                unsafe { libc::_exit(i32::from(result.is_err())) }
            }
        }
    }

    /// All interfaces, sockets, forwarding and firewall changes in this test live
    /// in throwaway namespaces. The external listener is another local fixture.
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, CAP_NET_ADMIN, sysfs and nftables"]
    fn isolated_bridge_routes_only_intended_traffic() {
        use nix::mount::{mount, MsFlags};
        use nix::sched::{unshare, CloneFlags};
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::sync::mpsc;
        use std::time::Duration;

        fn guest() -> (u32, mpsc::Sender<()>) {
            let (ready, tid) = mpsc::channel();
            let (guard, wait) = mpsc::channel();
            std::thread::spawn(move || {
                unshare(CloneFlags::CLONE_NEWNET).unwrap();
                ready.send(nix::unistd::gettid().as_raw() as u32).unwrap();
                let _ = wait.recv();
            });
            (tid.recv().unwrap(), guard)
        }
        fn listen(ns: &netns::Namespaces, addr: SocketAddr) -> TcpListener {
            let mut listener = None;
            ns.configure(|| {
                listener = Some(TcpListener::bind(addr)?);
                Ok(())
            })
            .unwrap();
            listener.unwrap()
        }
        fn connects(ns: &netns::Namespaces, addr: SocketAddr) -> bool {
            let mut ok = false;
            ns.configure(|| {
                ok = TcpStream::connect_timeout(&addr, Duration::from_millis(700)).is_ok();
                Ok(())
            })
            .unwrap();
            ok
        }

        std::thread::spawn(|| {
            unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS).unwrap();
            mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            )
            .unwrap();
            mount(
                Some("sysfs"),
                "/sys",
                Some("sysfs"),
                MsFlags::empty(),
                None::<&str>,
            )
            .unwrap();
            netlink::set_link_up("lo").unwrap();
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();

            let (outside, _outside) = guest();
            let upstream = netns::Namespaces::open(outside, false).unwrap();
            netlink::create_veth("wan", "remote").unwrap();
            netlink::set_link_netns("remote", &upstream.net).unwrap();
            netlink::add_addr("wan", "192.0.2.1".parse().unwrap(), 24).unwrap();
            netlink::set_link_up("wan").unwrap();
            upstream
                .configure(|| {
                    netlink::add_addr("remote", "192.0.2.2".parse().unwrap(), 24)?;
                    netlink::set_link_up("remote")?;
                    netlink::add_default_route("192.0.2.1".parse().unwrap())
                })
                .unwrap();

            let (a, _a) = guest();
            let (b, _b) = guest();
            let cfg = BridgeConfig {
                container_ip: Some("10.0.42.2".into()),
                port_forwards: vec![super::super::PortForward::parse("10443:8080").unwrap()],
                ..Default::default()
            };
            let server = BridgeNetwork::setup_with_id(a, &cfg, "server").unwrap();
            let client = BridgeNetwork::setup_with_id(
                b,
                &BridgeConfig {
                    container_ip: Some("10.0.42.3".into()),
                    ..Default::default()
                },
                "client",
            )
            .unwrap();
            let workload = listen(&server.ns, "10.0.42.2:8080".parse().unwrap());
            let remote = listen(&upstream, "192.0.2.2:10443".parse().unwrap());
            let host = TcpListener::bind("10.0.42.1:18080").unwrap();
            let host_port = "192.0.2.1:10443".parse().unwrap();
            assert!(connects(&upstream, host_port));
            workload.accept().unwrap();
            client
                .apply_egress_policy(
                    b,
                    &EgressPolicy::default().with_allowed_cidrs(vec!["0.0.0.0/0".into()]),
                )
                .unwrap();
            assert!(connects(&client.ns, remote.local_addr().unwrap()));
            remote.set_nonblocking(true).unwrap();
            remote
                .accept()
                .expect("transit traffic reached the original destination");
            assert!(!connects(&client.ns, workload.local_addr().unwrap()));
            assert!(!connects(&client.ns, host.local_addr().unwrap()));
            assert!(!connects(&client.ns, host_port));

            // An explicitly named fabric permits its peers, including on a
            // non-/24 subnet. The other fabric still cannot route into it.
            let named = BridgeConfig {
                bridge_name: "nxshared".into(),
                subnet: "10.8.0.64/28".into(),
                ..Default::default()
            };
            let (c, _c) = guest();
            let (d, _d) = guest();
            let first = BridgeNetwork::setup_with_id(c, &named, "first").unwrap();
            let second = BridgeNetwork::setup_with_id(d, &named, "second").unwrap();
            let address = format!("{}:18081", first.ip).parse().unwrap();
            let _named_service = listen(&first.ns, address);
            assert!(connects(&second.ns, address));
            assert!(!connects(&client.ns, address));
            first.cleanup().unwrap();
            second.cleanup().unwrap();

            // Simulate a lost supervisor journal entry. Recovery must leave the
            // live attachment intact and reap its private tables after link loss.
            let dir = server.alloc_dir.clone();
            let lease_path = server.lease.path(&dir);
            let _lock = lifecycle_lock(&dir).unwrap();
            BridgeNetwork::cleanup_orphaned_rules(&dir).unwrap();
            assert!(lease_path.exists());
            netlink::del_link(&server.lease.veth).unwrap();
            BridgeNetwork::cleanup_orphaned_rules(&dir).unwrap();
            assert!(!lease_path.exists() && client.lease.path(&dir).exists());
            drop(_lock);
            client.cleanup().unwrap();
            server.cleanup().unwrap();
            assert_eq!(
                std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                    .unwrap()
                    .trim(),
                "1"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn published_ports_only_match_local_destinations_on_both_hooks() {
        let lease = Lease {
            id: "test".into(),
            bridge: "nucleus0".into(),
            veth: "nxvtest".into(),
            peer: "nxptest".into(),
        };
        let cfg = BridgeConfig {
            port_forwards: vec![super::super::PortForward::parse("127.0.0.1:8080:80").unwrap()],
            ..Default::default()
        };
        let rules = BridgeNetwork::host_rules(&cfg, &lease, "10.0.42.2", "02:00:00:00:00:02", None);
        assert_eq!(
            rules
                .matches(
                    "fib daddr type local ip daddr 127.0.0.1 tcp dport 8080 dnat to 10.0.42.2:80"
                )
                .count(),
            2
        );
    }

    #[test]
    fn writable_resolv_conf_replaces_leaf_and_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("resolv.conf");
        std::fs::write(&victim, "unchanged").unwrap();
        symlink(outside.path(), root.path().join("etc")).unwrap();
        assert!(BridgeNetwork::write_resolv_conf(root.path(), &[]).is_err());
        std::fs::remove_file(root.path().join("etc")).unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        symlink(&victim, root.path().join("etc/resolv.conf")).unwrap();
        BridgeNetwork::write_resolv_conf(root.path(), &["10.0.0.2".into()]).unwrap();
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "unchanged");
    }
}
