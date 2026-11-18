use super::{firewall, netlink, netns::Namespaces, BridgeConfig, EgressPolicy};
use crate::error::{NucleusError, Result};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn public_destination(ip: Ipv4Addr, bridge: &BridgeConfig) -> Result<bool> {
    let [a, b, c, _] = ip.octets();
    // Reject special-use and non-unicast ranges before installing any result.
    let special = a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113);
    Ok(!special
        && !bridge
            .contains_ipv4(ip)
            .map_err(NucleusError::NetworkError)?
        && !netlink::is_addr_in_use(&ip)?)
}

fn resolve(domains: &[String], bridge: &BridgeConfig) -> Result<BTreeSet<Ipv4Addr>> {
    let mut ips = BTreeSet::new();
    for domain in domains {
        super::validate_egress_domain(domain).map_err(NucleusError::NetworkError)?;
        let mut found = false;
        for address in (domain.as_str(), 0).to_socket_addrs()? {
            if let IpAddr::V4(ip) = address.ip() {
                if !public_destination(ip, bridge)? {
                    return Err(NucleusError::NetworkError(format!(
                        "Domain {domain} returned a protected destination {ip}"
                    )));
                }
                ips.insert(ip);
                found = true;
            }
        }
        if !found {
            return Err(NucleusError::NetworkError(format!(
                "No eligible IPv4 addresses for {domain}"
            )));
        }
    }
    Ok(ips)
}

fn allow_destination(rules: &mut String, dest: &str, policy: &EgressPolicy) {
    if policy.allowed_tcp_ports.is_empty() && policy.allowed_udp_ports.is_empty() {
        rules.push_str(&format!("ip daddr {dest} accept\n"));
    }
    for (proto, ports) in [
        ("tcp", &policy.allowed_tcp_ports),
        ("udp", &policy.allowed_udp_ports),
    ] {
        if !ports.is_empty() {
            let ports = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            rules.push_str(&format!(
                "ip daddr {dest} {proto} dport {{ {ports} }} accept\n"
            ));
        }
    }
}

fn replace_domains(set: &str, ips: &BTreeSet<Ipv4Addr>) -> String {
    let mut rules = format!("flush set inet nucleus_egress {set}\n");
    if !ips.is_empty() {
        let elements = ips
            .iter()
            .map(Ipv4Addr::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        rules.push_str(&format!(
            "add element inet nucleus_egress {set} {{ {elements} }}\n"
        ));
    }
    rules
}

// Dropping the sender stops the worker. Kernel timeouts close the grant even
// when the host resolver hangs or the supervisor exits unexpectedly.
struct DomainRefresh {
    _stop: mpsc::Sender<()>,
}

#[derive(Default)]
pub(super) struct GuestFirewall {
    refresh: Mutex<Option<DomainRefresh>>,
}

impl GuestFirewall {
    pub fn apply(
        &self,
        ns: Arc<Namespaces>,
        bridge: &BridgeConfig,
        policy: &EgressPolicy,
    ) -> Result<()> {
        let mut worker = self
            .refresh
            .lock()
            .map_err(|_| NucleusError::NetworkError("egress worker lock poisoned".into()))?;
        *worker = install(ns, bridge, policy)?;
        Ok(())
    }
}

fn install(
    ns: Arc<Namespaces>,
    bridge: &BridgeConfig,
    policy: &EgressPolicy,
) -> Result<Option<DomainRefresh>> {
    bridge.validate()?;
    if policy.allow_dns && bridge.dns.is_empty() {
        return Err(NucleusError::NetworkError(
            "DNS egress requires configured resolvers".into(),
        ));
    }
    if policy.log_denied
        && std::fs::read_to_string("/proc/sys/net/netfilter/nf_log_all_netns")
            .unwrap_or_default()
            .trim()
            != "1"
    {
        return Err(NucleusError::NetworkError(
            "Denied-packet kernel logging requires host net.netfilter.nf_log_all_netns=1".into(),
        ));
    }
    let ips = resolve(&policy.allowed_domains, bridge)?;
    // A delayed refresh from a previous policy cannot populate the new set.
    static NEXT_SET: AtomicU64 = AtomicU64::new(0);
    let set = format!("domains_{}", NEXT_SET.fetch_add(1, Ordering::Relaxed));
    let mut rules = format!(
        r#"add table inet nucleus_egress
delete table inet nucleus_egress
table inet nucleus_egress {{
  set {set} {{ type ipv4_addr; flags timeout; timeout 60s; }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    meta nfproto ipv4 ct direction reply ct state established,related accept
"#
    );
    if policy.allow_dns {
        for dns in &bridge.dns {
            for proto in ["udp", "tcp"] {
                rules.push_str(&format!("ip daddr {dns} {proto} dport 53 accept\n"));
            }
        }
    }
    for cidr in &policy.allowed_cidrs {
        super::validate_egress_cidr(cidr).map_err(NucleusError::NetworkError)?;
        allow_destination(&mut rules, cidr, policy);
    }
    if !policy.allowed_domains.is_empty() {
        allow_destination(&mut rules, &format!("@{set}"), policy);
    }
    if policy.log_denied {
        rules.push_str("limit rate 5/minute log prefix \"nucleus-egress-denied: \"\n");
    }
    rules.push_str("counter drop\n}\n}\n");
    rules.push_str(&replace_domains(&set, &ips));
    firewall::transact(Some(&ns), &rules)?;
    if policy.allowed_domains.is_empty() {
        return Ok(None);
    }
    let names = policy.allowed_domains.clone();
    let bridge = bridge.clone();
    let (stop, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("nucleus-egress-dns".into())
        .spawn(move || {
            while matches!(
                rx.recv_timeout(Duration::from_secs(30)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                let ips = resolve(&names, &bridge).unwrap_or_else(|e| {
                    tracing::warn!("Withdrawing DNS egress grants: {e}");
                    BTreeSet::new()
                });
                if let Err(e) = firewall::transact(Some(&ns), &replace_domains(&set, &ips)) {
                    tracing::warn!("Cannot refresh DNS egress grants: {e}");
                }
            }
        })?;
    Ok(Some(DomainRefresh { _stop: stop }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_answers_cannot_grant_special_or_bridge_addresses() {
        let bridge = BridgeConfig {
            subnet: "9.8.7.0/24".into(),
            ..Default::default()
        };
        for ip in [
            "169.254.169.254",
            "10.0.0.1",
            "9.8.7.1",
            "100.64.0.1",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_destination(ip.parse().unwrap(), &bridge).unwrap());
        }
    }

    #[test]
    #[ignore = "requires private mount and network namespaces, nftables and CAP_NET_ADMIN"]
    fn domain_refresh_withdraws_protected_results_and_expires_without_supervisor() {
        use nix::mount::{mount, MsFlags};
        use nix::sched::{unshare, CloneFlags};
        use std::io::Write;
        use std::path::Path;
        std::thread::spawn(|| {
            unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET).unwrap();
            mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            )
            .unwrap();
            let mut hosts = tempfile::NamedTempFile::new().unwrap();
            writeln!(hosts, "93.184.216.34 allow.nucleus.test").unwrap();
            mount(
                Some(hosts.path()),
                Path::new("/etc/hosts"),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .unwrap();
            let ns = Arc::new(Namespaces {
                net: std::fs::File::open("/proc/thread-self/ns/net").unwrap(),
                user: None,
                mapped_root: None,
            });
            let nft = super::super::BridgeNetwork::resolve_bin("nft").unwrap();
            let list = || {
                let out = ns
                    .command(&nft)
                    .unwrap()
                    .args(["list", "table", "inet", "nucleus_egress"])
                    .output()
                    .unwrap();
                assert!(out.status.success());
                String::from_utf8(out.stdout).unwrap()
            };
            let policy =
                EgressPolicy::default().with_allowed_domains(vec!["allow.nucleus.test".into()]);
            let firewall = GuestFirewall::default();
            firewall
                .apply(ns.clone(), &BridgeConfig::default(), &policy)
                .unwrap();
            assert!(list().contains("93.184.216.34"));
            std::fs::write(hosts.path(), "169.254.169.254 allow.nucleus.test\n").unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(50);
            while list().contains("93.184.216.34") {
                assert!(
                    std::time::Instant::now() < deadline,
                    "stale grant survived the refresh"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
            assert!(!list().contains("169.254.169.254"));
            std::fs::write(hosts.path(), "93.184.216.34 allow.nucleus.test\n").unwrap();
            firewall
                .apply(ns.clone(), &BridgeConfig::default(), &policy)
                .unwrap();
            drop(firewall);
            assert!(list().contains("93.184.216.34"));
            let deadline = std::time::Instant::now() + Duration::from_secs(75);
            while list().contains("93.184.216.34") {
                assert!(
                    std::time::Instant::now() < deadline,
                    "kernel failed to expire DNS grant"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    #[ignore = "requires private netns, nftables and CAP_NET_ADMIN"]
    fn deny_all_sets_both_kernel_output_policies() {
        std::thread::spawn(|| {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
            let ns = Arc::new(Namespaces {
                net: std::fs::File::open("/proc/thread-self/ns/net").unwrap(),
                user: None,
                mapped_root: None,
            });
            GuestFirewall::default()
                .apply(
                    ns.clone(),
                    &BridgeConfig::default(),
                    &EgressPolicy::deny_all(),
                )
                .unwrap();
            let nft = super::super::BridgeNetwork::resolve_bin("nft").unwrap();
            let out = ns
                .command(&nft)
                .unwrap()
                .args(["list", "chain", "inet", "nucleus_egress", "output"])
                .output()
                .unwrap();
            assert!(out.status.success());
            let listing = String::from_utf8(out.stdout).unwrap();
            assert!(listing.contains("policy drop;") && listing.contains("oifname \"lo\" accept"));
            assert!(!listing.contains("dport 53"));
        })
        .join()
        .unwrap();
    }
}
