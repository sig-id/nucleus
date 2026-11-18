use super::{netns, BridgeNetwork, EgressPolicy};
use crate::error::{NucleusError, Result};
use std::net::{IpAddr, ToSocketAddrs};
use tracing::{debug, info};

fn resolve_domain_cidrs(domains: &[String]) -> Result<Vec<String>> {
    let mut cidrs = Vec::new();

    for domain in domains {
        crate::network::config::validate_egress_domain(domain)
            .map_err(|e| NucleusError::NetworkError(format!("Invalid egress domain: {}", e)))?;

        let mut resolved_any_ipv4 = false;
        let addrs = (domain.as_str(), 0).to_socket_addrs().map_err(|e| {
            NucleusError::NetworkError(format!(
                "Failed to resolve egress domain '{}': {}",
                domain, e
            ))
        })?;

        for addr in addrs {
            if let IpAddr::V4(ip) = addr.ip() {
                resolved_any_ipv4 = true;
                cidrs.push(format!("{}/32", ip));
            }
        }

        if !resolved_any_ipv4 {
            return Err(NucleusError::NetworkError(format!(
                "Egress domain '{}' resolved no IPv4 addresses",
                domain
            )));
        }
    }

    cidrs.sort();
    cidrs.dedup();
    Ok(cidrs)
}

pub(crate) fn apply_egress_policy(
    pid: u32,
    dns: &[String],
    policy: &EgressPolicy,
    join_userns: bool,
) -> Result<()> {
    for cidr in &policy.allowed_cidrs {
        crate::network::config::validate_egress_cidr(cidr)
            .map_err(|e| NucleusError::NetworkError(format!("Invalid egress CIDR: {}", e)))?;
    }
    let resolved_domain_cidrs = resolve_domain_cidrs(&policy.allowed_domains)?;
    let allowed_cidrs = policy
        .allowed_cidrs
        .iter()
        .chain(resolved_domain_cidrs.iter());

    // The bridge allowlist uses IPv4 CIDRs. Close the entire other address
    // family before releasing the workload, including when DNS is allowed.
    let ip6t = BridgeNetwork::resolve_bin("ip6tables")?;
    for args in [
        &["-P", "OUTPUT", "DROP"][..],
        &["-F", "OUTPUT"],
        &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    ] {
        if join_userns {
            netns::exec_in_user_netns(pid, &ip6t, "ip6tables", args)?;
        } else {
            netns::exec_in_netns(pid, &ip6t, "ip6tables", args)?;
        }
    }
    let ipt = BridgeNetwork::resolve_bin("iptables")?;
    let exec = |args: &[&str]| {
        if join_userns {
            netns::exec_in_user_netns(pid, &ipt, "iptables", args)
        } else {
            netns::exec_in_netns(pid, &ipt, "iptables", args)
        }
    };

    exec(&["-P", "OUTPUT", "DROP"])?;
    exec(&["-F", "OUTPUT"])?;
    exec(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    exec(&[
        "-A",
        "OUTPUT",
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    if policy.allow_dns {
        for dns in dns {
            exec(&[
                "-A", "OUTPUT", "-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT",
            ])?;
            exec(&[
                "-A", "OUTPUT", "-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT",
            ])?;
        }
    }

    for cidr in allowed_cidrs {
        if policy.allowed_tcp_ports.is_empty() && policy.allowed_udp_ports.is_empty() {
            exec(&["-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"])?;
        } else {
            for port in &policy.allowed_tcp_ports {
                let port_s = port.to_string();
                exec(&[
                    "-A", "OUTPUT", "-p", "tcp", "-d", cidr, "--dport", &port_s, "-j", "ACCEPT",
                ])?;
            }
            for port in &policy.allowed_udp_ports {
                let port_s = port.to_string();
                exec(&[
                    "-A", "OUTPUT", "-p", "udp", "-d", cidr, "--dport", &port_s, "-j", "ACCEPT",
                ])?;
            }
        }
    }

    if policy.log_denied {
        exec(&[
            "-A",
            "OUTPUT",
            "-m",
            "limit",
            "--limit",
            "5/min",
            "-j",
            "LOG",
            "--log-prefix",
            "nucleus-egress-denied: ",
        ])?;
    }

    exec(&["-P", "OUTPUT", "DROP"])?;

    info!(
        "Egress policy applied: {} allowed CIDRs, {} allowed domains",
        policy.allowed_cidrs.len(),
        policy.allowed_domains.len()
    );
    debug!("Egress policy details: {:?}", policy);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires a private network namespace, netfilter and iptables/ip6tables"]
    fn deny_all_sets_both_kernel_output_policies() {
        use std::os::unix::process::CommandExt;
        match unsafe { nix::unistd::fork().unwrap() } {
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0)
            ),
            nix::unistd::ForkResult::Child => {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
                super::apply_egress_policy(
                    std::process::id(),
                    &[],
                    &super::EgressPolicy::deny_all(),
                    false,
                )
                .unwrap();
                for name in ["iptables", "ip6tables"] {
                    let tool = super::BridgeNetwork::resolve_bin(name).unwrap();
                    let output = std::process::Command::new(tool)
                        .arg0(name)
                        .args(["-S", "OUTPUT"])
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    let rules = String::from_utf8(output.stdout).unwrap();
                    assert!(rules.lines().any(|line| line == "-P OUTPUT DROP"));
                    assert!(rules
                        .lines()
                        .any(|line| line == "-A OUTPUT -o lo -j ACCEPT"));
                    if name == "ip6tables" {
                        assert_eq!(rules.lines().count(), 2);
                    }
                }
                std::process::exit(0);
            }
        }
    }

    #[test]
    fn test_egress_policy_preserves_iptables_applet_argv0() {
        let source = include_str!("egress.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();

        assert!(
            implementation.contains("exec_in_user_netns(pid, &ipt, \"iptables\", args)"),
            "rootless egress policy must preserve iptables argv[0] inside the target namespaces"
        );
        assert!(
            implementation.contains("exec_in_netns(pid, &ipt, \"iptables\", args)"),
            "privileged egress policy must preserve iptables argv[0] inside the target netns"
        );
    }
}
