use crate::container::{ContainerConfig, KernelLockdownMode};
use crate::error::{NucleusError, Result};
use crate::network::NetworkMode;
use crate::security::{GVisorRuntime, SeccompDenyLogger, SeccompTraceReader};
use std::path::Path;
use tracing::{info, warn};

use super::runtime::Container;

impl Container {
    pub(super) fn allow_degraded_security(config: &ContainerConfig) -> bool {
        if std::env::var("NUCLEUS_ALLOW_DEGRADED_SECURITY")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
            && !config.allow_degraded_security
        {
            warn!(
                "Ignoring NUCLEUS_ALLOW_DEGRADED_SECURITY environment variable; use \
                 --allow-degraded-security for explicit opt-in"
            );
        }
        config.allow_degraded_security
    }

    pub(super) fn apply_trust_level_guards(config: &mut ContainerConfig) -> Result<()> {
        use crate::container::TrustLevel;

        match config.trust_level {
            TrustLevel::Trusted => Ok(()),
            TrustLevel::Untrusted => {
                // Native host networking collapses the network isolation
                // boundary and is never acceptable for untrusted workloads.
                // The explicit gvisor-host mode keeps gVisor as the runtime
                // boundary while opting out of network namespace isolation.
                if matches!(config.network, NetworkMode::Host) {
                    return Err(NucleusError::ConfigError(
                        "Untrusted workloads cannot use native host network mode. Use \
                         --network gvisor-host with --runtime gvisor and --allow-host-network, \
                         or set --trust-level trusted to override."
                            .to_string(),
                    ));
                }

                if matches!(config.network, NetworkMode::GVisorHost)
                    && !(config.use_gvisor && config.allow_host_network)
                {
                    return Err(NucleusError::ConfigError(
                        "Untrusted workloads require --runtime gvisor and --allow-host-network \
                         for --network gvisor-host. Set --trust-level trusted to override."
                            .to_string(),
                    ));
                }

                if !config.use_gvisor {
                    if config.broker_socket.is_some() {
                        // gVisor cannot confine connections to the broker
                        // socket, and running natively is a trust decision.
                        return Err(NucleusError::ConfigError(
                            "--broker-socket is not supported with the gVisor runtime that \
                             untrusted workloads require. Pass --trust-level trusted with \
                             --runtime native to use the broker."
                                .to_string(),
                        ));
                    }
                    if GVisorRuntime::is_available() {
                        info!(
                            "Untrusted workload: auto-enabling gVisor runtime \
                             (runsc detected on PATH)"
                        );
                        config.use_gvisor = true;
                    } else if config.allow_degraded_security {
                        warn!(
                            "Untrusted workload without gVisor: running with \
                             degraded isolation (native kernel only). \
                             Install runsc for full protection."
                        );
                    } else {
                        return Err(NucleusError::ConfigError(
                            "Untrusted workloads require gVisor (runsc). \
                             Install runsc: https://gvisor.dev/docs/user_guide/install/ \
                             – or pass --allow-degraded-security to run with native \
                             kernel isolation only, or --trust-level trusted to skip \
                             this check."
                                .to_string(),
                        ));
                    }
                }

                Ok(())
            }
        }
    }

    pub(super) fn apply_network_mode_guards(
        config: &mut ContainerConfig,
        _is_root: bool,
    ) -> Result<()> {
        match &config.network {
            NetworkMode::Host => {
                if config.use_gvisor {
                    return Err(NucleusError::NetworkError(
                        "gVisor host networking requires --network gvisor-host; --network host is native host networking"
                            .to_string(),
                    ));
                }
                if !config.allow_host_network {
                    return Err(NucleusError::NetworkError(
                        "Host network mode requires explicit opt-in: pass --allow-host-network"
                            .to_string(),
                    ));
                }
                warn!(
                    "Host network mode enabled: container shares host network namespace and can \
                     access localhost services, scan LAN-reachable endpoints, and bypass network \
                     namespace isolation"
                );
                info!("Host network mode: skipping network namespace");
                config.namespaces.net = false;
            }
            NetworkMode::GVisorHost => {
                if !config.use_gvisor {
                    return Err(NucleusError::NetworkError(
                        "gVisor host network mode requires --runtime gvisor".to_string(),
                    ));
                }
                if !config.allow_host_network {
                    return Err(NucleusError::NetworkError(
                        "gVisor host network mode requires explicit opt-in: pass --allow-host-network"
                            .to_string(),
                    ));
                }
                warn!(
                    "gVisor host network mode enabled: runsc uses hostinet and the OCI network \
                     namespace is omitted, weakening network isolation"
                );
                info!("gVisor host network mode: preserving config namespace state for OCI setup");
            }
            NetworkMode::None | NetworkMode::Bridge(_) => {}
        }
        Ok(())
    }

    pub(super) fn assert_kernel_lockdown(config: &ContainerConfig) -> Result<()> {
        let Some(required) = config.required_kernel_lockdown else {
            return Ok(());
        };

        let path = "/sys/kernel/security/lockdown";
        let content = std::fs::read_to_string(path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Kernel lockdown assertion requested, but {} could not be read: {}",
                path, e
            ))
        })?;

        let active = Self::parse_active_lockdown_mode(&content).ok_or_else(|| {
            NucleusError::ConfigError(format!(
                "Kernel lockdown assertion requested, but active mode could not be parsed from {}",
                path
            ))
        })?;

        if required.accepts(active) {
            info!(
                required = required.as_str(),
                active = active.as_str(),
                "Kernel lockdown requirement satisfied"
            );
            Ok(())
        } else {
            Err(NucleusError::ConfigError(format!(
                "Kernel lockdown mode '{}' does not satisfy required mode '{}'",
                active.as_str(),
                required.as_str()
            )))
        }
    }

    pub(super) fn parse_active_lockdown_mode(content: &str) -> Option<KernelLockdownMode> {
        let start = content.find('[')?;
        let end = content[start + 1..].find(']')?;
        match &content[start + 1..start + 1 + end] {
            "integrity" => Some(KernelLockdownMode::Integrity),
            "confidentiality" => Some(KernelLockdownMode::Confidentiality),
            _ => None,
        }
    }

    pub(super) fn maybe_start_seccomp_trace_reader(
        config: &ContainerConfig,
        target_pid: u32,
        cgroup_path: Option<&Path>,
    ) -> Result<Option<SeccompTraceReader>> {
        if config.seccomp_mode != crate::container::config::SeccompMode::Trace {
            return Ok(None);
        }

        let log_path = config.seccomp_trace_log.as_ref().ok_or_else(|| {
            NucleusError::ConfigError(
                "Seccomp trace mode requires --seccomp-log / seccomp_trace_log".to_string(),
            )
        })?;

        let mut reader = SeccompTraceReader::new(target_pid, log_path);
        reader.start_scoped(cgroup_path.map(Path::to_owned))?;
        Ok(Some(reader))
    }

    pub(super) fn maybe_start_seccomp_deny_logger(
        config: &ContainerConfig,
        target_pid: u32,
        cgroup_path: Option<&Path>,
    ) -> Result<Option<SeccompDenyLogger>> {
        if !config.seccomp_log_denied {
            return Ok(None);
        }
        if config.seccomp_mode == crate::container::config::SeccompMode::Trace {
            // Trace mode already logs everything; deny logger would be redundant
            return Ok(None);
        }

        let mut logger = SeccompDenyLogger::new(target_pid, cgroup_path.map(Path::to_path_buf));
        logger.start()?;
        Ok(Some(logger))
    }
}
