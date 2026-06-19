//! Dependency DAG resolution with topological sort.
//!
//! Resolves service dependencies into a startup order using Kahn's algorithm.
//! Detects circular dependencies and generates systemd-compatible ordering
//! (After=/Requires= edges).

use crate::error::{NucleusError, Result};
use crate::topology::config::TopologyConfig;
use std::collections::{BTreeMap, VecDeque};

/// A resolved dependency graph with startup ordering.
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    /// Services in topological order (dependencies first).
    pub startup_order: Vec<String>,

    /// For each service, the services it must wait for.
    pub edges: BTreeMap<String, Vec<DependencyEdge>>,

    /// Reverse map: for each service, the services that depend on it.
    pub dependents: BTreeMap<String, Vec<String>>,
}

/// A dependency edge with condition metadata.
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// The upstream service this depends on.
    pub service: String,
    /// Condition: "started" or "healthy".
    pub condition: String,
}

impl DependencyGraph {
    /// Resolve dependencies from a topology config into a startup-ordered graph.
    ///
    /// Returns an error if circular dependencies are detected.
    pub fn resolve(config: &TopologyConfig) -> Result<Self> {
        let services: Vec<String> = config.services.keys().cloned().collect();

        // Build adjacency list and in-degree map
        let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
        let mut edges: BTreeMap<String, Vec<DependencyEdge>> = BTreeMap::new();
        let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for name in &services {
            in_degree.entry(name.clone()).or_insert(0);
            edges.entry(name.clone()).or_default();
            dependents.entry(name.clone()).or_default();
        }

        for (name, svc) in &config.services {
            for dep in &svc.depends_on {
                if !config.services.contains_key(&dep.service) {
                    return Err(NucleusError::ConfigError(format!(
                        "Service '{}' depends on undefined service '{}'",
                        name, dep.service
                    )));
                }
                *in_degree.entry(name.clone()).or_insert(0) += 1;
                edges.entry(name.clone()).or_default().push(DependencyEdge {
                    service: dep.service.clone(),
                    condition: dep.condition.clone(),
                });
                dependents
                    .entry(dep.service.clone())
                    .or_default()
                    .push(name.clone());
            }
        }

        // Kahn's algorithm for topological sort
        let mut queue: VecDeque<String> = VecDeque::new();
        for (name, &degree) in &in_degree {
            if degree == 0 {
                queue.push_back(name.clone());
            }
        }

        let mut order = Vec::new();
        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            if let Some(deps) = dependents.get(&node) {
                for dependent in deps {
                    if let Some(degree) = in_degree.get_mut(dependent) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(dependent.clone());
                        }
                    }
                }
            }
        }

        if order.len() != services.len() {
            let remaining: Vec<&String> = services.iter().filter(|s| !order.contains(s)).collect();
            return Err(NucleusError::ConfigError(format!(
                "Circular dependency detected among services: {:?}",
                remaining
            )));
        }

        Ok(Self {
            startup_order: order,
            edges,
            dependents,
        })
    }

    /// Get the shutdown order (reverse of startup order).
    pub fn shutdown_order(&self) -> Vec<String> {
        let mut order = self.startup_order.clone();
        order.reverse();
        order
    }

    /// Generate systemd unit dependency directives for a service.
    ///
    /// Returns (After, Requires) string pairs suitable for systemd unit files.
    pub fn systemd_deps(&self, service: &str, topology_name: &str) -> (Vec<String>, Vec<String>) {
        let mut after = Vec::new();
        let mut requires = Vec::new();

        if let Some(deps) = self.edges.get(service) {
            for dep in deps {
                let unit = format!("nucleus-{}-{}.service", topology_name, dep.service);
                after.push(unit.clone());
                if dep.condition == "healthy" {
                    // For health-conditioned deps, use Type=notify + Requires
                    requires.push(unit);
                }
            }
        }

        (after, requires)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_topology(deps: &[(&str, &[(&str, &str)])]) -> TopologyConfig {
        use crate::topology::config::*;
        let mut services = BTreeMap::new();
        for (name, dep_list) in deps {
            let depends_on = dep_list
                .iter()
                .map(|(svc, cond)| DependsOn {
                    service: svc.to_string(),
                    condition: cond.to_string(),
                })
                .collect();
            services.insert(
                name.to_string(),
                ServiceDef {
                    rootfs: format!("/nix/store/{}", name),
                    command: vec![format!("/bin/{}", name)],
                    memory: "256M".to_string(),
                    cpus: 1.0,
                    pids: 512,
                    networks: vec![],
                    volumes: vec![],
                    depends_on,
                    health_check: None,
                    health_interval: 30,
                    egress_allow: vec![],
                    egress_domains: vec![],
                    egress_tcp_ports: vec![],
                    egress_udp_ports: vec![],
                    credential_broker: None,
                    credential_broker_no_proxy_env: false,
                    port_forwards: vec![],
                    environment: BTreeMap::new(),
                    user: None,
                    group: None,
                    additional_groups: vec![],
                    secrets: vec![],
                    dns: vec![],
                    nat_backend: crate::network::NatBackend::Auto,
                    replicas: 1,
                    runtime: "native".to_string(),
                },
            );
        }

        TopologyConfig {
            name: "test".to_string(),
            networks: BTreeMap::new(),
            volumes: BTreeMap::new(),
            services,
        }
    }

    #[test]
    fn test_linear_dependency() {
        let config = make_topology(&[
            ("db", &[]),
            ("cache", &[("db", "healthy")]),
            ("web", &[("cache", "started")]),
        ]);

        let graph = DependencyGraph::resolve(&config).unwrap();
        assert_eq!(graph.startup_order, vec!["db", "cache", "web"]);
        assert_eq!(graph.shutdown_order(), vec!["web", "cache", "db"]);
    }

    #[test]
    fn test_diamond_dependency() {
        let config = make_topology(&[
            ("db", &[]),
            ("cache", &[("db", "started")]),
            ("worker", &[("db", "started")]),
            ("web", &[("cache", "started"), ("worker", "started")]),
        ]);

        let graph = DependencyGraph::resolve(&config).unwrap();
        // db must be first, web must be last
        assert_eq!(graph.startup_order[0], "db");
        assert_eq!(graph.startup_order[3], "web");
    }

    #[test]
    fn test_circular_dependency_detected() {
        let config = make_topology(&[("a", &[("b", "started")]), ("b", &[("a", "started")])]);

        let result = DependencyGraph::resolve(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular"));
    }

    #[test]
    fn test_no_dependencies() {
        let config = make_topology(&[("a", &[]), ("b", &[]), ("c", &[])]);

        let graph = DependencyGraph::resolve(&config).unwrap();
        assert_eq!(graph.startup_order.len(), 3);
    }

    #[test]
    fn test_systemd_deps() {
        let config = make_topology(&[("db", &[]), ("web", &[("db", "healthy")])]);

        let graph = DependencyGraph::resolve(&config).unwrap();
        let (after, requires) = graph.systemd_deps("web", "myapp");
        assert_eq!(after, vec!["nucleus-myapp-db.service"]);
        assert_eq!(requires, vec!["nucleus-myapp-db.service"]);
    }

    #[test]
    fn test_missing_dependency_gives_clear_error() {
        // BUG-05: When a service depends on an undefined service, the error
        // must say "undefined service", not "circular dependency"
        let config = make_topology(&[("web", &[("nonexistent", "started")])]);
        let result = DependencyGraph::resolve(&config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("undefined")
                || err_msg.contains("unknown")
                || err_msg.contains("not found"),
            "Error for missing dependency must mention 'undefined/unknown/not found', got: {}",
            err_msg
        );
        // Must NOT say "circular"
        assert!(
            !err_msg.contains("ircular"),
            "Missing dependency must not be reported as circular, got: {}",
            err_msg
        );
    }
}
