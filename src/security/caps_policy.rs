//! Capability policy: external TOML-based capability configuration.
//!
//! Allows operators to define capability bounding/ambient/effective/inheritable
//! sets in a standalone TOML file, separate from Nix service definitions.
//!
//! # Example
//!
//! ```toml
//! # Drop everything (default). Empty keep lists = deny all.
//! [bounding]
//! keep = []
//!
//! [ambient]
//! keep = []
//!
//! # Or keep specific capabilities:
//! # [bounding]
//! # keep = ["NET_BIND_SERVICE"]
//! ```

use crate::error::{NucleusError, Result};
use crate::security::{CapabilityManager, CapabilitySets};
use caps::Capability;
use serde::Deserialize;
use tracing::info;

/// Parsed capability policy from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct CapsPolicy {
    /// Bounding set configuration. Empty keep = drop all from bounding.
    #[serde(default)]
    pub bounding: CapSetPolicy,

    /// Ambient set configuration.
    #[serde(default)]
    pub ambient: CapSetPolicy,

    /// Effective set configuration.
    #[serde(default)]
    pub effective: CapSetPolicy,

    /// Inheritable set configuration.
    #[serde(default)]
    pub inheritable: CapSetPolicy,
}

/// Policy for a single capability set.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CapSetPolicy {
    /// Capabilities to keep. Empty list = drop all.
    /// Names use Linux format without CAP_ prefix: e.g. "NET_BIND_SERVICE".
    #[serde(default)]
    pub keep: Vec<String>,
}

/// Capabilities that are too dangerous for container workloads.
/// Rejected in every workload service mode.
pub(super) const DANGEROUS_CAPABILITIES: &[Capability] = &[
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_SYS_MODULE,
    Capability::CAP_SYS_RAWIO,
    Capability::CAP_SYS_PTRACE,
    Capability::CAP_DAC_OVERRIDE,
    Capability::CAP_DAC_READ_SEARCH,
    Capability::CAP_SYS_BOOT,
    Capability::CAP_MAC_ADMIN,
    Capability::CAP_MAC_OVERRIDE,
    Capability::CAP_SYS_PACCT,
    Capability::CAP_LINUX_IMMUTABLE,
    Capability::CAP_BPF,
    Capability::CAP_PERFMON,
    Capability::CAP_NET_ADMIN,
    Capability::CAP_SYS_RESOURCE,
    Capability::CAP_MKNOD,
    Capability::CAP_NET_RAW,
    Capability::CAP_SETUID,
    Capability::CAP_SETGID,
    Capability::CAP_FOWNER,
];

impl CapsPolicy {
    /// Validate a policy without applying it.
    pub fn validate_production(&self) -> Result<()> {
        self.resolve_sets().map(|_| ())
    }

    fn validate_sets(sets: &CapabilitySets) -> Result<()> {
        let all_kept: Vec<&Capability> = sets
            .bounding
            .iter()
            .chain(&sets.permitted)
            .chain(&sets.effective)
            .chain(&sets.inheritable)
            .chain(&sets.ambient)
            .collect();
        let mut rejected = Vec::new();
        for &dangerous in DANGEROUS_CAPABILITIES {
            if all_kept.contains(&&dangerous) {
                rejected.push(format!("{:?}", dangerous));
            }
        }
        if !rejected.is_empty() {
            return Err(NucleusError::ConfigError(format!(
                "Capability policy retains dangerous capabilities: [{}].",
                rejected.join(", ")
            )));
        }
        Ok(())
    }

    /// Apply this policy using the given CapabilityManager.
    ///
    /// If all sets are empty, delegates to `drop_all()`.
    /// Otherwise, applies each set explicitly.
    pub fn apply(&self, mgr: &mut CapabilityManager) -> Result<()> {
        let sets = self.resolve_sets()?;

        if sets.bounding.is_empty()
            && sets.permitted.is_empty()
            && sets.effective.is_empty()
            && sets.inheritable.is_empty()
            && sets.ambient.is_empty()
        {
            info!("Capability policy: drop all");
            mgr.drop_all()
        } else {
            info!("Capability policy: applying explicit sets {:?}", sets);
            mgr.apply_sets(&sets)
        }
    }

    pub(crate) fn resolve_sets(&self) -> Result<CapabilitySets> {
        let bounding = resolve_cap_list(&self.bounding.keep)?;
        let effective = resolve_cap_list(&self.effective.keep)?;
        let ambient = resolve_cap_list(&self.ambient.keep)?;
        let mut inheritable = resolve_cap_list(&self.inheritable.keep)?;
        extend_unique(&mut inheritable, &ambient);

        let mut permitted = Vec::new();
        extend_unique(&mut permitted, &effective);
        extend_unique(&mut permitted, &inheritable);
        extend_unique(&mut permitted, &ambient);

        let sets = CapabilitySets {
            bounding,
            permitted,
            effective,
            inheritable,
            ambient,
        };
        Self::validate_sets(&sets)?;
        Ok(sets)
    }

    /// Resolve all keep lists into a deduplicated set of Capability values.
    #[cfg(test)]
    fn resolve_keep_set(&self) -> Result<Vec<Capability>> {
        let sets = self.resolve_sets()?;
        let mut caps = Vec::new();
        extend_unique(&mut caps, &sets.bounding);
        extend_unique(&mut caps, &sets.permitted);
        extend_unique(&mut caps, &sets.effective);
        extend_unique(&mut caps, &sets.inheritable);
        extend_unique(&mut caps, &sets.ambient);
        Ok(caps)
    }
}

fn resolve_cap_list(names: &[String]) -> Result<Vec<Capability>> {
    let mut caps = Vec::new();
    for name in names {
        let cap = parse_capability_name(name)?;
        if !caps.contains(&cap) {
            caps.push(cap);
        }
    }
    Ok(caps)
}

fn extend_unique(dst: &mut Vec<Capability>, src: &[Capability]) {
    for &cap in src {
        if !dst.contains(&cap) {
            dst.push(cap);
        }
    }
}

/// Parse a capability name string to a `caps::Capability` enum variant.
///
/// Accepts names with or without the `CAP_` prefix:
/// - `"NET_BIND_SERVICE"` or `"CAP_NET_BIND_SERVICE"` both work.
fn parse_capability_name(name: &str) -> Result<Capability> {
    let normalized = name.strip_prefix("CAP_").unwrap_or(name);
    match normalized {
        "CHOWN" => Ok(Capability::CAP_CHOWN),
        "DAC_OVERRIDE" => Ok(Capability::CAP_DAC_OVERRIDE),
        "DAC_READ_SEARCH" => Ok(Capability::CAP_DAC_READ_SEARCH),
        "FOWNER" => Ok(Capability::CAP_FOWNER),
        "FSETID" => Ok(Capability::CAP_FSETID),
        "KILL" => Ok(Capability::CAP_KILL),
        "SETGID" => Ok(Capability::CAP_SETGID),
        "SETUID" => Ok(Capability::CAP_SETUID),
        "SETPCAP" => Ok(Capability::CAP_SETPCAP),
        "LINUX_IMMUTABLE" => Ok(Capability::CAP_LINUX_IMMUTABLE),
        "NET_BIND_SERVICE" => Ok(Capability::CAP_NET_BIND_SERVICE),
        "NET_BROADCAST" => Ok(Capability::CAP_NET_BROADCAST),
        "NET_ADMIN" => Ok(Capability::CAP_NET_ADMIN),
        "NET_RAW" => Ok(Capability::CAP_NET_RAW),
        "IPC_LOCK" => Ok(Capability::CAP_IPC_LOCK),
        "IPC_OWNER" => Ok(Capability::CAP_IPC_OWNER),
        "SYS_MODULE" => Ok(Capability::CAP_SYS_MODULE),
        "SYS_RAWIO" => Ok(Capability::CAP_SYS_RAWIO),
        "SYS_CHROOT" => Ok(Capability::CAP_SYS_CHROOT),
        "SYS_PTRACE" => Ok(Capability::CAP_SYS_PTRACE),
        "SYS_PACCT" => Ok(Capability::CAP_SYS_PACCT),
        "SYS_ADMIN" => Ok(Capability::CAP_SYS_ADMIN),
        "SYS_BOOT" => Ok(Capability::CAP_SYS_BOOT),
        "SYS_NICE" => Ok(Capability::CAP_SYS_NICE),
        "SYS_RESOURCE" => Ok(Capability::CAP_SYS_RESOURCE),
        "SYS_TIME" => Ok(Capability::CAP_SYS_TIME),
        "SYS_TTY_CONFIG" => Ok(Capability::CAP_SYS_TTY_CONFIG),
        "MKNOD" => Ok(Capability::CAP_MKNOD),
        "LEASE" => Ok(Capability::CAP_LEASE),
        "AUDIT_WRITE" => Ok(Capability::CAP_AUDIT_WRITE),
        "AUDIT_CONTROL" => Ok(Capability::CAP_AUDIT_CONTROL),
        "SETFCAP" => Ok(Capability::CAP_SETFCAP),
        "MAC_OVERRIDE" => Ok(Capability::CAP_MAC_OVERRIDE),
        "MAC_ADMIN" => Ok(Capability::CAP_MAC_ADMIN),
        "SYSLOG" => Ok(Capability::CAP_SYSLOG),
        "WAKE_ALARM" => Ok(Capability::CAP_WAKE_ALARM),
        "BLOCK_SUSPEND" => Ok(Capability::CAP_BLOCK_SUSPEND),
        "AUDIT_READ" => Ok(Capability::CAP_AUDIT_READ),
        "PERFMON" => Ok(Capability::CAP_PERFMON),
        "BPF" => Ok(Capability::CAP_BPF),
        "CHECKPOINT_RESTORE" => Ok(Capability::CAP_CHECKPOINT_RESTORE),
        _ => Err(NucleusError::ConfigError(format!(
            "Unknown capability: '{}'. Use Linux names like NET_BIND_SERVICE.",
            name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_drop_all_policy() {
        let toml = r#"
[bounding]
keep = []

[ambient]
keep = []
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        assert!(policy.bounding.keep.is_empty());
        assert!(policy.resolve_keep_set().unwrap().is_empty());
    }

    #[test]
    fn test_parse_keep_some_policy() {
        let toml = r#"
[bounding]
keep = ["NET_BIND_SERVICE", "CHOWN"]
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        let keep = policy.resolve_keep_set().unwrap();
        assert_eq!(keep.len(), 2);
        assert!(keep.contains(&Capability::CAP_NET_BIND_SERVICE));
        assert!(keep.contains(&Capability::CAP_CHOWN));
    }

    #[test]
    fn test_parse_cap_prefix() {
        assert_eq!(
            parse_capability_name("CAP_NET_RAW").unwrap(),
            Capability::CAP_NET_RAW
        );
        assert_eq!(
            parse_capability_name("NET_RAW").unwrap(),
            Capability::CAP_NET_RAW
        );
    }

    #[test]
    fn test_unknown_capability_error() {
        assert!(parse_capability_name("DOES_NOT_EXIST").is_err());
    }

    #[test]
    fn test_default_policy_is_drop_all() {
        let toml = "";
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        assert!(policy.resolve_keep_set().unwrap().is_empty());
    }

    #[test]
    fn test_dedup_across_sets() {
        let toml = r#"
[bounding]
keep = ["CHOWN"]

[effective]
keep = ["CHOWN"]
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        let keep = policy.resolve_keep_set().unwrap();
        assert_eq!(keep.len(), 1);
    }

    #[test]
    fn test_resolve_sets_preserves_set_specificity() {
        let toml = r#"
[bounding]
keep = ["NET_BIND_SERVICE"]

[effective]
keep = ["CHOWN"]

[ambient]
keep = ["NET_BIND_SERVICE"]
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        let resolved = policy.resolve_sets().unwrap();

        assert_eq!(resolved.bounding, vec![Capability::CAP_NET_BIND_SERVICE]);
        assert_eq!(resolved.effective, vec![Capability::CAP_CHOWN]);
        assert_eq!(resolved.ambient, vec![Capability::CAP_NET_BIND_SERVICE]);
        assert_eq!(resolved.inheritable, vec![Capability::CAP_NET_BIND_SERVICE]);
        assert_eq!(
            resolved.permitted,
            vec![Capability::CAP_CHOWN, Capability::CAP_NET_BIND_SERVICE]
        );
    }

    #[test]
    fn test_ambient_caps_promote_into_inheritable_and_permitted() {
        let toml = r#"
[ambient]
keep = ["NET_BIND_SERVICE"]
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();
        let resolved = policy.resolve_sets().unwrap();

        assert_eq!(resolved.ambient, vec![Capability::CAP_NET_BIND_SERVICE]);
        assert_eq!(resolved.inheritable, vec![Capability::CAP_NET_BIND_SERVICE]);
        assert_eq!(resolved.permitted, vec![Capability::CAP_NET_BIND_SERVICE]);
    }

    #[test]
    fn test_validate_production_rejects_newly_classified_dangerous_caps() {
        let toml = r#"
[bounding]
keep = ["NET_RAW", "SETUID", "SETGID", "FOWNER", "MKNOD", "NET_ADMIN", "SYS_RESOURCE"]
"#;
        let policy: CapsPolicy = toml::from_str(toml).unwrap();

        let err = policy.validate_production().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CAP_NET_RAW"));
        assert!(msg.contains("CAP_SETUID"));
        assert!(msg.contains("CAP_SETGID"));
        assert!(msg.contains("CAP_FOWNER"));
        for cap in ["CAP_MKNOD", "CAP_NET_ADMIN", "CAP_SYS_RESOURCE"] {
            assert!(msg.contains(cap));
        }
    }
}
