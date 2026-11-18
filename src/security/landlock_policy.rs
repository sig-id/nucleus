//! Landlock policy: external TOML-based filesystem access rules.
//!
//! Allows operators to define per-service Landlock rules in a standalone
//! TOML file, replacing the hardcoded default policy.
//!
//! # Example
//!
//! ```toml
//! min_abi = 3
//!
//! [[rules]]
//! path = "/bin"
//! access = ["read", "execute"]
//!
//! [[rules]]
//! path = "/tmp"
//! access = ["read", "write", "create", "remove"]
//!
//! [[rules]]
//! path = "/run/secrets"
//! access = ["read"]
//! ```

use crate::error::{NucleusError, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use serde::Deserialize;
use tracing::{info, warn};

/// Target ABI for access flag construction.
const TARGET_ABI: ABI = ABI::V5;

/// Parsed Landlock policy from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct LandlockPolicy {
    /// Minimum required ABI version (1-5). Default: 3.
    #[serde(default = "default_min_abi")]
    pub min_abi: u8,

    /// Filesystem access rules.
    #[serde(default)]
    pub rules: Vec<LandlockRule>,
}

fn default_min_abi() -> u8 {
    3
}

/// A single filesystem access rule.
#[derive(Debug, Clone, Deserialize)]
pub struct LandlockRule {
    /// Path to grant access to.
    pub path: String,

    /// Access permissions: "read", "write", "execute", "create", "remove", "readdir".
    pub access: Vec<String>,
}

/// Snapshot of the filesystem grant configuration for launch and native helpers.
#[derive(Debug, Clone)]
pub enum NativeLandlock {
    Default(super::LandlockManager),
    Custom(LandlockPolicy),
}

impl NativeLandlock {
    pub(crate) fn apply(
        &self,
        best_effort: bool,
        handoff: &std::os::unix::net::UnixStream,
    ) -> Result<bool> {
        match self {
            Self::Custom(policy) => policy.apply_with_handoff(best_effort, Some(handoff)),
            Self::Default(settings) => settings
                .clone()
                .apply_with_handoff(best_effort, Some(handoff)),
        }
    }
}

impl LandlockPolicy {
    /// Validate the policy for production safety.
    ///
    /// Rejects rules that grant both write and execute on the same path,
    /// as this enables drop-and-exec attacks.
    pub fn validate_production(&self) -> Result<()> {
        for rule in &self.rules {
            let flags = parse_access_flags(&rule.access)?;
            let has_write =
                flags.contains(AccessFs::WriteFile) || flags.contains(AccessFs::MakeReg);
            let has_execute = flags.contains(AccessFs::Execute);
            if has_write && has_execute {
                return Err(NucleusError::ConfigError(format!(
                    "Landlock policy grants both write and execute on '{}'. \
                     This enables drop-and-exec attacks. Use separate rules or \
                     'all_except_execute' for writable paths.",
                    rule.path
                )));
            }
        }
        Ok(())
    }

    /// Apply this policy, replacing the default hardcoded Landlock rules.
    ///
    /// Returns true if the policy was enforced (fully or partially),
    /// false if not enforced (kernel too old).
    pub fn apply(&self, best_effort: bool) -> Result<bool> {
        self.apply_with_handoff(best_effort, None)
    }

    fn apply_with_handoff(
        &self,
        best_effort: bool,
        handoff: Option<&std::os::unix::net::UnixStream>,
    ) -> Result<bool> {
        let access_all = AccessFs::from_all(TARGET_ABI);

        // Check minimum ABI
        let min_abi_enum = abi_from_version(self.min_abi)?;
        match Ruleset::default().handle_access(AccessFs::from_all(min_abi_enum)) {
            Ok(_) => {
                info!("Landlock ABI >= V{} confirmed", self.min_abi);
            }
            Err(e) => {
                let msg = format!(
                    "Kernel Landlock ABI below required V{}: {}",
                    self.min_abi, e
                );
                if best_effort {
                    warn!("{}", msg);
                    return Ok(false);
                } else {
                    return Err(NucleusError::LandlockError(msg));
                }
            }
        }

        let mut ruleset = Ruleset::default()
            .handle_access(access_all)
            .map_err(ll_err)?
            .create()
            .map_err(ll_err)?;

        for rule in &self.rules {
            let flags = parse_access_flags(&rule.access)?;
            match PathFd::new(&rule.path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, flags))
                        .map_err(ll_err)?;
                    info!("Landlock rule: {} => {:?}", rule.path, rule.access);
                }
                Err(e) => {
                    if best_effort {
                        warn!(
                            "Skipping Landlock rule for {:?} (path not accessible: {})",
                            rule.path, e
                        );
                    } else {
                        return Err(NucleusError::LandlockError(format!(
                            "Cannot open path {:?} for Landlock rule: {}",
                            rule.path, e
                        )));
                    }
                }
            }
        }

        let status = super::landlock_handoff::restrict_and_publish(ruleset, handoff)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                info!(
                    "Landlock custom policy fully enforced ({} rules)",
                    self.rules.len()
                );
                Ok(true)
            }
            RulesetStatus::PartiallyEnforced => {
                if best_effort {
                    info!("Landlock custom policy partially enforced");
                    Ok(true)
                } else {
                    Err(NucleusError::LandlockError(
                        "Landlock custom policy only partially enforced; strict mode requires full target ABI support".to_string(),
                    ))
                }
            }
            RulesetStatus::NotEnforced => {
                if best_effort {
                    warn!("Landlock custom policy not enforced (kernel unsupported)");
                    Ok(false)
                } else {
                    Err(NucleusError::LandlockError(
                        "Landlock custom policy not enforced (kernel unsupported) \
                         and best_effort=false"
                            .to_string(),
                    ))
                }
            }
        }
    }
}

/// Parse access flag strings into AccessFs bitflags.
fn parse_access_flags(names: &[String]) -> Result<landlock::BitFlags<AccessFs>> {
    let mut flags: landlock::BitFlags<AccessFs> = landlock::BitFlags::empty();
    for name in names {
        let flag: landlock::BitFlags<AccessFs> = match name.as_str() {
            "read" => AccessFs::from_read(TARGET_ABI),
            "write" => AccessFs::WriteFile | AccessFs::Truncate,
            "execute" => AccessFs::Execute.into(),
            "create" => {
                AccessFs::MakeChar
                    | AccessFs::MakeDir
                    | AccessFs::MakeReg
                    | AccessFs::MakeSock
                    | AccessFs::MakeFifo
                    | AccessFs::MakeSym
                    | AccessFs::MakeBlock
            }
            "remove" => AccessFs::RemoveDir | AccessFs::RemoveFile,
            "readdir" => AccessFs::ReadDir.into(),
            "all" => {
                tracing::warn!(
                    "Landlock policy uses 'all' access flag which includes Execute. \
                     Consider 'all_except_execute' for writable paths to prevent \
                     drop-and-exec attacks."
                );
                AccessFs::from_all(TARGET_ABI)
            }
            "all_except_execute" => {
                let mut a = AccessFs::from_all(TARGET_ABI);
                a.remove(AccessFs::Execute);
                a
            }
            _ => {
                return Err(NucleusError::ConfigError(format!(
                    "Unknown Landlock access flag: '{}'. Valid: read, write, execute, create, remove, readdir, all, all_except_execute",
                    name
                )));
            }
        };
        flags |= flag;
    }
    Ok(flags)
}

/// Convert a numeric ABI version (1-5) to the landlock crate enum.
fn abi_from_version(version: u8) -> Result<ABI> {
    match version {
        1 => Ok(ABI::V1),
        2 => Ok(ABI::V2),
        3 => Ok(ABI::V3),
        4 => Ok(ABI::V4),
        5 => Ok(ABI::V5),
        _ => Err(NucleusError::ConfigError(format!(
            "Invalid Landlock ABI version: {}. Valid: 1-5",
            version
        ))),
    }
}

fn ll_err(e: landlock::RulesetError) -> NucleusError {
    NucleusError::LandlockError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_policy() {
        let toml = r#"
[[rules]]
path = "/tmp"
access = ["read", "write"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 3);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].path, "/tmp");
    }

    #[test]
    fn test_parse_full_policy() {
        let toml = r#"
min_abi = 5

[[rules]]
path = "/bin"
access = ["read", "execute"]

[[rules]]
path = "/etc"
access = ["read"]

[[rules]]
path = "/tmp"
access = ["read", "write", "create", "remove"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 5);
        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn test_parse_access_flags_valid() {
        let flags = parse_access_flags(&["read".into(), "execute".into()]);
        assert!(flags.is_ok());
    }

    #[test]
    fn test_parse_access_flags_invalid() {
        let flags = parse_access_flags(&["destroy".into()]);
        assert!(flags.is_err());
    }

    #[test]
    fn test_abi_from_version() {
        assert!(matches!(abi_from_version(1), Ok(ABI::V1)));
        assert!(matches!(abi_from_version(5), Ok(ABI::V5)));
        assert!(abi_from_version(0).is_err());
        assert!(abi_from_version(6).is_err());
    }

    #[test]
    fn test_all_except_execute_excludes_execute() {
        let flags = parse_access_flags(&["all_except_execute".into()]).unwrap();
        assert!(
            !flags.contains(AccessFs::Execute),
            "all_except_execute must not include Execute"
        );
        assert!(
            flags.contains(AccessFs::WriteFile),
            "all_except_execute must include WriteFile"
        );
        assert!(
            flags.contains(AccessFs::ReadFile),
            "all_except_execute must include ReadFile"
        );
    }

    #[test]
    fn test_all_includes_execute() {
        let flags = parse_access_flags(&["all".into()]).unwrap();
        assert!(
            flags.contains(AccessFs::Execute),
            "all must include Execute"
        );
    }

    #[test]
    fn test_default_min_abi() {
        let toml = r#"
[[rules]]
path = "/"
access = ["readdir"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 3);
    }
}
