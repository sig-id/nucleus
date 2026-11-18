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
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use serde::Deserialize;
use tracing::{info, warn};

use super::landlock::{require_abi, TARGET_ABI};
use crate::network::NetworkMode;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockTcp {
    pub bind: Option<Vec<u16>>,
    pub connect: Option<Vec<u16>>,
}

impl LandlockTcp {
    fn for_network(&self, mode: &NetworkMode) -> Self {
        match mode {
            NetworkMode::None => Self {
                bind: Some(vec![]),
                connect: Some(vec![]),
            },
            _ => self.clone(),
        }
    }

    pub(super) fn create_workload_ruleset(&self) -> Result<RulesetCreated> {
        let mut builder = Ruleset::default()
            .handle_access(AccessFs::from_all(TARGET_ABI))
            .map_err(ll_err)?
            .scope(Scope::Signal | Scope::AbstractUnixSocket)
            .map_err(ll_err)?;
        let directions = [
            (AccessNet::BindTcp, &self.bind),
            (AccessNet::ConnectTcp, &self.connect),
        ];
        for (right, ports) in directions {
            if ports.is_some() {
                builder = builder.handle_access(right).map_err(ll_err)?;
            }
        }
        let mut ruleset = builder.create().map_err(ll_err)?;
        for (right, ports) in directions {
            for port in ports.iter().flatten() {
                ruleset = ruleset
                    .add_rule(NetPort::new(*port, right))
                    .map_err(ll_err)?;
            }
        }
        Ok(ruleset)
    }
}

/// Parsed Landlock policy from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockPolicy {
    #[serde(default)]
    pub tcp: LandlockTcp,
    /// Minimum required ABI version (1-6). Default: 3.
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
#[serde(deny_unknown_fields)]
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
        config: &crate::container::ContainerConfig,
    ) -> Result<RulesetStatus> {
        let best_effort =
            best_effort && config.namespaces.net && !matches!(config.network, NetworkMode::Host);
        if !best_effort {
            require_abi(TARGET_ABI as u8)?;
        }
        match self {
            Self::Custom(policy) => policy.apply_with_handoff(
                best_effort,
                Some(handoff),
                &policy.tcp.for_network(&config.network),
                config.service_mode == crate::container::ServiceMode::Production,
            ),
            Self::Default(settings) => settings.clone().apply_with_handoff(
                best_effort,
                Some(handoff),
                &LandlockTcp::default().for_network(&config.network),
            ),
        }
    }
}

impl LandlockPolicy {
    /// Validate the policy for production safety.
    ///
    /// Check configured rule trees before launch. Installation also checks the
    /// resolved paths, bind aliases and pinned inode identities after pivot_root.
    pub fn validate_production(&self) -> Result<()> {
        let mut grants = Vec::new();
        for rule in &self.rules {
            let path = Path::new(&rule.path);
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(NucleusError::ConfigError(format!(
                    "Invalid production Landlock path {path:?}"
                )));
            }
            check_overlap(
                &mut grants,
                path.to_owned(),
                parse_access_flags(&rule.access)?,
            )?;
        }
        Ok(())
    }

    /// Apply this policy, replacing the default hardcoded Landlock rules.
    ///
    /// Returns true if the policy was enforced (fully or partially),
    /// false if not enforced (kernel too old).
    pub fn apply(&self, best_effort: bool) -> Result<bool> {
        self.apply_with_handoff(best_effort, None, &self.tcp, false)
            .map(|status| status != RulesetStatus::NotEnforced)
    }

    fn apply_with_handoff(
        &self,
        best_effort: bool,
        handoff: Option<&std::os::unix::net::UnixStream>,
        tcp: &LandlockTcp,
        production: bool,
    ) -> Result<RulesetStatus> {
        if !(1..=TARGET_ABI as u8).contains(&self.min_abi) {
            return Err(NucleusError::ConfigError(format!(
                "Invalid minimum Landlock ABI {}",
                self.min_abi
            )));
        }
        require_abi(self.min_abi)?;
        // Explicit TCP limits must be enforced even when degradation was requested.
        let best_effort = best_effort && self.tcp.bind.is_none() && self.tcp.connect.is_none();
        let mut ruleset = tcp.create_workload_ruleset()?;
        let mut grants = Vec::new();
        let mut backing_grants = Vec::new();
        let mut inode_grants = Vec::new();
        let proc_dir = PathBuf::from(format!(
            "/proc/{}/task/{}",
            std::process::id(),
            nix::unistd::gettid()
        ));
        let mounts = production
            .then(|| std::fs::read_to_string(proc_dir.join("mountinfo")))
            .transpose()?;
        let mut skipped_rule = false;
        for rule in &self.rules {
            let flags = parse_access_flags(&rule.access)?;
            match PathFd::new(&rule.path) {
                Ok(fd) => {
                    if let Some(mounts) = &mounts {
                        // Compare the exact kernel objects added below, after pivot_root.
                        let n = fd.as_fd().as_raw_fd();
                        let visible = std::fs::read_link(proc_dir.join(format!("fd/{n}")))?;
                        let mut stat = std::mem::MaybeUninit::<libc::statx>::uninit();
                        // SAFETY: statx initializes stat on success and the fd remains pinned.
                        let result = unsafe {
                            libc::statx(
                                n,
                                c"".as_ptr(),
                                libc::AT_EMPTY_PATH,
                                libc::STATX_MNT_ID | libc::STATX_INO,
                                stat.as_mut_ptr(),
                            )
                        };
                        nix::errno::Errno::result(result)?;
                        let stat = unsafe { stat.assume_init() };
                        let required = libc::STATX_MNT_ID | libc::STATX_INO;
                        if stat.stx_mask & required != required {
                            return Err(NucleusError::LandlockError(
                                "Kernel omitted Landlock rule mount or inode identity".into(),
                            ));
                        }
                        let backing = backing_path(mounts, stat.stx_mnt_id, &visible)?;
                        let inode = PathBuf::from(format!(
                            "{}:{}/{}",
                            stat.stx_dev_major, stat.stx_dev_minor, stat.stx_ino
                        ));
                        check_overlap(&mut grants, visible, flags)?;
                        check_overlap(&mut backing_grants, backing, flags)?;
                        check_overlap(&mut inode_grants, inode, flags)?;
                    }
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, flags))
                        .map_err(ll_err)?;
                    info!("Landlock rule: {} => {:?}", rule.path, rule.access);
                }
                Err(e) => {
                    if best_effort {
                        skipped_rule = true;
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
            RulesetStatus::FullyEnforced if skipped_rule => Ok(RulesetStatus::PartiallyEnforced),
            RulesetStatus::FullyEnforced => {
                info!(
                    "Landlock custom policy fully enforced ({} rules)",
                    self.rules.len()
                );
                Ok(status.ruleset)
            }
            RulesetStatus::PartiallyEnforced => {
                if best_effort {
                    info!("Landlock custom policy partially enforced");
                    Ok(status.ruleset)
                } else {
                    Err(NucleusError::LandlockError(
                        "Landlock custom policy only partially enforced; strict mode requires full target ABI support".to_string(),
                    ))
                }
            }
            RulesetStatus::NotEnforced => {
                if best_effort {
                    warn!("Landlock custom policy not enforced (kernel unsupported)");
                    Ok(status.ruleset)
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
            "read" => AccessFs::ReadFile | AccessFs::ReadDir,
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

/// Translate a bind alias into its path within the underlying filesystem.
fn backing_path(mounts: &str, mount_id: u64, visible: &Path) -> Result<PathBuf> {
    let invalid = || {
        NucleusError::LandlockError(format!("Cannot identify mounted Landlock rule {visible:?}"))
    };
    let id = mount_id.to_string();
    for line in mounts.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some(id.as_str()) {
            continue;
        }
        let device = fields.nth(1).ok_or_else(invalid)?;
        let root = crate::filesystem::decode_mountinfo_field(fields.next().ok_or_else(invalid)?);
        let mountpoint =
            crate::filesystem::decode_mountinfo_field(fields.next().ok_or_else(invalid)?);
        let relative = visible.strip_prefix(mountpoint).map_err(|_| invalid())?;
        return Ok(Path::new(device)
            .join(Path::new(&root).strip_prefix("/").map_err(|_| invalid())?)
            .join(relative));
    }
    Err(invalid())
}

/// Landlock grants accumulate at a path and all of its descendants.
fn check_overlap(
    grants: &mut Vec<(PathBuf, bool, bool)>,
    path: PathBuf,
    flags: landlock::BitFlags<AccessFs>,
) -> Result<()> {
    let writable = flags.intersects(AccessFs::WriteFile | AccessFs::Truncate | AccessFs::MakeReg);
    let executable = flags.contains(AccessFs::Execute);
    if writable && executable
        || grants.iter().any(|(other, w, x)| {
            (writable && *x || executable && *w)
                && (path.starts_with(other) || other.starts_with(&path))
        })
    {
        return Err(NucleusError::ConfigError(format!(
            "Overlapping Landlock grants allow write and execute at {path:?}"
        )));
    }
    grants.push((path, writable, executable));
    Ok(())
}

fn ll_err(e: landlock::RulesetError) -> NucleusError {
    NucleusError::LandlockError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_mode_can_only_narrow_explicit_tcp_rules() {
        let tcp: LandlockTcp = toml::from_str("connect = [443]").unwrap();
        let isolated = tcp.for_network(&NetworkMode::None);
        assert_eq!(isolated.bind, Some(vec![]));
        assert_eq!(isolated.connect, Some(vec![]));
        let host = tcp.for_network(&NetworkMode::Host);
        assert_eq!(host.bind, None);
        assert_eq!(host.connect, Some(vec![443]));
        assert!(toml::from_str::<LandlockTcp>("conect = [443]").is_err());
    }

    #[test]
    #[ignore = "requires Landlock ABI 6 and loopback"]
    fn kernel_enforces_tcp_and_ipc_scopes() {
        use nix::sys::signal::{kill, Signal};
        use std::net::{TcpListener, TcpStream};
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
        let abstract_addr =
            |id| SocketAddr::from_abstract_name(format!("nucleus-landlock-{id}")).unwrap();
        if let Ok(ports) = std::env::var("NUCLEUS_TEST_LANDLOCK_PORTS") {
            let (allowed, denied) = ports.split_once(',').unwrap();
            let allowed: u16 = allowed.parse().unwrap();
            let denied: u16 = denied.parse().unwrap();
            let parent = nix::unistd::getppid();
            let outside = abstract_addr(parent.as_raw());
            UnixStream::connect_addr(&outside).unwrap();
            kill(parent, Signal::SIGWINCH).unwrap();

            let policy = LandlockPolicy {
                min_abi: 6,
                rules: vec![],
                tcp: LandlockTcp {
                    bind: Some(vec![0]),
                    connect: Some(vec![allowed]),
                },
            };
            assert!(policy.apply(false).unwrap());
            TcpStream::connect(("127.0.0.1", allowed)).unwrap();
            assert_eq!(
                TcpStream::connect(("127.0.0.1", denied))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
            TcpListener::bind(("127.0.0.1", 0)).unwrap();
            assert_eq!(
                TcpListener::bind(("127.0.0.1", denied))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
            assert_eq!(
                UnixStream::connect_addr(&outside)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(
                kill(parent, Signal::SIGWINCH),
                Err(nix::errno::Errno::EPERM)
            );
            let inside = abstract_addr(nix::unistd::getpid().as_raw());
            let _listener = UnixListener::bind_addr(&inside).unwrap();
            UnixStream::connect_addr(&inside).unwrap();
            return;
        }
        let _listener =
            UnixListener::bind_addr(&abstract_addr(nix::unistd::getpid().as_raw())).unwrap();
        let a = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let b = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "security::landlock_policy::tests::kernel_enforces_tcp_and_ipc_scopes",
            ])
            .env(
                "NUCLEUS_TEST_LANDLOCK_PORTS",
                format!(
                    "{},{}",
                    a.local_addr().unwrap().port(),
                    b.local_addr().unwrap().port()
                ),
            )
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    #[ignore = "requires a private mount namespace and Landlock ABI 6"]
    fn production_checks_bind_aliases_on_installed_rule_fds() {
        use nix::mount::{mount, MsFlags};
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let bin = data.join("bin");
        let alias = dir.path().join("alias");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&alias).unwrap();
        mount(
            Some(&bin),
            &alias,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        let policy = LandlockPolicy {
            min_abi: 6,
            tcp: Default::default(),
            rules: vec![
                LandlockRule {
                    path: data.display().to_string(),
                    access: vec!["write".into()],
                },
                LandlockRule {
                    path: alias.display().to_string(),
                    access: vec!["execute".into()],
                },
            ],
        };
        policy.validate_production().unwrap();
        let err = policy
            .apply_with_handoff(false, None, &policy.tcp, true)
            .unwrap_err();
        assert!(err.to_string().contains("write and execute"), "{err}");
        nix::mount::umount(&alias).unwrap();
    }

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
    fn production_checks_inherited_rights_in_both_directions() {
        for (parent, child) in [("write", "execute"), ("execute", "create")] {
            let mut policy = LandlockPolicy {
                min_abi: 3,
                tcp: LandlockTcp::default(),
                rules: vec![
                    LandlockRule {
                        path: "/data".into(),
                        access: vec![parent.into()],
                    },
                    LandlockRule {
                        path: "/data/bin".into(),
                        access: vec![child.into()],
                    },
                ],
            };
            assert!(policy.validate_production().is_err());
            policy.rules.reverse();
            assert!(policy.validate_production().is_err());
            policy.rules[0].path = "/database/bin".into();
            policy.validate_production().unwrap();
        }
        assert!(!parse_access_flags(&["read".into()])
            .unwrap()
            .contains(AccessFs::Execute));
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
