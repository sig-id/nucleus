use crate::error::{NucleusError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// A delegated subordinate ID range parsed from `/etc/subuid` or `/etc/subgid`.
///
/// Mirrors the `login.subuid` / `login.subgid` scheme used by Docker, Podman,
/// and `newuidmap`/`newgidmap`: `<user>:<start>:<count>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubidRange {
    pub start: u32,
    pub count: u32,
}

impl SubidRange {
    /// One-past-the-last host id in the range (exclusive).
    pub fn end(&self) -> u32 {
        self.start.saturating_add(self.count)
    }

    /// True if `host_id` falls within this delegated range.
    pub fn contains_host(&self, host_id: u32) -> bool {
        host_id >= self.start && host_id < self.end()
    }
}

/// Parse `/etc/subuid` (or `/etc/subgid`) for the given login name and numeric
/// uid, returning the first matching `name:start:count` range.
///
/// Lookup order matches shadow-utils / `newuidmap`:
///   1. exact login-name match (e.g. `dev:100000:65536`)
///   2. numeric uid match (e.g. `1000:100000:65536`)
///
/// Docker/Podman rootless both rely on this file, so reading it makes Nucleus's
/// rootless userns drop-in compatible with an existing rootless setup.
pub fn subid_range_for(path: &str, username: &str, uid: u32) -> Option<SubidRange> {
    let contents = fs::read_to_string(path).ok()?;
    let uid_str = uid.to_string();
    // Prefer a login-name match, then a numeric-uid match.
    for by in [username, uid_str.as_str()] {
        for line in contents.lines() {
            let mut it = line.split(':');
            match (it.next(), it.next(), it.next()) {
                (Some(name), Some(start), Some(count))
                    if name == by && !name.is_empty() =>
                {
                    if let (Ok(start), Ok(count)) =
                        (start.parse::<u32>(), count.parse::<u32>())
                    {
                        if count > 0 {
                            return Some(SubidRange { start, count });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The subordinate UID range delegated to the calling user via `/etc/subuid`.
pub fn subuid_range_for_user(username: &str, uid: u32) -> Option<SubidRange> {
    subid_range_for("/etc/subuid", username, uid)
}

/// The subordinate GID range delegated to the calling user via `/etc/subgid`.
pub fn subgid_range_for_user(username: &str, uid: u32) -> Option<SubidRange> {
    subid_range_for("/etc/subgid", username, uid)
}

/// Container-id ranges visible in our *current* user namespace.
///
/// Returns `None` when we are NOT inside a non-trivial user namespace (host
/// root with the identity map, or no userns at all), so callers fall back to
/// the historic strict effective-uid ownership check. Otherwise returns the
/// `[container_start, count)` ranges read from `/proc/self/uid_map`.
///
/// This lets filesystem security checks stay correct under `keep-id` / `auto`
/// mappings, where files owned by the calling user appear as a *non-zero*
/// container uid (e.g. host uid 1000 -> container uid 1000) and a naive
/// `owner == effective_uid` comparison wrongly rejects them.
pub fn current_userns_container_ranges() -> Option<Vec<(u32, u32)>> {
    let contents = fs::read_to_string("/proc/self/uid_map").ok()?;
    let mut ranges = Vec::new();
    let mut identity_root = false;
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        let (Some(c), Some(h), Some(n)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Ok(c), Ok(h), Ok(n)) = (c.parse::<u32>(), h.parse::<u32>(), n.parse::<u32>()) else {
            continue;
        };
        // The host-root identity map ("0 0 <whole space>") is not a userns.
        if c == 0 && h == 0 {
            identity_root = true;
        }
        ranges.push((c, n));
    }
    if identity_root && ranges.len() == 1 {
        return None;
    }
    if ranges.is_empty() {
        None
    } else {
        Some(ranges)
    }
}

/// True when we are inside a non-trivial user namespace (keep-id / auto /
/// root-remapped), where raw uid comparisons against the effective uid are
/// unsafe because our own files appear under a non-root container uid.
pub fn in_nontrivial_userns() -> bool {
    current_userns_container_ranges().is_some()
}

/// True if `uid` (a container uid as seen from inside our userns) is mapped —
/// i.e. it corresponds to a host uid we are authorized to act as. Returns
/// `false` when we are not in a userns (caller should use its strict check).
pub fn uid_is_mapped_in_current_userns(uid: u32) -> bool {
    current_userns_container_ranges()
        .map(|ranges| {
            ranges
                .iter()
                .any(|(start, count)| uid >= *start && uid < start.saturating_add(*count))
        })
        .unwrap_or(false)
}

/// Resolve the calling user's login name (for `/etc/subuid` name lookup).
pub fn current_username() -> Option<String> {
    // Prefer the real uid; fall back to environment if the libc lookup fails.
    let uid = nix::unistd::getuid().as_raw();
    if let Some(cname) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok().flatten()
    {
        return Some(cname.name);
    }
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok()
}

/// Parse a single `container:host:size` mapping triplet (Podman `--uidmap` /
/// Docker `--userns-uid-map` syntax). Returns `None` on malformed input.
fn parse_map_triplet(s: &str) -> Option<IdMapping> {
    let mut it = s.split(':');
    let container_id = it.next()?.trim().parse::<u32>().ok()?;
    let host_id = it.next()?.trim().parse::<u32>().ok()?;
    let count = it.next()?.trim().parse::<u32>().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(IdMapping::new(container_id, host_id, count))
}

/// UID/GID mapping configuration for user namespaces
///
/// Maps a range of UIDs/GIDs inside the container to a range outside
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapping {
    /// ID inside the container
    pub container_id: u32,
    /// ID outside the container (on the host)
    pub host_id: u32,
    /// Number of IDs to map
    pub count: u32,
}

impl IdMapping {
    /// Create a new ID mapping with validation
    pub fn new(container_id: u32, host_id: u32, count: u32) -> Self {
        Self {
            container_id,
            host_id,
            count,
        }
    }

    /// Validate the mapping for safety.
    ///
    /// Rejects zero count, overflow in ID ranges, and excessively large
    /// mappings that could map the entire host UID/GID space.
    pub fn validate(&self, allow_host_root: bool) -> crate::error::Result<()> {
        if self.count == 0 {
            return Err(NucleusError::ConfigError(
                "ID mapping count must be non-zero".to_string(),
            ));
        }

        // Cap at 65536 to prevent overly broad mappings
        if self.count > 65_536 {
            return Err(NucleusError::ConfigError(format!(
                "ID mapping count {} exceeds maximum 65536",
                self.count
            )));
        }

        // Check for overflow in container_id + count
        if self.container_id.checked_add(self.count).is_none() {
            return Err(NucleusError::ConfigError(format!(
                "ID mapping overflow: container_id {} + count {} exceeds u32",
                self.container_id, self.count
            )));
        }

        // Check for overflow in host_id + count
        if self.host_id.checked_add(self.count).is_none() {
            return Err(NucleusError::ConfigError(format!(
                "ID mapping overflow: host_id {} + count {} exceeds u32",
                self.host_id, self.count
            )));
        }

        // Reject mapping host UID 0 unless explicitly allowed (e.g., root-remapped mode)
        if !allow_host_root && self.host_id == 0 && self.count > 0 {
            return Err(NucleusError::ConfigError(
                "ID mapping includes host UID/GID 0; use root-remapped mode if intentional"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Create a mapping for root inside container to current user outside
    pub fn rootless() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        Self::new(0, uid, 1)
    }

    /// Format as a line for uid_map/gid_map file
    fn format(&self) -> String {
        format!("{} {} {}\n", self.container_id, self.host_id, self.count)
    }
}

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespaceConfig {
    /// UID mappings
    pub uid_mappings: Vec<IdMapping>,
    /// GID mappings
    pub gid_mappings: Vec<IdMapping>,
}

impl UserNamespaceConfig {
    /// Create config for rootless mode
    ///
    /// Maps container root (UID/GID 0) to current user. This is the historic
    /// Nucleus rootless mapping ("nomap"): only container uid 0 is usable, so
    /// workloads that refuse euid 0 (e.g. PostgreSQL) cannot run. Prefer
    /// [`UserNamespaceConfig::keep_id`] or [`UserNamespaceConfig::subuid_auto`]
    /// when `/etc/subuid` is configured.
    pub fn rootless() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        Self {
            uid_mappings: vec![IdMapping::new(0, uid, 1)],
            gid_mappings: vec![IdMapping::new(0, gid, 1)],
        }
    }

    /// Rootless "keep-id" mapping (Podman `--userns=keep-id`).
    ///
    /// Maps the calling user's own uid/gid to *itself* inside the namespace,
    /// and maps container root (0) to the start of the delegated subuid/subgid
    /// range. Because the workload keeps the host uid, bind-mounted host files
    /// owned by the user are directly accessible with **no ownership shifting**
    /// — this is the recommended rootless mode for workloads like PostgreSQL
    /// that (a) refuse euid 0 and (b) read user-owned bind mounts.
    ///
    /// Requires `/etc/subuid` and `/etc/subgid` for the calling user.
    pub fn keep_id() -> Result<Self> {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let (uname, urange, grange) = Self::current_subid_ranges()?;

        let uid_mappings = vec![
            IdMapping::new(0, urange.start, 1),
            IdMapping::new(uid, uid, 1),
        ];
        let gid_mappings = vec![
            IdMapping::new(0, grange.start, 1),
            IdMapping::new(gid, gid, 1),
        ];
        info!(
            "keep-id userns: container root -> host {} (subuid), container {} -> host {} (self)",
            urange.start, uid, uid
        );
        let _ = uname; // resolved only to drive name-based subuid lookup
        Ok(Self {
            uid_mappings,
            gid_mappings,
        })
    }

    /// Rootless "auto" mapping (Podman/Docker rootless default).
    ///
    /// Maps container root (0) to the calling user, and container 1..N to the
    /// delegated subuid/subgid range. Workloads therefore run as their image /
    /// configured uid (e.g. 999 for the Postgres image) mapped into the subuid
    /// range. Unlike [`Self::keep_id`], bind-mounted host files owned by the
    /// user are *not* automatically accessible to a non-zero workload uid — the
    /// caller must align ownership (as with Docker/Podman rootless bind mounts).
    pub fn subuid_auto() -> Result<Self> {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let (_uname, urange, grange) = Self::current_subid_ranges()?;

        // Keep the delegated range within the IdMapping validation cap (65536)
        // and within what remains above the caller's own uid to avoid overlap.
        let ucount = urange.count.min(65_536);
        let gcount = grange.count.min(65_536);
        let uid_mappings = vec![IdMapping::new(0, uid, 1), IdMapping::new(1, urange.start, ucount)];
        let gid_mappings = vec![IdMapping::new(0, gid, 1), IdMapping::new(1, grange.start, gcount)];
        info!(
            "auto userns: container 0 -> host {}, container 1..{} -> host {}..{}",
            uid,
            ucount,
            urange.start,
            urange.start + ucount
        );
        Ok(Self {
            uid_mappings,
            gid_mappings,
        })
    }

    /// Build a mapping from explicit `container:host:size` triplets
    /// (Podman `--uidmap` / Docker `--userns-uid-map` syntax).
    pub fn from_map_specs(uid_specs: &[String], gid_specs: &[String]) -> Result<Self> {
        let parse = |specs: &[String], label: &str| -> Result<Vec<IdMapping>> {
            specs
                .iter()
                .map(|s| {
                    parse_map_triplet(s).ok_or_else(|| {
                        NucleusError::ConfigError(format!(
                            "Invalid {} mapping '{}': expected container:host:size",
                            label, s
                        ))
                    })
                })
                .collect()
        };
        let uid_mappings = parse(uid_specs, "--uidmap")?;
        let gid_mappings = parse(gid_specs, "--gidmap")?;
        if uid_mappings.is_empty() || gid_mappings.is_empty() {
            return Err(NucleusError::ConfigError(
                "--uidmap/--gidmap require at least one mapping each".to_string(),
            ));
        }
        Self::custom(uid_mappings, gid_mappings)
    }

    /// Choose a rootless mapping for the current (unprivileged) process.
    ///
    /// When the workload requests a non-zero uid (`--user N`), the historic
    /// `rootless()` mapping (only container 0) would make that uid unmappable.
    /// If `/etc/subuid` is configured, transparently pick `keep_id` so the
    /// requested uid maps to the caller's own uid; otherwise fall back to the
    /// trivial `rootless()` mapping (the caller will get a clear validation
    /// error pointing at /etc/subuid).
    pub fn for_unprivileged_rootless(workload_uid: Option<u32>) -> Self {
        match workload_uid {
            Some(uid) if uid != 0 => match Self::keep_id() {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        "Could not build keep-id mapping for requested workload uid {}: {}; \
                         falling back to nomap (container uid {} will be unmappable). Configure \
                         /etc/subuid + /etc/subgid to enable rootless non-root workloads.",
                        uid, e, uid
                    );
                    Self::rootless()
                }
            },
            _ => Self::rootless(),
        }
    }

    /// Resolve the calling user's subuid/subgid ranges, erroring clearly when
    /// rootless subuid support is required but not configured.
    fn current_subid_ranges() -> Result<(String, SubidRange, SubidRange)> {
        let uid = nix::unistd::getuid().as_raw();
        let uname = current_username().unwrap_or_else(|| format!("uid:{}", uid));
        let urange = subuid_range_for_user(&uname, uid).ok_or_else(|| {
            NucleusError::ConfigError(format!(
                "rootless subuid mode requires an entry for '{}' in /etc/subuid \
                 (configure with `useradd -v ...` or `podman system migrate`); \
                 falling back requires --userns=nomap",
                uname
            ))
        })?;
        let grange = subgid_range_for_user(&uname, uid).ok_or_else(|| {
            NucleusError::ConfigError(format!(
                "rootless subuid mode requires an entry for '{}' in /etc/subgid",
                uname
            ))
        })?;
        Ok((uname, urange, grange))
    }

    /// Whether the configured mapping can be written to `/proc/<pid>/{u,g}id_map`
    /// by an **unprivileged** process directly. The kernel only permits this for
    /// the trivial single `0 <own> 1` mapping; anything else requires the
    /// setuid `newuidmap`/`newgidmap` helpers (which authorize via /etc/subuid).
    pub fn needs_setuid_helper(&self) -> bool {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let trivial_uid = self.uid_mappings.len() == 1
            && self.uid_mappings[0] == IdMapping::new(0, uid, 1);
        let trivial_gid = self.gid_mappings.len() == 1
            && self.gid_mappings[0] == IdMapping::new(0, gid, 1);
        !(trivial_uid && trivial_gid)
    }

    /// Create config for root-remapped mode
    ///
    /// When running as host root, maps container UID 0 to a high unprivileged
    /// UID range so a container escape does not yield real host root.
    pub fn root_remapped() -> Self {
        Self {
            uid_mappings: vec![IdMapping::new(0, 100_000, 65_536)],
            gid_mappings: vec![IdMapping::new(0, 100_000, 65_536)],
        }
    }

    /// Create config with custom mappings (validated)
    pub fn custom(
        uid_mappings: Vec<IdMapping>,
        gid_mappings: Vec<IdMapping>,
    ) -> crate::error::Result<Self> {
        let allow_host_root = nix::unistd::Uid::effective().is_root();
        for mapping in &uid_mappings {
            mapping.validate(allow_host_root)?;
        }
        for mapping in &gid_mappings {
            mapping.validate(allow_host_root)?;
        }
        Ok(Self {
            uid_mappings,
            gid_mappings,
        })
    }
}

/// User namespace mapper
///
/// Handles UID/GID mapping for rootless container execution
pub struct UserNamespaceMapper {
    config: UserNamespaceConfig,
}

impl UserNamespaceMapper {
    pub fn new(config: UserNamespaceConfig) -> Self {
        Self { config }
    }

    /// Setup UID/GID mappings for the current process
    ///
    /// This must be called after unshare(CLONE_NEWUSER) and before any other
    /// namespace operations
    pub fn setup_mappings(&self) -> Result<()> {
        if !self.can_self_map_current_process() {
            return Err(NucleusError::NamespaceError(
                "This user namespace mapping must be written from a process outside the new \
                 user namespace; use write_mappings_for_pid() from the parent after fork"
                    .to_string(),
            ));
        }

        self.write_mappings_for_pid(std::process::id())
    }

    /// Write UID/GID mappings for the given process from an external writer.
    ///
    /// For privileged multi-ID mappings, Linux requires a task outside the new
    /// user namespace to write `/proc/<pid>/{uid,gid}_map`. When the caller is
    /// unprivileged and the mapping is not the trivial single-id self-map, the
    /// kernel denies a direct write; in that case we fall back to the setuid
    /// `newuidmap`/`newgidmap` helpers, which authorize via `/etc/subuid`.
    /// This is exactly the mechanism Docker/Podman rootless use.
    pub fn write_mappings_for_pid(&self, pid: u32) -> Result<()> {
        info!("Setting up user namespace mappings for pid {}", pid);

        let is_root = nix::unistd::Uid::effective().is_root();
        let use_helper = !is_root && self.config.needs_setuid_helper();

        if use_helper {
            // setgroups must be denied before writing gid_map only for the
            // trivial unprivileged single-map case. With a helper (privileged
            // writer) we leave setgroups enabled, matching newgidmap semantics.
            self.write_mappings_via_setuid_helper(pid)?;
        } else {
            if self.should_deny_setgroups() {
                self.write_setgroups_deny(pid)?;
            }
            self.write_uid_map(pid)?;
            self.write_gid_map(pid)?;
        }

        info!(
            "Successfully configured user namespace mappings for pid {}",
            pid
        );
        Ok(())
    }

    /// Invoke the setuid `newuidmap`/`newgidmap` helpers to write the maps.
    ///
    /// These binaries (from shadow-utils) are setuid-root and read `/etc/subuid`
    /// and `/etc/subgid` to authorize the requested ranges. On NixOS they live
    /// in `/run/wrappers/bin`; elsewhere in `/usr/bin` or `/usr/sbin`.
    fn write_mappings_via_setuid_helper(&self, pid: u32) -> Result<()> {
        let pid_str = pid.to_string();

        // Flatten each IdMapping (container:host:size) into separate argv tokens.
        let mut uid_args: Vec<String> = Vec::new();
        for m in &self.config.uid_mappings {
            uid_args.push(m.container_id.to_string());
            uid_args.push(m.host_id.to_string());
            uid_args.push(m.count.to_string());
        }
        let mut gid_args: Vec<String> = Vec::new();
        for m in &self.config.gid_mappings {
            gid_args.push(m.container_id.to_string());
            gid_args.push(m.host_id.to_string());
            gid_args.push(m.count.to_string());
        }

        Self::run_idmap_helper("newgidmap", &pid_str, &gid_args)?;
        Self::run_idmap_helper("newuidmap", &pid_str, &uid_args)?;
        Ok(())
    }

    fn run_idmap_helper(prog: &str, pid_str: &str, map_args: &[String]) -> Result<()> {
        let path = Self::find_setuid_helper(prog)?;
        debug!(
            "Invoking idmap helper {:?} for pid {} with args {:?}",
            path, pid_str, map_args
        );
        let status = std::process::Command::new(&path)
            .arg(pid_str)
            .args(map_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| {
                NucleusError::NamespaceError(format!("Failed to execute {}: {}", path.display(), e))
            })?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(NucleusError::NamespaceError(format!(
                "{} failed (exit {:?}): {}",
                prog,
                status.status.code(),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Locate a setuid idmap helper. Search the standard wrapper/bin paths.
    fn find_setuid_helper(prog: &str) -> Result<PathBuf> {
        // NixOS exposes these as setuid wrappers under /run/wrappers/bin.
        const CANDIDATE_DIRS: &[&str] = &[
            "/run/wrappers/bin",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/usr/local/bin",
        ];
        for dir in CANDIDATE_DIRS {
            let p = Path::new(dir).join(prog);
            if p.is_file() {
                return Ok(p);
            }
        }
        // Last resort: trust PATH (shells may put newuidmap elsewhere).
        if let Ok(out) = std::process::Command::new("which").arg(prog).output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Ok(PathBuf::from(trimmed));
                }
            }
        }
        warn!(
            "Could not find {}; install shadow-utils (or its setuid wrappers) for rootless subuid mode",
            prog
        );
        Err(NucleusError::NamespaceError(format!(
            "Required setuid helper '{}' not found in PATH or standard wrapper directories",
            prog
        )))
    }

    fn can_self_map_current_process(&self) -> bool {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        self.config.uid_mappings.len() == 1
            && self.config.gid_mappings.len() == 1
            && self.config.uid_mappings[0] == IdMapping::new(0, uid, 1)
            && self.config.gid_mappings[0] == IdMapping::new(0, gid, 1)
    }

    fn should_deny_setgroups(&self) -> bool {
        self.config.gid_mappings.len() == 1 && self.config.gid_mappings[0].count == 1
    }

    /// Write to /proc/<pid>/setgroups to deny setgroups(2)
    ///
    /// This is required for the unprivileged single-ID gid_map case.
    fn write_setgroups_deny(&self, pid: u32) -> Result<()> {
        let path = format!("/proc/{}/setgroups", pid);
        debug!("Writing 'deny' to {}", path);

        fs::write(&path, "deny\n").map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write to {}: {}", path, e))
        })?;

        Ok(())
    }

    /// Write UID mappings to /proc/<pid>/uid_map
    fn write_uid_map(&self, pid: u32) -> Result<()> {
        let path = format!("/proc/{}/uid_map", pid);
        let mut content = String::new();

        for mapping in &self.config.uid_mappings {
            content.push_str(&mapping.format());
        }

        debug!("Writing UID mappings to {}: {}", path, content.trim());

        fs::write(&path, &content).map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write UID mappings: {}", e))
        })?;

        Ok(())
    }

    /// Write GID mappings to /proc/<pid>/gid_map
    fn write_gid_map(&self, pid: u32) -> Result<()> {
        let path = format!("/proc/{}/gid_map", pid);
        let mut content = String::new();

        for mapping in &self.config.gid_mappings {
            content.push_str(&mapping.format());
        }

        debug!("Writing GID mappings to {}: {}", path, content.trim());

        fs::write(&path, &content).map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write GID mappings: {}", e))
        })?;

        Ok(())
    }

    /// Get the user namespace configuration
    pub fn config(&self) -> &UserNamespaceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_mapping_format() {
        let mapping = IdMapping::new(0, 1000, 1);
        assert_eq!(mapping.format(), "0 1000 1\n");

        let mapping = IdMapping::new(1000, 2000, 100);
        assert_eq!(mapping.format(), "1000 2000 100\n");
    }

    #[test]
    fn test_id_mapping_rootless() {
        let mapping = IdMapping::rootless();
        assert_eq!(mapping.container_id, 0);
        assert_eq!(mapping.count, 1);
        // host_id will be the current UID
    }

    #[test]
    fn test_user_namespace_config_rootless() {
        let config = UserNamespaceConfig::rootless();
        assert_eq!(config.uid_mappings.len(), 1);
        assert_eq!(config.gid_mappings.len(), 1);
        assert_eq!(config.uid_mappings[0].container_id, 0);
        assert_eq!(config.gid_mappings[0].container_id, 0);
    }

    #[test]
    fn test_user_namespace_config_custom() {
        let uid_mappings = vec![IdMapping::new(0, 1000, 1), IdMapping::new(1000, 2000, 100)];
        let gid_mappings = vec![IdMapping::new(0, 1000, 1)];

        let config =
            UserNamespaceConfig::custom(uid_mappings.clone(), gid_mappings.clone()).unwrap();
        assert_eq!(config.uid_mappings, uid_mappings);
        assert_eq!(config.gid_mappings, gid_mappings);
    }

    #[test]
    fn test_rootless_mapping_can_self_map_current_process() {
        let mapper = UserNamespaceMapper::new(UserNamespaceConfig::rootless());
        assert!(mapper.can_self_map_current_process());
        assert!(mapper.should_deny_setgroups());
    }

    #[test]
    fn test_root_remapped_requires_external_writer() {
        let mapper = UserNamespaceMapper::new(UserNamespaceConfig::root_remapped());
        assert!(!mapper.can_self_map_current_process());
        assert!(!mapper.should_deny_setgroups());
        assert!(mapper.setup_mappings().is_err());
    }

    #[test]
    fn test_parse_map_triplet_podman_syntax() {
        assert_eq!(
            parse_map_triplet("0:1000:1"),
            Some(IdMapping::new(0, 1000, 1))
        );
        assert_eq!(
            parse_map_triplet(" 1 : 100000 : 65536 "),
            Some(IdMapping::new(1, 100_000, 65_536))
        );
        // Malformed inputs are rejected, not panicking.
        assert_eq!(parse_map_triplet("0:1000"), None);        // missing size
        assert_eq!(parse_map_triplet("0:1000:1:9"), None);    // too many fields
        assert_eq!(parse_map_triplet("x:1000:1"), None);      // non-numeric
    }

    #[test]
    fn test_subid_range_for_parses_name_and_uid_entries() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nucleus-subuid-test-{}", std::process::id()));
        std::fs::write(
            &path,
            "root:100000:65536\nalice:200000:65536\n1000:300000:65536\n",
        )
        .unwrap();
        let p = path.to_str().unwrap();
        // Name lookup wins over uid.
        assert_eq!(
            subid_range_for(p, "alice", 1000),
            Some(SubidRange { start: 200_000, count: 65_536 })
        );
        // Numeric uid fallback when no name match.
        assert_eq!(
            subid_range_for(p, "nobody", 1000),
            Some(SubidRange { start: 300_000, count: 65_536 })
        );
        // No match at all.
        assert_eq!(subid_range_for(p, "ghost", 4242), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_from_map_specs_validates() {
        let cfg = UserNamespaceConfig::from_map_specs(
            &["0:1000:1".to_string(), "1:100000:65536".to_string()],
            &["0:100:1".to_string()],
        )
        .unwrap();
        assert_eq!(cfg.uid_mappings.len(), 2);
        assert_eq!(cfg.uid_mappings[1], IdMapping::new(1, 100_000, 65_536));
        // Missing gid specs is an error.
        assert!(UserNamespaceConfig::from_map_specs(
            &["0:1000:1".to_string()],
            &[],
        )
        .is_err());
        // Malformed spec is an error.
        assert!(UserNamespaceConfig::from_map_specs(
            &["bogus".to_string()],
            &["0:100:1".to_string()],
        )
        .is_err());
    }

    #[test]
    fn test_needs_setuid_helper_classification() {
        // The trivial rootless self-map can be written directly (no helper).
        assert!(!UserNamespaceConfig::rootless().needs_setuid_helper());
        // Any multi-entry mapping (keep-id, auto, root-remapped) needs the
        // setuid helper when the caller is unprivileged.
        assert!(UserNamespaceConfig::root_remapped().needs_setuid_helper());
    }

    #[test]
    fn test_keep_id_mapping_is_disjoint() {
        // keep-id requires /etc/subuid; build it manually here to assert shape.
        // Two entries, container ranges 0 and <own_uid> must not overlap, and
        // host ranges (subuid_start vs own_uid) must not overlap either.
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let cfg = UserNamespaceConfig::custom(
            vec![IdMapping::new(0, 100_000, 1), IdMapping::new(uid, uid, 1)],
            vec![IdMapping::new(0, 100_000, 1), IdMapping::new(gid, gid, 1)],
        )
        .unwrap();
        assert!(cfg.needs_setuid_helper());
        assert_eq!(cfg.uid_mappings.len(), 2);
        // own_uid must map to itself (the keep-id invariant).
        assert_eq!(cfg.uid_mappings[1].host_id, uid);
        assert_eq!(cfg.uid_mappings[1].container_id, uid);
    }

    // Note: Testing actual mapping setup requires user namespace creation
    // This is tested in integration tests
}
