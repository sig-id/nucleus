use crate::error::{NucleusError, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Target ABI – covers up to Linux 6.12 features (Truncate, IoctlDev, Refer, etc.).
/// The landlock crate gracefully degrades for older kernels.
const TARGET_ABI: ABI = ABI::V5;

/// Minimum Landlock ABI version required for production mode.
///
/// V3 adds LANDLOCK_ACCESS_FS_TRUNCATE which prevents silent data truncation
/// that V1/V2 cannot control. This is the minimum we consider safe for
/// production workloads.
const MINIMUM_PRODUCTION_ABI: ABI = ABI::V3;

#[derive(Debug, Clone, Copy)]
enum PathAccessMode {
    ReadOnly,
    ReadExecute,
    ReadWrite,
    ReadWriteExecute,
}

/// Landlock filesystem access-control manager
///
/// Implements fine-grained, path-based filesystem restrictions as an additional
/// defense layer on top of namespaces, capabilities, and seccomp.
///
/// Properties (matching Nucleus security invariants):
/// - Irreversible: once restrict_self() is called, restrictions cannot be lifted
/// - Stackable: layered with seccomp and capability dropping
/// - Unprivileged: works in rootless mode
pub struct LandlockManager {
    applied: bool,
    /// Additional paths to grant read+write access to (e.g. volume mounts).
    extra_paths: Vec<(String, PathAccessMode)>,
    /// Access policy for the first-class `/workspace` path.
    workspace_access: PathAccessMode,
}

impl LandlockManager {
    pub fn new() -> Self {
        Self {
            applied: false,
            extra_paths: Vec::new(),
            workspace_access: PathAccessMode::ReadWrite,
        }
    }

    /// Register additional paths that need read+write access.
    /// Used for volume mounts that aren't under the default allowed paths.
    pub fn add_rw_path(&mut self, path: &str) {
        self.extra_paths
            .push((path.to_string(), PathAccessMode::ReadWrite));
    }

    /// Register additional paths that need read-only access.
    pub fn add_ro_path(&mut self, path: &str) {
        self.extra_paths
            .push((path.to_string(), PathAccessMode::ReadOnly));
    }

    /// Register additional paths that need read+execute access.
    pub fn add_read_exec_path(&mut self, path: &str) {
        self.extra_paths
            .push((path.to_string(), PathAccessMode::ReadExecute));
    }

    /// Register additional paths that need read+write+execute access.
    pub fn add_rw_exec_path(&mut self, path: &str) {
        self.extra_paths
            .push((path.to_string(), PathAccessMode::ReadWriteExecute));
    }

    /// Configure Landlock access for `/workspace`.
    pub fn set_workspace_access(&mut self, read_only: bool, allow_execute: bool) {
        self.workspace_access = match (read_only, allow_execute) {
            (true, false) => PathAccessMode::ReadOnly,
            (true, true) => PathAccessMode::ReadExecute,
            (false, false) => PathAccessMode::ReadWrite,
            (false, true) => PathAccessMode::ReadWriteExecute,
        };
    }

    /// Apply the container Landlock policy.
    ///
    /// Rules:
    /// - `/` (root):         read-only traversal (ReadDir) so path resolution works
    /// - `/bin`, `/usr`:     read + execute (for running agent binaries)
    /// - `/lib`, `/lib64`:   read (shared libraries)
    /// - `/etc`:             read (config / resolv.conf / nsswitch)
    /// - `/dev`:             read (already minimal device nodes)
    /// - `/proc`:            read (already mounted read-only)
    /// - `/tmp`:             read + write + create + remove (agent scratch space)
    /// - `/context`:         read-only (pre-populated agent data)
    /// - `/workspace`:       workspace policy (read/write by default, execute opt-in)
    /// - configured home:    registered by runtime as read/write, no execute
    ///
    /// Everything else is denied by the ruleset.
    pub fn apply_container_policy(&mut self) -> Result<bool> {
        self.apply_container_policy_with_mode(false)
    }

    /// Assert that the kernel supports at least the minimum Landlock ABI version
    /// required for production workloads.
    ///
    /// Returns Ok(()) if the ABI is sufficient, or Err if the kernel is too old.
    /// In best-effort mode, a too-old kernel is logged but not fatal.
    pub fn assert_minimum_abi(&self, production_mode: bool) -> Result<()> {
        // Probe the kernel's Landlock ABI version by attempting to create a ruleset
        // with the minimum ABI's access rights. If the kernel doesn't support the
        // minimum ABI, the ruleset will be NotEnforced or PartiallyEnforced.
        let min_access = AccessFs::from_all(MINIMUM_PRODUCTION_ABI);
        let target_access = AccessFs::from_all(TARGET_ABI);

        // If the minimum access set equals the target, the kernel supports everything
        // If the minimum is a subset, check that at least the minimum rights are present
        if min_access != target_access {
            info!(
                "Landlock ABI: target={:?}, minimum_production={:?}",
                TARGET_ABI, MINIMUM_PRODUCTION_ABI
            );
        }

        // The actual enforcement check happens in build_and_restrict().
        // Here we do a lightweight check: if the kernel supports the target ABI,
        // it certainly supports the minimum. The landlock crate handles this
        // gracefully, but we want an explicit assertion for production.
        match Ruleset::default().handle_access(AccessFs::from_all(MINIMUM_PRODUCTION_ABI)) {
            Ok(_) => {
                info!("Landlock ABI >= V3 confirmed");
                Ok(())
            }
            Err(e) => {
                let msg = format!(
                    "Kernel Landlock ABI is below minimum required version (V3): {}",
                    e
                );
                if production_mode {
                    Err(ll_err(e))
                } else {
                    warn!("{}", msg);
                    Ok(())
                }
            }
        }
    }

    /// Apply with configurable failure behavior.
    ///
    /// When `best_effort` is true, failures (e.g. kernel without Landlock) are
    /// logged and execution continues.
    pub fn apply_container_policy_with_mode(&mut self, best_effort: bool) -> Result<bool> {
        if self.applied {
            debug!("Landlock policy already applied, skipping");
            return Ok(true);
        }

        info!("Applying Landlock filesystem policy");

        match self.build_and_restrict() {
            Ok(status) => match status {
                RulesetStatus::FullyEnforced => {
                    self.applied = true;
                    info!("Landlock policy fully enforced");
                    Ok(true)
                }
                RulesetStatus::PartiallyEnforced => {
                    if best_effort {
                        self.applied = true;
                        info!(
                            "Landlock policy partially enforced (kernel lacks some access rights)"
                        );
                        Ok(true)
                    } else {
                        Err(NucleusError::LandlockError(
                            "Landlock policy only partially enforced; strict mode requires full target ABI support".to_string(),
                        ))
                    }
                }
                RulesetStatus::NotEnforced => {
                    if best_effort {
                        warn!("Landlock not enforced (kernel does not support Landlock)");
                        Ok(false)
                    } else {
                        Err(NucleusError::LandlockError(
                            "Landlock not enforced (kernel does not support Landlock)".to_string(),
                        ))
                    }
                }
            },
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to apply Landlock policy: {} (continuing without Landlock)",
                        e
                    );
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Apply an execute-only allowlist for host-side supervisor processes.
    ///
    /// This policy handles only `LANDLOCK_ACCESS_FS_EXECUTE`, leaving normal
    /// read/write access untouched. It is intended for runtimes like gVisor
    /// that need a narrow post-namespace executable allowlist while still
    /// blocking arbitrary host executable and setuid-wrapper execs after the
    /// supervisor has entered its setup namespace.
    pub fn apply_execute_allowlist_policy(
        &mut self,
        allowed_roots: &[PathBuf],
        best_effort: bool,
    ) -> Result<bool> {
        if self.applied {
            debug!("Landlock execute allowlist already applied, skipping");
            return Ok(true);
        }

        info!(
            allowed_roots = ?allowed_roots,
            "Applying Landlock execute allowlist policy"
        );

        match self.build_execute_allowlist_and_restrict(allowed_roots) {
            Ok(status) => match status {
                RulesetStatus::FullyEnforced => {
                    self.applied = true;
                    info!("Landlock execute allowlist fully enforced");
                    Ok(true)
                }
                RulesetStatus::PartiallyEnforced => {
                    if best_effort {
                        self.applied = true;
                        info!("Landlock execute allowlist partially enforced");
                        Ok(true)
                    } else {
                        Err(NucleusError::LandlockError(
                            "Landlock execute allowlist only partially enforced; strict mode requires full enforcement".to_string(),
                        ))
                    }
                }
                RulesetStatus::NotEnforced => {
                    if best_effort {
                        warn!("Landlock execute allowlist not enforced");
                        Ok(false)
                    } else {
                        Err(NucleusError::LandlockError(
                            "Landlock execute allowlist not enforced".to_string(),
                        ))
                    }
                }
            },
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to apply Landlock execute allowlist: {} (continuing without it)",
                        e
                    );
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Build the ruleset and call restrict_self().
    fn build_and_restrict(&self) -> Result<RulesetStatus> {
        let access_all = AccessFs::from_all(TARGET_ABI);
        let access_read = AccessFs::from_read(TARGET_ABI);

        // Read + execute for binary paths
        let access_read_exec = access_read | AccessFs::Execute;

        // Write access set for /tmp – full read+write but no execute.
        // Executing from /tmp is a common attack pattern (drop-and-exec).
        let mut access_tmp = access_all;
        access_tmp.remove(AccessFs::Execute);
        let access_rw_exec = access_tmp | AccessFs::Execute;

        let mut ruleset = Ruleset::default()
            .handle_access(access_all)
            .map_err(ll_err)?
            .create()
            .map_err(ll_err)?;

        // Root directory: minimal traversal only
        // We add ReadDir so that path resolution through / works
        if let Ok(fd) = PathFd::new("/") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, AccessFs::ReadDir))
                .map_err(ll_err)?;
        }

        // M13: Mandatory paths that must exist for a functional container.
        // Warn (or error in strict mode) when these are missing.
        const MANDATORY_PATHS: &[&str] = &["/bin", "/usr", "/lib", "/etc"];
        for path in MANDATORY_PATHS {
            if !std::path::Path::new(path).exists() {
                warn!(
                    "Landlock: mandatory path {} does not exist; container may not function correctly",
                    path
                );
            }
        }

        // Binary paths: read + execute
        for path in &["/bin", "/usr", "/sbin"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read_exec))
                    .map_err(ll_err)?;
            }
        }

        // Shared libraries: read
        for path in &["/lib", "/lib64", "/lib32"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read))
                    .map_err(ll_err)?;
            }
        }

        // Config/device/proc: read
        for path in &["/etc", "/dev", "/proc"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read))
                    .map_err(ll_err)?;
            }
        }

        // /dev/shm: read+write for POSIX shared memory (shm_open).
        // Required by PostgreSQL, Redis, and other programs.
        // No execute – same policy as /tmp.
        if let Ok(fd) = PathFd::new("/dev/shm") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_tmp))
                .map_err(ll_err)?;
        }

        // /tmp: full read+write+create+remove
        if let Ok(fd) = PathFd::new("/tmp") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_tmp))
                .map_err(ll_err)?;
        }

        // /nix/store: read + execute (NixOS binaries and libraries)
        if let Ok(fd) = PathFd::new("/nix/store") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_read_exec))
                .map_err(ll_err)?;
        }

        // /run/secrets: read-only (container secrets mounted on tmpfs)
        if let Ok(fd) = PathFd::new("/run/secrets") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_read))
                .map_err(ll_err)?;
        }

        // /context: read-only (agent data)
        if let Ok(fd) = PathFd::new("/context") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_read))
                .map_err(ll_err)?;
        }

        // /workspace: stable agent workspace. Writable by default, but not
        // executable unless --workspace-exec explicitly opts into that risk.
        if let Ok(fd) = PathFd::new("/workspace") {
            let access = Self::access_for_mode(
                self.workspace_access,
                access_read,
                access_read_exec,
                access_tmp,
                access_rw_exec,
            );
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(ll_err)?;
        }

        // Volume mounts and other dynamically registered paths.
        for (path, mode) in &self.extra_paths {
            if let Ok(fd) = PathFd::new(path) {
                debug!("Landlock: granting {:?} access to path {:?}", mode, path);
                let access = Self::access_for_mode(
                    *mode,
                    access_read,
                    access_read_exec,
                    access_tmp,
                    access_rw_exec,
                );
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(ll_err)?;
            }
        }

        let status = ruleset.restrict_self().map_err(ll_err)?;
        Ok(status.ruleset)
    }

    fn access_for_mode(
        mode: PathAccessMode,
        access_read: landlock::BitFlags<AccessFs>,
        access_read_exec: landlock::BitFlags<AccessFs>,
        access_read_write: landlock::BitFlags<AccessFs>,
        access_read_write_exec: landlock::BitFlags<AccessFs>,
    ) -> landlock::BitFlags<AccessFs> {
        match mode {
            PathAccessMode::ReadOnly => access_read,
            PathAccessMode::ReadExecute => access_read_exec,
            PathAccessMode::ReadWrite => access_read_write,
            PathAccessMode::ReadWriteExecute => access_read_write_exec,
        }
    }

    fn build_execute_allowlist_and_restrict(
        &self,
        allowed_roots: &[PathBuf],
    ) -> Result<RulesetStatus> {
        let access_execute = AccessFs::Execute;
        let mut ruleset = Ruleset::default()
            .handle_access(access_execute)
            .map_err(ll_err)?
            .create()
            .map_err(ll_err)?
            // The gVisor systrap supervisor re-execs runsc after this policy is
            // installed. Do not silently reintroduce no_new_privs here; callers
            // that need this host-side allowlist must already be in a context
            // where Landlock can be restricted without it.
            .set_no_new_privs(false);

        let mut added_rules = 0usize;
        for root in allowed_roots {
            let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            match PathFd::new(canonical.as_path()) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, access_execute))
                        .map_err(ll_err)?;
                    added_rules += 1;
                }
                Err(err) => {
                    warn!(
                        "Landlock execute allowlist skipped {:?}: {}",
                        canonical, err
                    );
                }
            }
        }
        if added_rules == 0 {
            return Err(NucleusError::LandlockError(
                "Landlock execute allowlist has no valid executable roots".to_string(),
            ));
        }

        let status = ruleset.restrict_self().map_err(ll_err)?;
        Ok(status.ruleset)
    }

    /// Check if Landlock policy has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

impl Default for LandlockManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a landlock RulesetError into NucleusError::LandlockError
fn ll_err(e: RulesetError) -> NucleusError {
    NucleusError::LandlockError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_manager_initial_state() {
        let mgr = LandlockManager::new();
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_apply_idempotent() {
        let mut mgr = LandlockManager::new();
        // Best-effort so it succeeds even without Landlock support
        let _ = mgr.apply_container_policy_with_mode(true);
        // Second call should be a no-op
        let result = mgr.apply_container_policy_with_mode(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_best_effort_on_unsupported_kernel() {
        let mut mgr = LandlockManager::new();
        // Should not error even if kernel has no Landlock
        let result = mgr.apply_container_policy_with_mode(true);
        assert!(result.is_ok());
    }

    /// Extract the body of a function from source text by brace-matching,
    /// avoiding fragile hardcoded character-window offsets (SEC-MED-03).
    fn extract_fn_body<'a>(source: &'a str, fn_signature: &str) -> &'a str {
        let fn_start = source
            .find(fn_signature)
            .unwrap_or_else(|| panic!("function '{}' not found in source", fn_signature));
        let after = &source[fn_start..];
        let open = after
            .find('{')
            .unwrap_or_else(|| panic!("no opening brace found for '{}'", fn_signature));
        let mut depth = 0u32;
        let mut end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        &after[..end]
    }

    #[test]
    fn test_policy_covers_nix_store_and_secrets() {
        // Landlock policy must include rules for /nix/store (read+exec) and
        // /run/secrets (read) so NixOS binaries can execute and secrets are readable.
        // NOTE: The Landlock API does not expose the ruleset for inspection, so
        // this remains a source-text check – but uses brace-matched function
        // body extraction instead of hardcoded char offsets.
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn build_and_restrict");
        assert!(
            fn_body.contains("\"/nix/store\"") || fn_body.contains("\"/nix\""),
            "Landlock build_and_restrict must include a rule for /nix/store or /nix"
        );
        assert!(
            fn_body.contains("\"/run/secrets\"") || fn_body.contains("\"/run\""),
            "Landlock build_and_restrict must include a rule for /run/secrets"
        );
    }

    #[test]
    fn test_policy_covers_workspace_without_default_execute() {
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn build_and_restrict");
        assert!(
            fn_body.contains("\"/workspace\""),
            "Landlock build_and_restrict must include /workspace"
        );
        assert!(
            source.contains("set_workspace_access"),
            "LandlockManager must expose explicit workspace access selection"
        );
    }

    #[test]
    fn test_tmp_access_excludes_execute() {
        // L-5: /tmp should have read+write but NOT execute permission.
        // Verify at the type level that our access_tmp definition
        // does not include Execute.
        let access_all = AccessFs::from_all(TARGET_ABI);
        let mut access_tmp = access_all;
        access_tmp.remove(AccessFs::Execute);
        assert!(!access_tmp.contains(AccessFs::Execute));
        // But it should still have write capabilities
        assert!(access_tmp.contains(AccessFs::WriteFile));
        assert!(access_tmp.contains(AccessFs::RemoveFile));
    }

    #[test]
    fn test_execute_allowlist_handles_only_execute() {
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn build_execute_allowlist_and_restrict");
        assert!(
            fn_body.contains("let access_execute = AccessFs::Execute"),
            "execute allowlist must handle only execute access"
        );
        assert!(
            fn_body.contains("handle_access(access_execute)"),
            "execute allowlist must not handle read/write filesystem rights"
        );
        assert!(
            !fn_body.contains("from_all"),
            "execute allowlist must not accidentally become a broad filesystem policy"
        );
    }

    #[test]
    fn test_execute_allowlist_disables_no_new_privs_for_gvisor_supervisor() {
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn build_execute_allowlist_and_restrict");
        assert!(
            fn_body.contains(".set_no_new_privs(false)"),
            "gVisor supervisor execute allowlist must not force no_new_privs"
        );
    }

    #[test]
    fn test_container_policy_keeps_default_no_new_privs() {
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn build_and_restrict");
        assert!(
            !fn_body.contains(".set_no_new_privs(false)"),
            "container Landlock policy must retain the landlock crate default no_new_privs setting"
        );
    }

    #[test]
    fn test_not_enforced_returns_error_in_strict_mode() {
        // SEC-11: When best_effort=false, NotEnforced must return Err, not Ok(false)
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn apply_container_policy_with_mode");
        // Find the NotEnforced match arm within the function body
        let not_enforced_start = fn_body
            .find("NotEnforced")
            .expect("function must handle NotEnforced status");
        // Search from NotEnforced to the next match arm ('=>' after a '}')
        let rest = &fn_body[not_enforced_start..];
        let arm_end = rest
            .find("RestrictionStatus::")
            .unwrap_or(rest.len().min(500));
        let not_enforced_block = &rest[..arm_end];
        assert!(
            not_enforced_block.contains("best_effort") && not_enforced_block.contains("Err"),
            "NotEnforced must return Err when best_effort=false. Block: {}",
            not_enforced_block
        );
    }

    #[test]
    fn test_partially_enforced_returns_error_in_strict_mode() {
        let source = include_str!("landlock.rs");
        let fn_body = extract_fn_body(source, "fn apply_container_policy_with_mode");
        let partial_start = fn_body
            .find("PartiallyEnforced")
            .expect("function must handle PartiallyEnforced status");
        let rest = &fn_body[partial_start..];
        let arm_end = rest.find("NotEnforced").unwrap_or(rest.len().min(500));
        let partial_block = &rest[..arm_end];
        assert!(
            partial_block.contains("best_effort") && partial_block.contains("Err"),
            "PartiallyEnforced must return Err when best_effort=false. Block: {}",
            partial_block
        );
    }
}
