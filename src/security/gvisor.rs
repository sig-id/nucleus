use super::landlock::LandlockManager;
use crate::error::{NucleusError, Result};
use crate::oci::OciBundle;
use nix::unistd::{Gid, Uid};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

const NIX_STORE_EXEC_ROOT: &str = "/nix/store";
const NIXOS_ROOTLESS_USERNS_WRAPPER_DIR: &str = "/run/wrappers/bin";
const ROOTLESS_USERNS_HELPERS: &[&str] = &["newuidmap", "newgidmap"];
const ROOTLESS_USERNS_HELPER_EXEC_ROOTS_ENV: &str = "NUCLEUS_ROOTLESS_USERNS_HELPER_EXEC_ROOTS";
const RUNSC_DEBUG_DIR_ENV: &str = "NUCLEUS_RUNSC_DEBUG_DIR";
const RUNSC_REEXEC_VIA_PROC_SELF_EXE_ENV: &str = "NUCLEUS_RUNSC_REEXEC_VIA_PROC_SELF_EXE";
const RUNSC_SUPERVISOR_PATH: &str =
    "/run/wrappers/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Network mode for gVisor runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GVisorNetworkMode {
    /// No networking (fully isolated). Default for agent workloads.
    None,
    /// gVisor user-space network stack. Suitable for networked production services
    /// that need gVisor isolation with network access.
    Sandbox,
    /// Share host network namespace. Use with caution.
    Host,
}

/// Platform backend for gVisor's Sentry.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum GVisorPlatform {
    /// systrap backend, the current default and most broadly compatible option.
    #[default]
    Systrap,
    /// KVM-backed sandboxing for the Sentry itself.
    Kvm,
    /// ptrace backend for maximal compatibility where systrap/KVM are unavailable.
    Ptrace,
}

impl GVisorPlatform {
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::Systrap => "systrap",
            Self::Kvm => "kvm",
            Self::Ptrace => "ptrace",
        }
    }
}

/// Options for running an OCI bundle with gVisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GVisorOciRunOptions {
    /// gVisor networking mode passed to runsc.
    pub network_mode: GVisorNetworkMode,
    /// Skip runsc's cgroup setup when Nucleus manages cgroups externally.
    pub ignore_cgroups: bool,
    /// Tell runsc to use its rootless launcher and helper handoff semantics.
    ///
    /// This is independent from `require_supervisor_exec_policy`: production
    /// callers decide separately whether the host-side execute allowlist is
    /// compatible with the selected handoff path.
    pub runsc_rootless: bool,
    /// Stage runsc into the per-container runtime directory before exec.
    ///
    /// This is for non-store runsc binaries and host-side supervisor execute
    /// policy isolation. Rootless bridge mode should normally leave runsc on
    /// its immutable package path so gVisor helpers can re-exec a globally
    /// traversable binary after they adjust credentials.
    pub stage_runsc_binary: bool,
    /// Fail if the host-side supervisor execute allowlist cannot be installed.
    pub require_supervisor_exec_policy: bool,
    /// gVisor Sentry platform backend.
    pub platform: GVisorPlatform,
    /// Optional OCI console socket that receives the terminal PTY master.
    pub console_socket: Option<PathBuf>,
}

impl Default for GVisorOciRunOptions {
    fn default() -> Self {
        Self {
            network_mode: GVisorNetworkMode::None,
            ignore_cgroups: false,
            runsc_rootless: false,
            stage_runsc_binary: false,
            require_supervisor_exec_policy: false,
            platform: GVisorPlatform::default(),
            console_socket: None,
        }
    }
}

impl GVisorOciRunOptions {
    fn network_flag(&self) -> &'static str {
        match self.network_mode {
            GVisorNetworkMode::None => "none",
            GVisorNetworkMode::Sandbox => "sandbox",
            GVisorNetworkMode::Host => "host",
        }
    }
}

/// GVisor runtime manager
///
/// Implements the gVisor state machine from
/// NucleusSecurity_GVisor_GVisorRuntime.tla
pub struct GVisorRuntime {
    runsc_path: String,
}

impl GVisorRuntime {
    /// Create a new GVisor runtime manager
    ///
    /// This checks for runsc binary availability
    pub fn new() -> Result<Self> {
        let runsc_path = Self::find_runsc()?;
        info!("Found runsc at: {}", runsc_path);
        Ok(Self { runsc_path })
    }

    /// Create a GVisor runtime with a pre-resolved runsc path.
    ///
    /// Use this when the path was resolved before privilege changes
    /// (e.g. before entering a user namespace where UID 0 would block
    /// PATH-based lookup).
    pub fn with_path(runsc_path: String) -> Self {
        Self { runsc_path }
    }

    /// Resolve the runsc path without constructing a full runtime.
    /// Call this before fork/unshare so the path is resolved while
    /// still unprivileged.
    pub fn resolve_path() -> Result<String> {
        Self::find_runsc()
    }

    /// Find the runsc binary
    fn find_runsc() -> Result<String> {
        // Try common locations
        let paths = vec![
            "/usr/local/bin/runsc",
            "/usr/bin/runsc",
            "/opt/gvisor/runsc",
        ];

        for path in &paths {
            if let Some(validated) = Self::validate_runsc_path(Path::new(path))? {
                return Ok(validated);
            }
        }

        // For privileged execution, do not resolve runtime binaries via PATH.
        // This avoids environment-based binary hijacking when running as root.
        if Uid::effective().is_root() {
            return Err(NucleusError::GVisorError(
                "runsc binary not found in trusted system paths".to_string(),
            ));
        }

        // Try to find in PATH without invoking a shell command.
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("runsc");
                if let Some(validated) = Self::validate_runsc_path(&candidate)? {
                    return Ok(validated);
                }
            }
        }

        Err(NucleusError::GVisorError(
            "runsc binary not found. Please install gVisor.".to_string(),
        ))
    }

    fn validate_runsc_path(path: &Path) -> Result<Option<String>> {
        if !path.exists() {
            return Ok(None);
        }
        if !path.is_file() {
            return Ok(None);
        }

        let canonical = std::fs::canonicalize(path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to canonicalize runsc path {:?}: {}",
                path, e
            ))
        })?;

        // If the candidate is a shell wrapper script (common on NixOS where
        // nix wraps binaries to inject PATH), look for the real ELF binary
        // next to it. The gVisor helper re-exec path must stay on the real
        // binary, not a bash wrapper.
        let resolved = Self::unwrap_nix_wrapper(&canonical).unwrap_or_else(|| canonical.clone());

        let metadata = std::fs::metadata(&resolved).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to stat runsc path {:?}: {}", resolved, e))
        })?;

        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::GVisorError(format!(
                "Refusing insecure runsc binary permissions at {:?} (mode {:o})",
                resolved, mode
            )));
        }
        if mode & 0o111 == 0 {
            return Ok(None);
        }

        // Reject binaries owned by other non-root users – a malicious user
        // could place a trojan runsc earlier in PATH.
        use std::os::unix::fs::MetadataExt;
        let owner = metadata.uid();
        let current_uid = nix::unistd::Uid::effective().as_raw();
        if !Self::is_trusted_runsc_owner(&resolved, owner, current_uid) {
            return Err(NucleusError::GVisorError(format!(
                "Refusing runsc binary at {:?} owned by uid {} (expected root, current user {}, or immutable /nix/store artifact)",
                resolved, owner, current_uid
            )));
        }

        Ok(Some(resolved.to_string_lossy().to_string()))
    }

    fn is_trusted_runsc_owner(path: &Path, owner: u32, current_uid: u32) -> bool {
        if owner == 0 || owner == current_uid {
            return true;
        }

        // Nix store artifacts are immutable content-addressed paths and are
        // commonly owned by `nobody` rather than root/current user.
        // Extra hardening: verify the binary is not writable by *anyone* and
        // the parent directory is also not writable, to guard against a
        // compromised or mutable store.
        if path.starts_with("/nix/store") {
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                // Reject if owner-writable (group/other already checked by caller)
                if mode & 0o200 != 0 {
                    return false;
                }
            } else {
                return false;
            }
            // Verify the immediate parent directory is not writable
            if let Some(parent) = path.parent() {
                if let Ok(parent_meta) = std::fs::metadata(parent) {
                    let parent_mode = parent_meta.permissions().mode();
                    if parent_mode & 0o222 != 0 {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            return true;
        }

        false
    }

    /// If `path` is a Nix wrapper script, extract the real binary path.
    ///
    /// Nix wrapper scripts end with a line like:
    ///   exec -a "$0" "/nix/store/…/.runsc-wrapped"  "$@"
    /// We parse that to find the actual ELF binary.
    fn unwrap_nix_wrapper(path: &Path) -> Option<std::path::PathBuf> {
        let content = std::fs::read_to_string(path).ok()?;
        // Only process short scripts (wrapper scripts are small)
        if content.len() > 4096 || !content.starts_with("#!") {
            return None;
        }
        // Look for the exec line that references the wrapped binary
        for line in content.lines().rev() {
            let trimmed = line.trim();
            if trimmed.starts_with("exec ") {
                // Parse: exec -a "$0" "/nix/store/.../bin/.runsc-wrapped"  "$@"
                // or:    exec "/nix/store/.../bin/.runsc-wrapped"  "$@"
                for token in trimmed.split_whitespace() {
                    let unquoted = token.trim_matches('"');
                    if unquoted.starts_with('/') && unquoted.contains("runsc") {
                        let candidate = std::path::PathBuf::from(unquoted);
                        if candidate.exists() && candidate.is_file() {
                            debug!("Resolved Nix wrapper {:?} → {:?}", path, candidate);
                            return Some(candidate);
                        }
                    }
                }
            }
        }
        None
    }

    /// Execute using gVisor with an OCI bundle
    ///
    /// This is the OCI-compliant way to run containers with gVisor using
    /// default options: no networking, systrap platform, no rootless flag,
    /// and no internal cgroup setup override.
    pub fn exec_with_oci_bundle(&self, container_id: &str, bundle: &OciBundle) -> Result<()> {
        self.exec_with_oci_bundle_options(container_id, bundle, GVisorOciRunOptions::default())
    }

    /// Execute using gVisor with an OCI bundle and explicit run options.
    ///
    /// `ignore_cgroups` skips runsc's internal cgroup configuration because
    /// Nucleus already manages cgroups externally and unprivileged callers
    /// cannot configure them directly. `runsc_rootless` tells runsc that its
    /// supervisor is not running with host-root privileges, so helpers must
    /// keep caller privileges during handoff. `stage_runsc_binary` forces a
    /// private runsc copy for non-store binaries or host-side supervisor
    /// execute policy isolation.
    /// `require_supervisor_exec_policy` fail-closes if Nucleus cannot install
    /// the host-side execute allowlist before handing control to runsc.
    pub fn exec_with_oci_bundle_options(
        &self,
        container_id: &str,
        bundle: &OciBundle,
        options: GVisorOciRunOptions,
    ) -> Result<()> {
        info!(
            "Executing with gVisor using OCI bundle at {:?} (network: {:?}, platform: {:?})",
            bundle.bundle_path(),
            options.network_mode,
            options.platform,
        );

        // Create a per-container root directory for runsc state. Do not derive
        // this from the OCI bundle parent: --bundle may be operator-provided,
        // shared, or attacker-writable, while runsc state includes a staged
        // executable used by the supervisor process.
        let runsc_root = Self::secure_runsc_root(container_id)?;

        let runsc_runtime_dir = runsc_root.join("runtime");
        Self::ensure_secure_runsc_dir(&runsc_runtime_dir, "runsc runtime directory")?;

        let (program_path, mut exec_allow_roots) =
            self.prepare_supervisor_runsc_program(&runsc_root, options.stage_runsc_binary)?;
        if options.runsc_rootless {
            exec_allow_roots.extend(Self::rootless_userns_helper_exec_roots());
        }

        // Build runsc command with OCI bundle.
        // Global flags (--root, --network, --platform) must come BEFORE the subcommand.
        // runsc --root <dir> --network <mode> --platform <plat> run --bundle <path> <id>
        let debug_dir = Self::runsc_debug_dir()?;
        let mut args = self.build_oci_run_args(
            container_id,
            bundle,
            &runsc_root,
            &options,
            debug_dir.as_deref(),
        );
        args[0] = program_path.to_string_lossy().to_string();

        debug!("runsc OCI args: {:?}", args);

        // Convert to CStrings for exec
        let program = CString::new(program_path.to_string_lossy().as_ref())
            .map_err(|e| NucleusError::GVisorError(format!("Invalid runsc path: {}", e)))?;

        let c_args: Result<Vec<CString>> = args
            .iter()
            .map(|arg| {
                CString::new(arg.as_str())
                    .map_err(|e| NucleusError::GVisorError(format!("Invalid argument: {}", e)))
            })
            .collect();
        let c_args = c_args?;

        // Rootless runsc helper processes may re-exec after switching into a
        // user namespace where the concrete Nix store path is no longer
        // executable. Use upstream's /proc/self/exe handoff for rootless
        // launches when no host-side execute allowlist is active. Rootful
        // production still keeps helpers anchored on the concrete path so the
        // supervisor Landlock policy can fail closed.
        let reexec_via_proc_self_exe =
            options.runsc_rootless && !options.require_supervisor_exec_policy;
        let c_env = self.exec_environment(&runsc_runtime_dir, reexec_via_proc_self_exe)?;

        // Install an execute-only Landlock allowlist before handing control to
        // runsc when the caller requested a fail-closed supervisor policy.
        // Rootless runsc flag selection remains independent from policy
        // selection; production callers request this policy explicitly except
        // for the pre-created bridge userns handoff.
        if options.require_supervisor_exec_policy {
            self.apply_supervisor_exec_policy(
                &exec_allow_roots,
                options.require_supervisor_exec_policy,
            )?;
        }

        // execve - this replaces the current process with runsc
        nix::unistd::execve::<std::ffi::CString, std::ffi::CString>(&program, &c_args, &c_env)?;

        // Should never reach here
        Ok(())
    }

    /// Execute using gVisor with an OCI bundle and explicit network mode.
    ///
    /// Prefer [`Self::exec_with_oci_bundle_options`] for new call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn exec_with_oci_bundle_network(
        &self,
        container_id: &str,
        bundle: &OciBundle,
        network_mode: GVisorNetworkMode,
        ignore_cgroups: bool,
        runsc_rootless: bool,
        stage_runsc_binary: bool,
        require_supervisor_exec_policy: bool,
        platform: GVisorPlatform,
    ) -> Result<()> {
        self.exec_with_oci_bundle_options(
            container_id,
            bundle,
            GVisorOciRunOptions {
                network_mode,
                ignore_cgroups,
                runsc_rootless,
                stage_runsc_binary,
                require_supervisor_exec_policy,
                platform,
                console_socket: None,
            },
        )
    }

    /// Check if gVisor is available on this system
    pub fn is_available() -> bool {
        Self::find_runsc().is_ok()
    }

    /// Get runsc version
    pub fn version(&self) -> Result<String> {
        let output = Command::new(&self.runsc_path)
            .arg("--version")
            .output()
            .map_err(|e| NucleusError::GVisorError(format!("Failed to get version: {}", e)))?;

        if !output.status.success() {
            return Err(NucleusError::GVisorError(
                "Failed to get runsc version".to_string(),
            ));
        }

        let version = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(version.trim().to_string())
    }

    fn exec_environment(
        &self,
        runtime_dir: &Path,
        reexec_via_proc_self_exe: bool,
    ) -> Result<Vec<CString>> {
        let mut env = Vec::new();
        let mut push = |key: &str, value: String| -> Result<()> {
            env.push(
                CString::new(format!("{}={}", key, value))
                    .map_err(|e| NucleusError::GVisorError(format!("Invalid {}: {}", key, e)))?,
            );
            Ok(())
        };

        // Use a hardcoded PATH for the runsc supervisor process to prevent
        // host PATH from leaking into the gVisor environment. NixOS exposes
        // privileged rootless-userns helpers through /run/wrappers/bin; runsc
        // needs newuidmap/newgidmap there when it creates an OCI user namespace.
        push("PATH", RUNSC_SUPERVISOR_PATH.to_string())?;
        let runtime_dir = runtime_dir.to_string_lossy().to_string();
        push("TMPDIR", runtime_dir.clone())?;
        push("XDG_RUNTIME_DIR", runtime_dir)?;

        // Hardcode safe values instead of leaking host identity/paths.
        // HOME could point to an attacker-controlled directory; USER/LOGNAME
        // leak host identity information – none of which gVisor needs.
        push("HOME", "/root".to_string())?;
        push("USER", "root".to_string())?;
        push("LOGNAME", "root".to_string())?;
        if reexec_via_proc_self_exe {
            push(RUNSC_REEXEC_VIA_PROC_SELF_EXE_ENV, "1".to_string())?;
        }

        Ok(env)
    }

    fn runsc_debug_dir() -> Result<Option<PathBuf>> {
        let Some(raw) = std::env::var_os(RUNSC_DEBUG_DIR_ENV).filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        let path = Self::absolute_path(Path::new(&raw), "runsc debug directory")?;
        Self::ensure_secure_runsc_dir(&path, "runsc debug directory")?;
        Ok(Some(path))
    }

    fn prepare_supervisor_runsc_program(
        &self,
        runsc_root: &Path,
        force_private_stage: bool,
    ) -> Result<(PathBuf, Vec<PathBuf>)> {
        let canonical = fs::canonicalize(&self.runsc_path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to canonicalize runsc path {:?}: {}",
                self.runsc_path, e
            ))
        })?;
        let canonical = Self::unwrap_nix_wrapper(&canonical).unwrap_or(canonical);

        Self::ensure_secure_runsc_dir(runsc_root, "runsc root directory")?;

        if !force_private_stage {
            if let Some(exec_root) = Self::nix_store_runsc_exec_root(&canonical) {
                // Nix store paths are immutable and already validated as trusted
                // runsc artifacts. Use the store binary directly so gVisor helper
                // re-execs do not depend on private runtime-directory ownership.
                return Ok((canonical, Self::supervisor_exec_allow_roots(exec_root)));
            }
        }

        let private_dir = runsc_root.join("exec-allow");
        Self::ensure_secure_runsc_dir(&private_dir, "private runsc exec directory")?;

        if force_private_stage {
            // Force a private copy only when the caller explicitly wants a
            // per-container executable root. Rootless bridge mode should not
            // set this: gVisor helpers may re-exec after changing credentials,
            // and the Nix store path remains easier to traverse safely.
            debug!(
                source = ?canonical,
                target_root = ?private_dir,
                "Staging runsc binary for private supervisor exec root"
            );
        }

        // Stage runsc when it is not an immutable Nix store artifact, or when
        // the caller explicitly requests a private executable root. Keeping the
        // executable under a per-container allowlist avoids granting execute
        // over broader host paths when a supervisor policy is installed.
        let stage_dir = Self::create_unique_runsc_stage_dir(&private_dir)?;
        let staged = stage_dir.join("runsc");
        Self::copy_runsc_nofollow(&canonical, &staged)?;

        Ok((staged, Self::supervisor_exec_allow_roots(private_dir)))
    }

    fn supervisor_exec_allow_roots(program_root: PathBuf) -> Vec<PathBuf> {
        // The patched runsc resolves helper re-execs to its concrete binary
        // path. Keep the supervisor policy scoped to that executable root.
        vec![program_root]
    }

    fn rootless_userns_helper_exec_roots() -> Vec<PathBuf> {
        // NixOS exposes newuidmap/newgidmap as setuid wrappers below
        // /run/wrappers/bin. Rootless runsc invokes them while creating the
        // OCI user namespace, after the supervisor execute allowlist is active.
        let mut roots: Vec<PathBuf> = ROOTLESS_USERNS_HELPERS
            .iter()
            .map(|helper| PathBuf::from(NIXOS_ROOTLESS_USERNS_WRAPPER_DIR).join(helper))
            .collect();

        // The NixOS wrappers exec immutable store binaries, but the wrapper
        // executables are intentionally unreadable so Nucleus cannot discover
        // those targets by inspecting the wrapper. Callers that install a
        // fail-closed supervisor policy can provide the concrete helper paths.
        if let Some(raw_roots) = std::env::var_os(ROOTLESS_USERNS_HELPER_EXEC_ROOTS_ENV)
            .filter(|value| !value.is_empty())
        {
            roots.extend(std::env::split_paths(&raw_roots).filter(|path| path.is_absolute()));
        }

        roots
    }

    fn nix_store_runsc_exec_root(program: &Path) -> Option<PathBuf> {
        if !program.starts_with(NIX_STORE_EXEC_ROOT) {
            return None;
        }

        program.parent().map(Path::to_path_buf)
    }

    fn secure_runsc_root(container_id: &str) -> Result<PathBuf> {
        let artifact_base = Self::gvisor_artifact_base()?;
        let artifact_dir = artifact_base.join(Self::runsc_state_component(container_id));

        if Self::host_root_requires_trusted_runsc_ancestry() {
            Self::ensure_trusted_host_root_runsc_ancestry(
                &artifact_base,
                "gVisor runsc artifact base",
            )?;
        }

        Self::ensure_secure_runsc_dir(&artifact_base, "gVisor runsc artifact base")?;
        Self::ensure_secure_runsc_dir(&artifact_dir, "gVisor runsc artifact directory")?;

        let runsc_root = artifact_dir.join("runsc-root");
        Self::ensure_secure_runsc_dir(&runsc_root, "runsc root directory")?;
        Ok(runsc_root)
    }

    fn gvisor_artifact_base() -> Result<PathBuf> {
        if let Some(path) =
            std::env::var_os("NUCLEUS_GVISOR_ARTIFACT_BASE").filter(|path| !path.is_empty())
        {
            return Self::absolute_path(Path::new(&path), "gVisor artifact base");
        }

        if !Uid::effective().is_root() || Self::root_uid_maps_to_unprivileged_host_uid_from_proc() {
            if let Some(dir) = dirs::runtime_dir() {
                return Ok(dir.join("nucleus-gvisor"));
            }
        }

        if Uid::effective().is_root() {
            Ok(PathBuf::from("/run/nucleus-gvisor"))
        } else {
            Ok(std::env::temp_dir().join(format!("nucleus-gvisor-{}", Uid::effective().as_raw())))
        }
    }

    fn absolute_path(path: &Path, label: &str) -> Result<PathBuf> {
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }

        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to resolve current directory for {} {:?}: {}",
                    label, path, e
                ))
            })
    }

    fn runsc_state_component(container_id: &str) -> String {
        if container_id.len() == 32 && container_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return container_id.to_string();
        }

        let digest = Sha256::digest(container_id.as_bytes());
        format!("id-{}", hex::encode(&digest[..16]))
    }

    fn root_uid_maps_to_unprivileged_host_uid_from_proc() -> bool {
        fs::read_to_string("/proc/self/uid_map")
            .map(|uid_map| Self::root_uid_maps_to_unprivileged_host_uid(&uid_map))
            .unwrap_or(false)
    }

    fn root_uid_maps_to_unprivileged_host_uid(uid_map: &str) -> bool {
        for line in uid_map.lines() {
            let mut fields = line.split_whitespace();
            let Some(namespace_start) = fields.next() else {
                continue;
            };
            let Some(host_start) = fields.next() else {
                continue;
            };
            let Some(length) = fields.next() else {
                continue;
            };
            if fields.next().is_some() {
                continue;
            }

            let Ok(namespace_start) = namespace_start.parse::<u64>() else {
                continue;
            };
            let Ok(host_start) = host_start.parse::<u64>() else {
                continue;
            };
            let Ok(length) = length.parse::<u64>() else {
                continue;
            };

            if namespace_start == 0 && length > 0 {
                return host_start != 0;
            }
        }

        false
    }

    fn host_root_requires_trusted_runsc_ancestry() -> bool {
        Uid::effective().is_root() && !Self::root_uid_maps_to_unprivileged_host_uid_from_proc()
    }

    fn ensure_trusted_host_root_runsc_ancestry(path: &Path, label: &str) -> Result<()> {
        let path = Self::absolute_path(path, label)?;

        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => current.push(prefix.as_os_str()),
                Component::RootDir => current.push(component.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(NucleusError::GVisorError(format!(
                        "{} {:?} contains a parent-directory component",
                        label, path
                    )));
                }
                Component::Normal(name) => {
                    current.push(name);
                    match fs::symlink_metadata(&current) {
                        Ok(metadata) => Self::ensure_trusted_host_root_runsc_ancestor_component(
                            &current, metadata, label,
                        )?,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                        Err(e) => {
                            return Err(NucleusError::GVisorError(format!(
                                "Failed to stat {} ancestor {:?}: {}",
                                label, current, e
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn ensure_trusted_host_root_runsc_ancestor_component(
        path: &Path,
        metadata: fs::Metadata,
        label: &str,
    ) -> Result<()> {
        if metadata.file_type().is_symlink() {
            return Err(NucleusError::GVisorError(format!(
                "Refusing symlink {} ancestor {:?}",
                label, path
            )));
        }
        if !metadata.file_type().is_dir() {
            return Err(NucleusError::GVisorError(format!(
                "{} ancestor {:?} is not a directory",
                label, path
            )));
        }

        let owner = metadata.uid();
        if owner != 0 {
            return Err(NucleusError::GVisorError(format!(
                "{} ancestor {:?} is owned by uid {} (expected root)",
                label, path, owner
            )));
        }

        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(NucleusError::GVisorError(format!(
                "{} ancestor {:?} has unsafe permissions {:o}",
                label,
                path,
                mode & 0o7777
            )));
        }

        Ok(())
    }

    fn ensure_secure_runsc_dir(path: &Path, label: &str) -> Result<()> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            Self::ensure_trusted_runsc_parent(parent, label)?;
        }

        let mut created = false;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(NucleusError::GVisorError(format!(
                    "Refusing symlink {} {:?}",
                    label, path
                )));
            }
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(NucleusError::GVisorError(format!(
                    "{} {:?} is not a directory",
                    label, path
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match DirBuilder::new().mode(0o700).create(path) {
                    Ok(()) => {
                        created = true;
                    }
                    Err(create_err) if create_err.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(create_err) => {
                        return Err(NucleusError::GVisorError(format!(
                            "Failed to create {} {:?}: {}",
                            label, path, create_err
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(NucleusError::GVisorError(format!(
                    "Failed to stat {} {:?}: {}",
                    label, path, e
                )));
            }
        }

        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to secure newly-created {} permissions {:?}: {}",
                    label, path, e
                ))
            })?;
        }

        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to open {} {:?} without following symlinks: {}",
                    label, path, e
                ))
            })?;

        let metadata = dir.metadata().map_err(|e| {
            NucleusError::GVisorError(format!("Failed to stat {} {:?}: {}", label, path, e))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(NucleusError::GVisorError(format!(
                "{} {:?} is not a directory",
                label, path
            )));
        }

        let owner = metadata.uid();
        let expected = Uid::effective().as_raw();
        if owner != expected {
            // Under a non-trivial user namespace (keep-id / auto), files we
            // legitimately own can appear under a non-root container uid
            // (e.g. host uid 1000 -> container uid 1000). If the owner is still
            // a uid mapped into our namespace, reclaim the directory by
            // chowning it to container root (the trusted owner) rather than
            // failing. This handles stale dirs left by a prior rootless mode.
            if crate::isolation::uid_is_mapped_in_current_userns(owner)
                && Uid::effective().is_root()
            {
                debug!(
                    "Reclaiming {} {:?} from mapped uid {} to container root",
                    label, path, owner
                );
                nix::unistd::chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
                    .map_err(|e| {
                        NucleusError::GVisorError(format!(
                            "Failed to reclaim {} {:?}: {}",
                            label, path, e
                        ))
                    })?;
            } else {
                return Err(NucleusError::GVisorError(format!(
                    "{} {:?} is owned by uid {} (expected {})",
                    label, path, owner, expected
                )));
            }
        }

        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            dir.set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|e| {
                    NucleusError::GVisorError(format!(
                        "Failed to secure {} permissions {:?}: {}",
                        label, path, e
                    ))
                })?;
        }

        Ok(())
    }

    fn ensure_trusted_runsc_parent(parent: &Path, label: &str) -> Result<()> {
        let metadata = fs::symlink_metadata(parent).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to stat parent for {} {:?}: {}",
                label, parent, e
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(NucleusError::GVisorError(format!(
                "Refusing symlink parent for {} {:?}",
                label, parent
            )));
        }
        if !metadata.file_type().is_dir() {
            return Err(NucleusError::GVisorError(format!(
                "Parent for {} {:?} is not a directory",
                label, parent
            )));
        }

        let owner = metadata.uid();
        let current = Uid::effective().as_raw();
        // A parent is trusted if it is owned by us, by container root, or by any
        // uid mapped into our (non-trivial) user namespace. The last clause is
        // required for keep-id / auto rootless, where our own runtime dir
        // (e.g. $XDG_RUNTIME_DIR) appears under a non-root container uid.
        let owner_trusted = owner == current
            || owner == 0
            || crate::isolation::uid_is_mapped_in_current_userns(owner);
        let mode = metadata.permissions().mode();
        let unsafe_writable = mode & 0o022 != 0 && mode & 0o1000 == 0;
        if !owner_trusted || unsafe_writable {
            return Err(NucleusError::GVisorError(format!(
                "Parent for {} {:?} is not trusted (owner uid {}, mode {:o})",
                label,
                parent,
                owner,
                mode & 0o7777
            )));
        }

        Ok(())
    }

    fn create_unique_runsc_stage_dir(private_dir: &Path) -> Result<PathBuf> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();

        for attempt in 0..100u32 {
            let stage_dir = private_dir.join(format!(
                "stage-{}-{}-{}",
                std::process::id(),
                nonce,
                attempt
            ));
            match DirBuilder::new().mode(0o700).create(&stage_dir) {
                Ok(()) => {
                    Self::ensure_secure_runsc_dir(&stage_dir, "runsc stage directory")?;
                    return Ok(stage_dir);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(NucleusError::GVisorError(format!(
                        "Failed to create runsc stage directory {:?}: {}",
                        stage_dir, e
                    )));
                }
            }
        }

        Err(NucleusError::GVisorError(format!(
            "Failed to create unique runsc stage directory under {:?}",
            private_dir
        )))
    }

    fn copy_runsc_nofollow(source: &Path, staged: &Path) -> Result<()> {
        let mut source_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(source)
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to open runsc source {:?}: {}",
                    source, e
                ))
            })?;

        let source_meta = source_file.metadata().map_err(|e| {
            NucleusError::GVisorError(format!("Failed to stat runsc source {:?}: {}", source, e))
        })?;
        if !source_meta.file_type().is_file() {
            return Err(NucleusError::GVisorError(format!(
                "runsc source {:?} is not a regular file",
                source
            )));
        }

        let mut staged_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(staged)
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to create staged runsc binary {:?}: {}",
                    staged, e
                ))
            })?;

        io::copy(&mut source_file, &mut staged_file).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to stage runsc binary from {:?} to {:?}: {}",
                source, staged, e
            ))
        })?;
        staged_file
            .set_permissions(fs::Permissions::from_mode(0o500))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to secure staged runsc binary {:?}: {}",
                    staged, e
                ))
            })?;
        staged_file.sync_all().map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to sync staged runsc binary {:?}: {}",
                staged, e
            ))
        })?;

        Ok(())
    }

    fn apply_supervisor_exec_policy(
        &self,
        allowed_roots: &[PathBuf],
        required: bool,
    ) -> Result<()> {
        let mut landlock = LandlockManager::new();
        let applied = landlock.apply_execute_allowlist_policy(allowed_roots, !required)?;
        if applied {
            info!(
                allowed_roots = ?allowed_roots,
                "Applied gVisor supervisor execute allowlist"
            );
        } else if required {
            return Err(NucleusError::LandlockError(
                "Required gVisor supervisor execute allowlist was not applied".to_string(),
            ));
        } else {
            warn!(
                allowed_roots = ?allowed_roots,
                "gVisor supervisor execute allowlist unavailable"
            );
        }
        Ok(())
    }

    fn build_oci_run_args(
        &self,
        container_id: &str,
        bundle: &OciBundle,
        runsc_root: &Path,
        options: &GVisorOciRunOptions,
        debug_dir: Option<&Path>,
    ) -> Vec<String> {
        let mut args = vec![
            self.runsc_path.clone(),
            "--root".to_string(),
            runsc_root.to_string_lossy().to_string(),
        ];

        if options.runsc_rootless {
            args.push("--rootless".to_string());
        }

        if options.ignore_cgroups {
            args.push("--ignore-cgroups".to_string());
        }

        if let Some(debug_dir) = debug_dir {
            let debug_pattern = debug_dir
                .join("%TIMESTAMP%.%COMMAND%.log")
                .to_string_lossy()
                .to_string();
            let panic_log = debug_dir
                .join("panic.%TIMESTAMP%.log")
                .to_string_lossy()
                .to_string();
            args.extend([
                "--debug".to_string(),
                "--alsologtostderr".to_string(),
                "--debug-to-user-log".to_string(),
                "--debug-log".to_string(),
                debug_pattern,
                "--panic-log".to_string(),
                panic_log,
            ]);
        }

        args.extend([
            "--network".to_string(),
            options.network_flag().to_string(),
            "--platform".to_string(),
            options.platform.as_flag().to_string(),
            "run".to_string(),
        ]);

        if let Some(console_socket) = &options.console_socket {
            args.extend([
                "--console-socket".to_string(),
                console_socket.to_string_lossy().to_string(),
            ]);
        }

        args.extend([
            "--bundle".to_string(),
            bundle.bundle_path().to_string_lossy().to_string(),
            container_id.to_string(),
        ]);

        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::OciConfig;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvLock {
        _guard: MutexGuard<'static, ()>,
    }

    impl EnvLock {
        fn acquire() -> Self {
            Self {
                _guard: ENV_LOCK.lock().unwrap(),
            }
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn test_gvisor_availability() {
        // This test just checks if we can determine availability
        // It may pass or fail depending on whether gVisor is installed
        let available = GVisorRuntime::is_available();
        println!("gVisor available: {}", available);
    }

    #[test]
    fn test_gvisor_new() {
        let runtime = GVisorRuntime::new();
        if let Ok(rt) = runtime {
            println!("Found runsc at: {}", rt.runsc_path);
            if let Ok(version) = rt.version() {
                println!("runsc version: {}", version);
            }
        }
    }

    #[test]
    fn test_find_runsc() {
        // Test that find_runsc either succeeds or returns appropriate error
        match GVisorRuntime::find_runsc() {
            Ok(path) => {
                println!("Found runsc at: {}", path);
                assert!(!path.is_empty());
            }
            Err(e) => {
                println!("runsc not found (expected if gVisor not installed): {}", e);
            }
        }
    }

    #[test]
    fn test_validate_runsc_rejects_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let fake_runsc = dir.path().join("runsc");
        std::fs::write(&fake_runsc, "#!/bin/sh\necho fake").unwrap();
        // Make world-writable
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o777)).unwrap();

        let result = GVisorRuntime::validate_runsc_path(&fake_runsc);
        assert!(
            result.is_err(),
            "validate_runsc_path must reject world-writable binaries"
        );
    }

    #[test]
    fn test_validate_runsc_rejects_group_writable() {
        let dir = tempfile::tempdir().unwrap();
        let fake_runsc = dir.path().join("runsc");
        std::fs::write(&fake_runsc, "#!/bin/sh\necho fake").unwrap();
        // Make group-writable
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o775)).unwrap();

        let result = GVisorRuntime::validate_runsc_path(&fake_runsc);
        assert!(
            result.is_err(),
            "validate_runsc_path must reject group-writable binaries"
        );
    }

    #[test]
    fn test_runsc_owner_accepts_nix_store_artifact_owner() {
        // Use a real Nix store binary so the metadata/permission checks pass.
        // The /nix/store contents are read-only and content-addressed, so any
        // existing file with mode 555 works.
        let nix_binary = std::fs::read_dir("/nix/store")
            .ok()
            .and_then(|mut entries| {
                entries.find_map(|e| {
                    let dir = e.ok()?.path();
                    let candidate = dir.join("bin/runsc");
                    if candidate.exists() {
                        Some(candidate)
                    } else {
                        None
                    }
                })
            });

        let path = match nix_binary {
            Some(p) => p,
            None => {
                eprintln!("skipping: no runsc binary found in /nix/store");
                return;
            }
        };

        assert!(GVisorRuntime::is_trusted_runsc_owner(&path, 65534, 1000));
    }

    #[test]
    fn test_exec_environment_uses_hardcoded_path() {
        // The gVisor supervisor must NOT inherit the host PATH, to prevent
        // host filesystem layout leaking into the container environment.
        // Verify by setting a distinctive PATH and checking exec_environment
        // returns a hardcoded value instead.
        std::env::set_var("PATH", "/tmp/evil-inject/bin:/opt/attacker/sbin");
        let rt = GVisorRuntime::with_path("/fake/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let env = rt.exec_environment(tmp.path(), false).unwrap();
        let path_entry = env
            .iter()
            .find(|e| e.to_str().is_ok_and(|s| s.starts_with("PATH=")))
            .expect("exec_environment must set PATH");
        let path_val = path_entry.to_str().unwrap();
        assert!(
            !path_val.contains("evil-inject") && !path_val.contains("attacker"),
            "exec_environment must use hardcoded PATH, not host PATH. Got: {}",
            path_val
        );
        assert_eq!(
            path_val,
            format!("PATH={RUNSC_SUPERVISOR_PATH}"),
            "exec_environment PATH must be the standard hardcoded value"
        );
    }

    #[test]
    fn test_exec_environment_can_request_proc_self_exe_reexec() {
        let rt = GVisorRuntime::with_path("/fake/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let env = rt.exec_environment(tmp.path(), true).unwrap();
        let expected = format!("{}=1", RUNSC_REEXEC_VIA_PROC_SELF_EXE_ENV);

        assert!(
            env.iter()
                .any(|entry| entry.to_str().is_ok_and(|entry| entry == expected)),
            "runsc env must request /proc/self/exe re-exec when explicitly requested"
        );
    }

    #[test]
    fn test_exec_environment_keeps_real_exe_reexec_for_supervisor_policy() {
        let rt = GVisorRuntime::with_path("/fake/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let env = rt.exec_environment(tmp.path(), false).unwrap();

        assert!(
            env.iter().all(|entry| entry.to_str().map_or(true, |entry| {
                !entry.starts_with(RUNSC_REEXEC_VIA_PROC_SELF_EXE_ENV)
            })),
            "runsc env must not enable /proc/self/exe re-exec when supervisor policy is active"
        );
    }

    #[test]
    fn test_builtin_rootless_args_pass_runsc_rootless() {
        let rt = GVisorRuntime::with_path("/nix/store/fake-runsc/bin/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let bundle = OciBundle::new(
            tmp.path().join("bundle"),
            OciConfig::new(vec!["/bin/true".to_string()], None),
        );

        let args = rt.build_oci_run_args(
            "container-id",
            &bundle,
            tmp.path(),
            &GVisorOciRunOptions {
                network_mode: GVisorNetworkMode::Host,
                ignore_cgroups: true,
                runsc_rootless: true,
                stage_runsc_binary: false,
                require_supervisor_exec_policy: false,
                platform: GVisorPlatform::Systrap,
                console_socket: None,
            },
            None,
        );

        assert!(args.iter().any(|arg| arg == "--rootless"));
        assert!(args.iter().any(|arg| arg == "--ignore-cgroups"));
    }

    #[test]
    fn test_runsc_rootless_does_not_force_supervisor_exec_policy() {
        let source = include_str!("gvisor.rs");
        let start = source.find("pub fn exec_with_oci_bundle_options").unwrap();
        let end = source[start..]
            .find("pub fn exec_with_oci_bundle_network")
            .map(|offset| start + offset)
            .unwrap();
        let fn_body = &source[start..end];

        assert!(
            fn_body.contains("if options.require_supervisor_exec_policy"),
            "supervisor execute policy must be selected explicitly"
        );
        assert!(
            !fn_body.contains("|| options.runsc_rootless"),
            "runsc --rootless must not force the host-side supervisor execute policy"
        );
        assert!(
            fn_body.contains("options.runsc_rootless && !options.require_supervisor_exec_policy"),
            "rootless runsc must use /proc/self/exe helper re-exec only without supervisor policy"
        );
    }

    #[test]
    fn test_rootless_oci_args_do_not_pass_runsc_rootless() {
        let rt = GVisorRuntime::with_path("/nix/store/fake-runsc/bin/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let bundle = OciBundle::new(
            tmp.path().join("bundle"),
            OciConfig::new(vec!["/bin/true".to_string()], None),
        );

        let args = rt.build_oci_run_args(
            "container-id",
            &bundle,
            tmp.path(),
            &GVisorOciRunOptions {
                network_mode: GVisorNetworkMode::Host,
                ignore_cgroups: true,
                runsc_rootless: false,
                stage_runsc_binary: false,
                require_supervisor_exec_policy: false,
                platform: GVisorPlatform::Systrap,
                console_socket: None,
            },
            None,
        );

        assert!(!args.iter().any(|arg| arg == "--rootless"));
        assert!(args.iter().any(|arg| arg == "--ignore-cgroups"));
    }

    #[test]
    fn test_runsc_args_pass_console_socket_after_run_subcommand() {
        let rt = GVisorRuntime::with_path("/nix/store/fake-runsc/bin/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let console_socket = tmp.path().join("console.sock");
        let bundle = OciBundle::new(
            tmp.path().join("bundle"),
            OciConfig::new(vec!["/bin/true".to_string()], None),
        );

        let args = rt.build_oci_run_args(
            "container-id",
            &bundle,
            tmp.path(),
            &GVisorOciRunOptions {
                network_mode: GVisorNetworkMode::Host,
                ignore_cgroups: true,
                runsc_rootless: false,
                stage_runsc_binary: false,
                require_supervisor_exec_policy: false,
                platform: GVisorPlatform::Systrap,
                console_socket: Some(console_socket.clone()),
            },
            None,
        );

        let run_index = args.iter().position(|arg| arg == "run").unwrap();
        let socket_index = args
            .iter()
            .position(|arg| arg == "--console-socket")
            .unwrap();
        assert!(socket_index > run_index);
        assert_eq!(
            args.get(socket_index + 1),
            Some(&console_socket.to_string_lossy().to_string())
        );
    }

    #[test]
    fn test_runsc_debug_dir_adds_debug_flags_before_subcommand() {
        let rt = GVisorRuntime::with_path("/nix/store/fake-runsc/bin/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let debug_dir = tmp.path().join("runsc-debug");
        let bundle = OciBundle::new(
            tmp.path().join("bundle"),
            OciConfig::new(vec!["/bin/true".to_string()], None),
        );

        let args = rt.build_oci_run_args(
            "container-id",
            &bundle,
            tmp.path(),
            &GVisorOciRunOptions {
                network_mode: GVisorNetworkMode::Host,
                ignore_cgroups: true,
                runsc_rootless: true,
                stage_runsc_binary: false,
                require_supervisor_exec_policy: false,
                platform: GVisorPlatform::Ptrace,
                console_socket: None,
            },
            Some(&debug_dir),
        );

        let run_index = args.iter().position(|arg| arg == "run").unwrap();
        let debug_index = args.iter().position(|arg| arg == "--debug").unwrap();
        assert!(
            debug_index < run_index,
            "runsc debug flags must be top-level flags before the subcommand"
        );
        assert!(args.iter().any(|arg| arg == "--alsologtostderr"));
        assert!(args.iter().any(|arg| arg == "--debug-to-user-log"));
        assert!(args.iter().any(|arg| arg == "--debug-log"));
        assert!(args.iter().any(|arg| arg.contains("%COMMAND%.log")));
        assert!(args.iter().any(|arg| arg.contains("panic.%TIMESTAMP%.log")));
    }

    #[test]
    fn test_non_nix_runsc_is_staged_for_supervisor_exec_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_runsc = tmp.path().join("runsc-source");
        std::fs::write(&fake_runsc, b"fake-runsc").unwrap();
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o500)).unwrap();

        let rt = GVisorRuntime::with_path(fake_runsc.to_string_lossy().to_string());
        let runsc_root = tmp.path().join("runsc-root");
        let (program, allow_roots) = rt
            .prepare_supervisor_runsc_program(&runsc_root, false)
            .unwrap();

        assert!(program.starts_with(runsc_root.join("exec-allow")));
        assert_eq!(allow_roots, vec![runsc_root.join("exec-allow")]);
        assert_eq!(std::fs::read(&program).unwrap(), b"fake-runsc");
        let mode = std::fs::metadata(&program).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o500);
    }

    #[test]
    fn test_nix_store_runsc_uses_package_bin_exec_root() {
        let program = Path::new("/nix/store/hash-gvisor-20251110.0/bin/.runsc-wrapped");

        assert_eq!(
            GVisorRuntime::nix_store_runsc_exec_root(program),
            Some(PathBuf::from("/nix/store/hash-gvisor-20251110.0/bin"))
        );
    }

    #[test]
    fn test_non_nix_runsc_has_no_store_exec_root() {
        let program = Path::new("/tmp/nucleus/runsc");

        assert_eq!(GVisorRuntime::nix_store_runsc_exec_root(program), None);
    }

    #[test]
    fn test_supervisor_exec_allow_roots_use_only_runsc_exec_root() {
        let roots = GVisorRuntime::supervisor_exec_allow_roots(PathBuf::from(NIX_STORE_EXEC_ROOT));

        assert_eq!(roots, vec![PathBuf::from(NIX_STORE_EXEC_ROOT)]);
    }

    #[test]
    fn test_rootless_userns_helper_exec_roots_include_default_wrappers() {
        let _env_lock = EnvLock::acquire();
        let _helper_roots = EnvVarGuard::remove(ROOTLESS_USERNS_HELPER_EXEC_ROOTS_ENV);
        let roots = GVisorRuntime::rootless_userns_helper_exec_roots();

        assert_eq!(
            roots,
            vec![
                PathBuf::from("/run/wrappers/bin/newuidmap"),
                PathBuf::from("/run/wrappers/bin/newgidmap"),
            ]
        );
    }

    #[test]
    fn test_rootless_userns_helper_exec_roots_include_configured_absolute_roots() {
        let _env_lock = EnvLock::acquire();
        let configured_roots = std::env::join_paths([
            PathBuf::from("/nix/store/shadow/bin/newuidmap"),
            PathBuf::from("relative/newgidmap"),
            PathBuf::from("/nix/store/shadow/bin/newgidmap"),
        ])
        .unwrap();
        let _helper_roots =
            EnvVarGuard::set(ROOTLESS_USERNS_HELPER_EXEC_ROOTS_ENV, configured_roots);

        let roots = GVisorRuntime::rootless_userns_helper_exec_roots();

        assert_eq!(
            roots,
            vec![
                PathBuf::from("/run/wrappers/bin/newuidmap"),
                PathBuf::from("/run/wrappers/bin/newgidmap"),
                PathBuf::from("/nix/store/shadow/bin/newuidmap"),
                PathBuf::from("/nix/store/shadow/bin/newgidmap"),
            ]
        );
    }

    #[test]
    fn test_rootless_supervisor_policy_allows_userns_helpers() {
        let source = include_str!("gvisor.rs");
        let start = source.find("pub fn exec_with_oci_bundle_options").unwrap();
        let end = source[start..]
            .find("pub fn exec_with_oci_bundle_network")
            .map(|offset| start + offset)
            .unwrap();
        let fn_body = &source[start..end];
        let helper_roots = fn_body
            .find("exec_allow_roots.extend(Self::rootless_userns_helper_exec_roots())")
            .unwrap();
        let policy = fn_body.find("self.apply_supervisor_exec_policy").unwrap();

        assert!(
            helper_roots < policy,
            "rootless runsc must allow newuidmap/newgidmap before installing Landlock"
        );
    }

    #[test]
    fn test_runsc_root_uses_hardened_artifact_dir_not_bundle_parent() {
        let _env_lock = EnvLock::acquire();
        let tmp = tempfile::tempdir().unwrap();
        let artifact_base = tmp.path().join("gvisor-artifacts");
        let _artifact_base = EnvVarGuard::set("NUCLEUS_GVISOR_ARTIFACT_BASE", &artifact_base);
        let _runtime = EnvVarGuard::remove("XDG_RUNTIME_DIR");

        let bundle_parent = tmp.path().join("shared");
        std::fs::create_dir_all(&bundle_parent).unwrap();
        std::fs::set_permissions(&bundle_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let bundle = OciBundle::new(
            bundle_parent.join("bundle"),
            OciConfig::new(vec!["/bin/true".to_string()], None),
        );

        let runsc_root = GVisorRuntime::secure_runsc_root("container-id").unwrap();

        assert!(runsc_root
            .starts_with(artifact_base.join(GVisorRuntime::runsc_state_component("container-id"))));
        assert!(
            !runsc_root.starts_with(bundle.bundle_path().parent().unwrap()),
            "runsc root must not be derived from a custom bundle parent"
        );
    }

    #[test]
    fn test_runsc_staging_rejects_symlink_exec_allow_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_runsc = tmp.path().join("runsc-source");
        std::fs::write(&fake_runsc, b"fake-runsc").unwrap();
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o500)).unwrap();

        let runsc_root = tmp.path().join("runsc-root");
        std::fs::create_dir(&runsc_root).unwrap();
        std::fs::set_permissions(&runsc_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim_dir = tmp.path().join("victim");
        std::fs::create_dir(&victim_dir).unwrap();
        std::os::unix::fs::symlink(&victim_dir, runsc_root.join("exec-allow")).unwrap();

        let rt = GVisorRuntime::with_path(fake_runsc.to_string_lossy().to_string());
        let err = rt
            .prepare_supervisor_runsc_program(&runsc_root, false)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("Refusing symlink private runsc exec directory"),
            "unexpected error: {}",
            err
        );
        assert!(
            !victim_dir.join("runsc").exists(),
            "staging must not follow the exec-allow symlink"
        );
    }

    #[test]
    fn test_runsc_owner_rejects_untrusted_non_store_owner() {
        assert!(!GVisorRuntime::is_trusted_runsc_owner(
            Path::new("/tmp/runsc"),
            4242,
            1000
        ));
    }
}
