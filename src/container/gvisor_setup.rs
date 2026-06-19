use crate::error::{NucleusError, Result};
use crate::filesystem::{
    create_dev_nodes, create_minimal_fs, read_regular_file_nofollow, resolve_container_destination,
    snapshot_context_dir, validate_production_rootfs_path, verify_context_manifest,
    verify_rootfs_attestation, ContextPopulator,
};
use crate::network::{BridgeNetwork, NetworkMode};
use crate::security::{
    load_json_policy, GVisorNetworkMode, GVisorOciRunOptions, GVisorRuntime, OciBundle, OciConfig,
    OciMount, OciSeccomp,
};
use nix::unistd::Uid;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tracing::info;

use super::{config::ServiceMode, runtime::Container};

fn require_gvisor_supervisor_exec_policy(
    service_mode: ServiceMode,
    precreated_userns: bool,
) -> bool {
    service_mode == ServiceMode::Production && !precreated_userns
}

impl Container {
    /// Set up container with gVisor and exec.
    pub(super) fn setup_and_exec_gvisor(&self, precreated_userns: bool) -> Result<()> {
        info!("Using gVisor runtime");

        let gvisor = if let Some(ref path) = self.runsc_path {
            GVisorRuntime::with_path(path.clone())
        } else {
            GVisorRuntime::new().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to initialize gVisor runtime: {}", e))
            })?
        };

        self.setup_and_exec_gvisor_oci(&gvisor, precreated_userns)
    }

    /// Set up container with gVisor using OCI bundle format.
    fn setup_and_exec_gvisor_oci(
        &self,
        gvisor: &GVisorRuntime,
        precreated_userns: bool,
    ) -> Result<()> {
        info!("Using gVisor with OCI bundle format");

        let mut oci_config =
            OciConfig::new(self.config.command.clone(), self.config.hostname.clone());
        if self.config.terminal {
            oci_config = oci_config.with_terminal(self.config.console_size);
        }
        if precreated_userns {
            // In rootless bridge mode Nucleus creates the mapped user namespace
            // before execing runsc so the prepared netns can be inherited.
            // Keep OCI noNewPrivileges out of this handoff and let gVisor
            // enforce its own sandbox process model after startup.
            oci_config = oci_config.with_no_new_privileges(false);
        }
        let artifact_dir = Self::gvisor_artifact_dir(&self.config.id);
        Self::ensure_secure_gvisor_artifact_dir(&artifact_dir)?;
        let context_manifest = if self.config.verify_context_integrity {
            self.config
                .context_dir
                .as_ref()
                .map(|dir| snapshot_context_dir(dir))
                .transpose()?
        } else {
            None
        };

        oci_config = oci_config.with_resources(&self.config.limits);
        oci_config = oci_config.with_namespace_config(&self.config.namespaces);
        oci_config = oci_config.with_workdir(&self.config.workdir)?;
        if precreated_userns {
            // Nucleus already created and mapped the user namespace before
            // execing runsc. Do not leave an OCI user namespace request in the
            // bundle, or runsc will try to create a nested user namespace for
            // its gofer/sandbox helper exec path.
            oci_config = oci_config.without_user_namespace();
        }
        oci_config = oci_config.with_process_identity(&self.config.process_identity);
        oci_config =
            oci_config.with_home_tmpfs(&self.config.home, &self.config.process_identity)?;
        if matches!(
            self.config.network,
            NetworkMode::Bridge(_) | NetworkMode::GVisorHost
        ) {
            // Bridge: Nucleus configures userspace NAT against the child
            // process' network namespace before exec, then runsc inherits it.
            // gvisor-host: runsc hostinet only reaches the host namespace when
            // no OCI network namespace entry is present.
            oci_config = oci_config.without_network_namespace();
        }
        oci_config = oci_config.with_rlimits(&self.config.limits);

        if let Some(profile_path) = self.config.seccomp_profile.as_ref() {
            let seccomp: OciSeccomp =
                load_json_policy(profile_path, self.config.seccomp_profile_sha256.as_deref())?;
            oci_config = oci_config.with_seccomp(seccomp);
            info!(
                "Attached OCI linux.seccomp profile to gVisor bundle from {:?}",
                profile_path
            );
        }

        // Inject user-configured environment variables
        if !self.config.environment.is_empty() {
            oci_config = oci_config.with_env(&self.config.environment);
        }

        // Inject launch-derived environment variables (credential-broker
        // proxy/identity, etc.). These reach the workload but are excluded
        // from image commit manifests. User env wins on collision.
        if !self.config.derived_environment.is_empty() {
            let user_keys: std::collections::HashSet<&String> = self
                .config
                .environment
                .iter()
                .map(|(key, _)| key)
                .collect();
            let derived: Vec<(String, String)> = self
                .config
                .derived_environment
                .iter()
                .filter(|(key, _)| !user_keys.contains(key))
                .cloned()
                .collect();
            if !derived.is_empty() {
                oci_config = oci_config.with_env(&derived);
            }
        }

        // Pass through sd_notify socket
        if self.config.sd_notify {
            oci_config = oci_config.with_sd_notify();
        }

        // Mount pre-built rootfs if provided
        if let Some(ref rootfs_path) = self.config.rootfs_path {
            let rootfs_path = if self.config.service_mode == ServiceMode::Production {
                validate_production_rootfs_path(rootfs_path)?
            } else {
                rootfs_path.clone()
            };
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(&rootfs_path)?;
            }
            oci_config = oci_config.with_rootfs_binds(&rootfs_path)?;
        } else {
            oci_config = oci_config.with_host_runtime_binds();
        }

        oci_config = oci_config.with_workspace_mount(&self.config.workspace)?;

        if !self.config.provider_configs.is_empty() {
            oci_config = oci_config
                .with_provider_config_mounts(&self.config.home, &self.config.provider_configs)?;
        }

        if !self.config.volumes.is_empty() {
            oci_config = oci_config.with_volume_mounts(&self.config.volumes)?;
        }

        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::BindMount
            ) {
                ContextPopulator::new(context_dir, "/context").validate_source_tree()?;
                oci_config = oci_config.with_context_bind(context_dir);
            }
        }

        if !self.config.secrets.is_empty() {
            let secret_stage_dir = artifact_dir.join("secrets-stage");
            Self::mount_gvisor_secret_stage_tmpfs(&secret_stage_dir)?;
            Self::apply_secret_dir_identity(&secret_stage_dir, &self.config.process_identity)?;
            let staged_secrets = Self::stage_gvisor_secret_files(
                &secret_stage_dir,
                &self.config.secrets,
                &self.config.process_identity,
            )?;
            oci_config =
                oci_config.with_inmemory_secret_mounts(&secret_stage_dir, &staged_secrets)?;
        }

        if let Some(user_ns_config) = &self.config.user_ns_config {
            // Rootless gVisor handoff already placed runsc in a mapped user
            // namespace so it can inherit the prepared launch context. Do not
            // ask runsc to create a nested OCI user namespace with host IDs
            // that are not mapped in the intermediate namespace.
            if precreated_userns {
                info!("Using pre-created rootless user namespace for gVisor handoff");
            } else {
                oci_config = oci_config.with_rootless_user_namespace(user_ns_config);
            }
        }

        // Pass OCI hooks into the gVisor config.json so gVisor executes them
        if let Some(ref hooks) = self.config.hooks {
            oci_config = oci_config.with_hooks(hooks.clone());
        }

        // Use --bundle path if provided, otherwise default
        let bundle_path = self
            .config
            .bundle_dir
            .clone()
            .unwrap_or_else(|| Self::gvisor_bundle_path(&self.config.id));
        let oci_mounts = oci_config.mounts.clone();
        let bundle = OciBundle::new(bundle_path, oci_config);
        bundle.create()?;

        let rootfs = bundle.rootfs_path();
        create_minimal_fs(&rootfs)?;
        Self::prepare_oci_mountpoints(&rootfs, &oci_mounts)?;
        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::Copy
            ) {
                let context_dest = rootfs.join("context");
                ContextPopulator::new(context_dir, &context_dest).populate()?;
                if let Some(expected) = &context_manifest {
                    verify_context_manifest(expected, &context_dest)?;
                }
            }
        }

        let dev_path = rootfs.join("dev");
        create_dev_nodes(&dev_path, self.config.terminal)?;

        // Write resolv.conf for bridge networking into the OCI rootfs
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            BridgeNetwork::write_resolv_conf(&rootfs, &bridge_config.dns)?;
        }

        // Select gVisor network mode based on container network config
        let gvisor_net = match &self.config.network {
            NetworkMode::None => GVisorNetworkMode::None,
            NetworkMode::Host => {
                return Err(NucleusError::ConfigError(
                    "gVisor runtime requires --network gvisor-host for host networking; --network host is native host networking"
                        .to_string(),
                ));
            }
            NetworkMode::GVisorHost => GVisorNetworkMode::Host,
            NetworkMode::Bridge(_) => GVisorNetworkMode::Host,
        };

        let rootless_gvisor = self.config.user_ns_config.is_some() || !Uid::effective().is_root();
        let ignore_cgroups = rootless_gvisor;
        // Tell runsc whenever the launch is rootless. Pre-created gVisor
        // handoff namespaces need this so helper handoff keeps mapped
        // privileges; OCI user namespace launches need it because runsc itself
        // starts as the non-root service user.
        let runsc_rootless = rootless_gvisor;
        let platform = self.config.gvisor_platform;
        // Production gVisor launches fail closed under the host-side
        // supervisor execute policy except for the pre-created gVisor userns
        // handoff. Do not key this off user_ns_config: root-run production
        // auto-enables root_remapped() and still needs the policy.
        let require_supervisor_exec_policy =
            require_gvisor_supervisor_exec_policy(self.config.service_mode, precreated_userns);
        // Keep runsc on its immutable package path. gVisor helper processes may
        // drop to credentials that cannot traverse Nucleus' private runtime
        // directory, while the Nix store binary is world-executable and
        // validated before this handoff.
        let stage_runsc_binary = false;
        gvisor.exec_with_oci_bundle_options(
            &self.config.id,
            &bundle,
            GVisorOciRunOptions {
                network_mode: gvisor_net,
                ignore_cgroups,
                runsc_rootless,
                stage_runsc_binary,
                require_supervisor_exec_policy,
                platform,
                console_socket: self.config.console_socket.clone(),
            },
        )?;

        Ok(())
    }

    pub(super) fn prepare_oci_mountpoints(
        rootfs: &std::path::Path,
        mounts: &[OciMount],
    ) -> Result<()> {
        for mount in mounts {
            let normalized = crate::filesystem::normalize_container_destination(
                std::path::Path::new(&mount.destination),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Invalid OCI mount destination {:?}: {}",
                    mount.destination, e
                ))
            })?;
            let relative = normalized.strip_prefix("/").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to convert OCI mount destination {:?} into a rootfs-relative path: {}",
                    normalized, e
                ))
            })?;
            let target = rootfs.join(relative);
            if mount.mount_type == "bind" && std::path::Path::new(&mount.source).is_file() {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount parent {:?}: {}",
                            parent, e
                        ))
                    })?;
                }
                if !target.exists() {
                    std::fs::File::create(&target).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount target {:?}: {}",
                            target, e
                        ))
                    })?;
                }
            } else {
                std::fs::create_dir_all(&target).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create OCI mount target {:?}: {}",
                        target, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub(super) fn gvisor_artifact_dir(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_base().join(container_id)
    }

    pub(super) fn gvisor_bundle_path(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("bundle")
    }

    fn gvisor_secret_stage_dir(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("secrets-stage")
    }

    fn gvisor_artifact_base() -> std::path::PathBuf {
        if let Some(path) =
            std::env::var_os("NUCLEUS_GVISOR_ARTIFACT_BASE").filter(|path| !path.is_empty())
        {
            return std::path::PathBuf::from(path);
        }

        // Rootless bridge setup temporarily becomes uid 0 inside a user
        // namespace; XDG_RUNTIME_DIR still points at the service-owned host
        // runtime dir and must win over the host-root default.
        if !Uid::effective().is_root() || std::env::var_os("XDG_RUNTIME_DIR").is_some() {
            if let Some(dir) = dirs::runtime_dir() {
                return dir.join("nucleus-gvisor");
            }
        }

        if Uid::effective().is_root() {
            std::path::PathBuf::from("/run/nucleus-gvisor")
        } else {
            std::env::temp_dir().join(format!("nucleus-gvisor-{}", Uid::effective().as_raw()))
        }
    }

    fn ensure_secure_gvisor_artifact_dir(path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            Self::ensure_secure_gvisor_dir(parent, "gVisor artifact base")?;
        }
        Self::ensure_secure_gvisor_dir(path, "gVisor artifact dir")
    }

    fn ensure_secure_gvisor_dir(path: &std::path::Path, label: &str) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NucleusError::FilesystemError(format!(
                    "Refusing symlink {} {:?}",
                    label, path
                )));
            }
            Ok(_) | Err(_) => {}
        }

        std::fs::create_dir_all(path).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to create {} {:?}: {}", label, path, e))
        })?;

        let metadata = std::fs::metadata(path).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to stat {} {:?}: {}", label, path, e))
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        let owner = metadata.uid();
        let euid = Uid::effective().as_raw();
        if owner != euid {
            return Err(NucleusError::FilesystemError(format!(
                "{} {:?} is owned by uid {} (expected {})",
                label, path, owner, euid
            )));
        }
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to secure {} permissions {:?}: {}",
                        label, path, e
                    ))
                },
            )?;
        }

        Ok(())
    }

    fn mount_gvisor_secret_stage_tmpfs(stage_dir: &std::path::Path) -> Result<()> {
        match std::fs::symlink_metadata(stage_dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NucleusError::FilesystemError(format!(
                    "Refusing symlink gVisor secret stage dir {:?}",
                    stage_dir
                )));
            }
            Ok(_) | Err(_) => {}
        }

        std::fs::create_dir(stage_dir)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create gVisor secret stage dir {:?}: {}",
                    stage_dir, e
                ))
            })?;
        std::fs::set_permissions(stage_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                NucleusError::FilesystemError(format!(
                    "Failed to secure gVisor secret stage dir {:?}: {}",
                    stage_dir, e
                ))
            },
        )?;

        nix::mount::mount(
            Some("tmpfs"),
            stage_dir,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("size=16m,mode=0700"),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to mount gVisor secret stage tmpfs at {:?}: {}",
                stage_dir, e
            ))
        })
    }

    fn apply_secret_dir_identity(
        path: &std::path::Path,
        identity: &crate::container::ProcessIdentity,
    ) -> Result<()> {
        if identity.is_root() {
            return Ok(());
        }

        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(identity.uid)),
            Some(nix::unistd::Gid::from_raw(identity.gid)),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to set secret directory owner on {:?} to {}:{}: {}",
                path, identity.uid, identity.gid, e
            ))
        })
    }

    fn apply_secret_file_identity(
        path: &std::path::Path,
        identity: &crate::container::ProcessIdentity,
    ) -> Result<()> {
        if identity.is_root() {
            return Ok(());
        }

        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(identity.uid)),
            Some(nix::unistd::Gid::from_raw(identity.gid)),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to set secret owner on {:?} to {}:{}: {}",
                path, identity.uid, identity.gid, e
            ))
        })
    }

    pub(super) fn stage_gvisor_secret_files(
        stage_dir: &std::path::Path,
        secrets: &[crate::container::SecretMount],
        identity: &crate::container::ProcessIdentity,
    ) -> Result<Vec<crate::container::SecretMount>> {
        let mut staged = Vec::with_capacity(secrets.len());

        for secret in secrets {
            let staged_source = resolve_container_destination(stage_dir, &secret.dest)?;
            if let Some(parent) = staged_source.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create gVisor secret parent {:?}: {}",
                        parent, e
                    ))
                })?;
            }

            let mut content = read_regular_file_nofollow(&secret.source)?;
            std::fs::write(&staged_source, &content).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to write staged secret {:?}: {}",
                    staged_source, e
                ))
            })?;

            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &staged_source,
                    std::fs::Permissions::from_mode(secret.mode),
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to set permissions on staged secret {:?}: {}",
                        staged_source, e
                    ))
                })?;
            }

            Self::apply_secret_file_identity(&staged_source, identity)?;

            zeroize::Zeroize::zeroize(&mut content);

            staged.push(crate::container::SecretMount {
                source: staged_source,
                dest: secret.dest.clone(),
                mode: secret.mode,
            });
        }

        Ok(staged)
    }

    pub(super) fn cleanup_gvisor_artifacts(container_id: &str) -> Result<()> {
        let artifact_dir = Self::gvisor_artifact_dir(container_id);
        let secret_stage_dir = Self::gvisor_secret_stage_dir(container_id);

        if secret_stage_dir.exists() {
            match nix::mount::umount2(&secret_stage_dir, nix::mount::MntFlags::MNT_DETACH) {
                Ok(()) => {}
                Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
                Err(e) => {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to unmount gVisor secret stage {:?}: {}",
                        secret_stage_dir, e
                    )));
                }
            }
        }

        if artifact_dir.exists() {
            std::fs::remove_dir_all(&artifact_dir).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to remove gVisor artifact dir {:?}: {}",
                    artifact_dir, e
                ))
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_remapped_production_gvisor_requires_supervisor_exec_policy() {
        let user_ns_config = crate::isolation::UserNamespaceConfig::root_remapped();

        assert!(!user_ns_config.uid_mappings.is_empty());
        assert!(require_gvisor_supervisor_exec_policy(
            ServiceMode::Production,
            false
        ));
    }

    #[test]
    fn test_precreated_gvisor_userns_skips_supervisor_exec_policy() {
        assert!(!require_gvisor_supervisor_exec_policy(
            ServiceMode::Production,
            true
        ));
    }

    #[test]
    fn test_non_production_gvisor_does_not_require_supervisor_exec_policy() {
        assert!(!require_gvisor_supervisor_exec_policy(
            ServiceMode::Agent,
            false
        ));
    }

    #[test]
    fn test_ensure_secure_gvisor_artifact_dir_sets_owner_only_permissions() {
        let temp = tempfile::TempDir::new().unwrap();
        let artifact_dir = temp.path().join("artifacts").join("container-a");

        Container::ensure_secure_gvisor_artifact_dir(&artifact_dir).unwrap();

        let parent_mode = std::fs::metadata(artifact_dir.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let artifact_mode = std::fs::metadata(&artifact_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(parent_mode, 0o700);
        assert_eq!(artifact_mode, 0o700);
    }
}
