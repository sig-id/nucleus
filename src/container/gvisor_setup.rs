use crate::error::{NucleusError, Result};
use crate::filesystem::{
    create_dev_nodes, create_minimal_fs, read_regular_file_nofollow, resolve_container_destination,
    snapshot_context_dir, validate_production_rootfs_path, verify_context_manifest,
    ContextPopulator, GpuDeviceSet,
};
use crate::network::{BridgeNetwork, NetworkMode};
use crate::security::{
    load_json_policy, GVisorNetworkMode, GVisorOciRunOptions, GVisorRuntime, OciBundle, OciConfig,
    OciMount, OciSeccomp,
};
use nix::unistd::Uid;
use std::os::unix::fs::PermissionsExt;
use tracing::info;

use super::{config::ServiceMode, runtime::Container};

fn require_gvisor_supervisor_exec_policy(
    service_mode: ServiceMode,
    precreated_userns: bool,
) -> bool {
    service_mode == ServiceMode::Production && !precreated_userns
}

fn gvisor_network_mode(network: &NetworkMode) -> Result<GVisorNetworkMode> {
    Ok(match network {
        NetworkMode::None => GVisorNetworkMode::None,
        NetworkMode::Host => {
            return Err(NucleusError::ConfigError(
                "gVisor host networking requires --network gvisor-host".into(),
            ));
        }
        NetworkMode::GVisorHost => GVisorNetworkMode::Host,
        NetworkMode::Bridge(_) => GVisorNetworkMode::Sandbox,
    })
}

/// runsc resolves OCI source pathnames after exec. Give it private mountpoints
/// backed by the descriptors checked in the launcher namespace.
fn stage_bind_sources(
    dir: &std::path::Path,
    offset: usize,
    mounts: &mut [OciMount],
    pin: impl Fn(&std::path::Path) -> Result<std::os::fd::OwnedFd>,
) -> Result<()> {
    use crate::filesystem::{bind_tree, fd_path, mount_target};
    for (i, mount) in mounts
        .iter_mut()
        .enumerate()
        .filter(|(_, m)| m.mount_type == "bind")
    {
        let fd = pin(std::path::Path::new(&mount.source))?;
        let source = fd_path(&fd);
        let directory = std::fs::metadata(&source)?.is_dir();
        let relative = std::path::PathBuf::from(format!("bind-{}", offset + i));
        let target = mount_target(dir, &relative, directory)?;
        let mut attrs = libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV;
        if mount.options.iter().any(|v| v == "ro") {
            attrs |= libc::MOUNT_ATTR_RDONLY;
        }
        if mount.options.iter().any(|v| v == "noexec") {
            attrs |= libc::MOUNT_ATTR_NOEXEC;
        }
        bind_tree(&source, &target, directory, attrs)?;
        mount.source = dir
            .join(relative)
            .to_str()
            .ok_or_else(|| NucleusError::ConfigError("OCI staging path must be UTF-8".into()))?
            .to_owned();
    }
    Ok(())
}

impl Container {
    /// Set up container with gVisor and exec.
    pub(super) fn setup_and_exec_gvisor(
        &self,
        artifact_base: std::path::PathBuf,
        runsc_debug_dir: Option<std::path::PathBuf>,
        precreated_userns: bool,
        gpu_device_set: Option<&GpuDeviceSet>,
    ) -> Result<()> {
        info!("Using gVisor runtime");

        let gvisor = if let Some(ref path) = self.runsc_path {
            GVisorRuntime::with_path(path.clone())
        } else {
            GVisorRuntime::new().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to initialize gVisor runtime: {}", e))
            })?
        };

        let gvisor = gvisor
            .with_prepared_base(artifact_base)
            .with_prepared_debug_dir(runsc_debug_dir);
        self.setup_and_exec_gvisor_oci(&gvisor, precreated_userns, gpu_device_set)
    }

    /// Set up container with gVisor using OCI bundle format.
    fn setup_and_exec_gvisor_oci(
        &self,
        gvisor: &GVisorRuntime,
        precreated_userns: bool,
        gpu_device_set: Option<&GpuDeviceSet>,
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
        let artifact_dir = gvisor.prepare_artifact_dir(&self.config.id)?;
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

        // Inject user-configured environment variables. In broker mode, the
        // broker identity keys are launch-owned and must not be spoofed by user
        // env before derived env is applied below.
        let user_environment: Vec<(String, String)> = self
            .config
            .environment
            .iter()
            .filter(|(key, _)| !self.config.credential_broker_owns_env(key))
            .cloned()
            .collect();
        if !user_environment.is_empty() {
            oci_config = oci_config.with_env(&user_environment);
        }

        // Inject launch-derived environment variables (credential-broker
        // proxy/identity, etc.). These reach the workload but are excluded
        // from image commit manifests. User env wins on generic derived-env
        // collisions; broker identity remains authoritative in broker mode.
        if !self.config.derived_environment.is_empty() {
            let user_keys: std::collections::HashSet<&String> =
                self.config.environment.iter().map(|(key, _)| key).collect();
            let derived: Vec<(String, String)> = self
                .config
                .derived_environment
                .iter()
                .filter(|(key, _)| {
                    self.config.credential_broker_owns_env(key) || !user_keys.contains(key)
                })
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
            let offset = oci_config.mounts.len();
            let sources = crate::filesystem::RootfsSources::load(&rootfs_path)?;
            oci_config = oci_config.with_rootfs_sources(&sources)?;
            if !crate::filesystem::is_immediate_nix_store_object_path(&rootfs_path) {
                stage_bind_sources(
                    &artifact_dir,
                    offset,
                    &mut oci_config.mounts[offset..],
                    |p| {
                        let fd = nix::fcntl::open(
                            p,
                            nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
                            nix::sys::stat::Mode::empty(),
                        )?;
                        sources.validate_resolved(&std::fs::read_link(
                            crate::filesystem::fd_path(&fd),
                        )?)?;
                        Ok(fd)
                    },
                )?;
            }
        } else {
            oci_config = oci_config.with_host_runtime_binds();
        }

        let offset = oci_config.mounts.len();
        oci_config = oci_config.with_workspace_mount(&self.config.workspace)?;
        if self.config.workspace.mode != super::WorkspaceMode::CopyInOut {
            stage_bind_sources(
                &artifact_dir,
                offset,
                &mut oci_config.mounts[offset..],
                crate::filesystem::pin_workspace_source,
            )?;
        }

        if !self.config.provider_configs.is_empty() {
            let offset = oci_config.mounts.len();
            oci_config = oci_config
                .with_provider_config_mounts(&self.config.home, &self.config.provider_configs)?;
            stage_bind_sources(
                &artifact_dir,
                offset,
                &mut oci_config.mounts[offset..],
                crate::filesystem::pin_provider_source,
            )?;
        }

        if !self.config.volumes.is_empty() {
            let offset = oci_config.mounts.len();
            oci_config = oci_config.with_volume_mounts(&self.config.volumes)?;
            stage_bind_sources(
                &artifact_dir,
                offset,
                &mut oci_config.mounts[offset..],
                crate::filesystem::pin_volume_source,
            )?;
        }

        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::BindMount
            ) {
                // Stage the context bind like every other host source: the
                // directory is pinned, validated through the pin and bound
                // from the staging area, so a concurrent writer cannot swap
                // the source between validation and the runsc mount.
                let offset = oci_config.mounts.len();
                oci_config = oci_config.with_context_bind(context_dir);
                stage_bind_sources(
                    &artifact_dir,
                    offset,
                    &mut oci_config.mounts[offset..],
                    |path| {
                        let fd = nix::fcntl::open(
                            path,
                            nix::fcntl::OFlag::O_PATH
                                | nix::fcntl::OFlag::O_DIRECTORY
                                | nix::fcntl::OFlag::O_NOFOLLOW
                                | nix::fcntl::OFlag::O_CLOEXEC,
                            nix::sys::stat::Mode::empty(),
                        )?;
                        ContextPopulator::validate_pinned_tree(&fd)?;
                        Ok(fd)
                    },
                )?;
            }
        }

        if !self.config.secrets.is_empty() {
            let secret_stage_dir = artifact_dir.join("secrets-stage");
            Self::mount_gvisor_secret_stage_tmpfs(&secret_stage_dir)?;

            let staged_secrets = Self::stage_gvisor_secret_files(
                &secret_stage_dir,
                &self.config.secrets,
                &self.config.process_identity,
            )?;
            Self::apply_secret_dir_identity(&secret_stage_dir, &self.config.process_identity)?;
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

        // Apply this after user namespace configuration, which may remove the
        // default network entry. An empty or absent entry gives netstack a new,
        // unconfigured namespace. Join the one prepared before the parent gate.
        let gvisor_net = gvisor_network_mode(&self.config.network)?;
        oci_config = match gvisor_net {
            GVisorNetworkMode::Sandbox => {
                oci_config.with_bridge_network_namespace(std::process::id())
            }
            GVisorNetworkMode::Host => oci_config.without_network_namespace(),
            GVisorNetworkMode::None => oci_config,
        };

        // GPU passthrough (gVisor): emit OCI device entries + driver support
        // binds + NVIDIA env. runsc owns device node creation and the cgroup
        // device rules inside its sandbox.
        if let (Some(set), Some(gpu_config)) = (gpu_device_set, &self.config.gpu) {
            let mut gpu_config = gpu_config.clone();
            gpu_config.bind_driver_libraries &= self.config.rootfs_path.is_none();
            oci_config =
                oci_config.with_gpu_passthrough(&gpu_config, set, &self.config.process_identity)?;
        }

        // Use --bundle path if provided, otherwise default
        let bundle_path = self
            .config
            .bundle_dir
            .clone()
            .unwrap_or_else(|| artifact_dir.join("bundle"));
        let oci_mounts = oci_config.mounts.clone();
        let bundle = OciBundle::new(bundle_path, oci_config);
        if precreated_userns {
            bundle.create_in_trusted_parent()?;
        } else {
            bundle.create()?;
        }

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

        let rootless_gvisor = self.config.user_ns_config.is_some() || !Uid::effective().is_root();
        let ignore_cgroups = rootless_gvisor;
        // runsc rejects --rootless with netstack. For bridge, Nucleus has
        // already entered its mapped user namespace and switched to UID 0.
        // With explicit OCI ID mappings an unprivileged runsc sets up the
        // mappings itself. --rootless would first remap the caller to UID 0
        // in a single-ID namespace where the configured host IDs are invalid.
        let runsc_rootless = rootless_gvisor
            && gvisor_net != GVisorNetworkMode::Sandbox
            && (precreated_userns || self.config.user_ns_config.is_none());
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
            let file = mount.mount_type == "bind" && std::path::Path::new(&mount.source).is_file();
            crate::filesystem::mount_target(rootfs, relative, !file)?;
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
            let staged_source = resolve_container_destination(
                stage_dir,
                &crate::filesystem::normalize_secret_destination(&secret.dest)?,
            )?;
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
        let artifact_dir = GVisorRuntime::artifact_dir(container_id)?;
        if !artifact_dir.try_exists()? {
            return Ok(());
        }
        crate::filesystem::trusted_directory(&artifact_dir, false)?;
        // Secret and bind staging mounts lived in the child's private mount
        // namespace and expired with it. Cleanup never resolves a mount target.
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
    fn bridge_uses_netstack_in_the_prepared_namespace() {
        let network = NetworkMode::Bridge(crate::network::BridgeConfig::default());
        assert_eq!(
            gvisor_network_mode(&network).unwrap(),
            GVisorNetworkMode::Sandbox
        );
        assert_eq!(
            gvisor_network_mode(&NetworkMode::GVisorHost).unwrap(),
            GVisorNetworkMode::Host
        );
        assert_eq!(
            gvisor_network_mode(&NetworkMode::None).unwrap(),
            GVisorNetworkMode::None
        );
        assert!(gvisor_network_mode(&NetworkMode::Host).is_err());
        let config =
            OciConfig::new(vec!["/bin/true".into()], None).with_bridge_network_namespace(123);
        let namespaces = config.linux.unwrap().namespaces.unwrap();
        let network: Vec<_> = namespaces
            .iter()
            .filter(|ns| ns.namespace_type == "network")
            .collect();
        assert_eq!(network.len(), 1);
        assert_eq!(
            network[0].path.as_deref(),
            Some(std::path::Path::new("/proc/123/ns/net"))
        );
    }

    #[test]
    fn test_root_remapped_production_gvisor_requires_supervisor_exec_policy() {
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
}
