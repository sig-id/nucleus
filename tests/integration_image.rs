/// Integration tests for the local image snapshot workflow.
///
/// These tests exercise the image commit / load / inspect / run glue without
/// requiring root or a real overlay mount. They walk the library API the same
/// way the CLI does, with a synthetic Nix-style rootfs and an upperdir that
/// stands in for a live overlay. They focus on cross-cutting behavior:
///
/// - HMAC verification must reject any post-commit mutation of the image dir.
/// - Diff export must skip `/dev`, `/proc`, `/sys`, `/run/secrets`, and the
///   pivot-time `.old_root`, so runtime artifacts never leak into snapshots.
/// - User-supplied env / workdir must round-trip through commit and load.
/// - Credential-broker derived env must NOT round-trip into the committed
///   manifest, because the broker endpoint and per-container token are
///   host/container specific.
///
/// Tests that need a real overlay mount live behind `NUCLEUS_RUN_PRIVILEGED_E2E`
/// because they require root and a kernel that supports overlayfs.
#[cfg(test)]
mod tests {
    use nucleus::container::{
        ContainerConfig, ContainerState, ContainerStateParams, RootfsMode, TrustLevel,
    };
    use nucleus::filesystem::{ROOTFS_ATTESTATION_FILE, ROOTFS_STORE_PATHS_FILE};
    use nucleus::image::{
        commit_container_image, load_image, ImageCommitOptions, IMAGE_DIFF_DIR,
        IMAGE_MANIFEST_FILE, IMAGE_ROOTFS_ATTESTATION_FILE, IMAGE_SIGNATURE_FILE,
        IMAGE_STORE_PATHS_FILE,
    };
    use nucleus::network::{BridgeConfig, CredentialBrokerConfig, NatBackend, NetworkMode};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Build a synthetic Nix-style rootfs closure with the sidecars that
    /// `image::commit_container_image` expects to copy.
    fn synthetic_rootfs(dir: &std::path::Path) -> PathBuf {
        let rootfs = dir.join("rootfs");
        fs::create_dir_all(rootfs.join("bin")).unwrap();
        fs::write(rootfs.join("bin/app"), b"app-body").unwrap();
        fs::write(rootfs.join("bin/sh"), b"shell-body").unwrap();

        // Attestation sidecar: "<sha256>\t<rel-path>" lines.
        let app_hash = sha256_hex(&fs::read(rootfs.join("bin/app")).unwrap());
        let sh_hash = sha256_hex(&fs::read(rootfs.join("bin/sh")).unwrap());
        fs::write(
            rootfs.join(ROOTFS_ATTESTATION_FILE),
            format!("{app_hash}\tbin/app\n{sh_hash}\tbin/sh\n"),
        )
        .unwrap();

        fs::write(
            rootfs.join(ROOTFS_STORE_PATHS_FILE),
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-coreutils\n\
             /nix/store/0123456789abcdfghijklmnpqrsvwxyz-bash\n",
        )
        .unwrap();

        rootfs
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Stand in for a running container's overlay upperdir. Includes a couple
    /// of changes, a new file, a symlink, and runtime directories that the
    /// diff exporter is supposed to skip.
    fn synthetic_upper(upper: &std::path::Path) {
        fs::create_dir_all(upper.join("etc")).unwrap();
        fs::write(upper.join("etc/config"), b"committed-config").unwrap();
        fs::create_dir_all(upper.join("var/lib/app")).unwrap();
        fs::write(upper.join("var/lib/app/state"), b"state").unwrap();
        symlink("config", upper.join("etc/config-link")).unwrap();

        // These must be filtered out of the diff.
        fs::create_dir_all(upper.join("dev")).unwrap();
        fs::write(upper.join("dev/runtime-node"), b"skip").unwrap();
        fs::create_dir_all(upper.join("run/secrets")).unwrap();
        fs::write(upper.join("run/secrets/api-key"), b"skip").unwrap();
        fs::create_dir_all(upper.join("proc")).unwrap();
        fs::write(upper.join("proc/leak"), b"skip").unwrap();
        fs::create_dir_all(upper.join(".old_root")).unwrap();
        fs::write(upper.join(".old_root/leak"), b"skip").unwrap();
    }

    fn state_for_commit(
        config: &ContainerConfig,
        rootfs: &std::path::Path,
        upper: &std::path::Path,
        work: &std::path::Path,
    ) -> ContainerState {
        let mut state = ContainerState::new(ContainerStateParams {
            id: config.id.clone(),
            name: config.name.clone(),
            pid: 123,
            command: config.command.clone(),
            memory_limit: None,
            cpu_limit: None,
            using_gvisor: false,
            rootless: false,
            cgroup_path: None,
            process_uid: config.process_identity.uid,
            process_gid: config.process_identity.gid,
            additional_gids: config.process_identity.additional_gids.clone(),
        });
        // Mirror what `container::runtime` captures: only user env, never
        // derived env. This is the seam that keeps broker endpoints and
        // per-container tokens out of committed image manifests.
        state.environment = config.environment.iter().cloned().collect();
        state.workdir = config.workdir.display().to_string();
        state.rootfs_path = Some(rootfs.display().to_string());
        state.rootfs_mode = RootfsMode::Overlay;
        state.rootfs_upperdir = Some(upper.display().to_string());
        state.rootfs_workdir = Some(work.display().to_string());
        state
    }

    /// Configure a brokered sandbox the same way the CLI does. The derived
    /// env (broker proxy vars + per-container identity) is intentionally kept
    /// out of `config.environment`.
    fn brokered_config(rootfs: PathBuf) -> ContainerConfig {
        let broker = CredentialBrokerConfig::parse_endpoint("10.0.42.1:8080").unwrap();
        let mut config = ContainerConfig::try_new_with_id(
            Some("0123456789abcdef0123456789abcdef".to_string()),
            None,
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_network(NetworkMode::Bridge(
            BridgeConfig::default().with_nat_backend(NatBackend::Kernel),
        ))
        .with_rootfs_path(rootfs)
        .with_rootfs_mode(RootfsMode::Overlay)
        .with_workdir(PathBuf::from("/srv/app"))
        // Real users always go through `environment` and round-trip into
        // the image manifest.
        .with_env("APP_PORT".to_string(), "8080".to_string())
        .with_env("RUST_LOG".to_string(), "info".to_string())
        .with_process_identity(nucleus::container::ProcessIdentity {
            uid: 1000,
            gid: 1000,
            additional_gids: vec![27],
        })
        .with_credential_broker(broker.clone())
        .with_egress_policy(broker.egress_policy());

        // CLI parity: broker proxy env lands in `derived_environment`.
        for (key, value) in broker.proxy_environment() {
            config = config.with_derived_env(key, value);
        }
        config
    }

    #[test]
    fn test_image_commit_round_trips_user_env_and_workdir() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = brokered_config(rootfs.clone());
        let state = state_for_commit(&config, &rootfs, &upper, &work);

        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        // User env and workdir round-trip into the manifest.
        assert_eq!(manifest.config.workdir, "/srv/app");
        assert_eq!(
            manifest.config.env.get("APP_PORT").map(String::as_str),
            Some("8080")
        );
        assert_eq!(
            manifest.config.env.get("RUST_LOG").map(String::as_str),
            Some("info")
        );
        assert_eq!(manifest.config.uid, 1000);
        assert_eq!(manifest.config.gid, 1000);
        assert_eq!(manifest.config.additional_gids, vec![27]);
    }

    #[test]
    fn test_image_commit_writes_full_manifest_layout() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = brokered_config(rootfs.clone());
        let state = state_for_commit(&config, &rootfs, &upper, &work);

        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        // The on-disk layout matches the documented schema.
        assert!(image_dir.join(IMAGE_MANIFEST_FILE).is_file());
        assert!(image_dir.join(IMAGE_SIGNATURE_FILE).is_file());
        assert!(image_dir.join(IMAGE_ROOTFS_ATTESTATION_FILE).is_file());
        assert!(image_dir.join(IMAGE_STORE_PATHS_FILE).is_file());
        assert!(image_dir.join(IMAGE_DIFF_DIR).is_dir());

        // Sidecar contents match the rootfs closure.
        let side_attribution =
            fs::read_to_string(image_dir.join(IMAGE_ROOTFS_ATTESTATION_FILE)).unwrap();
        assert!(side_attribution.contains("bin/app"));
        assert!(side_attribution.contains("bin/sh"));
        let side_store = fs::read_to_string(image_dir.join(IMAGE_STORE_PATHS_FILE)).unwrap();
        assert!(side_store.contains("0123456789abcdfghijklmnpqrsvwxyz-coreutils"));

        // Diff content: real files survive, runtime artifacts are filtered.
        assert!(image_dir.join(IMAGE_DIFF_DIR).join("etc/config").is_file());
        assert!(image_dir
            .join(IMAGE_DIFF_DIR)
            .join("var/lib/app/state")
            .is_file());
        assert!(
            std::fs::symlink_metadata(image_dir.join(IMAGE_DIFF_DIR).join("etc/config-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!image_dir.join(IMAGE_DIFF_DIR).join("dev").exists());
        assert!(!image_dir.join(IMAGE_DIFF_DIR).join("proc").exists());
        assert!(!image_dir.join(IMAGE_DIFF_DIR).join("run/secrets").exists());
        assert!(!image_dir.join(IMAGE_DIFF_DIR).join(".old_root").exists());

        // Diff digest is recorded so tampering with diff contents is detectable
        // via HMAC mismatch on load.
        let diff = manifest.diff.expect("committed image must carry a diff");
        assert!(!diff.digest.is_empty());
        assert!(diff.manifest.contains_key("etc/config"));
        assert!(diff.manifest.contains_key("var/lib/app/state"));
        assert!(!diff.manifest.contains_key("dev/runtime-node"));
    }

    #[test]
    fn test_image_load_verifies_hmac_and_rejects_tampering() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = brokered_config(rootfs.clone());
        let state = state_for_commit(&config, &rootfs, &upper, &work);

        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        // Load succeeds and reproduces the same manifest.
        let loaded = load_image(&image_dir).unwrap();
        assert_eq!(loaded.image_id, manifest.image_id);
        assert_eq!(
            loaded.config.env.get("APP_PORT").map(String::as_str),
            Some("8080")
        );

        // Tampering with the diff must break HMAC verification.
        fs::write(
            image_dir.join(IMAGE_DIFF_DIR).join("etc/config"),
            b"tampered",
        )
        .unwrap();
        let err = load_image(&image_dir).unwrap_err();
        assert!(
            err.to_string().contains("HMAC mismatch"),
            "expected HMAC mismatch, got: {err}"
        );
    }

    /// Cross-cutting regression: image commit must not bake broker endpoints
    /// or per-container identity env into a committed image manifest. Those
    /// values live in `derived_environment` and are dropped from the
    /// `state.environment` capture path.
    #[test]
    fn test_image_commit_excludes_credential_broker_env() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = brokered_config(rootfs.clone());

        // Sanity: derived env carries the broker endpoint and identity, while
        // the user env surface stays clean. This is what makes the capture
        // path safe by construction.
        let broker_keys = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NUCLEUS_CONTAINER_ID",
            "NUCLEUS_CREDENTIAL_BROKER_TOKEN",
        ];
        for key in broker_keys {
            assert!(
                !config.environment.iter().any(|(k, _)| k == key),
                "broker env `{key}` leaked into user environment before commit"
            );
        }
        assert!(config
            .derived_environment
            .iter()
            .any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(config
            .derived_environment
            .iter()
            .any(|(k, _)| k == "NUCLEUS_CREDENTIAL_BROKER_TOKEN"));

        let state = state_for_commit(&config, &rootfs, &upper, &work);
        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        for key in broker_keys {
            assert!(
                !manifest.config.env.contains_key(key),
                "broker-derived env `{key}` was baked into the committed image manifest"
            );
        }

        // Loading the image back must also keep the broker env out.
        let loaded = load_image(&image_dir).unwrap();
        for key in broker_keys {
            assert!(
                !loaded.config.env.contains_key(key),
                "broker-derived env `{key}` re-appeared after image load"
            );
        }
    }

    /// The Nix-built `mkImage` path produces manifest directories without an
    /// `image.sig` (because the Nix store/substituter is the integrity root).
    /// `load_image` must accept those only when they live in `/nix/store`.
    #[test]
    fn test_image_load_rejects_unsigned_image_outside_nix_store() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = brokered_config(rootfs.clone());
        let state = state_for_commit(&config, &rootfs, &upper, &work);

        let image_dir = temp.path().join("image");
        commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        // Strip the signature; out-of-store images must refuse to load.
        fs::remove_file(image_dir.join(IMAGE_SIGNATURE_FILE)).unwrap();
        let err = load_image(&image_dir).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "expected signature failure outside Nix store, got: {err}"
        );
    }

    /// Empty-env commit must still produce a valid manifest so that the
    /// simplest workflow (no `-e` flags) keeps working.
    #[test]
    fn test_image_commit_handles_empty_user_env() {
        let temp = TempDir::new().unwrap();
        let rootfs = synthetic_rootfs(temp.path());
        let overlay_dir = temp.path().join("overlay");
        let upper = overlay_dir.join("upper");
        let work = overlay_dir.join("work");
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();
        synthetic_upper(&upper);

        let config = ContainerConfig::try_new_with_id(
            Some("0123456789abcdef0123456789abcdef".to_string()),
            None,
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_rootfs_path(rootfs.clone())
        .with_rootfs_mode(RootfsMode::Overlay)
        .with_trust_level(TrustLevel::Trusted);

        let state = state_for_commit(&config, &rootfs, &upper, &work);
        let image_dir = temp.path().join("image");
        let manifest =
            commit_container_image(&state, &image_dir, &ImageCommitOptions::default()).unwrap();

        assert_eq!(manifest.config.env, BTreeMap::new());
        assert!(manifest.diff.is_some());
        load_image(&image_dir).expect("empty-env image must load cleanly");
    }
}
