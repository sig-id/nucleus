/// Integration test for complete container lifecycle
///
/// This test verifies the complete container execution flow matching
/// NucleusVerification_IntegrationTests_ContainerLifecycleTest.tla
///
/// State transitions tested:
/// test_start -> container_created -> container_running -> container_exited -> cleanup_done
#[cfg(test)]
mod tests {
    use nucleus::container::{Container, ContainerConfig, TrustLevel};
    use nucleus::error::NucleusError;
    use nucleus::isolation::NamespaceConfig;
    use nucleus::resources::ResourceLimits;
    use nucleus::security::GVisorRuntime;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_lifecycle_echo() {
        // Create temporary context directory
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let context_path = temp_dir.path().to_path_buf();

        // Create a simple file in context
        std::fs::write(context_path.join("test.txt"), "Hello from nucleus")
            .expect("Failed to write test file");

        // Configure container with minimal resources
        let limits = ResourceLimits::unlimited()
            .with_memory("128M")
            .expect("Failed to set memory")
            .with_cpu_cores(1.0)
            .expect("Failed to set CPU");

        let config = ContainerConfig::try_new(
            Some("test-echo".to_string()),
            vec!["/bin/echo".to_string(), "hello".to_string()],
        )
        .unwrap()
        .with_context(context_path)
        .with_limits(limits)
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        // Run container
        let container = Container::new(config);
        let result = container.run();

        // Verify successful execution
        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Container should exit with code 0");
    }

    #[test]
    fn test_container_config_builder() {
        // Test the configuration builder pattern
        let config = ContainerConfig::try_new(
            Some("test".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
        )
        .unwrap()
        .with_context(PathBuf::from("/tmp/test"))
        .with_namespaces(NamespaceConfig::minimal())
        .with_gvisor(false);

        assert_eq!(config.name, "test");
        assert_eq!(config.command.len(), 3);
        assert!(config.context_dir.is_some());
        assert!(!config.use_gvisor);
    }

    #[test]
    fn test_resource_limits_configuration() {
        // Test resource limit parsing and configuration
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .expect("Failed to set memory")
            .with_cpu_cores(2.0)
            .expect("Failed to set CPU")
            .with_pids(100)
            .expect("Failed to set PIDs");

        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.cpu_quota_us, Some(200_000)); // 2.0 * 100_000
        assert_eq!(limits.pids_max, Some(100));
    }

    #[test]
    fn test_namespace_config_variations() {
        // Test different namespace configurations
        let all = NamespaceConfig::all();
        assert!(all.pid && all.mnt && all.net && all.uts && all.ipc && all.cgroup);
        assert!(!all.time);

        let minimal = NamespaceConfig::minimal();
        assert!(minimal.pid && minimal.mnt && minimal.net && minimal.cgroup);
        // M10: UTS and IPC now enabled in minimal config
        assert!(minimal.uts && minimal.ipc && !minimal.time);
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_with_device_nodes() {
        // Test that device nodes are accessible in container
        let config = ContainerConfig::try_new(
            Some("test-dev".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test -c /dev/null && test -c /dev/zero && test -c /dev/random".to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Device nodes should be accessible");
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_with_hostname() {
        // Test that hostname is set correctly in UTS namespace
        let mut namespaces = NamespaceConfig::minimal();
        namespaces.uts = true; // Enable UTS namespace

        let config = ContainerConfig::try_new(
            Some("test-hostname".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "test $(hostname) = 'custom-hostname'".to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(namespaces)
        .with_hostname(Some("custom-hostname".to_string()))
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Hostname should be set correctly");
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_full_isolation() {
        // Test container with all isolation mechanisms enabled
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let context_path = temp_dir.path().to_path_buf();

        // Create test script
        std::fs::write(
            context_path.join("test.sh"),
            "#!/bin/sh\necho 'Testing full isolation'\nexit 0\n",
        )
        .expect("Failed to write test script");

        let limits = ResourceLimits::unlimited()
            .with_memory("256M")
            .expect("Failed to set memory")
            .with_cpu_cores(1.0)
            .expect("Failed to set CPU")
            .with_pids(50)
            .expect("Failed to set PIDs");

        let mut namespaces = NamespaceConfig::all();
        namespaces.uts = true;

        let config = ContainerConfig::try_new(
            Some("test-full".to_string()),
            vec!["/bin/sh".to_string(), "/context/test.sh".to_string()],
        )
        .unwrap()
        .with_context(context_path)
        .with_limits(limits)
        .with_namespaces(namespaces)
        .with_hostname(Some("nucleus-test".to_string()))
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Container should complete successfully");
    }

    #[test]
    fn test_container_with_custom_hostname() {
        // Test hostname configuration
        let config =
            ContainerConfig::try_new(Some("test".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_hostname(Some("custom-host".to_string()));

        assert_eq!(config.hostname, Some("custom-host".to_string()));
    }

    #[test]
    fn test_container_default_hostname() {
        // Test that default hostname is set to container name
        let config = ContainerConfig::try_new(
            Some("my-container".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap();

        assert_eq!(config.hostname, Some("my-container".to_string()));
    }

    #[test]
    fn test_container_rootless_config() {
        let config =
            ContainerConfig::try_new(Some("test".to_string()), vec!["/bin/sh".to_string()])
                .unwrap()
                .with_rootless();

        assert!(
            config.namespaces.user,
            "User namespace should be enabled in rootless mode"
        );
        assert_eq!(
            config.user_ns_config.is_some(),
            !nix::unistd::Uid::effective().is_root()
        );
    }

    #[test]
    fn test_gvisor_unavailable_returns_error() {
        use nucleus::security::GVisorRuntime;

        if GVisorRuntime::is_available() {
            // runsc is present on this machine; skip
            return;
        }
        let result = GVisorRuntime::new();
        assert!(
            result.is_err(),
            "GVisorRuntime::new() should fail when runsc is not available"
        );
    }

    #[test]
    fn test_resource_stats_parsing() {
        use nucleus::resources::ResourceStats;

        let temp = tempfile::TempDir::new().unwrap();
        let p = temp.path();
        std::fs::write(p.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(p.join("memory.max"), "536870912\n").unwrap();
        std::fs::write(p.join("cpu.stat"), "usage_usec 1000000\nother 0\n").unwrap();
        std::fs::write(p.join("pids.current"), "5\n").unwrap();

        let stats = ResourceStats::from_cgroup(p.to_str().unwrap()).unwrap();
        assert_eq!(stats.memory_usage, 1_048_576);
        assert_eq!(stats.memory_limit, 536_870_912);
        assert_eq!(stats.cpu_usage_ns, 1_000_000_000); // 1_000_000 µs → ns
        assert_eq!(stats.pid_count, 5);
    }

    // --- Seccomp clone-flag integration test ---

    #[test]
    #[ignore] // Requires root privileges
    fn test_seccomp_blocks_clone_newuser() {
        // Verify that seccomp denies CLONE_NEWUSER inside the container.
        // The shell script checks if `unshare -U true` succeeds:
        //   - exit 0 = seccomp correctly blocked it (or unshare not available)
        //   - exit 1 = filter is broken, unshare succeeded
        let config = ContainerConfig::try_new(
            Some("test-seccomp-clone".to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "if ! command -v unshare >/dev/null 2>&1; then exit 0; fi; \
                 if unshare -U true 2>/dev/null; then exit 1; else exit 0; fi"
                    .to_string(),
            ],
        )
        .unwrap()
        .with_namespaces(NamespaceConfig::minimal())
        .with_trust_level(TrustLevel::Trusted);

        let container = Container::new(config);
        let result = container.run();

        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(
            exit_code, 0,
            "Seccomp should deny CLONE_NEWUSER (exit 1 means filter is broken)"
        );
    }

    // --- Trust-level tests ---

    #[test]
    fn test_trust_level_default_is_untrusted() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert_eq!(config.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn test_untrusted_workload_rejects_host_network() {
        use nucleus::network::NetworkMode;

        // Untrusted + host network should be rejected before fork (ConfigError)
        let config = ContainerConfig::try_new(
            Some("test-untrusted-host".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Untrusted)
        .with_network(NetworkMode::Host)
        .with_allow_host_network(true)
        .with_namespaces(NamespaceConfig::minimal());

        let container = Container::new(config);
        let result = container.run();
        assert!(result.is_err(), "Untrusted + host network should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, NucleusError::ConfigError(_)),
            "Should be ConfigError, got: {:?}",
            err
        );
    }

    #[test]
    fn test_untrusted_workload_requires_gvisor_or_degraded() {
        if GVisorRuntime::is_available() {
            // gVisor is available: trust-level guard would auto-enable it,
            // so we can't test the rejection path. Skip.
            return;
        }

        let config = ContainerConfig::try_new(
            Some("test-untrusted-no-gvisor".to_string()),
            vec!["/bin/sh".to_string()],
        )
        .unwrap()
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Untrusted)
        .with_namespaces(NamespaceConfig::minimal());

        let container = Container::new(config);
        let result = container.run();
        assert!(
            result.is_err(),
            "Untrusted without gVisor or degraded should fail"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, NucleusError::ConfigError(_)),
            "Should be ConfigError, got: {:?}",
            err
        );
    }

    // --- Opt-in start gate (--start-fd) ---

    /// Everything a gated launch needs: the supervisor process, the gate's
    /// write end (held by the "orchestrator"), and the event stream file.
    struct GatedLaunch {
        child: std::process::Child,
        gate_writer: Option<std::fs::File>,
        events_path: std::path::PathBuf,
        state_root: std::path::PathBuf,
    }

    /// Spawn `nucleus --events-fd 4 run --start-fd 3 ...` with the gate pipe
    /// on fd 3 and the event stream on fd 4, as an orchestrator would.
    ///
    /// SAFETY: `pre_exec` runs between fork and exec and only calls the
    /// async-signal-safe `fcntl(F_DUPFD)`, `dup2` and `close`.
    fn spawn_gated(workload: &str, state_root: &std::path::Path) -> GatedLaunch {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

        let (gate_reader, gate_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let events_path = state_root.join("events.jsonl");
        let events = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&events_path)
            .unwrap();
        let gate_fd = gate_reader.as_raw_fd();
        let events_fd = events.as_raw_fd();

        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_nucleus"));
        cmd.args(["--events-fd", "4", "run", "--start-fd", "3", "--root"])
            .arg(state_root)
            .args([
                "--runtime",
                "native",
                "--trust-level",
                "trusted",
                "--rootless",
                "--pids",
                "0",
                "--",
                "/bin/sh",
                "-c",
                workload,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure only calls async-signal-safe fcntl/dup2/close.
        unsafe {
            cmd.pre_exec(move || {
                // Copy onto the fixed numbers Nucleus expects without clobbering
                // either original if it already sits on 3 or 4.
                let gate_copy = libc::fcntl(gate_fd, libc::F_DUPFD, 10);
                if gate_copy < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let events_copy = libc::fcntl(events_fd, libc::F_DUPFD, 10);
                if events_copy < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(gate_copy, 3) < 0 || libc::dup2(events_copy, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(gate_copy);
                libc::close(events_copy);
                Ok(())
            });
        }

        let child = cmd.spawn().unwrap();
        // The parent ("orchestrator") keeps only the write end; the child
        // inherited the read end as fd 3.
        drop(gate_reader);
        GatedLaunch {
            child,
            gate_writer: Some(gate_writer.into()),
            events_path,
            state_root: state_root.to_path_buf(),
        }
    }

    /// Wait until the event stream contains a record of the given type.
    /// Skips the test (with a note) if unprivileged user namespaces are
    /// unavailable on this machine and the launch failed for that reason.
    fn wait_for_event(launch: &mut GatedLaunch, event_type: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Ok(text) = std::fs::read_to_string(&launch.events_path) {
                for line in text.lines() {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                        if value["type"] == event_type {
                            return;
                        }
                    }
                }
            }
            if let Some(status) = launch.child.try_wait().unwrap() {
                let stderr = launch
                    .child
                    .stderr
                    .take()
                    .map(|mut pipe| {
                        let mut text = String::new();
                        std::io::Read::read_to_string(&mut pipe, &mut text)
                            .map(|_| text)
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                if stderr.contains("Failed to create namespace")
                    || stderr.contains("Operation not permitted")
                {
                    eprintln!(
                        "skipping: unprivileged user namespaces are unavailable here \
                         (nucleus exited {status})"
                    );
                    std::process::exit(0);
                }
                panic!("nucleus exited with {status} before '{event_type}' was emitted:\n{stderr}");
            }
            if std::time::Instant::now() > deadline {
                let _ = launch.child.kill();
                panic!("timed out waiting for the '{event_type}' event");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn event_records(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    #[test]
    fn start_gate_holds_workload_until_released_after_container_started() {
        use std::io::Write;
        let state = tempfile::tempdir().unwrap();
        let mut launch = spawn_gated("echo WORKLOAD-RAN; exit 7", state.path());

        // The workload stays held after `container_started`: the release
        // byte has not been written yet.
        wait_for_event(&mut launch, "container_started");
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            launch.child.try_wait().unwrap().is_none(),
            "the workload must still be held at the start gate"
        );
        let so_far = event_records(&launch.events_path);
        assert!(
            so_far
                .iter()
                .all(|event| event["type"] != "container_summary"),
            "no summary may be emitted while the workload is held"
        );

        // Release the gate; the workload runs and its exit code is reported.
        launch
            .gate_writer
            .take()
            .expect("gate writer held")
            .write_all(b"go")
            .unwrap();
        let output = launch.child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("WORKLOAD-RAN"),
            "the workload should have run after the release byte"
        );

        let events = event_records(&launch.events_path);
        let summary = events
            .iter()
            .find(|event| event["type"] == "container_summary")
            .expect("container_summary after the workload exits");
        assert_eq!(summary["exit_status"]["code"], 7);
    }

    #[test]
    fn start_gate_eof_tears_down_without_running_the_workload() {
        let state = tempfile::tempdir().unwrap();
        let mut launch = spawn_gated("echo WORKLOAD-RAN; exit 7", state.path());

        wait_for_event(&mut launch, "container_started");

        // Closing the gate without a byte refuses the posture: the container
        // is torn down and Nucleus exits non-zero without running anything.
        drop(launch.gate_writer.take().expect("gate writer held"));

        let output = launch.child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stdout.contains("WORKLOAD-RAN"),
            "the workload must not run when the gate reaches EOF: {stdout}"
        );
        assert!(
            stderr.contains("Start gate closed"),
            "the refusal should be reported on stderr: {stderr}"
        );

        let events = event_records(&launch.events_path);
        let summary = events
            .iter()
            .find(|event| event["type"] == "container_summary")
            .expect("container_summary after the refusal");
        let error = summary["exit_status"]["error"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            error.contains("start gate"),
            "the summary should carry the refusal: {error}"
        );

        // The teardown removed the persisted state.
        let leftover: Vec<_> = std::fs::read_dir(&launch.state_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .collect();
        assert!(leftover.is_empty(), "no container state may survive");
    }
}
