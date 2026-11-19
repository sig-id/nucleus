/// Integration tests for resource management
///
/// Tests resource limits parsing, validation, I/O device limits,
/// resource stats from fake cgroup files, and cgroup state machine.
#[cfg(test)]
mod tests {
    use nucleus::resources::{CgroupState, IoDeviceLimit, ResourceLimits, ResourceStats};
    use nucleus::StateTransition;
    use tempfile::TempDir;

    // --- ResourceLimits: memory parsing ---

    #[test]
    fn test_parse_memory_bytes() {
        assert_eq!(ResourceLimits::parse_memory("1024").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_memory_suffixes() {
        assert_eq!(ResourceLimits::parse_memory("1K").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("1k").unwrap(), 1024);
        assert_eq!(
            ResourceLimits::parse_memory("512M").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("512m").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("2G").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("2g").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("1T").unwrap(),
            1024u64 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn test_parse_memory_whitespace_trimmed() {
        assert_eq!(
            ResourceLimits::parse_memory("  512M  ").unwrap(),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn test_parse_memory_invalid() {
        assert!(ResourceLimits::parse_memory("").is_err());
        assert!(ResourceLimits::parse_memory("abc").is_err());
        assert!(ResourceLimits::parse_memory("M").is_err());
        assert!(ResourceLimits::parse_memory("-512M").is_err());
    }

    #[test]
    fn test_parse_memory_overflow() {
        assert!(ResourceLimits::parse_memory("99999999999999T").is_err());
    }

    // --- ResourceLimits: with_memory auto-configuration ---

    #[test]
    fn test_with_memory_leaves_high_unset_so_overruns_oom_kill() {
        let limits = ResourceLimits::unlimited().with_memory("1G").unwrap();
        assert_eq!(limits.memory_bytes, Some(1024u64 * 1024 * 1024));
        assert_eq!(limits.memory_high, None);
    }

    #[test]
    fn test_with_memory_disables_swap() {
        let limits = ResourceLimits::unlimited().with_memory("256M").unwrap();
        assert_eq!(limits.memory_swap_max, Some(0));
    }

    #[test]
    fn test_with_swap_enabled_clears_restriction() {
        let limits = ResourceLimits::unlimited()
            .with_memory("256M")
            .unwrap()
            .with_swap_enabled();
        assert!(limits.memory_swap_max.is_none());
    }

    // --- ResourceLimits: CPU ---

    #[test]
    fn test_cpu_cores_to_quota() {
        let limits = ResourceLimits::unlimited().with_cpu_cores(2.0).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(200_000));
    }

    #[test]
    fn test_cpu_cores_fractional() {
        let limits = ResourceLimits::unlimited().with_cpu_cores(0.25).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(25_000));
    }

    #[test]
    fn test_cpu_cores_invalid() {
        assert!(ResourceLimits::unlimited().with_cpu_cores(0.0).is_err());
        assert!(ResourceLimits::unlimited().with_cpu_cores(-1.0).is_err());
        assert!(ResourceLimits::unlimited()
            .with_cpu_cores(f64::NAN)
            .is_err());
        assert!(ResourceLimits::unlimited()
            .with_cpu_cores(f64::INFINITY)
            .is_err());
    }

    // --- ResourceLimits: CPU weight ---

    #[test]
    fn test_cpu_weight_boundaries() {
        assert!(ResourceLimits::unlimited().with_cpu_weight(1).is_ok());
        assert!(ResourceLimits::unlimited().with_cpu_weight(10000).is_ok());
        assert!(ResourceLimits::unlimited().with_cpu_weight(0).is_err());
        assert!(ResourceLimits::unlimited().with_cpu_weight(10001).is_err());
    }

    // --- ResourceLimits: PIDs ---

    #[test]
    fn test_pids_zero_rejected() {
        assert!(ResourceLimits::unlimited().with_pids(0).is_err());
    }

    #[test]
    fn test_pids_valid() {
        let limits = ResourceLimits::unlimited().with_pids(512).unwrap();
        assert_eq!(limits.pids_max, Some(512));
    }

    // --- ResourceLimits: defaults ---

    #[test]
    fn test_unlimited_has_no_limits() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.memory_bytes.is_none());
        assert!(limits.memory_high.is_none());
        assert!(limits.memory_swap_max.is_none());
        assert!(limits.cpu_quota_us.is_none());
        assert!(limits.cpu_weight.is_none());
        assert!(limits.pids_max.is_none());
        assert!(limits.io_limits.is_empty());
        assert_eq!(limits.cpu_period_us, 100_000);
    }

    #[test]
    fn test_default_has_pids_limit() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.pids_max, Some(512));
    }

    // --- IoDeviceLimit ---

    #[test]
    fn test_io_limit_parse() {
        let limit = IoDeviceLimit::parse("8:0 riops=1000 wbps=10485760").unwrap();
        assert_eq!(limit.device, "8:0");
        assert_eq!(limit.riops, Some(1000));
        assert!(limit.wiops.is_none());
        assert!(limit.rbps.is_none());
        assert_eq!(limit.wbps, Some(10485760));
    }

    #[test]
    fn test_io_limit_all_params() {
        let limit = IoDeviceLimit::parse("8:0 riops=100 wiops=200 rbps=300 wbps=400").unwrap();
        assert_eq!(limit.riops, Some(100));
        assert_eq!(limit.wiops, Some(200));
        assert_eq!(limit.rbps, Some(300));
        assert_eq!(limit.wbps, Some(400));
    }

    #[test]
    fn test_io_limit_to_io_max_line() {
        let limit = IoDeviceLimit::parse("8:16 riops=500 wbps=1048576").unwrap();
        let line = limit.to_io_max_line();
        assert!(line.starts_with("8:16"));
        assert!(line.contains("riops=500"));
        assert!(line.contains("wbps=1048576"));
    }

    #[test]
    fn test_io_limit_invalid_device() {
        assert!(IoDeviceLimit::parse("").is_err());
        assert!(IoDeviceLimit::parse("bad").is_err());
        assert!(IoDeviceLimit::parse("8:0:1").is_err());
        assert!(IoDeviceLimit::parse("a:b").is_err());
    }

    #[test]
    fn test_io_limit_invalid_params() {
        assert!(IoDeviceLimit::parse("8:0 riops").is_err()); // missing =value
        assert!(IoDeviceLimit::parse("8:0 foo=100").is_err()); // unknown key
        assert!(IoDeviceLimit::parse("8:0 riops=abc").is_err()); // non-numeric
    }

    #[test]
    fn test_resource_limits_with_io_limit() {
        let limit = IoDeviceLimit::parse("8:0 riops=1000").unwrap();
        let limits = ResourceLimits::unlimited().with_io_limit(limit);
        assert_eq!(limits.io_limits.len(), 1);
        assert_eq!(limits.io_limits[0].device, "8:0");
    }

    // --- ResourceStats from fake cgroup ---

    #[test]
    fn test_resource_stats_from_cgroup() {
        let temp = TempDir::new().unwrap();
        let p = temp.path();

        std::fs::write(p.join("memory.current"), "2097152\n").unwrap();
        std::fs::write(p.join("memory.max"), "268435456\n").unwrap();
        std::fs::write(
            p.join("cpu.stat"),
            "usage_usec 500000\nuser_usec 300000\nsystem_usec 200000\n",
        )
        .unwrap();
        std::fs::write(p.join("pids.current"), "10\n").unwrap();

        let stats = ResourceStats::from_cgroup(p.to_str().unwrap()).unwrap();
        assert_eq!(stats.memory_usage, 2_097_152);
        assert_eq!(stats.memory_limit, 268_435_456);
        assert_eq!(stats.cpu_usage_ns, 500_000_000); // 500_000 µs → ns
        assert_eq!(stats.pid_count, 10);

        let expected_pct = (2_097_152.0 / 268_435_456.0) * 100.0;
        assert!((stats.memory_percent - expected_pct).abs() < 0.01);
    }

    #[test]
    fn test_resource_stats_unlimited_memory() {
        let temp = TempDir::new().unwrap();
        let p = temp.path();

        std::fs::write(p.join("memory.current"), "1024\n").unwrap();
        std::fs::write(p.join("memory.max"), "max\n").unwrap();
        std::fs::write(p.join("cpu.stat"), "usage_usec 0\n").unwrap();
        std::fs::write(p.join("pids.current"), "1\n").unwrap();

        let stats = ResourceStats::from_cgroup(p.to_str().unwrap()).unwrap();
        assert_eq!(stats.memory_limit, 0); // "max" → 0
        assert_eq!(stats.memory_percent, 0.0);
    }

    #[test]
    fn test_resource_stats_missing_file_errors() {
        let temp = TempDir::new().unwrap();
        let result = ResourceStats::from_cgroup(temp.path().to_str().unwrap());
        assert!(result.is_err());
    }

    // --- ResourceStats formatting ---

    #[test]
    fn test_format_memory_units() {
        assert_eq!(ResourceStats::format_memory(500), "500B");
        assert_eq!(ResourceStats::format_memory(1024), "1.00K");
        assert_eq!(ResourceStats::format_memory(1024 * 1024), "1.00M");
        assert_eq!(ResourceStats::format_memory(1024 * 1024 * 1024), "1.00G");
        assert_eq!(ResourceStats::format_memory(1536 * 1024), "1.50M");
    }

    #[test]
    fn test_format_cpu_time() {
        assert_eq!(ResourceStats::format_cpu_time(0), "0.00s");
        assert_eq!(ResourceStats::format_cpu_time(1_000_000_000), "1.00s");
        assert_eq!(ResourceStats::format_cpu_time(2_500_000_000), "2.50s");
    }

    // --- CgroupState machine ---

    #[test]
    fn test_cgroup_state_happy_path() {
        let state = CgroupState::Nonexistent;
        let state = state.transition(CgroupState::Created).unwrap();
        let state = state.transition(CgroupState::Configured).unwrap();
        let state = state.transition(CgroupState::Attached).unwrap();
        let state = state.transition(CgroupState::Monitoring).unwrap();
        let state = state.transition(CgroupState::Removed).unwrap();
        assert!(state.is_terminal());
    }

    #[test]
    fn test_cgroup_state_early_cleanup() {
        // Can jump to Removed from Created, Configured, Attached
        assert!(CgroupState::Created
            .transition(CgroupState::Removed)
            .is_ok());
        assert!(CgroupState::Configured
            .transition(CgroupState::Removed)
            .is_ok());
        assert!(CgroupState::Attached
            .transition(CgroupState::Removed)
            .is_ok());
    }

    #[test]
    fn test_cgroup_state_cannot_skip_forward() {
        assert!(CgroupState::Nonexistent
            .transition(CgroupState::Configured)
            .is_err());
        assert!(CgroupState::Created
            .transition(CgroupState::Attached)
            .is_err());
    }

    #[test]
    fn test_cgroup_state_cannot_go_backwards() {
        assert!(CgroupState::Removed
            .transition(CgroupState::Nonexistent)
            .is_err());
        assert!(CgroupState::Monitoring
            .transition(CgroupState::Attached)
            .is_err());
    }

    #[test]
    fn test_cgroup_only_removed_is_terminal() {
        assert!(!CgroupState::Nonexistent.is_terminal());
        assert!(!CgroupState::Created.is_terminal());
        assert!(!CgroupState::Configured.is_terminal());
        assert!(!CgroupState::Attached.is_terminal());
        assert!(!CgroupState::Monitoring.is_terminal());
        assert!(CgroupState::Removed.is_terminal());
    }
}
