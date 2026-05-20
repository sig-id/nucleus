use crate::error::{NucleusError, Result};
use crate::security::policy::sha256_hex;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
use crate::security::syscall_numbers::{SYS_FADVISE64, SYS_SENDFILE};
use seccompiler::{BpfProgram, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::{debug, info, warn};

/// Seccomp filter manager
///
/// Implements syscall whitelisting for the security state machine
/// (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
pub struct SeccompManager {
    applied: bool,
}

const DENIED_CLONE_NAMESPACE_FLAGS: u64 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWTIME) as u64;

impl SeccompManager {
    pub fn new() -> Self {
        Self { applied: false }
    }

    fn base_allowed_syscalls() -> Vec<i64> {
        let mut syscalls = vec![
            // File I/O
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_lseek,
            libc::SYS_fcntl,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_preadv,
            libc::SYS_pwritev,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readlinkat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_pipe2,
            libc::SYS_unlinkat,
            libc::SYS_renameat,
            libc::SYS_renameat2,
            libc::SYS_linkat,
            libc::SYS_symlinkat,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_truncate,
            libc::SYS_ftruncate,
            libc::SYS_fallocate,
            #[cfg(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "riscv64"
            ))]
            SYS_FADVISE64,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_sync_file_range,
            libc::SYS_flock,
            libc::SYS_fstatfs,
            libc::SYS_statfs,
            #[cfg(any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "riscv64"
            ))]
            SYS_SENDFILE,
            libc::SYS_copy_file_range,
            libc::SYS_splice,
            libc::SYS_tee,
            // Memory management
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_msync,
            libc::SYS_mlock,
            libc::SYS_munlock,
            libc::SYS_mlock2,
            // SysV shared memory – used by PostgreSQL, Redis, and many databases
            // for shared buffer pools. Safe in PID/IPC namespaces (isolated keyspace).
            libc::SYS_shmget,
            libc::SYS_shmat,
            libc::SYS_shmdt,
            libc::SYS_shmctl,
            // POSIX semaphores (used by PostgreSQL for lightweight locking)
            libc::SYS_semget,
            libc::SYS_semop,
            libc::SYS_semctl,
            libc::SYS_semtimedop,
            // Process management
            // fork intentionally excluded – modern glibc/musl use clone(), which
            // has namespace-flag filtering. Removing SYS_fork forces all forks
            // through the filtered clone path (defense-in-depth against fork bombs
            // and unfiltered namespace creation).
            libc::SYS_execve,
            // execveat is conditionally allowed below (AT_EMPTY_PATH blocked)
            libc::SYS_wait4,
            libc::SYS_waitid,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
            libc::SYS_getppid,
            libc::SYS_setsid,
            libc::SYS_getgroups,
            // Signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigsuspend,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_rt_sigpending,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_sigaltstack,
            libc::SYS_restart_syscall,
            // L7: kill/tgkill are safe when PID namespace is active (container
            // can only signal its own processes). If PID namespace creation fails,
            // the runtime aborts, so this is safe.
            libc::SYS_kill,
            libc::SYS_tgkill,
            // Time and timers
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_clock_nanosleep,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            libc::SYS_setitimer,
            libc::SYS_getitimer,
            // Directories
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_fchdir,
            libc::SYS_mkdirat,
            libc::SYS_getdents64,
            // Misc
            libc::SYS_uname,
            libc::SYS_getrandom,
            libc::SYS_futex,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            // L8: sysinfo removed – leaks host RAM, uptime, and process count.
            // Applications needing this info should use /proc/meminfo instead.
            libc::SYS_umask,
            // prlimit64 moved to arg-filtered section (M3)
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_setaffinity,
            libc::SYS_sched_getparam,
            libc::SYS_sched_getscheduler,
            libc::SYS_getcpu,
            // Extended attributes – read-only queries, safe
            libc::SYS_getxattr,
            libc::SYS_lgetxattr,
            libc::SYS_fgetxattr,
            libc::SYS_listxattr,
            libc::SYS_llistxattr,
            libc::SYS_flistxattr,
            libc::SYS_rseq,
            libc::SYS_close_range,
            // Ownership – safe after capability drop (CAP_CHOWN/CAP_FOWNER gone;
            // operations on files not owned by the container UID will EPERM).
            libc::SYS_fchown,
            libc::SYS_fchownat,
            // Legacy AIO – used by databases and storage engines. Operations are
            // bounded by the process's existing fd permissions.
            libc::SYS_io_setup,
            libc::SYS_io_destroy,
            libc::SYS_io_submit,
            libc::SYS_io_getevents,
            // NOTE: io_uring intentionally excluded from defaults – large kernel
            // attack surface with a history of CVEs. Applications needing io_uring
            // (e.g. PostgreSQL 18+ io_method=io_uring) should use a custom seccomp
            // profile that adds io_uring_setup/io_uring_enter/io_uring_register.
            // Process groups – safe in PID namespace (can only affect own pgrp).
            libc::SYS_setpgid,
            libc::SYS_getpgid,
            // NOTE: memfd_create intentionally excluded – combined with execveat
            // it enables fileless code execution bypassing all FS controls (SEC-02).
            // Landlock bootstrap (runtime applies seccomp before Landlock)
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
            // Socket/Network (safe introspection + local socketpair)
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_socketpair,
            libc::SYS_getsockopt,
            // Poll/Select
            libc::SYS_ppoll,
            libc::SYS_pselect6,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_signalfd4,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
        ];

        // Legacy syscalls only available on x86_64 (aarch64 only has the *at variants)
        #[cfg(target_arch = "x86_64")]
        syscalls.extend_from_slice(&[
            libc::SYS_open,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_access,
            libc::SYS_readlink,
            libc::SYS_dup2,
            libc::SYS_pipe,
            libc::SYS_unlink,
            libc::SYS_rename,
            libc::SYS_link,
            libc::SYS_symlink,
            libc::SYS_chmod,
            libc::SYS_mkdir,
            libc::SYS_rmdir,
            libc::SYS_getdents,
            libc::SYS_getpgrp,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_arch_prctl,
            libc::SYS_getrlimit,
            libc::SYS_poll,
            libc::SYS_select,
            libc::SYS_epoll_create,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd,
            libc::SYS_signalfd,
        ]);

        syscalls
    }

    fn allowed_socket_domains(allow_network: bool) -> Vec<i32> {
        if allow_network {
            vec![libc::AF_UNIX, libc::AF_INET, libc::AF_INET6]
        } else {
            vec![libc::AF_UNIX]
        }
    }

    fn network_mode_syscalls(allow_network: bool) -> Vec<i64> {
        if allow_network {
            vec![
                libc::SYS_connect,
                libc::SYS_sendto,
                libc::SYS_recvfrom,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
                libc::SYS_shutdown,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_accept,
                libc::SYS_accept4,
                libc::SYS_setsockopt,
            ]
        } else {
            Vec::new()
        }
    }

    /// Get minimal syscall whitelist for basic container operation
    ///
    /// This is a restrictive whitelist that blocks dangerous syscalls:
    /// - ptrace (process tracing)
    /// - kexec_load (kernel loading)
    /// - add_key, request_key, keyctl (kernel keyring)
    /// - bpf (eBPF programs)
    /// - perf_event_open (performance monitoring)
    /// - userfaultfd (user fault handling)
    fn minimal_filter(
        allow_network: bool,
        extra_syscalls: &[String],
    ) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Essential syscalls for basic operation
        let allowed_syscalls = Self::base_allowed_syscalls();

        // Allow all these syscalls unconditionally
        for syscall in allowed_syscalls {
            rules.insert(syscall, Vec::new());
        }

        // Add network-mode-specific syscalls
        for syscall in Self::network_mode_syscalls(allow_network) {
            rules.insert(syscall, Vec::new());
        }

        // Add user-requested extra syscalls (--seccomp-allow).
        // - Already in default/arg-filtered: silently accepted (no-op).
        // - In OPT_IN_SYSCALLS: added to allowlist.
        // - Security-critical denied names: WARN and blocked even if later
        //   accidentally added to OPT_IN_SYSCALLS.
        // - Known but not opt-in: WARN and blocked (defense-in-depth).
        // - Unknown name: WARN and blocked.
        for name in extra_syscalls {
            if Self::ARG_FILTERED_SYSCALLS.contains(&name.as_str()) {
                continue;
            }

            if let Some(nr) = syscall_name_to_number(name) {
                if let std::collections::btree_map::Entry::Vacant(entry) = rules.entry(nr) {
                    if Self::SECURITY_CRITICAL_DENIED_SYSCALLS.contains(&name.as_str()) {
                        warn!(
                            "--seccomp-allow: security-critical syscall '{}' is always blocked",
                            name
                        );
                    } else if Self::OPT_IN_SYSCALLS.contains(&name.as_str()) {
                        entry.insert(Vec::new());
                    } else {
                        warn!(
                            "--seccomp-allow: syscall '{}' is not in the opt-in allowlist – blocked",
                            name
                        );
                    }
                }
            } else {
                warn!("--seccomp-allow: unknown syscall '{}' – blocked", name);
            }
        }

        // Restrict socket() domains by network mode.
        // none: AF_UNIX only; network-enabled: AF_UNIX/AF_INET/AF_INET6.
        let mut socket_rules = Vec::new();
        for domain in Self::allowed_socket_domains(allow_network) {
            let condition = SeccompCondition::new(
                0, // arg0 is socket(domain, type, protocol)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                domain as u64,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!(
                    "Failed to create socket domain condition: {}",
                    e
                ))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create socket rule: {}", e))
            })?;
            socket_rules.push(rule);
        }
        rules.insert(libc::SYS_socket, socket_rules);

        // ioctl: allow only safe terminal operations (arg0 = request code)
        let ioctl_allowed: &[u64] = &[
            0x5401, // TCGETS
            0x5402, // TCSETS
            0x5403, // TCSETSW
            0x5404, // TCSETSF
            0x540B, // TCFLSH
            0x540E, // TIOCSCTTY
            0x540F, // TIOCGPGRP
            0x5410, // TIOCSPGRP
            0x5413, // TIOCGWINSZ
            0x5429, // TIOCGSID
            0x541B, // FIONREAD
            0x5421, // M12: FIONBIO – allowed because fcntl(F_SETFL, O_NONBLOCK)
            // achieves the same result and is already permitted. Blocking
            // FIONBIO only breaks tokio/mio for no security gain.
            0x5451, // FIOCLEX
            0x5450, // FIONCLEX
        ];
        let mut ioctl_rules = Vec::new();
        for &request in ioctl_allowed {
            let condition = SeccompCondition::new(
                1, // arg1 is the request code for ioctl(fd, request, ...)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                request,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create ioctl condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create ioctl rule: {}", e))
            })?;
            ioctl_rules.push(rule);
        }
        rules.insert(libc::SYS_ioctl, ioctl_rules);

        // prctl: allow only safe operations.
        // Notably absent (hit default deny):
        //   PR_CAPBSET_DROP (24) – could weaken the capability bounding set
        //   PR_SET_SECUREBITS (28) – could disable secure-exec restrictions
        //   PR_CAP_AMBIENT mutations – could activate retained inheritable caps
        let prctl_allowed: &[u64] = &[
            1,  // PR_SET_PDEATHSIG
            2,  // PR_GET_PDEATHSIG
            15, // PR_SET_NAME
            16, // PR_GET_NAME
            23, // PR_CAPBSET_READ – glibc probes this at startup to discover
            // cap_last_cap when /proc/sys is masked. Read-only, harmless
            // after capabilities have been dropped.
            27, // PR_GET_SECUREBITS – read-only query of securebits flags
            36, // PR_SET_CHILD_SUBREAPER – safe, only affects own descendants
            37, // PR_GET_CHILD_SUBREAPER
            38, // PR_SET_NO_NEW_PRIVS
            40, // PR_GET_TID_ADDRESS – read-only, returns thread ID address
            39, // PR_GET_NO_NEW_PRIVS
        ];
        let mut prctl_rules = Vec::new();
        for &option in prctl_allowed {
            let condition = SeccompCondition::new(
                0, // arg0 is the option for prctl(option, ...)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                option,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create prctl condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create prctl rule: {}", e))
            })?;
            prctl_rules.push(rule);
        }

        let ambient_option = SeccompCondition::new(
            0, // arg0 is the option for prctl(option, ...)
            seccompiler::SeccompCmpArgLen::Dword,
            seccompiler::SeccompCmpOp::Eq,
            libc::PR_CAP_AMBIENT as u64,
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!(
                "Failed to create PR_CAP_AMBIENT prctl condition: {}",
                e
            ))
        })?;
        let ambient_is_set = SeccompCondition::new(
            1, // arg1 is the PR_CAP_AMBIENT subcommand.
            seccompiler::SeccompCmpArgLen::Dword,
            seccompiler::SeccompCmpOp::Eq,
            libc::PR_CAP_AMBIENT_IS_SET as u64,
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!(
                "Failed to create PR_CAP_AMBIENT_IS_SET prctl condition: {}",
                e
            ))
        })?;
        let ambient_probe_rule =
            SeccompRule::new(vec![ambient_option, ambient_is_set]).map_err(|e| {
                NucleusError::SeccompError(format!(
                    "Failed to create PR_CAP_AMBIENT_IS_SET prctl rule: {}",
                    e
                ))
            })?;
        prctl_rules.push(ambient_probe_rule);
        rules.insert(libc::SYS_prctl, prctl_rules);

        // M3: prlimit64 – only allow GET (new_limit == NULL, i.e. arg2 == 0).
        // SET operations could raise RLIMIT_NPROC to bypass fork-bomb protection.
        let prlimit_condition = SeccompCondition::new(
            2, // arg2 = new_limit pointer for prlimit64(pid, resource, new_limit, old_limit)
            seccompiler::SeccompCmpArgLen::Qword,
            seccompiler::SeccompCmpOp::Eq,
            0u64, // new_limit == NULL means GET-only
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create prlimit64 condition: {}", e))
        })?;
        let prlimit_rule = SeccompRule::new(vec![prlimit_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create prlimit64 rule: {}", e))
        })?;
        rules.insert(libc::SYS_prlimit64, vec![prlimit_rule]);

        // mprotect: permit RW or RX transitions, but reject PROT_WRITE|PROT_EXEC.
        let mut mprotect_rules = Vec::new();
        for allowed in [0, libc::PROT_WRITE as u64, libc::PROT_EXEC as u64] {
            let condition = SeccompCondition::new(
                2, // arg2 is prot for mprotect(addr, len, prot)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::MaskedEq((libc::PROT_WRITE | libc::PROT_EXEC) as u64),
                allowed,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create mprotect condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create mprotect rule: {}", e))
            })?;
            mprotect_rules.push(rule);
        }
        rules.insert(libc::SYS_mprotect, mprotect_rules);

        // preadv2/pwritev2: allow only flags == 0, which makes them equivalent
        // to preadv/pwritev. Nonzero RWF_* flags include cache-observing
        // behavior such as RWF_NOWAIT and future flags seccomp cannot review.
        for (syscall, name) in [
            (libc::SYS_preadv2, "preadv2"),
            (libc::SYS_pwritev2, "pwritev2"),
        ] {
            let condition = SeccompCondition::new(
                5, // arg5 = flags for preadv2/pwritev2(fd, iov, iovcnt, off_lo, off_hi, flags)
                seccompiler::SeccompCmpArgLen::Qword,
                seccompiler::SeccompCmpOp::Eq,
                0,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!(
                    "Failed to create {} flags condition: {}",
                    name, e
                ))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create {} rule: {}", name, e))
            })?;
            rules.insert(syscall, vec![rule]);
        }

        // clone3 is intentionally absent from the allow map. Its flags live in a
        // user pointer (struct clone_args), which seccomp BPF cannot dereference,
        // so it cannot be safely namespace-filtered. The BPF compiler adds an
        // exact-match ENOSYS deny for clone3 so libc falls back to filtered clone.

        // clone: allow but deny namespace-creating flags to prevent nested namespace creation
        let clone_condition = SeccompCondition::new(
            0, // arg0 = flags
            seccompiler::SeccompCmpArgLen::Qword,
            seccompiler::SeccompCmpOp::MaskedEq(DENIED_CLONE_NAMESPACE_FLAGS),
            0, // (flags & ns_flags) == 0: none of the namespace flags set
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create clone condition: {}", e))
        })?;
        let clone_rule = SeccompRule::new(vec![clone_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create clone rule: {}", e))
        })?;
        rules.insert(libc::SYS_clone, vec![clone_rule]);

        // execveat: allow but block AT_EMPTY_PATH (0x1000) to prevent fileless
        // execution. With AT_EMPTY_PATH, execveat can execute code from any open
        // fd (e.g., open + unlink, or even a socket fd), bypassing filesystem
        // controls – not just memfd_create. Blocking memfd_create alone is
        // insufficient. Normal execveat with dirfd+pathname (no AT_EMPTY_PATH)
        // remains allowed.
        let execveat_condition = SeccompCondition::new(
            4, // arg4 = flags for execveat(dirfd, pathname, argv, envp, flags)
            seccompiler::SeccompCmpArgLen::Dword,
            seccompiler::SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
            0, // (flags & AT_EMPTY_PATH) == 0: AT_EMPTY_PATH not set
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create execveat condition: {}", e))
        })?;
        let execveat_rule = SeccompRule::new(vec![execveat_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create execveat rule: {}", e))
        })?;
        rules.insert(libc::SYS_execveat, vec![execveat_rule]);

        Ok(rules)
    }

    /// Validate `--seccomp-allow` entries for production mode.
    ///
    /// Development runs warn and ignore unsupported names at filter construction
    /// time. Production mode rejects them early so operators cannot accidentally
    /// believe a weakened or unsupported syscall fragment was applied.
    pub fn validate_extra_syscalls_for_production(
        allow_network: bool,
        extra_syscalls: &[String],
    ) -> Result<()> {
        let base_syscalls = Self::base_allowed_syscalls();
        let network_syscalls = Self::network_mode_syscalls(allow_network);

        for name in extra_syscalls {
            let Some(nr) = syscall_name_to_number(name) else {
                return Err(NucleusError::ConfigError(format!(
                    "Production mode rejects unknown --seccomp-allow syscall '{}'",
                    name
                )));
            };

            if base_syscalls.contains(&nr)
                || network_syscalls.contains(&nr)
                || Self::ARG_FILTERED_SYSCALLS.contains(&name.as_str())
            {
                continue;
            }

            if Self::SECURITY_CRITICAL_DENIED_SYSCALLS.contains(&name.as_str()) {
                return Err(NucleusError::ConfigError(format!(
                    "Production mode forbids --seccomp-allow for security-critical syscall '{}'",
                    name
                )));
            }

            if Self::OPT_IN_SYSCALLS.contains(&name.as_str()) {
                continue;
            }

            return Err(NucleusError::ConfigError(format!(
                "Production mode rejects unsupported --seccomp-allow syscall '{}'",
                name
            )));
        }

        Ok(())
    }

    /// Compile the minimal BPF filter without applying it
    ///
    /// This is useful for benchmarking filter compilation overhead
    /// without the irreversible side effect of applying the filter.
    ///
    /// Uses bitmap-based BPF compilation for O(1) syscall dispatch.
    pub fn compile_minimal_filter() -> Result<BpfProgram> {
        let rules = Self::minimal_filter(true, &[])?;
        let target_arch = std::env::consts::ARCH.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
        })?;
        super::seccomp_bpf::compile_bitmap_bpf_with_errno_syscalls(
            rules,
            Self::errno_denied_syscalls(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            target_arch,
        )
    }

    /// Expose minimal_filter for tests in sibling modules.
    #[cfg(test)]
    pub(crate) fn minimal_filter_for_test(
        allow_network: bool,
        extra_syscalls: &[String],
    ) -> BTreeMap<i64, Vec<SeccompRule>> {
        Self::minimal_filter(allow_network, extra_syscalls).unwrap()
    }

    #[cfg(test)]
    pub(crate) fn errno_denied_syscalls_for_test() -> &'static [(i64, u32)] {
        Self::errno_denied_syscalls()
    }

    /// Apply seccomp filter
    ///
    /// This implements the transition: no_filter -> whitelist_active
    /// in the seccomp state machine (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
    ///
    /// Once applied, the filter cannot be removed (irreversible property)
    /// In rootless mode or if seccomp setup fails, this will warn and continue
    pub fn apply_minimal_filter(&mut self) -> Result<bool> {
        self.apply_minimal_filter_with_mode(false, false)
    }

    /// Apply seccomp filter with configurable failure behavior
    ///
    /// When `best_effort` is true, failures are logged and execution continues.
    /// When false, seccomp setup is fail-closed.
    pub fn apply_minimal_filter_with_mode(
        &mut self,
        best_effort: bool,
        log_denied: bool,
    ) -> Result<bool> {
        self.apply_filter_for_network_mode(true, best_effort, log_denied, &[])
    }

    /// Apply seccomp filter with network-mode-aware socket restrictions
    ///
    /// When `allow_network` is false, `SYS_socket` is restricted to AF_UNIX only,
    /// preventing creation of network sockets (AF_INET, AF_INET6, etc.).
    /// When `allow_network` is true, all socket domains are permitted.
    ///
    /// When `best_effort` is true, failures are logged and execution continues.
    /// When false, seccomp setup is fail-closed.
    pub fn apply_filter_for_network_mode(
        &mut self,
        allow_network: bool,
        best_effort: bool,
        log_denied: bool,
        extra_syscalls: &[String],
    ) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(true);
        }

        info!(allow_network, "Applying seccomp filter");

        let rules = match Self::minimal_filter(allow_network, extra_syscalls) {
            Ok(r) => r,
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to create seccomp rules: {} (continuing without seccomp)",
                        e
                    );
                    return Ok(false);
                }
                return Err(e);
            }
        };

        let target_arch = match std::env::consts::ARCH.try_into() {
            Ok(a) => a,
            Err(e) => {
                let msg = format!("Unsupported architecture: {:?}", e);
                if best_effort {
                    warn!("{} (continuing without seccomp)", msg);
                    return Ok(false);
                }
                return Err(NucleusError::SeccompError(msg));
            }
        };

        let bpf_prog: BpfProgram = match super::seccomp_bpf::compile_bitmap_bpf_with_errno_syscalls(
            rules,
            Self::errno_denied_syscalls(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            target_arch,
        ) {
            Ok(p) => p,
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to compile BPF program: {} (continuing without seccomp)",
                        e
                    );
                    return Ok(false);
                }
                return Err(e);
            }
        };

        // Apply the filter
        match Self::apply_bpf_program(&bpf_prog, log_denied) {
            Ok(_) => {
                self.applied = true;
                info!("Successfully applied seccomp filter");
                Ok(true)
            }
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to apply seccomp filter: {} (continuing without seccomp)",
                        e
                    );
                    Ok(false)
                } else {
                    Err(NucleusError::SeccompError(format!(
                        "Failed to apply seccomp filter: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Apply a seccomp profile loaded from a JSON file.
    ///
    /// The profile format is a JSON object with:
    /// ```json
    /// {
    ///   "defaultAction": "SCMP_ACT_ERRNO",
    ///   "syscalls": [
    ///     { "names": ["read", "write", "open", ...], "action": "SCMP_ACT_ALLOW" }
    ///   ]
    /// }
    /// ```
    ///
    /// This is a subset of the OCI seccomp profile format. Only the syscall name
    /// allowlist is used; argument-level filtering from the built-in profile is
    /// not applied when using a custom profile.
    ///
    /// If `expected_sha256` is provided, the file's SHA-256 hash is verified
    /// against it before loading. This prevents silent profile tampering.
    pub fn apply_profile_from_file(
        &mut self,
        profile_path: &Path,
        expected_sha256: Option<&str>,
        audit_mode: bool,
    ) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(true);
        }

        info!("Loading seccomp profile from {:?}", profile_path);

        // Read profile file
        let content = std::fs::read(profile_path).map_err(|e| {
            NucleusError::SeccompError(format!(
                "Failed to read seccomp profile {:?}: {}",
                profile_path, e
            ))
        })?;

        // Verify SHA-256 hash if expected
        if let Some(expected) = expected_sha256 {
            let actual = sha256_hex(&content);
            if actual != expected {
                return Err(NucleusError::SeccompError(format!(
                    "Seccomp profile hash mismatch: expected {}, got {}",
                    expected, actual
                )));
            }
            info!("Seccomp profile hash verified: {}", actual);
        }

        // Parse profile
        let profile: SeccompProfile = serde_json::from_slice(&content).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to parse seccomp profile: {}", e))
        })?;

        // Warn when custom profile allows security-critical syscalls without
        // argument-level filtering. The built-in filter restricts clone, ioctl,
        // prctl, and socket at the argument level; a custom profile that allows
        // them by name only silently removes all of that hardening.
        Self::warn_missing_arg_filters(&profile);

        // Build filter from profile
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        for syscall_group in &profile.syscalls {
            if syscall_group.action == "SCMP_ACT_ALLOW" {
                for name in &syscall_group.names {
                    if name == "clone3" {
                        warn!(
                            "Custom seccomp profile requested clone3; ignoring it and returning \
                             ENOSYS because clone3 namespace flags cannot be argument-filtered"
                        );
                        continue;
                    }
                    if let Some(nr) = syscall_name_to_number(name) {
                        rules.insert(nr, Vec::new());
                    } else {
                        warn!("Unknown syscall in profile: {} (skipping)", name);
                    }
                }
            }
        }

        // SEC-01: Merge built-in argument filters for security-critical syscalls.
        // Custom profiles that allow clone/ioctl/prctl/socket/mprotect by name
        // without argument-level filters would silently remove all hardening.
        // Overwrite their empty rules with the built-in argument-filtered rules.
        let builtin_rules = Self::minimal_filter(true, &[])?;
        for syscall_name in Self::ARG_FILTERED_SYSCALLS {
            if let Some(nr) = syscall_name_to_number(syscall_name) {
                if let std::collections::btree_map::Entry::Occupied(mut entry) = rules.entry(nr) {
                    if let Some(builtin) = builtin_rules.get(&nr) {
                        if !builtin.is_empty() {
                            info!(
                                "Merging built-in argument filters for '{}' into custom profile",
                                syscall_name
                            );
                            entry.insert(builtin.clone());
                        }
                    }
                }
            }
        }
        let target_arch = std::env::consts::ARCH.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
        })?;

        let bpf_prog: BpfProgram = super::seccomp_bpf::compile_bitmap_bpf_with_errno_syscalls(
            rules,
            Self::errno_denied_syscalls(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            target_arch,
        )?;

        match Self::apply_bpf_program(&bpf_prog, audit_mode) {
            Ok(_) => {
                self.applied = true;
                info!(
                    "Seccomp profile applied from {:?} (log_denied={})",
                    profile_path, audit_mode
                );
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Install an allow-all seccomp filter with SECCOMP_FILTER_FLAG_LOG.
    ///
    /// Used in trace mode: all syscalls are allowed but logged to the kernel
    /// audit subsystem. A separate reader collects the logged syscalls.
    pub fn apply_trace_filter(&mut self) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping trace filter");
            return Ok(true);
        }

        info!("Applying seccomp trace filter (allow-all + LOG)");

        // Create an empty rule set – with SeccompAction::Allow as default,
        // every syscall is permitted. The LOG flag causes the kernel to
        // audit each syscall decision.
        let filter = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow, // default: allow everything
            SeccompAction::Allow, // match action (unused – no rules)
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        )
        .map_err(|e| NucleusError::SeccompError(format!("Failed to create trace filter: {}", e)))?;

        let bpf_prog: BpfProgram = filter.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Failed to compile trace BPF: {}", e))
        })?;

        // Apply with LOG flag so kernel audits every syscall
        Self::apply_bpf_program(&bpf_prog, true)?;
        self.applied = true;
        info!("Seccomp trace filter applied (all syscalls allowed + logged)");
        Ok(true)
    }

    /// Syscalls that the built-in filter restricts at the argument level.
    /// Custom profiles allowing these without argument filters weaken security.
    const ARG_FILTERED_SYSCALLS: &'static [&'static str] = &[
        "clone", "execveat", "ioctl", "mprotect", "preadv2", "prctl", "pwritev2", "socket",
    ];

    /// Security-critical syscalls that must not be re-enabled by the
    /// convenience `--seccomp-allow` fragment mechanism.
    const SECURITY_CRITICAL_DENIED_SYSCALLS: &'static [&'static str] = &[
        // Namespace entry/creation bypasses clone namespace-flag filtering.
        "clone3",
        "unshare",
        "setns",
        // Kernel keyrings are deliberately outside the built-in policy.
        "add_key",
        "request_key",
        "keyctl",
    ];

    fn errno_denied_syscalls() -> &'static [(i64, u32)] {
        &[(libc::SYS_clone3, libc::ENOSYS as u32)]
    }

    /// Non-default syscalls that may be opted into via `--seccomp-allow`.
    ///
    /// Every syscall known to `syscall_name_to_number` but absent from both
    /// `base_allowed_syscalls` and `ARG_FILTERED_SYSCALLS` must appear here
    /// to be enableable. Requesting a known syscall that is NOT in this list
    /// emits a WARN and is silently dropped (defense-in-depth).
    const OPT_IN_SYSCALLS: &'static [&'static str] = &[
        // io_uring – large attack surface but needed by modern databases
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        // SysV message queues
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
        // POSIX message queues
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        // POSIX timers
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        // Inotify / fanotify
        "inotify_init",
        "inotify_init1",
        "inotify_add_watch",
        "inotify_rm_watch",
        "fanotify_init",
        "fanotify_mark",
        // Memory (non-default)
        "mincore",
        "mlockall",
        "munlockall",
        "membarrier",
        "process_madvise",
        "mbind",
        "set_mempolicy",
        "get_mempolicy",
        "set_mempolicy_home_node",
        "pkey_mprotect",
        "pkey_alloc",
        "pkey_free",
        "cachestat",
        "remap_file_pages",
        // File I/O (non-default)
        "sync",
        "syncfs",
        "sync_file_range",
        "readahead",
        "vmsplice",
        "openat2",
        "name_to_handle_at",
        "open_by_handle_at",
        "io_cancel",
        "io_pgetevents",
        "creat",
        "fchmodat2",
        "statmount",
        "listmount",
        "utimensat",
        "utimes",
        "utime",
        "futimesat",
        // Extended attributes (write)
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "setxattrat",
        "getxattrat",
        "listxattrat",
        "removexattrat",
        // Network (non-default)
        "recvmmsg",
        "sendmmsg",
        // Scheduling (non-default)
        "sched_setparam",
        "sched_setscheduler",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_rr_get_interval",
        "sched_setattr",
        "sched_getattr",
        // Resource limits / priority
        "setrlimit",
        "getpriority",
        "setpriority",
        "ioprio_set",
        "ioprio_get",
        // Process (non-default, low risk)
        "vfork",
        "pause",
        "alarm",
        "tkill",
        "sysinfo",
        "personality",
        "vhangup",
        "time",
        "pidfd_open",
        "pidfd_send_signal",
        "pidfd_getfd",
        // UID/GID
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
        "setresuid",
        "getresuid",
        "setresgid",
        "getresgid",
        "setfsuid",
        "setfsgid",
        "setgroups",
        "getsid",
        // Capabilities (read-only query)
        "capget",
        // Signals (non-default)
        "rt_tgsigqueueinfo",
        // Misc
        "mknod",
        "mknodat",
        "syslog",
        "clock_settime",
        "clock_adjtime",
        "adjtimex",
        "kcmp",
        "epoll_pwait2",
        // Futex (non-default)
        "futex_waitv",
        "futex_wake",
        "futex_wait",
        "futex_requeue",
        // Landlock (already in default but listed for completeness)
        "seccomp",
    ];

    /// Warn when a custom seccomp profile allows security-critical syscalls
    /// without argument-level filtering.
    fn warn_missing_arg_filters(profile: &SeccompProfile) {
        for group in &profile.syscalls {
            if group.action != "SCMP_ACT_ALLOW" {
                continue;
            }
            for name in &group.names {
                if Self::ARG_FILTERED_SYSCALLS.contains(&name.as_str()) && group.args.is_empty() {
                    warn!(
                        "Custom seccomp profile allows '{}' without argument filters. \
                         The built-in filter restricts this syscall at the argument level. \
                         This profile weakens security compared to the default.",
                        name
                    );
                }
            }
        }
    }

    /// Check if seccomp filter has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    fn apply_bpf_program(bpf_prog: &BpfProgram, log_denied: bool) -> Result<()> {
        let mut flags: libc::c_ulong = 0;
        if log_denied {
            flags |= libc::SECCOMP_FILTER_FLAG_LOG as libc::c_ulong;
        }

        match Self::apply_bpf_program_with_flags(bpf_prog, flags) {
            Ok(()) => Ok(()),
            Err(err)
                if log_denied
                    && err.raw_os_error() == Some(libc::EINVAL)
                    && libc::SECCOMP_FILTER_FLAG_LOG != 0 =>
            {
                warn!(
                    "Kernel rejected SECCOMP_FILTER_FLAG_LOG; continuing with seccomp \
                     enforcement without deny logging"
                );
                Self::apply_bpf_program_with_flags(bpf_prog, 0)?;
                Ok(())
            }
            Err(err) => Err(NucleusError::SeccompError(format!(
                "Failed to apply seccomp filter: {}",
                err
            ))),
        }
    }

    fn apply_bpf_program_with_flags(
        bpf_prog: &BpfProgram,
        flags: libc::c_ulong,
    ) -> std::io::Result<()> {
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, ...)` has no pointer arguments here
        // and only affects the current thread/process as required before seccomp.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let prog = libc::sock_fprog {
            len: bpf_prog.len() as u16,
            filter: bpf_prog.as_ptr() as *mut libc::sock_filter,
        };

        // SAFETY: `prog` points to a live BPF program buffer for the duration of
        // the syscall and the kernel copies the pointed-to filter immediately.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &prog as *const libc::sock_fprog,
            )
        };

        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

// SeccompProfile and SeccompSyscallGroup are defined in seccomp_generate.rs
use crate::security::seccomp_generate::SeccompProfile;

/// Map a syscall name (e.g. "read", "write") to its Linux syscall number.
///
/// Covers the most common syscalls. Unknown names return None.
fn syscall_name_to_number(name: &str) -> Option<i64> {
    match name {
        // File I/O
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        #[cfg(target_arch = "x86_64")]
        "open" => Some(libc::SYS_open),
        "openat" => Some(libc::SYS_openat),
        "close" => Some(libc::SYS_close),
        #[cfg(target_arch = "x86_64")]
        "stat" => Some(libc::SYS_stat),
        "fstat" => Some(libc::SYS_fstat),
        #[cfg(target_arch = "x86_64")]
        "lstat" => Some(libc::SYS_lstat),
        "lseek" => Some(libc::SYS_lseek),
        #[cfg(target_arch = "x86_64")]
        "access" => Some(libc::SYS_access),
        "fcntl" => Some(libc::SYS_fcntl),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "preadv" => Some(libc::SYS_preadv),
        "pwritev" => Some(libc::SYS_pwritev),
        "preadv2" => Some(libc::SYS_preadv2),
        "pwritev2" => Some(libc::SYS_pwritev2),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        #[cfg(target_arch = "x86_64")]
        "readlink" => Some(libc::SYS_readlink),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "statx" => Some(libc::SYS_statx),
        "faccessat" => Some(libc::SYS_faccessat),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "dup" => Some(libc::SYS_dup),
        #[cfg(target_arch = "x86_64")]
        "dup2" => Some(libc::SYS_dup2),
        "dup3" => Some(libc::SYS_dup3),
        #[cfg(target_arch = "x86_64")]
        "pipe" => Some(libc::SYS_pipe),
        "pipe2" => Some(libc::SYS_pipe2),
        #[cfg(target_arch = "x86_64")]
        "unlink" => Some(libc::SYS_unlink),
        "unlinkat" => Some(libc::SYS_unlinkat),
        #[cfg(target_arch = "x86_64")]
        "rename" => Some(libc::SYS_rename),
        "renameat" => Some(libc::SYS_renameat),
        "renameat2" => Some(libc::SYS_renameat2),
        #[cfg(target_arch = "x86_64")]
        "link" => Some(libc::SYS_link),
        "linkat" => Some(libc::SYS_linkat),
        #[cfg(target_arch = "x86_64")]
        "symlink" => Some(libc::SYS_symlink),
        "symlinkat" => Some(libc::SYS_symlinkat),
        #[cfg(target_arch = "x86_64")]
        "chmod" => Some(libc::SYS_chmod),
        "fchmod" => Some(libc::SYS_fchmod),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "truncate" => Some(libc::SYS_truncate),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "fallocate" => Some(libc::SYS_fallocate),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        "fadvise64" => Some(SYS_FADVISE64),
        "fsync" => Some(libc::SYS_fsync),
        "fdatasync" => Some(libc::SYS_fdatasync),
        "flock" => Some(libc::SYS_flock),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        "sendfile" => Some(SYS_SENDFILE),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "splice" => Some(libc::SYS_splice),
        "tee" => Some(libc::SYS_tee),
        // Memory
        "mmap" => Some(libc::SYS_mmap),
        "munmap" => Some(libc::SYS_munmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "brk" => Some(libc::SYS_brk),
        "mremap" => Some(libc::SYS_mremap),
        "madvise" => Some(libc::SYS_madvise),
        "msync" => Some(libc::SYS_msync),
        "mlock" => Some(libc::SYS_mlock),
        "mlock2" => Some(libc::SYS_mlock2),
        "munlock" => Some(libc::SYS_munlock),
        // SysV IPC
        "shmget" => Some(libc::SYS_shmget),
        "shmat" => Some(libc::SYS_shmat),
        "shmdt" => Some(libc::SYS_shmdt),
        "shmctl" => Some(libc::SYS_shmctl),
        "semget" => Some(libc::SYS_semget),
        "semop" => Some(libc::SYS_semop),
        "semctl" => Some(libc::SYS_semctl),
        "semtimedop" => Some(libc::SYS_semtimedop),
        // Process
        #[cfg(target_arch = "x86_64")]
        "fork" => Some(libc::SYS_fork),
        "clone" => Some(libc::SYS_clone),
        "clone3" => Some(libc::SYS_clone3),
        "execve" => Some(libc::SYS_execve),
        "execveat" => Some(libc::SYS_execveat),
        "wait4" => Some(libc::SYS_wait4),
        "waitid" => Some(libc::SYS_waitid),
        "exit" => Some(libc::SYS_exit),
        "exit_group" => Some(libc::SYS_exit_group),
        "getpid" => Some(libc::SYS_getpid),
        "gettid" => Some(libc::SYS_gettid),
        "getuid" => Some(libc::SYS_getuid),
        "getgid" => Some(libc::SYS_getgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "getppid" => Some(libc::SYS_getppid),
        #[cfg(target_arch = "x86_64")]
        "getpgrp" => Some(libc::SYS_getpgrp),
        "setsid" => Some(libc::SYS_setsid),
        "getgroups" => Some(libc::SYS_getgroups),
        // Signals
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "rt_sigsuspend" => Some(libc::SYS_rt_sigsuspend),
        "rt_sigtimedwait" => Some(libc::SYS_rt_sigtimedwait),
        "rt_sigpending" => Some(libc::SYS_rt_sigpending),
        "rt_sigqueueinfo" => Some(libc::SYS_rt_sigqueueinfo),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "restart_syscall" => Some(libc::SYS_restart_syscall),
        "kill" => Some(libc::SYS_kill),
        "tgkill" => Some(libc::SYS_tgkill),
        // Time
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_getres" => Some(libc::SYS_clock_getres),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "gettimeofday" => Some(libc::SYS_gettimeofday),
        "nanosleep" => Some(libc::SYS_nanosleep),
        // Directories
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fchdir" => Some(libc::SYS_fchdir),
        #[cfg(target_arch = "x86_64")]
        "mkdir" => Some(libc::SYS_mkdir),
        "mkdirat" => Some(libc::SYS_mkdirat),
        #[cfg(target_arch = "x86_64")]
        "rmdir" => Some(libc::SYS_rmdir),
        #[cfg(target_arch = "x86_64")]
        "getdents" => Some(libc::SYS_getdents),
        "getdents64" => Some(libc::SYS_getdents64),
        // Network
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "shutdown" => Some(libc::SYS_shutdown),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "accept" => Some(libc::SYS_accept),
        "accept4" => Some(libc::SYS_accept4),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        // Poll/Select
        #[cfg(target_arch = "x86_64")]
        "poll" => Some(libc::SYS_poll),
        "ppoll" => Some(libc::SYS_ppoll),
        #[cfg(target_arch = "x86_64")]
        "select" => Some(libc::SYS_select),
        "pselect6" => Some(libc::SYS_pselect6),
        #[cfg(target_arch = "x86_64")]
        "epoll_create" => Some(libc::SYS_epoll_create),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        #[cfg(target_arch = "x86_64")]
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        "eventfd" => Some(libc::SYS_eventfd),
        "eventfd2" => Some(libc::SYS_eventfd2),
        #[cfg(target_arch = "x86_64")]
        "signalfd" => Some(libc::SYS_signalfd),
        "signalfd4" => Some(libc::SYS_signalfd4),
        "timerfd_create" => Some(libc::SYS_timerfd_create),
        "timerfd_settime" => Some(libc::SYS_timerfd_settime),
        "timerfd_gettime" => Some(libc::SYS_timerfd_gettime),
        // Misc
        "uname" => Some(libc::SYS_uname),
        "getrandom" => Some(libc::SYS_getrandom),
        "futex" => Some(libc::SYS_futex),
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "get_robust_list" => Some(libc::SYS_get_robust_list),
        #[cfg(target_arch = "x86_64")]
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "umask" => Some(libc::SYS_umask),
        #[cfg(target_arch = "x86_64")]
        "getrlimit" => Some(libc::SYS_getrlimit),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "getrusage" => Some(libc::SYS_getrusage),
        "times" => Some(libc::SYS_times),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "getcpu" => Some(libc::SYS_getcpu),
        "rseq" => Some(libc::SYS_rseq),
        "close_range" => Some(libc::SYS_close_range),
        // Ownership
        "fchown" => Some(libc::SYS_fchown),
        "fchownat" => Some(libc::SYS_fchownat),
        #[cfg(target_arch = "x86_64")]
        "chown" => Some(libc::SYS_chown),
        #[cfg(target_arch = "x86_64")]
        "lchown" => Some(libc::SYS_lchown),
        // io_uring
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        // Legacy AIO
        "io_setup" => Some(libc::SYS_io_setup),
        "io_destroy" => Some(libc::SYS_io_destroy),
        "io_submit" => Some(libc::SYS_io_submit),
        "io_getevents" => Some(libc::SYS_io_getevents),
        // Timers
        "setitimer" => Some(libc::SYS_setitimer),
        "getitimer" => Some(libc::SYS_getitimer),
        // Process groups
        "setpgid" => Some(libc::SYS_setpgid),
        "getpgid" => Some(libc::SYS_getpgid),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "ioctl" => Some(libc::SYS_ioctl),
        "prctl" => Some(libc::SYS_prctl),
        // Landlock
        "landlock_create_ruleset" => Some(libc::SYS_landlock_create_ruleset),
        "landlock_add_rule" => Some(libc::SYS_landlock_add_rule),
        "landlock_restrict_self" => Some(libc::SYS_landlock_restrict_self),
        // --- Additional syscalls (not in default allowlist, available via --seccomp-allow) ---
        // Memory
        "mincore" => Some(libc::SYS_mincore),
        "mlockall" => Some(libc::SYS_mlockall),
        "munlockall" => Some(libc::SYS_munlockall),
        "mbind" => Some(libc::SYS_mbind),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "memfd_secret" => Some(libc::SYS_memfd_secret),
        "membarrier" => Some(libc::SYS_membarrier),
        "process_madvise" => Some(libc::SYS_process_madvise),
        "pkey_mprotect" => Some(libc::SYS_pkey_mprotect),
        "pkey_alloc" => Some(libc::SYS_pkey_alloc),
        "pkey_free" => Some(libc::SYS_pkey_free),
        "mseal" => Some(libc::SYS_mseal),
        "map_shadow_stack" => Some(453),
        "remap_file_pages" => Some(libc::SYS_remap_file_pages),
        "set_mempolicy_home_node" => Some(libc::SYS_set_mempolicy_home_node),
        "cachestat" => Some(451),
        // Process
        #[cfg(target_arch = "x86_64")]
        "vfork" => Some(libc::SYS_vfork),
        #[cfg(target_arch = "x86_64")]
        "pause" => Some(libc::SYS_pause),
        #[cfg(target_arch = "x86_64")]
        "alarm" => Some(libc::SYS_alarm),
        "tkill" => Some(libc::SYS_tkill),
        "ptrace" => Some(libc::SYS_ptrace),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv),
        "process_vm_writev" => Some(libc::SYS_process_vm_writev),
        "process_mrelease" => Some(libc::SYS_process_mrelease),
        "kcmp" => Some(libc::SYS_kcmp),
        "unshare" => Some(libc::SYS_unshare),
        "setns" => Some(libc::SYS_setns),
        "pidfd_open" => Some(libc::SYS_pidfd_open),
        "pidfd_send_signal" => Some(libc::SYS_pidfd_send_signal),
        "pidfd_getfd" => Some(libc::SYS_pidfd_getfd),
        // UID/GID
        "setuid" => Some(libc::SYS_setuid),
        "setgid" => Some(libc::SYS_setgid),
        "setreuid" => Some(libc::SYS_setreuid),
        "setregid" => Some(libc::SYS_setregid),
        "setresuid" => Some(libc::SYS_setresuid),
        "getresuid" => Some(libc::SYS_getresuid),
        "setresgid" => Some(libc::SYS_setresgid),
        "getresgid" => Some(libc::SYS_getresgid),
        "setfsuid" => Some(libc::SYS_setfsuid),
        "setfsgid" => Some(libc::SYS_setfsgid),
        "setgroups" => Some(libc::SYS_setgroups),
        "getsid" => Some(libc::SYS_getsid),
        // Capabilities
        "capget" => Some(libc::SYS_capget),
        "capset" => Some(libc::SYS_capset),
        // Signals
        "rt_tgsigqueueinfo" => Some(libc::SYS_rt_tgsigqueueinfo),
        // SysV message queues
        "msgget" => Some(libc::SYS_msgget),
        "msgsnd" => Some(libc::SYS_msgsnd),
        "msgrcv" => Some(libc::SYS_msgrcv),
        "msgctl" => Some(libc::SYS_msgctl),
        // Timers
        "timer_create" => Some(libc::SYS_timer_create),
        "timer_settime" => Some(libc::SYS_timer_settime),
        "timer_gettime" => Some(libc::SYS_timer_gettime),
        "timer_getoverrun" => Some(libc::SYS_timer_getoverrun),
        "timer_delete" => Some(libc::SYS_timer_delete),
        "clock_settime" => Some(libc::SYS_clock_settime),
        "clock_adjtime" => Some(libc::SYS_clock_adjtime),
        #[cfg(target_arch = "x86_64")]
        "time" => Some(libc::SYS_time),
        // File I/O (non-default)
        #[cfg(target_arch = "x86_64")]
        "creat" => Some(libc::SYS_creat),
        "readahead" => Some(libc::SYS_readahead),
        "sync" => Some(libc::SYS_sync),
        "syncfs" => Some(libc::SYS_syncfs),
        "vmsplice" => Some(libc::SYS_vmsplice),
        "utimensat" => Some(libc::SYS_utimensat),
        #[cfg(target_arch = "x86_64")]
        "utimes" => Some(libc::SYS_utimes),
        #[cfg(target_arch = "x86_64")]
        "utime" => Some(libc::SYS_utime),
        #[cfg(target_arch = "x86_64")]
        "futimesat" => Some(libc::SYS_futimesat),
        "openat2" => Some(libc::SYS_openat2),
        "name_to_handle_at" => Some(libc::SYS_name_to_handle_at),
        "open_by_handle_at" => Some(libc::SYS_open_by_handle_at),
        "fchmodat2" => Some(libc::SYS_fchmodat2),
        "statmount" => Some(457),
        "listmount" => Some(458),
        // Extended attributes (write)
        "setxattr" => Some(libc::SYS_setxattr),
        "lsetxattr" => Some(libc::SYS_lsetxattr),
        "fsetxattr" => Some(libc::SYS_fsetxattr),
        "removexattr" => Some(libc::SYS_removexattr),
        "lremovexattr" => Some(libc::SYS_lremovexattr),
        "fremovexattr" => Some(libc::SYS_fremovexattr),
        "setxattrat" => Some(463),
        "getxattrat" => Some(464),
        "listxattrat" => Some(465),
        "removexattrat" => Some(466),
        // Network (non-default)
        "recvmmsg" => Some(libc::SYS_recvmmsg),
        "sendmmsg" => Some(libc::SYS_sendmmsg),
        // Inotify
        #[cfg(target_arch = "x86_64")]
        "inotify_init" => Some(libc::SYS_inotify_init),
        "inotify_init1" => Some(libc::SYS_inotify_init1),
        "inotify_add_watch" => Some(libc::SYS_inotify_add_watch),
        "inotify_rm_watch" => Some(libc::SYS_inotify_rm_watch),
        // Fanotify
        "fanotify_init" => Some(libc::SYS_fanotify_init),
        "fanotify_mark" => Some(libc::SYS_fanotify_mark),
        // Epoll (non-default)
        "epoll_pwait2" => Some(libc::SYS_epoll_pwait2),
        // Scheduling (non-default)
        "sched_setparam" => Some(libc::SYS_sched_setparam),
        "sched_setscheduler" => Some(libc::SYS_sched_setscheduler),
        "sched_get_priority_max" => Some(libc::SYS_sched_get_priority_max),
        "sched_get_priority_min" => Some(libc::SYS_sched_get_priority_min),
        "sched_rr_get_interval" => Some(libc::SYS_sched_rr_get_interval),
        "sched_setattr" => Some(libc::SYS_sched_setattr),
        "sched_getattr" => Some(libc::SYS_sched_getattr),
        "sched_setaffinity" => Some(libc::SYS_sched_setaffinity),
        // Resource limits
        #[cfg(target_arch = "x86_64")]
        "setrlimit" => Some(libc::SYS_setrlimit),
        "getpriority" => Some(libc::SYS_getpriority),
        "setpriority" => Some(libc::SYS_setpriority),
        "ioprio_set" => Some(libc::SYS_ioprio_set),
        "ioprio_get" => Some(libc::SYS_ioprio_get),
        // Futex (non-default)
        "futex_waitv" => Some(libc::SYS_futex_waitv),
        "futex_wake" => Some(454),
        "futex_wait" => Some(455),
        "futex_requeue" => Some(456),
        // Kernel modules
        "init_module" => Some(libc::SYS_init_module),
        "finit_module" => Some(libc::SYS_finit_module),
        "delete_module" => Some(libc::SYS_delete_module),
        // eBPF and performance
        "bpf" => Some(libc::SYS_bpf),
        "perf_event_open" => Some(libc::SYS_perf_event_open),
        // Seccomp
        "seccomp" => Some(libc::SYS_seccomp),
        // Userfaultfd
        "userfaultfd" => Some(libc::SYS_userfaultfd),
        // Mount (non-default)
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        "pivot_root" => Some(libc::SYS_pivot_root),
        "mount_setattr" => Some(libc::SYS_mount_setattr),
        "open_tree" => Some(libc::SYS_open_tree),
        "open_tree_attr" => Some(467),
        "move_mount" => Some(libc::SYS_move_mount),
        "fsopen" => Some(libc::SYS_fsopen),
        "fsconfig" => Some(libc::SYS_fsconfig),
        "fsmount" => Some(libc::SYS_fsmount),
        "fspick" => Some(libc::SYS_fspick),
        // Misc (non-default)
        "syslog" => Some(libc::SYS_syslog),
        "reboot" => Some(libc::SYS_reboot),
        "swapon" => Some(libc::SYS_swapon),
        "swapoff" => Some(libc::SYS_swapoff),
        "chroot" => Some(libc::SYS_chroot),
        "acct" => Some(libc::SYS_acct),
        "settimeofday" => Some(libc::SYS_settimeofday),
        "sethostname" => Some(libc::SYS_sethostname),
        "setdomainname" => Some(libc::SYS_setdomainname),
        "adjtimex" => Some(libc::SYS_adjtimex),
        #[cfg(target_arch = "x86_64")]
        "modify_ldt" => Some(libc::SYS_modify_ldt),
        #[cfg(target_arch = "x86_64")]
        "iopl" => Some(libc::SYS_iopl),
        #[cfg(target_arch = "x86_64")]
        "ioperm" => Some(libc::SYS_ioperm),
        "quotactl" => Some(libc::SYS_quotactl),
        "quotactl_fd" => Some(libc::SYS_quotactl_fd),
        "personality" => Some(libc::SYS_personality),
        "vhangup" => Some(libc::SYS_vhangup),
        #[cfg(target_arch = "x86_64")]
        "ustat" => Some(libc::SYS_ustat),
        #[cfg(target_arch = "x86_64")]
        "sysfs" => Some(libc::SYS_sysfs),
        "mknod" => Some(libc::SYS_mknod),
        "mknodat" => Some(libc::SYS_mknodat),
        "migrate_pages" => Some(libc::SYS_migrate_pages),
        "move_pages" => Some(libc::SYS_move_pages),
        #[cfg(target_arch = "x86_64")]
        "kexec_load" => Some(libc::SYS_kexec_load),
        "kexec_file_load" => Some(libc::SYS_kexec_file_load),
        // POSIX message queues
        "mq_open" => Some(libc::SYS_mq_open),
        "mq_unlink" => Some(libc::SYS_mq_unlink),
        "mq_timedsend" => Some(libc::SYS_mq_timedsend),
        "mq_timedreceive" => Some(libc::SYS_mq_timedreceive),
        "mq_notify" => Some(libc::SYS_mq_notify),
        "mq_getsetattr" => Some(libc::SYS_mq_getsetattr),
        // Keyring
        "add_key" => Some(libc::SYS_add_key),
        "request_key" => Some(libc::SYS_request_key),
        "keyctl" => Some(libc::SYS_keyctl),
        // IO pgetevents
        "io_pgetevents" => Some(333),
        // LSM
        "lsm_get_self_attr" => Some(459),
        "lsm_set_self_attr" => Some(460),
        "lsm_list_modules" => Some(461),
        #[cfg(target_arch = "x86_64")]
        "lookup_dcookie" => Some(libc::SYS_lookup_dcookie),
        "uretprobe" => Some(335),
        _ => None,
    }
}

impl Default for SeccompManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_manager_initial_state() {
        let mgr = SeccompManager::new();
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_apply_idempotent() {
        let mgr = SeccompManager::new();
        // Note: We can't actually test application in unit tests
        // as it would affect the test process itself
        // This is tested in integration tests instead
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_clone_denied_flags_include_newcgroup() {
        assert_ne!(
            DENIED_CLONE_NAMESPACE_FLAGS & libc::CLONE_NEWCGROUP as u64,
            0
        );
    }

    #[test]
    fn test_clone_denied_flags_include_newtime() {
        assert_ne!(
            DENIED_CLONE_NAMESPACE_FLAGS & libc::CLONE_NEWTIME as u64,
            0,
            "CLONE_NEWTIME must be in denied clone namespace flags"
        );
    }

    #[test]
    fn test_network_none_socket_domains_are_unix_only() {
        let domains = SeccompManager::allowed_socket_domains(false);
        assert_eq!(domains, vec![libc::AF_UNIX]);
    }

    #[test]
    fn test_network_enabled_socket_domains_exclude_netlink() {
        let domains = SeccompManager::allowed_socket_domains(true);
        assert!(domains.contains(&libc::AF_UNIX));
        assert!(domains.contains(&libc::AF_INET));
        assert!(domains.contains(&libc::AF_INET6));
        assert!(!domains.contains(&libc::AF_NETLINK));
    }

    #[test]
    fn test_network_mode_syscalls_only_enabled_when_network_allowed() {
        let none = SeccompManager::network_mode_syscalls(false);
        assert!(none.is_empty());

        let enabled = SeccompManager::network_mode_syscalls(true);
        assert!(enabled.contains(&libc::SYS_connect));
        assert!(enabled.contains(&libc::SYS_bind));
        assert!(enabled.contains(&libc::SYS_listen));
        assert!(enabled.contains(&libc::SYS_accept));
        assert!(enabled.contains(&libc::SYS_setsockopt));
    }

    #[test]
    fn test_landlock_bootstrap_syscalls_present_in_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        assert!(base.contains(&libc::SYS_landlock_create_ruleset));
        assert!(base.contains(&libc::SYS_landlock_add_rule));
        assert!(base.contains(&libc::SYS_landlock_restrict_self));
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    #[test]
    fn test_generic_file_syscalls_present_in_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        assert!(
            base.contains(&SYS_FADVISE64),
            "fadvise64 must be allowed on architectures with a generic syscall table"
        );
        assert!(
            base.contains(&SYS_SENDFILE),
            "sendfile must be allowed on architectures with a generic syscall table"
        );
    }

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    #[test]
    fn test_generic_file_syscall_names_resolve_for_profiles() {
        assert_eq!(syscall_name_to_number("fadvise64"), Some(SYS_FADVISE64));
        assert_eq!(syscall_name_to_number("sendfile"), Some(SYS_SENDFILE));
    }

    #[test]
    fn test_x32_legacy_range_not_allowlisted() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);
        for nr in 512_i64..=547_i64 {
            assert!(
                !base.contains(&nr) && !net.contains(&nr),
                "x32 syscall number {} unexpectedly allowlisted",
                nr
            );
        }
    }

    #[test]
    fn test_i386_compat_socketcall_range_not_allowlisted() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);
        // i386 compat per syscall_32.tbl: socket..shutdown live at 359..373.
        // On x86_64 these numbers are outside our native allowlist surface.
        for nr in 359_i64..=373_i64 {
            assert!(
                !base.contains(&nr) && !net.contains(&nr),
                "i386 compat syscall number {} unexpectedly allowlisted",
                nr
            );
        }
    }

    #[test]
    fn test_minimal_filter_allowlist_counts_are_stable() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);

        // Snapshot counts to catch unintended policy drift.
        // +9 accounts for conditional rules inserted in minimal_filter():
        // socket/ioctl/prctl/prlimit64/mprotect/preadv2/pwritev2/clone/execveat.
        // fork removed (forces through filtered clone path).
        // execveat removed from base (arg-filtered separately).
        // sysinfo removed (L8: leaks host info).
        // prlimit64 moved to arg-filtered (M3).
        assert_eq!(base.len(), 171);
        assert_eq!(net.len(), 11);
        assert_eq!(base.len() + 9, 180);
        assert_eq!(base.len() + net.len() + 9, 191);
    }

    #[test]
    fn test_arg_filtered_syscalls_list_includes_critical_syscalls() {
        // These syscalls must be in the arg-filtered list so custom profiles
        // get warnings when they allow them without filters.
        for name in &[
            "clone", "execveat", "ioctl", "preadv2", "prctl", "pwritev2", "socket",
        ] {
            assert!(
                SeccompManager::ARG_FILTERED_SYSCALLS.contains(name),
                "'{}' must be in ARG_FILTERED_SYSCALLS",
                name
            );
        }
    }

    #[test]
    fn test_clone3_not_allowlisted_in_minimal_filter() {
        // clone3 carries flags through struct clone_args, which seccomp BPF
        // cannot inspect. It must not be unconditionally allowed; the compiler
        // adds an exact ENOSYS deny so libc falls back to filtered clone.
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_clone3),
            "clone3 must not be in the seccomp allowlist"
        );
        assert!(
            SeccompManager::errno_denied_syscalls()
                .iter()
                .any(|(nr, errno)| *nr == libc::SYS_clone3 && *errno == libc::ENOSYS as u32),
            "clone3 must be denied with ENOSYS to trigger libc fallback"
        );
    }

    #[test]
    fn test_clone_is_allowed_with_arg_filter() {
        // clone (not clone3) should still be in the rules with arg filtering
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();
        assert!(
            rules.contains_key(&libc::SYS_clone),
            "clone must be in the seccomp allowlist with arg filters"
        );
    }

    #[test]
    fn test_high_risk_syscalls_removed_from_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        // chown/fchown/lchown/fchownat: allowed – safe after CAP_CHOWN/CAP_FOWNER drop
        // mlock/munlock: allowed – needed by databases, bounded by RLIMIT_MEMLOCK
        let removed = [
            libc::SYS_sync,
            libc::SYS_syncfs,
            libc::SYS_mincore,
            libc::SYS_vfork,
            libc::SYS_tkill,
            // io_uring: large attack surface, many CVEs – require custom profile
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ];

        for syscall in removed {
            assert!(
                !base.contains(&syscall),
                "syscall {} unexpectedly present in base allowlist",
                syscall
            );
        }
    }

    #[test]
    fn test_custom_profile_preserves_clone_arg_filters() {
        // SEC-01: Custom seccomp profiles that allow "clone" must still get
        // argument-level filtering to block namespace-creating flags.
        // Verify by inspecting the built-in filter rules that serve as the
        // merge source for apply_profile_from_file.
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();

        // Every ARG_FILTERED_SYSCALLS entry must have non-empty argument-level
        // rules in the built-in filter so apply_profile_from_file can merge them.
        for name in SeccompManager::ARG_FILTERED_SYSCALLS {
            if let Some(nr) = syscall_name_to_number(name) {
                let entry = rules.get(&nr);
                assert!(
                    entry.is_some() && !entry.unwrap().is_empty(),
                    "built-in filter must have argument-level rules for '{}' \
                     so apply_profile_from_file can merge them into custom profiles",
                    name
                );
            }
        }
    }

    #[test]
    fn test_memfd_create_not_in_default_allowlist() {
        // SEC-02: memfd_create enables fileless code execution when combined with execveat.
        let base = SeccompManager::base_allowed_syscalls();
        assert!(
            !base.contains(&libc::SYS_memfd_create),
            "memfd_create must not be in the default seccomp allowlist (fileless exec risk)"
        );
        // Also verify it's not sneaked into the compiled filter rules
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_memfd_create),
            "memfd_create must not be in the compiled seccomp filter rules"
        );
    }

    #[test]
    fn test_mprotect_has_arg_filtering() {
        // SEC-03: mprotect must have argument-level filtering to prevent W^X
        // (PROT_WRITE|PROT_EXEC) violations. Verify via runtime data structures.

        // mprotect must NOT be in the unconditional base allowlist
        let base = SeccompManager::base_allowed_syscalls();
        assert!(
            !base.contains(&libc::SYS_mprotect),
            "SYS_mprotect must not be unconditionally allowed - needs arg filtering"
        );

        // mprotect must be present in the compiled filter with non-empty
        // argument conditions (the conditions enforce W^X)
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();
        let mprotect_rules = rules.get(&libc::SYS_mprotect);
        assert!(
            mprotect_rules.is_some(),
            "mprotect must be present in the seccomp filter rules"
        );
        assert!(
            !mprotect_rules.unwrap().is_empty(),
            "mprotect must have argument-level conditions to prevent W^X violations"
        );
    }

    #[test]
    fn test_preadv2_pwritev2_have_flags_arg_filtering() {
        // v2 vectored I/O has an extra flags argument. The built-in profile
        // permits the v2 entrypoints only when flags == 0, leaving preadv/pwritev
        // available for ordinary positioned vectored I/O.
        let base = SeccompManager::base_allowed_syscalls();
        let rules = SeccompManager::minimal_filter(true, &[]).unwrap();

        for (name, syscall) in [
            ("preadv2", libc::SYS_preadv2),
            ("pwritev2", libc::SYS_pwritev2),
        ] {
            assert!(
                !base.contains(&syscall),
                "{} must not be unconditionally allowed",
                name
            );
            assert!(
                rules.get(&syscall).is_some_and(|chain| !chain.is_empty()),
                "{} must have argument-level conditions",
                name
            );
            assert!(
                SeccompManager::ARG_FILTERED_SYSCALLS.contains(&name),
                "{} must be listed as argument-filtered for custom profiles",
                name
            );
        }
    }

    #[test]
    fn test_unsafe_blocks_have_safety_comments() {
        // SEC-08: All unsafe blocks must have // SAFETY: documentation
        let source = include_str!("seccomp.rs");
        let mut pos = 0;
        while let Some(idx) = source[pos..].find("unsafe {") {
            let abs_idx = pos + idx;
            // Check that there's a SAFETY comment within 200 chars before the unsafe block
            let start = abs_idx.saturating_sub(200);
            let context = &source[start..abs_idx];
            assert!(
                context.contains("SAFETY:"),
                "unsafe block at byte {} must have a // SAFETY: comment. Context: ...{}...",
                abs_idx,
                &source[abs_idx.saturating_sub(80)..abs_idx + 10]
            );
            pos = abs_idx + 1;
        }
    }

    // --- H-1: mprotect MaskedEq logic verification ---
    //
    // The mprotect filter uses MaskedEq((PROT_WRITE | PROT_EXEC), value) to
    // allow only combinations where the W|X bits match one of {0, W, X}.
    // These tests prove the logic is correct without installing a real
    // seccomp filter (which would affect the test process).

    /// Helper: simulates the MaskedEq check that the seccomp BPF would perform.
    /// Returns true if the prot value would be ALLOWED by one of the rules.
    fn mprotect_would_allow(prot: u64) -> bool {
        let mask = (libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let allowed_values: &[u64] = &[0, libc::PROT_WRITE as u64, libc::PROT_EXEC as u64];
        let masked = prot & mask;
        allowed_values.contains(&masked)
    }

    #[test]
    fn test_mprotect_allows_prot_none() {
        assert!(mprotect_would_allow(0), "PROT_NONE must be allowed");
    }

    #[test]
    fn test_mprotect_allows_prot_read_only() {
        assert!(
            mprotect_would_allow(libc::PROT_READ as u64),
            "PROT_READ must be allowed (W|X bits are 0)"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_read_write() {
        assert!(
            mprotect_would_allow((libc::PROT_READ | libc::PROT_WRITE) as u64),
            "PROT_READ|PROT_WRITE must be allowed"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_read_exec() {
        assert!(
            mprotect_would_allow((libc::PROT_READ | libc::PROT_EXEC) as u64),
            "PROT_READ|PROT_EXEC must be allowed"
        );
    }

    #[test]
    fn test_mprotect_rejects_prot_write_exec() {
        assert!(
            !mprotect_would_allow((libc::PROT_WRITE | libc::PROT_EXEC) as u64),
            "PROT_WRITE|PROT_EXEC (W^X violation) must be REJECTED"
        );
    }

    #[test]
    fn test_mprotect_rejects_prot_read_write_exec() {
        assert!(
            !mprotect_would_allow((libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64),
            "PROT_READ|PROT_WRITE|PROT_EXEC (W^X violation) must be REJECTED"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_write_alone() {
        assert!(
            mprotect_would_allow(libc::PROT_WRITE as u64),
            "PROT_WRITE alone must be allowed"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_exec_alone() {
        assert!(
            mprotect_would_allow(libc::PROT_EXEC as u64),
            "PROT_EXEC alone must be allowed"
        );
    }

    // --- Extra syscall allowlist tests ---

    #[test]
    fn test_extra_syscalls_are_merged_into_filter() {
        let extra = vec!["io_uring_setup".to_string(), "sysinfo".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(
            rules.contains_key(&libc::SYS_io_uring_setup),
            "io_uring_setup must be in filter when requested via extra_syscalls"
        );
        assert!(
            rules.contains_key(&libc::SYS_sysinfo),
            "sysinfo must be in filter when requested via extra_syscalls"
        );
    }

    #[test]
    fn test_extra_syscalls_do_not_override_arg_filtered() {
        // If a user requests an arg-filtered syscall via extra_syscalls, the
        // version from the built-in filter should still be present (not replaced
        // with an unconditional allow).
        let extra = vec![
            "clone".to_string(),
            "preadv2".to_string(),
            "pwritev2".to_string(),
        ];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        for (name, syscall) in [
            ("clone", libc::SYS_clone),
            ("preadv2", libc::SYS_preadv2),
            ("pwritev2", libc::SYS_pwritev2),
        ] {
            assert!(
                rules.get(&syscall).is_some_and(|chain| !chain.is_empty()),
                "{} must retain argument-level filtering even when in extra_syscalls",
                name
            );
        }
    }

    #[test]
    fn test_extra_syscalls_unknown_name_is_warned_and_skipped() {
        // Unknown syscall names emit a WARN and are skipped (not fatal)
        let extra = vec!["not_a_real_syscall".to_string()];
        let result = SeccompManager::minimal_filter(true, &extra);
        assert!(
            result.is_ok(),
            "Unknown syscall name should warn and skip, not error"
        );
    }

    #[test]
    fn test_extra_syscalls_empty_is_noop() {
        let rules_without = SeccompManager::minimal_filter(true, &[]).unwrap();
        let rules_with = SeccompManager::minimal_filter(true, &[]).unwrap();
        assert_eq!(rules_without.len(), rules_with.len());
    }

    #[test]
    fn test_extra_syscalls_duplicate_of_default_is_harmless() {
        // Requesting a syscall that's already in the default allowlist should work fine
        let extra = vec!["read".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(rules.contains_key(&libc::SYS_read));
    }

    #[test]
    fn test_extra_syscalls_blocked_known_syscall_not_added() {
        // A known syscall that is NOT in OPT_IN_SYSCALLS must be blocked
        // (not added to the filter rules). E.g. kexec_load, bpf, ptrace.
        let extra = vec!["kexec_load".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_kexec_load),
            "kexec_load must be blocked even when requested via --seccomp-allow"
        );
    }

    #[test]
    fn test_extra_syscalls_unshare_remains_blocked() {
        let extra = vec!["unshare".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_unshare),
            "unshare must stay blocked even when requested via --seccomp-allow"
        );
    }

    #[test]
    fn test_extra_syscalls_keyring_remain_blocked() {
        let extra = vec![
            "add_key".to_string(),
            "request_key".to_string(),
            "keyctl".to_string(),
        ];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();

        for (name, syscall) in [
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("keyctl", libc::SYS_keyctl),
        ] {
            assert!(
                !rules.contains_key(&syscall),
                "{} must stay blocked even when requested via --seccomp-allow",
                name
            );
            assert!(
                !SeccompManager::OPT_IN_SYSCALLS.contains(&name),
                "{} must not be in the seccomp opt-in allowlist",
                name
            );
        }
    }

    #[test]
    fn test_security_critical_syscalls_remain_absent_from_filter() {
        let extra = SeccompManager::SECURITY_CRITICAL_DENIED_SYSCALLS
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>();
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();

        for name in SeccompManager::SECURITY_CRITICAL_DENIED_SYSCALLS {
            let syscall = syscall_name_to_number(name).unwrap();
            assert!(
                !rules.contains_key(&syscall),
                "{} must not appear in the built-in filter even when requested via --seccomp-allow",
                name
            );
            assert!(
                !SeccompManager::OPT_IN_SYSCALLS.contains(name),
                "{} must not be in the seccomp opt-in allowlist",
                name
            );
        }
    }

    #[test]
    fn test_extra_syscalls_clone3_remains_blocked() {
        let extra = vec!["clone3".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_clone3),
            "clone3 must stay out of the allowlist even when requested via --seccomp-allow"
        );
        assert!(
            SeccompManager::errno_denied_syscalls()
                .iter()
                .any(|(nr, _)| *nr == libc::SYS_clone3),
            "clone3 must remain covered by the exact ENOSYS deny"
        );
    }

    #[test]
    fn test_extra_syscalls_opt_in_syscall_is_added() {
        // Syscalls in OPT_IN_SYSCALLS must be added when requested
        let extra = vec!["io_uring_setup".to_string()];
        let rules = SeccompManager::minimal_filter(true, &extra).unwrap();
        assert!(
            rules.contains_key(&libc::SYS_io_uring_setup),
            "io_uring_setup is in OPT_IN_SYSCALLS and must be added"
        );
    }

    #[test]
    fn test_production_validation_rejects_security_critical_extra_syscalls() {
        for name in [
            "clone3",
            "unshare",
            "setns",
            "add_key",
            "request_key",
            "keyctl",
        ] {
            let extra = vec![name.to_string()];
            let err =
                SeccompManager::validate_extra_syscalls_for_production(true, &extra).unwrap_err();
            assert!(err.to_string().contains("security-critical"));
            assert!(err.to_string().contains(name));
        }
    }

    #[test]
    fn test_production_validation_rejects_unsupported_extra_syscalls() {
        let extra = vec!["kexec_load".to_string()];
        let err = SeccompManager::validate_extra_syscalls_for_production(true, &extra).unwrap_err();
        assert!(err.to_string().contains("unsupported"));
        assert!(err.to_string().contains("kexec_load"));
    }

    #[test]
    fn test_production_validation_allows_supported_extra_syscalls() {
        let extra = vec![
            "read".to_string(),
            "clone".to_string(),
            "connect".to_string(),
            "io_uring_setup".to_string(),
        ];
        SeccompManager::validate_extra_syscalls_for_production(true, &extra).unwrap();
    }
}
