//! Seccomp trace mode: record syscalls for profile generation.
//!
//! In trace mode, an allow-all seccomp filter is installed with
//! `SECCOMP_FILTER_FLAG_LOG`, causing the kernel to log every syscall to
//! the audit subsystem. A reader thread monitors `/dev/kmsg` for
//! SECCOMP audit records matching the container PID and writes unique
//! syscalls to an NDJSON trace file.
//!
//! This is a development tool – requires root or CAP_SYSLOG for
//! `/dev/kmsg` access.

use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const DENY_SCOPE_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const DENY_SCOPE_STALE_PID_TTL: Duration = Duration::from_secs(5);
const DENY_SCOPE_POLL_TIMEOUT_MS: libc::c_int = 250;
const PROC_ROOT: &str = "/proc";
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// A single trace record in the NDJSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Syscall number (e.g. 0 for read on x86_64).
    pub syscall: i64,
    /// Syscall name if known.
    pub name: Option<String>,
    /// Number of times this syscall was observed.
    pub count: u64,
}

/// Reads `/dev/kmsg` for SECCOMP audit records and collects unique syscalls.
pub struct SeccompTraceReader {
    pid: u32,
    output_path: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SeccompTraceReader {
    /// Create a new trace reader for the given child PID.
    pub fn new(pid: u32, output_path: &Path) -> Self {
        Self {
            pid,
            output_path: output_path.to_path_buf(),
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start the background reader thread.
    ///
    /// Opens `/dev/kmsg` and filters for `audit: type=1326` (SECCOMP)
    /// messages matching the target PID.
    pub fn start_recording(&mut self) -> Result<()> {
        self.start_scoped(None)
    }

    pub(crate) fn start_scoped(&mut self, cgroup_path: Option<PathBuf>) -> Result<()> {
        let mut kmsg = File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open("/dev/kmsg")?;
        // Skip historical records for previous occupants of these PID numbers.
        kmsg.seek(SeekFrom::End(0))?;
        let output = create_trace_file(&self.output_path)?;
        let mut scope = SeccompAuditScope::new(self.pid, cgroup_path);
        scope.refresh(Instant::now());
        let stop = self.stop.clone();
        let handle = std::thread::spawn(move || {
            if let Err(e) = record_loop(kmsg, output, scope, &stop) {
                warn!("Seccomp trace reader error: {}", e);
            }
        });

        self.handle = Some(handle);
        info!("Seccomp trace reader started for PID {}", self.pid);
        Ok(())
    }

    /// Signal the reader to stop and wait for it to flush.
    pub fn stop_and_flush(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        info!(
            "Seccomp trace reader stopped, output at {:?}",
            self.output_path
        );
    }
}

impl Drop for SeccompTraceReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Exclusively create a private output file without traversing symlinks.
fn create_trace_file(path: &Path) -> Result<File> {
    use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag, AT_FDCWD};
    use nix::sys::stat::Mode;
    let how = OpenHow::new()
        .flags(OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_WRONLY | OFlag::O_CLOEXEC)
        .mode(Mode::S_IRUSR | Mode::S_IWUSR)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    Ok(File::from(openat2(AT_FDCWD, path, how).map_err(|e| {
        NucleusError::ConfigError(format!("Cannot create new trace file {path:?}: {e}"))
    })?))
}

fn record_loop(
    file: File,
    output: File,
    mut scope: SeccompAuditScope,
    stop: &AtomicBool,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mut syscalls: BTreeMap<i64, u64> = BTreeMap::new();
    let fd = file.as_raw_fd();
    let reader = BufReader::new(file);

    let mut stopping_since = None;
    for line in reader.lines() {
        if stop.load(Ordering::Acquire)
            && stopping_since.get_or_insert_with(Instant::now).elapsed()
                >= DENY_SCOPE_REFRESH_INTERVAL
        {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    scope.refresh_if_stale(Instant::now());
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: pfd is a valid stack-allocated pollfd with a valid fd.
                    // The timeout bounds the interval between membership refreshes.
                    unsafe { libc::poll(&mut pfd, 1, DENY_SCOPE_POLL_TIMEOUT_MS) };
                    continue;
                }
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
        };

        // SECCOMP audit lines look like:
        // audit: type=1326 ... pid=<PID> ... syscall=<NR> ...
        if let Some((_, nr)) = syscall_record_for_scope(&line, &mut scope, Instant::now()) {
            *syscalls.entry(nr).or_insert(0) += 1;
        }
    }

    write_trace_file(output, &syscalls)?;
    info!("Seccomp trace: recorded {} unique syscalls", syscalls.len());
    Ok(())
}

/// Extract the syscall number from an audit SECCOMP line.
fn extract_syscall_nr(line: &str) -> Option<i64> {
    // Look for "syscall=NNN" in the line
    line.split_whitespace()
        .find(|s| s.starts_with("syscall="))
        .and_then(|s| s.strip_prefix("syscall="))
        .and_then(|s| s.parse().ok())
}

/// Extract the syscalling process PID from an audit SECCOMP line.
fn extract_audit_pid(line: &str) -> Option<u32> {
    line.split_whitespace()
        .find(|s| s.starts_with("pid="))
        .and_then(|s| s.strip_prefix("pid="))
        .and_then(|s| s.parse().ok())
}

/// Write the accumulated trace data as NDJSON.
fn write_trace_file(mut file: File, syscalls: &BTreeMap<i64, u64>) -> Result<()> {
    for (&nr, &count) in syscalls {
        let record = TraceRecord {
            syscall: nr,
            name: super::seccomp_generate::syscall_number_to_name(nr).map(String::from),
            count,
        };
        let line =
            serde_json::to_string(&record).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        writeln!(file, "{}", line).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to write trace record: {}", e))
        })?;
    }

    Ok(())
}

/// Reads `/dev/kmsg` for SECCOMP deny records and emits WARN-level logs.
///
/// When `--seccomp-log-denied` is set with `SECCOMP_FILTER_FLAG_LOG`, the
/// kernel logs denied syscalls to the audit subsystem. This reader runs in
/// the parent process (which survives the child kill) and surfaces those
/// records as application-level warnings. The audit record PID is matched
/// against the container's target process, descendants, cgroup, and PID
/// namespace so forked workload denials are not silently dropped.
pub struct SeccompDenyLogger {
    pid: u32,
    cgroup_path: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SeccompDenyLogger {
    pub fn new(pid: u32, cgroup_path: Option<PathBuf>) -> Self {
        Self {
            pid,
            cgroup_path,
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start the background reader thread.
    pub fn start(&mut self) -> Result<()> {
        let pid = self.pid;
        let cgroup_path = self.cgroup_path.clone();
        let stop = self.stop.clone();

        let handle = std::thread::spawn(move || {
            if let Err(e) = deny_log_loop(pid, cgroup_path, &stop) {
                warn!("Seccomp deny logger error: {}", e);
            }
        });

        self.handle = Some(handle);
        debug!(
            cgroup = self
                .cgroup_path
                .as_ref()
                .map(|path| path.display().to_string()),
            "Seccomp deny logger started for PID {}", self.pid
        );
        Ok(())
    }

    /// Signal the logger to stop and join the thread.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SeccompDenyLogger {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug)]
struct SeccompAuditScope {
    target_pid: u32,
    proc_root: PathBuf,
    cgroup_path: Option<PathBuf>,
    cgroup_relative_path: Option<String>,
    target_pid_namespace: Option<String>,
    target_inode: Option<u64>,
    known_pids: BTreeMap<u32, (Instant, Option<u64>)>,
    last_refresh: Option<Instant>,
}

impl SeccompAuditScope {
    fn new(target_pid: u32, cgroup_path: Option<PathBuf>) -> Self {
        Self::with_proc_root(target_pid, PathBuf::from(PROC_ROOT), cgroup_path, None)
    }

    fn with_proc_root(
        target_pid: u32,
        proc_root: PathBuf,
        cgroup_path: Option<PathBuf>,
        cgroup_relative_path: Option<String>,
    ) -> Self {
        let cgroup_relative_path = cgroup_relative_path.or_else(|| {
            cgroup_path
                .as_deref()
                .and_then(cgroup_relative_path_from_host_path)
        });
        let target_inode = proc_inode(&proc_root, target_pid);
        Self {
            target_pid,
            target_inode,
            proc_root,
            cgroup_path,
            cgroup_relative_path,
            target_pid_namespace: None,
            known_pids: BTreeMap::new(),
            last_refresh: None,
        }
    }

    fn matches_pid(&mut self, pid: u32, now: Instant) -> bool {
        if pid == self.target_pid {
            return self.is_original_target() || self.has_recent_pid(pid, now);
        }

        self.refresh_if_stale(now);
        if self.has_recent_pid(pid, now) {
            return true;
        }

        // A deny line for an unknown PID is exactly the forked-workload case.
        // Force a fresh scope scan before deciding that the audit record belongs
        // to some other process on the host.
        self.refresh(now);
        if self.has_recent_pid(pid, now) {
            return true;
        }

        if self.process_matches_cgroup(pid) || self.process_matches_pid_namespace(pid) {
            self.remember_pid(pid, now);
            return true;
        }

        false
    }

    fn refresh_if_stale(&mut self, now: Instant) {
        let should_refresh = self
            .last_refresh
            .and_then(|last| now.checked_duration_since(last))
            .map(|age| age >= DENY_SCOPE_REFRESH_INTERVAL)
            .unwrap_or(true);
        if should_refresh {
            self.refresh(now);
        }
    }

    fn refresh(&mut self, now: Instant) {
        self.expire_stale_pids(now);
        let target_is_live = self.is_original_target();
        if target_is_live && self.target_pid_namespace.is_none() {
            self.target_pid_namespace = read_pid_namespace(&self.proc_root, self.target_pid)
                .filter(|ns| {
                    Some(ns) != read_pid_namespace(&self.proc_root, std::process::id()).as_ref()
                });
        }

        let mut scoped_pids = BTreeSet::new();
        if target_is_live {
            collect_process_tree_pids(&self.proc_root, self.target_pid, &mut scoped_pids);
        }
        for pid in scoped_pids {
            self.remember_pid(pid, now);
        }

        if let Some(cgroup_path) = &self.cgroup_path {
            for pid in read_pids_from_file(&cgroup_path.join("cgroup.procs")) {
                self.remember_pid(pid, now);
            }
        }

        self.last_refresh = Some(now);
    }

    fn is_original_target(&self) -> bool {
        self.target_inode.is_some()
            && proc_inode(&self.proc_root, self.target_pid) == self.target_inode
    }

    fn remember_pid(&mut self, pid: u32, now: Instant) {
        self.known_pids
            .insert(pid, (now, proc_inode(&self.proc_root, pid)));
    }

    fn has_recent_pid(&self, pid: u32, now: Instant) -> bool {
        self.known_pids
            .get(&pid)
            .map(|(seen, inode)| {
                // A dead child can leave a queued audit record. A live process
                // reusing its numeric PID has a different procfs inode.
                let current = proc_inode(&self.proc_root, pid);
                is_recent(*seen, now) && (current.is_none() || current == *inode)
            })
            .unwrap_or(false)
    }

    fn expire_stale_pids(&mut self, now: Instant) {
        self.known_pids.retain(|_, (seen, _)| is_recent(*seen, now));
    }

    fn process_matches_cgroup(&self, pid: u32) -> bool {
        let Some(expected) = self.cgroup_relative_path.as_deref() else {
            return false;
        };
        let cgroup_file = self.proc_root.join(pid.to_string()).join("cgroup");
        let Ok(content) = std::fs::read_to_string(cgroup_file) else {
            return false;
        };
        cgroup_content_matches_path(&content, expected)
    }

    fn process_matches_pid_namespace(&self, pid: u32) -> bool {
        let Some(target_ns) = self.target_pid_namespace.as_deref() else {
            return false;
        };
        read_pid_namespace(&self.proc_root, pid)
            .as_deref()
            .map(|pid_ns| pid_ns == target_ns)
            .unwrap_or(false)
    }
}

fn proc_inode(proc_root: &Path, pid: u32) -> Option<u64> {
    std::fs::metadata(proc_root.join(pid.to_string()))
        .ok()
        .map(|meta| meta.ino())
}

fn is_recent(seen: Instant, now: Instant) -> bool {
    now.checked_duration_since(seen)
        .map(|age| age <= DENY_SCOPE_STALE_PID_TTL)
        .unwrap_or(true)
}

fn collect_process_tree_pids(proc_root: &Path, root_pid: u32, out: &mut BTreeSet<u32>) {
    let mut stack = vec![root_pid];
    let mut visited = BTreeSet::new();

    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) {
            continue;
        }
        out.insert(pid);
        stack.extend(read_child_pids(proc_root, pid));
    }
}

fn read_child_pids(proc_root: &Path, pid: u32) -> Vec<u32> {
    let task_dir = proc_root.join(pid.to_string()).join("task");
    let Ok(entries) = std::fs::read_dir(task_dir) else {
        return Vec::new();
    };

    let mut children = Vec::new();
    for entry in entries.flatten() {
        let children_path = entry.path().join("children");
        if let Ok(content) = std::fs::read_to_string(children_path) {
            children.extend(parse_pid_list(&content));
        }
    }
    children
}

fn read_pids_from_file(path: &Path) -> Vec<u32> {
    std::fs::read_to_string(path)
        .map(|content| parse_pid_list(&content))
        .unwrap_or_default()
}

fn parse_pid_list(content: &str) -> Vec<u32> {
    content
        .split_whitespace()
        .filter_map(|pid| pid.parse::<u32>().ok())
        .collect()
}

fn read_pid_namespace(proc_root: &Path, pid: u32) -> Option<String> {
    std::fs::read_link(proc_root.join(pid.to_string()).join("ns").join("pid"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn cgroup_relative_path_from_host_path(cgroup_path: &Path) -> Option<String> {
    let root = Path::new(CGROUP_V2_ROOT);
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let canonical_path =
        std::fs::canonicalize(cgroup_path).unwrap_or_else(|_| cgroup_path.to_path_buf());
    let relative = canonical_path.strip_prefix(canonical_root).ok()?;
    Some(normalize_cgroup_path(&format!(
        "/{}",
        relative.to_string_lossy()
    )))
}

fn cgroup_content_matches_path(content: &str, expected: &str) -> bool {
    let expected = normalize_cgroup_path(expected);
    content
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path.trim()))
        .any(|actual| cgroup_path_contains(&normalize_cgroup_path(actual), &expected))
}

fn cgroup_path_contains(actual: &str, expected: &str) -> bool {
    if expected == "/" {
        return actual == "/";
    }
    actual == expected
        || actual
            .strip_prefix(expected)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn normalize_cgroup_path(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

/// Main deny-log loop – reads /dev/kmsg and emits WARN for denied syscalls.
fn deny_log_loop(pid: u32, cgroup_path: Option<PathBuf>, stop: &AtomicBool) -> Result<()> {
    let kmsg_path = std::path::Path::new("/dev/kmsg");
    if let Ok(meta) = std::fs::symlink_metadata(kmsg_path) {
        if meta.file_type().is_symlink() {
            warn!("/dev/kmsg is a symlink – refusing to open for seccomp deny logging");
            return Ok(());
        }
    }

    let file = match std::fs::File::open(kmsg_path) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "Cannot open /dev/kmsg for seccomp deny logging: {} \
                 (requires root or CAP_SYSLOG)",
                e
            );
            return Ok(());
        }
    };

    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: fd is a valid file descriptor from File::open("/dev/kmsg").
    // F_GETFL/F_SETFL only modify the file status flags; O_NONBLOCK is safe
    // to set and required for poll-based reading.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let reader = BufReader::new(file);
    let mut scope = SeccompAuditScope::new(pid, cgroup_path);
    scope.refresh(Instant::now());

    for line in reader.lines() {
        if stop.load(Ordering::Acquire) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    scope.refresh_if_stale(Instant::now());
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: pfd is a valid stack-allocated pollfd with a valid fd.
                    // poll with nfds=1 and a bounded timeout is safe; it only blocks.
                    unsafe { libc::poll(&mut pfd, 1, DENY_SCOPE_POLL_TIMEOUT_MS) };
                    continue;
                }
                debug!("kmsg read error: {}", e);
                continue;
            }
        };

        if let Some((audit_pid, nr)) = syscall_record_for_scope(&line, &mut scope, Instant::now()) {
            let name = super::seccomp_generate::syscall_number_to_name(nr).unwrap_or("unknown");
            warn!(
                syscall = nr,
                name = name,
                pid = audit_pid,
                target_pid = pid,
                "seccomp denied syscall"
            );
        }
    }

    Ok(())
}

fn syscall_record_for_scope(
    line: &str,
    scope: &mut SeccompAuditScope,
    now: Instant,
) -> Option<(u32, i64)> {
    if !line.split_whitespace().any(|field| field == "type=1326") {
        return None;
    }
    let pid = extract_audit_pid(line)?;
    if !scope.matches_pid(pid, now) {
        return None;
    }
    extract_syscall_nr(line).map(|nr| (pid, nr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_syscall_nr() {
        let line = "6,1234,5678,-;audit: type=1326 audit(123:456): auid=0 uid=0 gid=0 ses=1 pid=42 comm=\"test\" exe=\"/bin/test\" sig=0 arch=c000003e syscall=257 compat=0 ip=0x7f action=0x7fff0000";
        assert_eq!(extract_syscall_nr(line), Some(257));
    }

    #[test]
    fn test_extract_syscall_nr_missing() {
        assert_eq!(extract_syscall_nr("no syscall here"), None);
    }

    #[test]
    fn test_extract_audit_pid_ignores_ppid() {
        let line = "audit: type=1326 audit(123:456): ppid=7 pid=42 comm=\"test\" syscall=257";
        assert_eq!(extract_audit_pid(line), Some(42));
    }

    #[test]
    fn test_deny_scope_matches_forked_child_audit_pid() {
        let temp = tempfile::tempdir().unwrap();
        let target_task = temp.path().join("42/task/42");
        std::fs::create_dir_all(&target_task).unwrap();
        std::fs::write(target_task.join("children"), "43\n").unwrap();

        let mut scope =
            SeccompAuditScope::with_proc_root(42, temp.path().to_path_buf(), None, None);
        let line = "6,1234,5678,-;audit: type=1326 audit(123:456): auid=0 uid=0 gid=0 ses=1 pid=43 comm=\"probe\" exe=\"/bin/probe\" sig=31 arch=c000003e syscall=257 compat=0 ip=0x7f action=0x80000000";

        assert_eq!(
            syscall_record_for_scope(line, &mut scope, Instant::now()),
            Some((43, 257))
        );
    }

    #[test]
    fn test_trace_scope_rejects_pid_prefix_and_parent_fields() {
        let temp = tempfile::tempdir().unwrap();
        let target_task = temp.path().join("42/task/42");
        std::fs::create_dir_all(&target_task).unwrap();
        std::fs::write(target_task.join("children"), "").unwrap();

        let mut scope =
            SeccompAuditScope::with_proc_root(42, temp.path().to_path_buf(), None, None);
        let line = "6,1234,5678,-;audit: type=1326 audit(123:456): auid=0 uid=0 gid=0 ses=1 ppid=42 pid=423 comm=\"other\" exe=\"/bin/other\" sig=31 arch=c000003e syscall=257 compat=0 ip=0x7f action=0x80000000";

        assert_eq!(
            syscall_record_for_scope(line, &mut scope, Instant::now()),
            None
        );
    }

    #[test]
    fn test_deny_scope_matches_cgroup_member_audit_pid() {
        let temp = tempfile::tempdir().unwrap();
        let proc_root = temp.path().join("proc");
        let cgroup_dir = temp.path().join("cgroup");
        std::fs::create_dir_all(proc_root.join("42/task/42")).unwrap();
        std::fs::create_dir_all(proc_root.join("43")).unwrap();
        std::fs::create_dir_all(&cgroup_dir).unwrap();
        std::fs::write(proc_root.join("42/task/42/children"), "").unwrap();
        std::fs::write(cgroup_dir.join("cgroup.procs"), "43\n").unwrap();

        let mut scope = SeccompAuditScope::with_proc_root(
            42,
            proc_root,
            Some(cgroup_dir),
            Some("/nucleus-test".to_string()),
        );
        let line = "6,1234,5678,-;audit: type=1326 audit(123:456): auid=0 uid=0 gid=0 ses=1 pid=43 comm=\"probe\" exe=\"/bin/probe\" sig=31 arch=c000003e syscall=257 compat=0 ip=0x7f action=0x80000000";

        assert_eq!(
            syscall_record_for_scope(line, &mut scope, Instant::now()),
            Some((43, 257))
        );
    }

    #[test]
    fn test_cgroup_content_matches_subgroup_membership() {
        assert!(cgroup_content_matches_path(
            "0::/nucleus-test/workers\n",
            "/nucleus-test"
        ));
        assert!(!cgroup_content_matches_path(
            "0::/nucleus-other\n",
            "/nucleus-test"
        ));
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
    fn test_reader_uses_nonblocking_io() {
        // Verify record_loop uses O_NONBLOCK + poll, not socket-only APIs.
        // /dev/kmsg is a character device; socket APIs like SO_RCVTIMEO silently fail.
        // NOTE: Uses brace-matched function body extraction (SEC-MED-03).
        let source = include_str!("seccomp_trace.rs");
        let fn_body = extract_fn_body(source, "fn record_loop");
        assert!(
            extract_fn_body(source, "fn start_scoped").contains("O_NONBLOCK"),
            "record_loop must use O_NONBLOCK for non-blocking reads on /dev/kmsg"
        );
        assert!(
            fn_body.contains("libc::poll"),
            "record_loop must use poll() for timed waits on /dev/kmsg"
        );
        // setsockopt must not appear in the function (socket API doesn't work on char devices)
        let setsockopt_lines: Vec<&str> = fn_body
            .lines()
            .filter(|l| !l.trim().starts_with("//"))
            .filter(|l| l.contains("setsockopt"))
            .collect();
        assert!(
            setsockopt_lines.is_empty(),
            "record_loop must not call setsockopt on /dev/kmsg"
        );
    }

    #[test]
    fn trace_file_is_private_and_never_follows_or_replaces_existing_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trace");
        let output = create_trace_file(&path).unwrap();
        assert_eq!(
            output.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(create_trace_file(&path).is_err());
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(create_trace_file(&link).is_err());
        let dir_link = temp.path().join("directory-link");
        symlink(temp.path(), &dir_link).unwrap();
        assert!(create_trace_file(&dir_link.join("unexpected")).is_err());
        assert!(!temp.path().join("unexpected").exists());
    }

    #[test]
    fn test_trace_record_serialization() {
        let record = TraceRecord {
            syscall: 0,
            name: Some("read".to_string()),
            count: 42,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"syscall\":0"));
        assert!(json.contains("\"name\":\"read\""));
        assert!(json.contains("\"count\":42"));
    }
}
