//! Ties a container's lifetime to the supervisor that launched it.
//!
//! The supervisor normally tears the container down itself. If it is killed
//! outright (SIGKILL, OOM) it runs no cleanup, and the workload used to live
//! on as an orphan. Two mechanisms close that gap:
//!
//! * every setup process between the supervisor and the workload arms
//!   `PR_SET_PDEATHSIG(SIGKILL)`, so the kernel takes the container's init
//!   down with the supervisor (and the PID namespace with its init);
//! * a small reaper process outlives the supervisor and, once it is gone,
//!   kills and removes the container cgroup. This catches anything the
//!   signal chain cannot reach: processes outside the PID namespace, and
//!   helpers that reset their parent-death signal.
//!
//! Both hang off one pipe. The supervisor holds the only write end for as
//! long as it lives; end-of-file on the read end means it is gone.

use crate::error::{NucleusError, Result};
use nix::fcntl::{open, OFlag};
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use std::ffi::CString;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

/// Read end of the lifeline in a container setup process, or -1.
static SUPERVISOR_LINK: AtomicI32 = AtomicI32::new(-1);

/// How long the reaper waits for a killed cgroup to drain before giving up.
const REAPER_REMOVE_ATTEMPTS: u32 = 500;
const REAPER_REMOVE_INTERVAL_NS: libc::c_long = 10_000_000;
/// Directory depth the reaper descends into when removing a state tree.
const REAPER_TREE_DEPTH: u32 = 32;

/// A directory tree the reaper removes once the container is gone, named by
/// its parent and a single path component.
pub(crate) struct ReapedTree<'a> {
    pub parent: &'a Path,
    pub name: &'a std::ffi::OsStr,
}

/// A pipe whose write end marks the supervisor as alive.
pub(crate) struct Lifeline {
    read: OwnedFd,
    write: OwnedFd,
}

impl Lifeline {
    pub(crate) fn new() -> Result<Self> {
        let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| {
            NucleusError::ExecError(format!("Failed to create supervisor lifeline: {e}"))
        })?;
        Ok(Self { read, write })
    }

    /// Supervisor side: keep the returned descriptor open until the container
    /// has been torn down.
    pub(crate) fn hold(self) -> OwnedFd {
        self.write
    }

    /// Container side, right after the fork: give up the write end so only
    /// the supervisor keeps the pipe open, and remember the read end for
    /// [`die_with_supervisor`].
    pub(crate) fn adopt_in_child(self) {
        drop(self.write);
        SUPERVISOR_LINK.store(self.read.into_raw_fd(), Ordering::Relaxed);
    }

    /// Fork a detached reaper that kills and removes `cgroup` once the
    /// supervisor is gone, then removes `state` (the gVisor state and bundle
    /// directory), which need not exist yet.
    ///
    /// After an orderly teardown the cgroup no longer exists and the reaper
    /// exits without doing anything. It is double-forked so the supervisor
    /// never has to reap it, and it keeps none of the supervisor's
    /// descriptors: holding the workload's stdout open would stall a caller
    /// waiting for end-of-file.
    pub(crate) fn spawn_cgroup_reaper(
        &self,
        cgroup: &Path,
        state: Option<ReapedTree<'_>>,
    ) -> Result<()> {
        let invalid =
            || NucleusError::CgroupError(format!("Cannot watch cgroup {cgroup:?} for cleanup"));
        let parent = cgroup.parent().ok_or_else(invalid)?;
        let name = CString::new(cgroup.file_name().ok_or_else(invalid)?.as_bytes())
            .map_err(|_| invalid())?;
        let state_name = state
            .as_ref()
            .map(|tree| {
                let name = tree.name.as_bytes();
                if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
                    return Err(NucleusError::CgroupError(format!(
                        "Invalid state directory name {:?}",
                        tree.name
                    )));
                }
                CString::new(name).map_err(|_| invalid())
            })
            .transpose()?;
        let dir_flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let fds = ReaperFds {
            lifeline: self.read.as_raw_fd(),
            cgroup: open(cgroup, dir_flags | OFlag::O_NOFOLLOW, Mode::empty())?,
            parent: open(parent, dir_flags, Mode::empty())?,
            null: open("/dev/null", OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())?,
            state_parent: state
                .map(|tree| open(tree.parent, dir_flags, Mode::empty()))
                .transpose()?,
        };

        // SAFETY: the caller has asserted this process is single-threaded,
        // and the child only issues raw system calls before `_exit`.
        match unsafe { fork() }? {
            ForkResult::Child => {
                // SAFETY: as above; the intermediate exits immediately so the
                // reaper is reparented away from the supervisor.
                match unsafe { libc::fork() } {
                    0 => fds.run(&name, state_name.as_deref()),
                    pid => unsafe { libc::_exit(if pid > 0 { 0 } else { 1 }) },
                }
            }
            ForkResult::Parent { child } => loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => return Ok(()),
                    Err(nix::errno::Errno::EINTR) => continue,
                    other => {
                        return Err(NucleusError::CgroupError(format!(
                            "Failed to start cgroup reaper: {other:?}"
                        )))
                    }
                }
            },
        }
    }
}

struct ReaperFds {
    lifeline: RawFd,
    cgroup: OwnedFd,
    parent: OwnedFd,
    null: OwnedFd,
    state_parent: Option<OwnedFd>,
}

impl ReaperFds {
    /// Body of the reaper process. Runs after `fork`, so it sticks to raw
    /// system calls and never allocates.
    fn run(self, name: &CString, state_name: Option<&std::ffi::CStr>) -> ! {
        const LIFELINE: RawFd = 3;
        const CGROUP: RawFd = 4;
        const PARENT: RawFd = 5;
        const STATE_PARENT: RawFd = 6;
        // SAFETY: every call below operates on descriptors this process owns
        // or on constant, NUL-terminated strings.
        unsafe {
            // A signal aimed at the supervisor's process group or session
            // must not take the reaper down with it.
            libc::setsid();
            for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGPIPE] {
                libc::signal(signal, libc::SIG_IGN);
            }
            libc::prctl(libc::PR_SET_NAME, c"nucleus-reaper".as_ptr());

            for stdio in 0..=2 {
                libc::dup2(self.null.as_raw_fd(), stdio);
            }
            // Lift the three descriptors clear of their targets before
            // renumbering, then drop everything else that was inherited.
            let lifeline = libc::fcntl(self.lifeline, libc::F_DUPFD, 16);
            let cgroup = libc::fcntl(self.cgroup.as_raw_fd(), libc::F_DUPFD, 16);
            let parent = libc::fcntl(self.parent.as_raw_fd(), libc::F_DUPFD, 16);
            let state_parent = match &self.state_parent {
                Some(fd) => libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, 16),
                None => libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY),
            };
            if lifeline < 0 || cgroup < 0 || parent < 0 || state_parent < 0 {
                libc::_exit(1);
            }
            libc::dup2(lifeline, LIFELINE);
            libc::dup2(cgroup, CGROUP);
            libc::dup2(parent, PARENT);
            libc::dup2(state_parent, STATE_PARENT);
            if libc::syscall(libc::SYS_close_range, STATE_PARENT + 1, u32::MAX, 0) != 0 {
                for fd in STATE_PARENT + 1..1024 {
                    libc::close(fd);
                }
            }

            // Nothing is ever written: read returns only at end-of-file,
            // which is the supervisor's last descriptor closing.
            let mut byte = 0u8;
            loop {
                let n = libc::read(LIFELINE, (&raw mut byte).cast(), 1);
                if n == 0 || (n < 0 && *libc::__errno_location() != libc::EINTR) {
                    break;
                }
            }

            let kill = libc::openat(
                CGROUP,
                c"cgroup.kill".as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            );
            if kill >= 0 {
                libc::write(kill, c"1".as_ptr().cast(), 1);
                libc::close(kill);
            }
            // Removal succeeds once the killed processes have been reaped.
            let pause = libc::timespec {
                tv_sec: 0,
                tv_nsec: REAPER_REMOVE_INTERVAL_NS,
            };
            for _ in 0..REAPER_REMOVE_ATTEMPTS {
                if libc::unlinkat(PARENT, name.as_ptr(), libc::AT_REMOVEDIR) == 0
                    || *libc::__errno_location() != libc::EBUSY
                {
                    break;
                }
                libc::nanosleep(&pause, std::ptr::null_mut());
            }
            // The sandbox and gofer were in the cgroup and are gone; their
            // state and bundle directory is not, and would pile up on a tmpfs.
            if let Some(state_name) = state_name {
                remove_tree(STATE_PARENT, state_name.as_ptr(), REAPER_TREE_DEPTH);
            }
            libc::_exit(0)
        }
    }
}

/// Remove `name` below the directory `parent` and everything under it,
/// using raw system calls only so it can run after `fork`. Symlinks are
/// removed, never followed, and the walk stops `depth` levels down.
///
/// # Safety
///
/// `name` must point to a NUL-terminated string valid for the call.
unsafe fn remove_tree(parent: RawFd, name: *const libc::c_char, depth: u32) {
    // SAFETY: the caller guarantees `name`; every other pointer refers to a
    // local buffer that outlives the call using it.
    unsafe {
        if libc::unlinkat(parent, name, 0) == 0 || *libc::__errno_location() != libc::EISDIR {
            return;
        }
        if depth == 0 {
            return;
        }
        let dir = libc::openat(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        );
        if dir < 0 {
            return;
        }
        let mut buffer = [0u8; 4096];
        loop {
            let len = libc::syscall(libc::SYS_getdents64, dir, buffer.as_mut_ptr(), buffer.len());
            if len <= 0 {
                break;
            }
            let mut offset = 0usize;
            while offset < len as usize {
                // linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
                let entry = buffer.as_ptr().add(offset);
                let reclen = u16::from_ne_bytes([*entry.add(16), *entry.add(17)]) as usize;
                let child = entry.add(19).cast::<libc::c_char>();
                let dot = *child == b'.' as libc::c_char
                    && (*child.add(1) == 0
                        || (*child.add(1) == b'.' as libc::c_char && *child.add(2) == 0));
                if !dot {
                    remove_tree(dir, child, depth - 1);
                }
                if reclen == 0 {
                    break;
                }
                offset += reclen;
            }
        }
        libc::close(dir);
        libc::unlinkat(parent, name, libc::AT_REMOVEDIR);
    }
}

/// Arrange for this process to be killed when its parent dies.
///
/// A no-op outside a container setup process. The kernel clears the setting
/// whenever the process changes credentials, so this is called again after
/// each identity switch on the way to the workload. The setting only covers
/// deaths that happen after the call; the lifeline check covers a supervisor
/// that was already gone, in which case the process exits here.
pub(crate) fn die_with_supervisor() -> Result<()> {
    let link = SUPERVISOR_LINK.load(Ordering::Relaxed);
    if link < 0 {
        return Ok(());
    }
    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| {
        NucleusError::ExecError(format!("Failed to set the parent-death signal: {e}"))
    })?;
    if supervisor_is_gone(link) {
        std::process::exit(1);
    }
    Ok(())
}

fn supervisor_is_gone(link: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd: link,
        events: 0,
        revents: 0,
    };
    // SAFETY: `poll` points to one valid pollfd for the duration of the call.
    let ready = unsafe { libc::poll(&mut poll, 1, 0) };
    ready > 0 && poll.revents & libc::POLLHUP != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifeline_reports_hangup_only_after_the_last_writer_closes() {
        let lifeline = Lifeline::new().unwrap();
        let read = lifeline.read.as_raw_fd();
        assert!(!supervisor_is_gone(read));
        let keep_read = lifeline.read.try_clone().unwrap();
        drop(lifeline.hold());
        // A test forking concurrently can hold a copy of the write end until
        // its child closes descriptors or exits.
        assert!(wait_until(|| supervisor_is_gone(keep_read.as_raw_fd())));
    }

    fn wait_until(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if done() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn reaper_removes_the_cgroup_once_the_supervisor_is_gone() {
        // A plain directory stands in for an already-empty cgroup.
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("nucleus-test");
        std::fs::create_dir(&cgroup).unwrap();

        let lifeline = Lifeline::new().unwrap();
        lifeline.spawn_cgroup_reaper(&cgroup, None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(cgroup.exists(), "reaper must wait for the supervisor");

        drop(lifeline);
        assert!(wait_until(|| !cgroup.exists()));
    }

    #[test]
    fn reaper_kills_the_cgroup_before_removing_it() {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("nucleus-test");
        std::fs::create_dir(&cgroup).unwrap();
        let kill = cgroup.join("cgroup.kill");
        std::fs::write(&kill, b"").unwrap();

        let lifeline = Lifeline::new().unwrap();
        lifeline.spawn_cgroup_reaper(&cgroup, None).unwrap();
        drop(lifeline);
        assert!(wait_until(|| std::fs::read(&kill).is_ok_and(|v| v == b"1")));
    }

    #[test]
    fn reaper_removes_the_state_tree_without_following_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("nucleus-test");
        std::fs::create_dir(&cgroup).unwrap();
        let base = root.path().join("nucleus-gvisor");
        std::fs::create_dir(&base).unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"x").unwrap();

        let lifeline = Lifeline::new().unwrap();
        // The state directory is created after the reaper starts.
        lifeline
            .spawn_cgroup_reaper(
                &cgroup,
                Some(ReapedTree {
                    parent: &base,
                    name: std::ffi::OsStr::new("abc"),
                }),
            )
            .unwrap();
        let state = base.join("abc");
        let deep = state.join("bundle/rootfs/a/b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file"), b"x").unwrap();
        std::fs::write(state.join("runsc.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&outside, state.join("bundle/escape")).unwrap();
        // Enough entries to need several getdents64 batches.
        for i in 0..300 {
            std::fs::write(state.join(format!("entry-with-a-long-name-{i:04}")), b"").unwrap();
        }

        drop(lifeline);
        assert!(wait_until(|| !state.exists()));
        assert!(base.exists(), "only the named tree is removed");
        assert!(outside.join("keep").exists(), "symlinks are not followed");
    }

    #[test]
    fn reaper_rejects_state_names_that_are_not_one_component() {
        let root = tempfile::tempdir().unwrap();
        let cgroup = root.path().join("nucleus-test");
        std::fs::create_dir(&cgroup).unwrap();
        let lifeline = Lifeline::new().unwrap();
        for name in ["", ".", "..", "a/b"] {
            let tree = ReapedTree {
                parent: root.path(),
                name: std::ffi::OsStr::new(name),
            };
            assert!(lifeline.spawn_cgroup_reaper(&cgroup, Some(tree)).is_err());
        }
    }

    #[test]
    fn die_with_supervisor_is_inert_outside_a_container_child() {
        // No lifeline was adopted in the test process: nothing is armed.
        die_with_supervisor().unwrap();
        assert_eq!(nix::sys::prctl::get_pdeathsig().unwrap(), None);
    }
}
