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
    /// supervisor is gone.
    ///
    /// After an orderly teardown the cgroup no longer exists and the reaper
    /// exits without doing anything. It is double-forked so the supervisor
    /// never has to reap it, and it keeps none of the supervisor's
    /// descriptors: holding the workload's stdout open would stall a caller
    /// waiting for end-of-file.
    pub(crate) fn spawn_cgroup_reaper(&self, cgroup: &Path) -> Result<()> {
        let invalid =
            || NucleusError::CgroupError(format!("Cannot watch cgroup {cgroup:?} for cleanup"));
        let parent = cgroup.parent().ok_or_else(invalid)?;
        let name = CString::new(cgroup.file_name().ok_or_else(invalid)?.as_bytes())
            .map_err(|_| invalid())?;
        let dir_flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let fds = ReaperFds {
            lifeline: self.read.as_raw_fd(),
            cgroup: open(cgroup, dir_flags | OFlag::O_NOFOLLOW, Mode::empty())?,
            parent: open(parent, dir_flags, Mode::empty())?,
            null: open("/dev/null", OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())?,
        };

        // SAFETY: the caller has asserted this process is single-threaded,
        // and the child only issues raw system calls before `_exit`.
        match unsafe { fork() }? {
            ForkResult::Child => {
                // SAFETY: as above; the intermediate exits immediately so the
                // reaper is reparented away from the supervisor.
                match unsafe { libc::fork() } {
                    0 => fds.run(&name),
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
}

impl ReaperFds {
    /// Body of the reaper process. Runs after `fork`, so it sticks to raw
    /// system calls and never allocates.
    fn run(self, name: &CString) -> ! {
        const LIFELINE: RawFd = 3;
        const CGROUP: RawFd = 4;
        const PARENT: RawFd = 5;
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
            if lifeline < 0 || cgroup < 0 || parent < 0 {
                libc::_exit(1);
            }
            libc::dup2(lifeline, LIFELINE);
            libc::dup2(cgroup, CGROUP);
            libc::dup2(parent, PARENT);
            if libc::syscall(libc::SYS_close_range, PARENT + 1, u32::MAX, 0) != 0 {
                for fd in PARENT + 1..1024 {
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
            libc::_exit(0)
        }
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
        assert!(supervisor_is_gone(keep_read.as_raw_fd()));
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
        lifeline.spawn_cgroup_reaper(&cgroup).unwrap();
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
        lifeline.spawn_cgroup_reaper(&cgroup).unwrap();
        drop(lifeline);
        assert!(wait_until(|| std::fs::read(&kill).is_ok_and(|v| v == b"1")));
    }

    #[test]
    fn die_with_supervisor_is_inert_outside_a_container_child() {
        // No lifeline was adopted in the test process: nothing is armed.
        die_with_supervisor().unwrap();
        assert_eq!(nix::sys::prctl::get_pdeathsig().unwrap(), None);
    }
}
