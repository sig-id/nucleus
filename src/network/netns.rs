//! Pin both namespace handles from one proc directory before touching the network.
use crate::error::{NucleusError, Result};
use nix::sched::{setns, CloneFlags};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(super) struct Namespaces {
    pub net: File,
    pub user: Option<File>,
    pub mapped_root: Option<u32>,
}

impl Namespaces {
    pub fn open(pid: u32, user: bool) -> Result<Self> {
        let proc = File::open(format!("/proc/{pid}"))?;
        let directory = format!("/proc/self/fd/{}", proc.as_raw_fd());
        let net = File::open(format!("{directory}/ns/net"))?;
        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
        let target = net.metadata()?;
        if (current.dev(), current.ino()) == (target.dev(), target.ino()) {
            return Err(NucleusError::NetworkError(
                "Bridge networking requires a private workload network namespace".into(),
            ));
        }
        let user = user
            .then(|| File::open(format!("{directory}/ns/user")))
            .transpose()?;
        let mapped_root = if let Some(ns) = &user {
            let current = std::fs::metadata("/proc/thread-self/ns/user")?;
            let target = ns.metadata()?;
            if (current.dev(), current.ino()) == (target.dev(), target.ino()) {
                return Err(NucleusError::NetworkError(
                    "Expected a separate workload user namespace".into(),
                ));
            }
            let map = std::fs::read_to_string(format!("{directory}/uid_map"))?;
            Some(
                map.lines()
                    .find_map(|line| {
                        let mut fields = line.split_whitespace();
                        (fields.next()? == "0")
                            .then(|| fields.next()?.parse::<u32>().ok())
                            .flatten()
                    })
                    .filter(|uid| *uid != 0)
                    .ok_or_else(|| {
                        NucleusError::NetworkError(
                            "Workload UID 0 must map to a nonzero host UID".into(),
                        )
                    })?,
            )
        } else {
            None
        };
        Ok(Self {
            net,
            user,
            mapped_root,
        })
    }

    pub fn enter_user(&self) -> std::io::Result<()> {
        if let Some(user) = &self.user {
            if Uid::effective().is_root() {
                nix::unistd::setgroups(&[])?;
            }
            setns(user, CloneFlags::CLONE_NEWUSER)?;
            let gid = Gid::from_raw(0);
            let uid = Uid::from_raw(0);
            setresgid(gid, gid, gid)?;
            setresuid(uid, uid, uid)?;
        }
        Ok(())
    }

    pub fn command(&self, program: &str) -> Result<Command> {
        let net = self.net.try_clone()?;
        let user = self.user.as_ref().map(File::try_clone).transpose()?;
        let ns = Self {
            net,
            user,
            mapped_root: self.mapped_root,
        };
        let mut command = Command::new(program);
        command.env_clear();
        // Only namespace and credential syscalls run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                ns.enter_user()?;
                setns(&ns.net, CloneFlags::CLONE_NEWNET)?;
                Ok(())
            });
        }
        Ok(command)
    }

    pub fn configure<F>(&self, configure: F) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send,
    {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    setns(&self.net, CloneFlags::CLONE_NEWNET).map_err(|e| {
                        NucleusError::NetworkError(format!("enter pinned network namespace: {e}"))
                    })?;
                    configure()
                })
                .join()
                .map_err(|_| NucleusError::NetworkError("netns worker panicked".into()))?
        })
    }
}
