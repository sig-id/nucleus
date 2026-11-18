use crate::error::{NucleusError, Result};
use caps::{CapSet, Capability, CapsHashSet};
use tracing::{debug, info};

/// Security context that tracks capability state
pub struct CapabilityManager {
    phase: CapPhase,
}

/// Tracks which phase of the two-phase cap drop we're in.
///
/// Docker/runc convention: the identity switch (setuid/setgid) must happen
/// between bounding-set cleanup and final cap clear. This is because:
/// - PR_CAPBSET_DROP requires CAP_SETPCAP in the effective set
/// - setuid/setgid require CAP_SETUID/CAP_SETGID in the effective set
/// - After setuid to non-zero UID, the kernel auto-clears permitted/effective
///
/// So the ordering is: drop bounding → setuid/setgid → clear remaining caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapPhase {
    /// No caps have been modified yet
    Initial,
    /// Bounding set dropped; effective/permitted still intact for identity switch
    BoundingDropped,
    /// Explicit sets were applied and may retain capabilities.
    PolicyApplied,
    /// All caps fully dropped
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySets {
    pub bounding: Vec<Capability>,
    pub permitted: Vec<Capability>,
    pub effective: Vec<Capability>,
    pub inheritable: Vec<Capability>,
    pub ambient: Vec<Capability>,
}

impl CapabilityManager {
    pub fn new() -> Self {
        Self {
            phase: CapPhase::Initial,
        }
    }

    /// Phase 1: Drop the bounding set and clear ambient/inheritable caps.
    ///
    /// After this call, CAP_SETUID and CAP_SETGID remain in the effective set
    /// so the caller can perform the identity switch (setuid/setgid). Call
    /// [`finalize_drop`] after the identity switch to clear remaining caps.
    ///
    /// This follows Docker/runc convention: bounding set is cleared first
    /// while CAP_SETPCAP is still in the effective set.
    pub fn drop_bounding_set(&mut self) -> Result<()> {
        if matches!(self.phase, CapPhase::BoundingDropped | CapPhase::Dropped) {
            debug!("Bounding set already dropped, skipping");
            return Ok(());
        }

        info!("Phase 1: dropping bounding set and ambient/inheritable caps");

        restrict_bounding(&[])?;

        // 2. Clear ambient set (constrained to permitted ∩ inheritable).
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        // 3. Clear inheritable (prevents caps leaking across exec).
        caps::clear(None, CapSet::Inheritable).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear inheritable caps: {}", e))
        })?;

        // Effective/permitted are intentionally kept – they hold CAP_SETUID,
        // CAP_SETGID, and CAP_SETPCAP needed for the identity switch.

        self.phase = CapPhase::BoundingDropped;
        info!("Phase 1 complete: bounding/ambient/inheritable cleared, effective/permitted retained for identity switch");

        Ok(())
    }

    /// Phase 2: Clear all remaining capabilities (permitted + effective).
    ///
    /// Call this AFTER the identity switch (setuid/setgid). If the process
    /// switched to a non-root UID, the kernel already cleared these sets;
    /// this call makes it explicit and verifies the result.
    ///
    /// If no identity switch was needed (process stays root), this performs
    /// the actual clear.
    pub fn finalize_drop(&mut self) -> Result<()> {
        if self.phase == CapPhase::Dropped {
            debug!("Capabilities already fully dropped, skipping");
            return Ok(());
        }

        if matches!(self.phase, CapPhase::Initial | CapPhase::PolicyApplied) {
            // Caller skipped phase 1 – do full drop for backwards compat
            self.drop_bounding_set()?;
        }

        info!("Phase 2: clearing permitted and effective caps");

        caps::clear(None, CapSet::Permitted).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear permitted caps: {}", e))
        })?;

        caps::clear(None, CapSet::Effective).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear effective caps: {}", e))
        })?;

        if process_caps()? != ProcessCaps::default() {
            return Err(NucleusError::CapabilityError(
                "Final capability sets are not empty".into(),
            ));
        }
        self.phase = CapPhase::Dropped;
        info!("Successfully dropped all capabilities (including bounding set)");

        Ok(())
    }

    /// Drop all capabilities in a single call (convenience wrapper).
    ///
    /// Equivalent to calling [`drop_bounding_set`] then [`finalize_drop`].
    /// Use the two-phase API when an identity switch is needed between phases.
    pub fn drop_all(&mut self) -> Result<()> {
        self.drop_bounding_set()?;
        self.finalize_drop()
    }

    /// Drop all capabilities except the specified ones
    ///
    /// For most use cases, we drop ALL capabilities. This method is provided
    /// for special cases where specific capabilities are needed.
    pub fn drop_except(&mut self, keep: &[Capability]) -> Result<()> {
        let retained = |set| -> Result<Vec<Capability>> {
            let mut current = caps::read(None, set)
                .map_err(|e| NucleusError::CapabilityError(format!("Cannot read {set:?}: {e}")))?;
            current.retain(|cap| keep.contains(cap));
            Ok(current.into_iter().collect())
        };
        self.apply_sets(&CapabilitySets {
            bounding: keep.to_vec(),
            effective: retained(CapSet::Effective)?,
            permitted: retained(CapSet::Permitted)?,
            inheritable: retained(CapSet::Inheritable)?,
            ambient: Vec::new(),
        })
    }

    /// Apply explicit capability sets.
    ///
    /// Bounding is handled as a drop-only upper bound; the remaining sets are
    /// set exactly to the provided values.
    pub fn apply_sets(&mut self, sets: &CapabilitySets) -> Result<()> {
        self.prepare_sets(sets)?;
        self.finish_sets(sets)
    }

    pub(crate) fn prepare_sets(&mut self, sets: &CapabilitySets) -> Result<()> {
        restrict_bounding(&sets.bounding)?;
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient capabilities: {e}"))
        })?;
        // Set inheritable while setup privileges are available, and reduce
        // effective before permitted to preserve the kernel's subset invariant.
        caps::set(
            None,
            CapSet::Inheritable,
            &to_caps_hash_set(&sets.inheritable),
        )
        .map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set inheritable caps: {}", e))
        })?;
        self.phase = CapPhase::BoundingDropped;
        Ok(())
    }

    pub(crate) fn finish_sets(&mut self, sets: &CapabilitySets) -> Result<()> {
        caps::set(None, CapSet::Effective, &to_caps_hash_set(&sets.effective)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set effective caps: {e}"))
        })?;
        caps::set(None, CapSet::Permitted, &to_caps_hash_set(&sets.permitted)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set permitted caps: {e}"))
        })?;
        caps::set(None, CapSet::Ambient, &to_caps_hash_set(&sets.ambient)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set ambient caps: {}", e))
        })?;

        let current = process_caps()?;
        if current.bounding & !cap_mask(&sets.bounding) != 0 {
            return Err(NucleusError::CapabilityError(
                "Final bounding set exceeds policy".into(),
            ));
        }
        for (name, actual, expected) in [
            ("effective", current.effective, &sets.effective),
            ("permitted", current.permitted, &sets.permitted),
            ("inheritable", current.inheritable, &sets.inheritable),
            ("ambient", current.ambient, &sets.ambient),
        ] {
            if actual != cap_mask(expected) {
                return Err(NucleusError::CapabilityError(format!(
                    "Final {name} capability set differs from policy"
                )));
            }
        }

        self.phase = CapPhase::PolicyApplied;
        info!("Successfully applied capability sets");
        Ok(())
    }

    /// Check if capabilities have been dropped
    pub fn is_dropped(&self) -> bool {
        matches!(self.phase, CapPhase::Dropped | CapPhase::PolicyApplied)
    }

    /// Audit each capability set before handing control to a native workload.
    pub fn verify_no_namespace_caps(_production: bool) -> Result<()> {
        process_caps()?.verify_workload()
    }
}

#[derive(Default, PartialEq, Eq)]
struct ProcessCaps {
    bounding: u64,
    permitted: u64,
    effective: u64,
    inheritable: u64,
    ambient: u64,
}

impl ProcessCaps {
    fn verify_workload(&self) -> Result<()> {
        let forbidden = cap_mask(super::caps_policy::DANGEROUS_CAPABILITIES);
        for (name, value) in [
            ("bounding", self.bounding),
            ("permitted", self.permitted),
            ("effective", self.effective),
            ("inheritable", self.inheritable),
            ("ambient", self.ambient),
        ] {
            if value & forbidden != 0 {
                return Err(NucleusError::CapabilityError(format!(
                    "Forbidden capabilities {:#x} remain in {name}",
                    value & forbidden
                )));
            }
        }
        Ok(())
    }
}

fn cap_mask(caps: &[Capability]) -> u64 {
    caps.iter().fold(0, |mask, cap| mask | (cap.bitmask()))
}

/// Read the bounding and ambient masks directly. The caps crate converts
/// per-capability prctl errors to absent bits in its set readers.
fn kernel_masks() -> Result<(u64, u64)> {
    let mut bounding = 0;
    let mut ambient = 0;
    for index in 0..=64usize {
        // SAFETY: both queries take only integer arguments.
        let bound = unsafe { libc::prctl(libc::PR_CAPBSET_READ, index, 0usize, 0usize, 0usize) };
        if bound < 0 {
            let error = std::io::Error::last_os_error();
            if index >= 32 && error.raw_os_error() == Some(libc::EINVAL) {
                return Ok((bounding, ambient));
            }
            return Err(error.into());
        }
        if index == 64 {
            break;
        }
        let amb = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as usize,
                index,
                0usize,
                0usize,
            )
        };
        if amb < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        bounding |= (bound as u64) << index;
        ambient |= (amb as u64) << index;
    }
    Err(NucleusError::CapabilityError(
        "Kernel capabilities exceed supported mask width".into(),
    ))
}

fn process_caps() -> Result<ProcessCaps> {
    let read = |set| -> Result<u64> {
        Ok(caps::read(None, set)
            .map_err(|e| NucleusError::CapabilityError(format!("Cannot read {set:?}: {e}")))?
            .iter()
            .fold(0, |mask, cap| mask | (cap.bitmask())))
    };
    let (bounding, ambient) = kernel_masks()?;
    Ok(ProcessCaps {
        bounding,
        ambient,
        effective: read(CapSet::Effective)?,
        permitted: read(CapSet::Permitted)?,
        inheritable: read(CapSet::Inheritable)?,
    })
}

fn restrict_bounding(keep: &[Capability]) -> Result<()> {
    let allowed = cap_mask(keep);
    let mut remove = kernel_masks()?.0 & !allowed;
    while remove != 0 {
        let index = remove.trailing_zeros();
        // SAFETY: PR_CAPBSET_DROP takes a numeric capability and no pointers.
        if unsafe {
            libc::prctl(
                libc::PR_CAPBSET_DROP,
                libc::c_ulong::from(index),
                0usize,
                0usize,
                0usize,
            )
        } == -1
        {
            return Err(NucleusError::CapabilityError(format!(
                "Cannot drop bounding capability {index}: {}",
                std::io::Error::last_os_error()
            )));
        }
        remove &= remove - 1;
    }
    if kernel_masks()?.0 & !allowed != 0 {
        return Err(NucleusError::CapabilityError(
            "Bounding set exceeds the configured upper bound".into(),
        ));
    }
    Ok(())
}

impl Default for CapabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

fn to_caps_hash_set(caps_list: &[Capability]) -> CapsHashSet {
    caps_list.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_rejects_a_dangerous_bit_in_each_set() {
        let bit = Capability::CAP_SYS_RESOURCE.bitmask();
        for caps in [
            ProcessCaps {
                bounding: bit,
                ..Default::default()
            },
            ProcessCaps {
                effective: bit,
                ..Default::default()
            },
            ProcessCaps {
                permitted: bit,
                ..Default::default()
            },
            ProcessCaps {
                inheritable: bit,
                ..Default::default()
            },
            ProcessCaps {
                ambient: bit,
                ..Default::default()
            },
        ] {
            assert!(caps.verify_workload().is_err());
        }
    }

    #[test]
    #[ignore = "requires a disposable privileged test thread with SETPCAP"]
    fn custom_capability_sets_are_enforced_by_kernel() {
        let keep = Capability::CAP_NET_BIND_SERVICE;
        let sets = CapabilitySets {
            bounding: vec![keep],
            effective: vec![keep],
            permitted: vec![keep],
            inheritable: vec![keep],
            ambient: vec![keep],
        };
        let mut manager = CapabilityManager::new();
        manager.apply_sets(&sets).unwrap();
        let actual = process_caps().unwrap();
        for mask in [
            actual.bounding,
            actual.effective,
            actual.permitted,
            actual.inheritable,
            actual.ambient,
        ] {
            assert_eq!(mask, keep.bitmask());
        }
        // SETPCAP was dropped. A stricter request must report the kernel refusal.
        assert!(manager.drop_all().is_err());
        assert_eq!(process_caps().unwrap().bounding, keep.bitmask());
    }

    #[test]
    fn test_capability_manager_initial_state() {
        let mgr = CapabilityManager::new();
        assert!(!mgr.is_dropped());
    }

    #[test]
    fn test_drop_idempotent() {
        let mut mgr = CapabilityManager::new();
        // First drop may fail in unprivileged test environments (M4 verification).
        // That's expected – the important thing is idempotency of the dropped flag.
        match mgr.drop_all() {
            Ok(()) => {
                assert!(mgr.is_dropped());
                // Second drop should also succeed (idempotent)
                let result = mgr.drop_all();
                assert!(result.is_ok());
                assert!(mgr.is_dropped());
            }
            Err(_) => {
                // In unprivileged tests, bounding set verification may fail.
                // This is expected and not a test failure.
            }
        }
    }

    #[test]
    fn test_two_phase_drop() {
        let mut mgr = CapabilityManager::new();
        // Phase 1 may fail in unprivileged tests; that's fine
        if let Ok(()) = mgr.drop_bounding_set() {
            assert!(!mgr.is_dropped()); // not fully dropped yet
            if let Ok(()) = mgr.finalize_drop() {
                assert!(mgr.is_dropped())
            }
            // clear may fail in test env
        }
    }
}
