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
    /// All caps fully dropped (terminal state)
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
        if self.phase != CapPhase::Initial {
            debug!("Bounding set already dropped, skipping");
            return Ok(());
        }

        info!("Phase 1: dropping bounding set and ambient/inheritable caps");

        // 1. Clear bounding set (requires CAP_SETPCAP in effective set).
        //    Prevents regaining capabilities through exec of setuid binaries.
        for cap in caps::all() {
            if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                debug!(
                    "Failed to drop bounding cap {:?}: {} (may not be present)",
                    cap, e
                );
            }
        }

        // M4: Verify the bounding set is actually empty after the drop loop
        let bounding = caps::read(None, CapSet::Bounding).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to read bounding set after drop: {}", e))
        })?;
        if !bounding.is_empty() {
            let leaked: Vec<String> = bounding.iter().map(|c| format!("{:?}", c)).collect();
            return Err(NucleusError::CapabilityError(format!(
                "Bounding set still contains capabilities after drop: [{}]",
                leaked.join(", ")
            )));
        }

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

        if self.phase == CapPhase::Initial {
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
        if self.phase == CapPhase::Dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Dropping capabilities except: {:?}", keep);

        let all_caps = caps::all();

        // 1. Drop bounding set entries FIRST (requires CAP_SETPCAP in effective).
        for cap in &all_caps {
            if !keep.contains(cap) {
                if let Err(e) = caps::drop(None, CapSet::Bounding, *cap) {
                    debug!(
                        "Failed to drop bounding cap {:?}: {} (may not be present)",
                        cap, e
                    );
                }
            }
        }

        // 2. Clear ambient set (constrained to permitted ∩ inheritable).
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        // 3. Drop from inheritable, permitted, effective for each non-kept cap.
        for cap in &all_caps {
            if !keep.contains(cap) {
                caps::drop(None, CapSet::Inheritable, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Permitted, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Effective, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;
            }
        }

        self.phase = CapPhase::Dropped;
        info!("Successfully dropped capabilities");

        Ok(())
    }

    /// Apply explicit capability sets.
    ///
    /// Bounding is handled as a drop-only upper bound; the remaining sets are
    /// set exactly to the provided values.
    pub fn apply_sets(&mut self, sets: &CapabilitySets) -> Result<()> {
        if self.phase == CapPhase::Dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Applying explicit capability sets");

        for cap in caps::all() {
            if !sets.bounding.contains(&cap) {
                if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                    debug!(
                        "Failed to drop bounding cap {:?}: {} (may not be present)",
                        cap, e
                    );
                }
            }
        }

        // M5: Set Permitted first, then Effective immediately after to avoid a
        // window where the old effective set exceeds the new permitted set.
        caps::set(None, CapSet::Permitted, &to_caps_hash_set(&sets.permitted)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set permitted caps: {}", e))
        })?;
        caps::set(None, CapSet::Effective, &to_caps_hash_set(&sets.effective)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set effective caps: {}", e))
        })?;
        caps::set(
            None,
            CapSet::Inheritable,
            &to_caps_hash_set(&sets.inheritable),
        )
        .map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set inheritable caps: {}", e))
        })?;
        caps::set(None, CapSet::Ambient, &to_caps_hash_set(&sets.ambient)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set ambient caps: {}", e))
        })?;

        self.phase = CapPhase::Dropped;
        info!("Successfully applied capability sets");
        Ok(())
    }

    /// Check if capabilities have been dropped
    pub fn is_dropped(&self) -> bool {
        self.phase == CapPhase::Dropped
    }

    /// Verify that namespace-creating capabilities are actually absent from
    /// the effective set. Seccomp blocks unshare, filters clone namespace flags,
    /// and returns ENOSYS for clone3; dropping these capabilities is the
    /// independent capability-layer guard. If the check fails in production
    /// mode, it returns an error; otherwise it emits a warning.
    pub fn verify_no_namespace_caps(production: bool) -> Result<()> {
        use caps::Capability;
        let ns_caps = [
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_NET_ADMIN,
            Capability::CAP_SYS_PTRACE,
        ];
        let effective = caps::read(None, CapSet::Effective).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to read effective caps: {}", e))
        })?;
        let mut leaked = Vec::new();
        for cap in &ns_caps {
            if effective.contains(cap) {
                leaked.push(format!("{:?}", cap));
            }
        }
        if !leaked.is_empty() {
            let msg = format!(
                "SEC-CLONE3: namespace-creating capabilities still present after drop: [{}]. \
                 seccomp denies unfilterable clone3, but these caps must still be \
                 absent for defense in depth.",
                leaked.join(", ")
            );
            if production {
                return Err(NucleusError::CapabilityError(msg));
            }
            tracing::warn!("{}", msg);
        }
        Ok(())
    }
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
