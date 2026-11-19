use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum NucleusError {
    #[error("Failed to create namespace: {0}")]
    NamespaceError(String),

    #[error("Failed to configure cgroup: {0}")]
    CgroupError(String),

    #[error("Failed to mount filesystem: {0}")]
    FilesystemError(String),

    #[error("Failed to pivot root: {0}")]
    PivotRootError(String),

    #[error("Failed to populate context: {0}")]
    ContextError(String),

    #[error("Failed to drop capabilities: {0}")]
    CapabilityError(String),

    #[error("Failed to apply seccomp filter: {0}")]
    SeccompError(String),

    #[error("Failed to apply Landlock policy: {0}")]
    LandlockError(String),

    #[error("Invalid resource limit: {0}")]
    InvalidResourceLimit(String),

    #[error("Resource error: {0}")]
    ResourceError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid path: {path:?}")]
    InvalidPath { path: PathBuf },

    #[error("Process execution failed: {0}")]
    ExecError(String),

    #[error("Start gate closed without a release byte: {0}")]
    StartGateClosed(String),

    #[error("gVisor runtime error: {0}")]
    GVisorError(String),

    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Ambiguous container reference: {0}")]
    AmbiguousContainer(String),

    #[error("Checkpoint error: {0}")]
    CheckpointError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Attach error: {0}")]
    AttachError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Container not running: {0}")]
    ContainerNotRunning(String),

    #[error("Syscall error: {0}")]
    SyscallError(#[from] nix::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid state transition: from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("OCI hook failed: {0}")]
    HookError(String),

    #[error("JSON serialization error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, NucleusError>;

/// Common trait for all state machine enums.
///
/// Each subsystem (filesystem, security, resources, isolation, network, checkpoint)
/// defines its own state enum with domain-specific transition rules. This trait
/// provides the shared `transition()` method so each enum only needs to implement
/// `can_transition_to()`.
pub trait StateTransition: std::fmt::Debug + Sized {
    /// Return `true` if moving from `self` to `next` is a valid transition.
    fn can_transition_to(&self, next: &Self) -> bool;

    /// Return `true` if this state is terminal (no forward transitions).
    fn is_terminal(&self) -> bool;

    /// Attempt to transition, returning `Err(InvalidStateTransition)` on failure.
    fn transition(self, next: Self) -> Result<Self> {
        if self.can_transition_to(&next) {
            Ok(next)
        } else {
            Err(NucleusError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            })
        }
    }
}
