#![cfg_attr(not(test), deny(clippy::unwrap_used))]

//! Extremely lightweight Docker alternative for agents and production services.
//!
//! Nucleus provides isolated execution using Linux cgroups, namespaces, seccomp,
//! Landlock, and optional gVisor integration. It implements a subset of the OCI
//! runtime spec and can be used both as a CLI tool and as a library.

pub mod audit;
pub mod checkpoint;
pub mod container;
pub mod error;
pub mod filesystem;
pub mod image;
pub mod isolation;
pub mod network;
pub mod oci;
pub mod resources;
pub mod security;
pub mod telemetry;
pub mod topology;

pub use error::{NucleusError, Result, StateTransition};
