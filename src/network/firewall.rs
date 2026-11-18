use super::{netns::Namespaces, BridgeNetwork};
use crate::error::{NucleusError, Result};
use std::io::{Seek, Write};
use std::process::Command;

/// A single nft input batch commits atomically or leaves the old rules intact.
pub(super) fn transact(ns: Option<&Namespaces>, rules: &str) -> Result<()> {
    let nft = BridgeNetwork::resolve_bin("nft")?;
    let mut command = match ns {
        Some(ns) => ns.command(&nft)?,
        None => Command::new(&nft),
    };
    let mut input = tempfile::tempfile()?;
    input.write_all(rules.as_bytes())?;
    input.rewind()?;
    let output = command
        .env_clear()
        .args(["-f", "-"])
        .stdin(input)
        .output()?;
    if !output.status.success() {
        return Err(NucleusError::NetworkError(format!(
            "nft firewall transaction: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
