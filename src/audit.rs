//! Structured audit logging for container lifecycle events.
//!
//! Every significant container event (start, stop, security hardening, network setup,
//! health check result, etc.) is emitted as a structured JSON event to the
//! `nucleus::audit` tracing target. This provides the minimum observability
//! required for post-incident analysis in production deployments.
//!
//! Events are written to journald via tracing's stdout integration and can be
//! filtered with `RUST_LOG=nucleus::audit=info`.

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit event types covering the full container lifecycle.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    ContainerStart,
    ContainerStop,
    ContainerExec,
    NamespaceCreated,
    CgroupCreated,
    FilesystemMounted,
    RootSwitched,
    MountAuditPassed,
    MountAuditFailed,
    CapabilitiesDropped,
    SeccompApplied,
    SeccompProfileLoaded,
    LandlockApplied,
    NoNewPrivsSet,
    NetworkBridgeSetup,
    EgressPolicyApplied,
    EgressDenied,
    HealthCheckPassed,
    HealthCheckFailed,
    HealthCheckUnhealthy,
    ReadinessProbeReady,
    ReadinessProbeFailed,
    SecretsMounted,
    InitSupervisorStarted,
    ZombieReaped,
    SignalForwarded,
    GVisorStarted,
}

/// A structured audit event emitted as JSON for post-incident analysis.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Unix epoch timestamp with millisecond precision (e.g. "1712345678.123")
    pub timestamp: String,
    /// Container ID (correlation ID for all events in a lifecycle)
    pub container_id: String,
    /// Container name
    pub container_name: String,
    /// Event type
    pub event_type: AuditEventType,
    /// Human-readable detail message
    pub detail: String,
    /// Whether this event represents a failure
    pub is_error: bool,
    /// Security posture details (populated for security-related events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_posture: Option<SecurityPosture>,
}

/// Security posture captured at container start for incident analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityPosture {
    /// Seccomp mode: "enforce", "trace", "profile:`<path>`", or "none"
    pub seccomp_mode: String,
    /// Landlock ABI version negotiated (e.g. "V5", "none")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landlock_abi: Option<String>,
    /// Capabilities that were dropped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_caps: Option<Vec<String>>,
    /// Whether gVisor was used
    pub gvisor: bool,
    /// Whether rootless mode was used
    pub rootless: bool,
}

impl AuditEvent {
    /// Create a new audit event for the given container.
    pub fn new(
        container_id: &str,
        container_name: &str,
        event_type: AuditEventType,
        detail: impl Into<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| {
                // RFC 3339 / ISO 8601 UTC timestamp for audit log interoperability.
                let total_secs = d.as_secs();
                let millis = d.subsec_millis();

                // Break epoch seconds into date/time components (no leap seconds).
                let days = total_secs / 86400;
                let day_secs = total_secs % 86400;
                let hours = day_secs / 3600;
                let minutes = (day_secs % 3600) / 60;
                let seconds = day_secs % 60;

                // Civil date from days since 1970-01-01 (Rata Die algorithm).
                let z = days as i64 + 719468;
                let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
                let doe = (z - era * 146097) as u64;
                let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                let y = yoe as i64 + era * 400;
                let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                let mp = (5 * doy + 2) / 153;
                let d = doy - (153 * mp + 2) / 5 + 1;
                let m = if mp < 10 { mp + 3 } else { mp - 9 };
                let y = if m <= 2 { y + 1 } else { y };

                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    y, m, d, hours, minutes, seconds, millis
                )
            })
            .unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".to_string());

        Self {
            timestamp,
            container_id: container_id.to_string(),
            container_name: container_name.to_string(),
            event_type,
            detail: detail.into(),
            is_error: false,
            security_posture: None,
        }
    }

    /// Mark this event as an error.
    pub fn as_error(mut self) -> Self {
        self.is_error = true;
        self
    }

    /// Attach security posture to this event.
    pub fn with_security_posture(mut self, posture: SecurityPosture) -> Self {
        self.security_posture = Some(posture);
        self
    }

    /// Emit this event to the audit log via tracing.
    pub fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|_| {
            // Avoid Debug format which could leak sensitive fields;
            // emit only the non-sensitive event envelope.
            format!(
                r#"{{"timestamp":"{}","container_id":"{}","event_type":"{:?}","detail":"[serialization failed]","is_error":{}}}"#,
                self.timestamp, self.container_id, self.event_type, self.is_error
            )
        });
        if self.is_error {
            tracing::error!(target: "nucleus::audit", "{}", json);
        } else {
            tracing::info!(target: "nucleus::audit", "{}", json);
        }
    }
}

/// Retain only the executable. Every argument, including positional values and
/// shell programs, can contain credentials.
pub fn redact_command(args: &[String]) -> Vec<String> {
    let mut display: Vec<_> = args.first().cloned().into_iter().collect();
    if args.len() > 1 {
        display.push("[REDACTED]".into());
    }
    display
}

#[cfg(test)]
#[test]
fn command_redaction_covers_positional_values_and_inline_options() {
    let args = [
        "tool",
        "username",
        "positional-value",
        "--auth=inline-value",
    ]
    .map(String::from);
    assert_eq!(redact_command(&args), ["tool", "[REDACTED]"]);
}

/// Convenience function to emit an audit event.
pub fn audit(
    container_id: &str,
    container_name: &str,
    event_type: AuditEventType,
    detail: impl Into<String>,
) {
    AuditEvent::new(container_id, container_name, event_type, detail).emit();
}

/// Convenience function to emit an audit event with security posture.
pub fn audit_with_posture(
    container_id: &str,
    container_name: &str,
    event_type: AuditEventType,
    detail: impl Into<String>,
    posture: SecurityPosture,
) {
    AuditEvent::new(container_id, container_name, event_type, detail)
        .with_security_posture(posture)
        .emit();
}

/// Convenience function to emit an error audit event.
pub fn audit_error(
    container_id: &str,
    container_name: &str,
    event_type: AuditEventType,
    detail: impl Into<String>,
) {
    AuditEvent::new(container_id, container_name, event_type, detail)
        .as_error()
        .emit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new("abc123", "test", AuditEventType::ContainerStart, "started");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("container_start"));
        assert!(json.contains("abc123"));
        // security_posture should be omitted when None
        assert!(!json.contains("security_posture"));
    }

    #[test]
    fn test_audit_event_with_security_posture() {
        let posture = SecurityPosture {
            seccomp_mode: "enforce".to_string(),
            landlock_abi: Some("V5".to_string()),
            dropped_caps: Some(vec!["CAP_SYS_ADMIN".to_string()]),
            gvisor: false,
            rootless: true,
        };
        let event = AuditEvent::new("abc123", "test", AuditEventType::ContainerStart, "started")
            .with_security_posture(posture);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("security_posture"));
        assert!(json.contains("enforce"));
        assert!(json.contains("V5"));
        assert!(json.contains("CAP_SYS_ADMIN"));
        assert!(json.contains("\"rootless\":true"));
    }

    #[test]
    fn test_audit_event_error_flag() {
        let event =
            AuditEvent::new("abc123", "test", AuditEventType::SeccompApplied, "applied").as_error();
        assert!(event.is_error);
    }
}
