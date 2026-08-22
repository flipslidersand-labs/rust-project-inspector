//! `audit-bridge` — surface RustSec advisories collected from `cargo audit`.
//!
//! The actual `cargo audit` invocation happens in `rpi-collect` (a side effect);
//! this inspection only formats [`Context::audit`], staying pure per the
//! [`Inspection`] contract. Empty unless collection ran with audit enabled.

use rpi_core::{Context, Finding, Inspection, Location, Severity};

pub struct AuditBridge;

impl AuditBridge {
    pub const NAME: &'static str = "audit-bridge";
}

impl Inspection for AuditBridge {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        ctx.audit
            .iter()
            .map(|v| Finding {
                inspection: Self::NAME,
                severity: Severity::Error,
                location: Location::default(),
                message: format!("{}: {} {} — {}", v.id, v.package, v.version, v.title),
                metric: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::AuditVuln;

    fn ctx(audit: Vec<AuditVuln>) -> Context {
        Context {
            audit,
            ..Default::default()
        }
    }

    #[test]
    fn emits_one_error_per_vuln() {
        let f = AuditBridge.run(&ctx(vec![AuditVuln {
            id: "RUSTSEC-2021-0001".into(),
            package: "bad".into(),
            version: "1.0.0".into(),
            title: "boom".into(),
        }]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0].message.contains("RUSTSEC-2021-0001"));
    }

    #[test]
    fn no_audit_data_yields_nothing() {
        assert!(AuditBridge.run(&ctx(Vec::new())).is_empty());
    }
}
