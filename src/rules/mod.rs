//! The rule registry.
//!
//! A rule is plain data plus a `check` function pointer. All rules live in one static
//! table (`RULES`), so adding a rule means writing one function and one table entry —
//! no allocation, no registration at runtime.

mod network;
mod pod;
mod rbac;

use crate::loader::Resource;
use crate::model::{Finding, Location, Severity};
use crate::workload::Workload;

/// What a rule gets to look at.
pub struct Ctx<'a> {
    pub res: &'a Resource,
    /// Present when the resource runs pods (Pod, Deployment, CronJob, …).
    pub workload: Option<&'a Workload>,
}

pub type CheckFn = fn(&Ctx<'_>, &mut Emitter<'_>);

pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub remediation: &'static str,
    pub check: CheckFn,
}

/// Collects findings for one rule and one resource, filling in the location and
/// metadata so each rule only has to say *where* and *what*.
pub struct Emitter<'a> {
    rule: &'static Rule,
    res: &'a Resource,
    out: &'a mut Vec<Finding>,
}

impl<'a> Emitter<'a> {
    pub fn new(rule: &'static Rule, res: &'a Resource, out: &'a mut Vec<Finding>) -> Self {
        Self { rule, res, out }
    }

    /// Report a finding at the rule's default severity.
    pub fn report(
        &mut self,
        path: impl Into<String>,
        container: Option<&str>,
        message: impl Into<String>,
    ) {
        self.report_with(self.rule.severity, path, container, message);
    }

    /// Report a finding with a severity that differs from the rule default
    /// (for example, mounting `/var/run/docker.sock` is worse than mounting `/tmp`).
    pub fn report_with(
        &mut self,
        severity: Severity,
        path: impl Into<String>,
        container: Option<&str>,
        message: impl Into<String>,
    ) {
        self.out.push(Finding {
            rule_id: self.rule.id,
            severity,
            title: self.rule.title,
            message: message.into(),
            remediation: self.rule.remediation,
            location: Location {
                file: self.res.source.clone(),
                line: self.res.line,
                kind: self.res.kind.clone(),
                name: self.res.name.clone(),
                namespace: self.res.namespace.clone(),
                container: container.map(str::to_owned),
                path: path.into(),
            },
        });
    }
}

pub static RULES: &[Rule] = &[
    pod::PRIVILEGED,
    pod::PRIVILEGE_ESCALATION,
    pod::RUN_AS_ROOT,
    pod::HOST_NAMESPACES,
    pod::HOST_PATH,
    pod::DANGEROUS_CAPABILITIES,
    pod::CAPABILITIES_NOT_DROPPED,
    pod::WRITABLE_ROOT_FS,
    pod::SECCOMP,
    pod::SECRET_IN_ENV,
    pod::SERVICE_ACCOUNT_TOKEN,
    pod::IMAGE_TAG,
    pod::IMAGE_DIGEST,
    pod::MEMORY_LIMIT,
    pod::RESOURCE_REQUESTS,
    rbac::WILDCARD_PERMISSIONS,
    rbac::CLUSTER_ADMIN_BINDING,
    rbac::SECRETS_ACCESS,
    network::EXTERNAL_SERVICE,
    network::INGRESS_WITHOUT_TLS,
];

pub fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
pub(crate) mod testutil {
    use crate::loader::{Loaded, parse_text};
    use crate::model::Finding;
    use crate::model::Severity;
    use crate::scan::{ScanOptions, scan};

    /// Scan a YAML snippet with every rule enabled, down to `info`.
    pub fn findings(yaml: &str) -> Vec<Finding> {
        let mut loaded = Loaded::default();
        parse_text("test.yaml", yaml, &mut loaded);
        assert!(loaded.errors.is_empty(), "{:?}", loaded.errors);
        let report = scan(
            loaded,
            &ScanOptions {
                min_severity: Severity::Info,
                skip: vec![],
            },
        );
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        report.findings
    }

    pub fn ids(yaml: &str) -> Vec<&'static str> {
        let mut ids: Vec<_> = findings(yaml).iter().map(|f| f.rule_id).collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn rule_ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule id {}", rule.id);
            assert!(
                rule.id.starts_with("KS") && rule.id.len() == 5,
                "bad id {}",
                rule.id
            );
            assert!(!rule.description.is_empty() && !rule.remediation.is_empty());
        }
    }

    #[test]
    fn find_is_case_insensitive() {
        assert_eq!(find("ks001").map(|r| r.id), Some("KS001"));
        assert!(find("KS999").is_none());
    }
}
