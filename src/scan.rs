//! The scan engine: run every enabled rule against every resource.

use crate::loader::{LoadError, Loaded};
use crate::model::{Finding, Severity};
use crate::rules::{Ctx, Emitter, RULES};
use crate::workload;
use std::collections::HashSet;

/// Annotation that suppresses rules for one resource, e.g.
/// `kubesieve.io/ignore: "KS005, KS004"` on a node-level agent that really needs hostPath.
pub const IGNORE_ANNOTATION: &str = "kubesieve.io/ignore";

pub struct ScanOptions {
    /// Findings below this severity are dropped.
    pub min_severity: Severity,
    /// Rule ids disabled for the whole run.
    pub skip: Vec<String>,
}

#[derive(Debug)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<LoadError>,
    pub files: usize,
    pub resources: usize,
    /// Findings silenced by the ignore annotation. Reported so suppressions stay visible.
    pub suppressed: usize,
}

impl ScanReport {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    pub fn has_at_least(&self, severity: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= severity)
    }
}

pub fn scan(loaded: Loaded, opts: &ScanOptions) -> ScanReport {
    let mut findings = Vec::new();
    let mut errors = loaded.errors;
    let mut suppressed = 0;

    for res in &loaded.resources {
        let workload = match workload::extract(res) {
            Some(Ok(w)) => Some(w),
            Some(Err(message)) => {
                errors.push(LoadError {
                    source: res.source.clone(),
                    line: res.line,
                    message,
                });
                continue;
            }
            None => None,
        };
        let ignored = ignored_rules(res.annotations.get(IGNORE_ANNOTATION));
        let ctx = Ctx {
            res,
            workload: workload.as_ref(),
        };

        for rule in RULES {
            if opts.skip.iter().any(|id| id.eq_ignore_ascii_case(rule.id)) {
                continue;
            }
            let mut local = Vec::new();
            (rule.check)(&ctx, &mut Emitter::new(rule, res, &mut local));
            if ignored.all || ignored.ids.contains(rule.id) {
                suppressed += local.len();
                continue;
            }
            findings.extend(
                local
                    .into_iter()
                    .filter(|f| f.severity >= opts.min_severity),
            );
        }
    }

    findings.sort_by(|a, b| {
        a.location
            .file
            .cmp(&b.location.file)
            .then(a.location.line.cmp(&b.location.line))
            .then(b.severity.cmp(&a.severity))
            .then(a.rule_id.cmp(b.rule_id))
            .then(a.location.path.cmp(&b.location.path))
    });

    ScanReport {
        findings,
        errors,
        files: loaded.files,
        resources: loaded.resources.len(),
        suppressed,
    }
}

struct Ignored {
    all: bool,
    ids: HashSet<String>,
}

fn ignored_rules(annotation: Option<&String>) -> Ignored {
    let ids: HashSet<String> = annotation
        .map(|v| {
            v.split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_uppercase)
                .collect()
        })
        .unwrap_or_default();
    Ignored {
        all: ids.contains("ALL"),
        ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse_text;

    fn run(yaml: &str, opts: ScanOptions) -> ScanReport {
        let mut loaded = Loaded::default();
        parse_text("t.yaml", yaml, &mut loaded);
        scan(loaded, &opts)
    }

    const POD: &str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: agent
  annotations:
    kubesieve.io/ignore: "ks004, KS005"
spec:
  hostNetwork: true
  volumes: [{name: v, hostPath: {path: /var/log}}]
  containers: [{name: c, image: "a:1"}]
"#;

    #[test]
    fn annotation_suppresses_and_counts() {
        let r = run(
            POD,
            ScanOptions {
                min_severity: Severity::Info,
                skip: vec![],
            },
        );
        assert!(
            r.findings
                .iter()
                .all(|f| f.rule_id != "KS004" && f.rule_id != "KS005")
        );
        assert_eq!(r.suppressed, 2);
    }

    #[test]
    fn min_severity_and_skip_filter() {
        let r = run(
            POD,
            ScanOptions {
                min_severity: Severity::High,
                skip: vec!["ks003".into()],
            },
        );
        assert!(r.findings.iter().all(|f| f.severity >= Severity::High));
        assert!(r.findings.iter().all(|f| f.rule_id != "KS003"));
        assert!(r.findings.iter().any(|f| f.rule_id == "KS002"));
    }

    #[test]
    fn malformed_pod_spec_is_an_error_not_a_crash() {
        let r = run(
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec:\n  containers: not-a-list\n",
            ScanOptions {
                min_severity: Severity::Info,
                skip: vec![],
            },
        );
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].message.contains("cannot read pod spec"));
    }
}
