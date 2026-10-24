//! SARIF 2.1.0 output — the format GitHub code scanning, GitLab and Azure DevOps understand.
//! Uploading it in CI turns every finding into an annotation on the pull request.

use super::Reporter;
use crate::model::Finding;
use crate::rules::RULES;
use crate::scan::ScanReport;
use serde_json::{Value, json};
use std::io::{self, Write};

pub struct Sarif;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI: &str = "https://github.com/zaremifa-cell/kubesieve";

impl Reporter for Sarif {
    fn render(&self, report: &ScanReport, out: &mut dyn Write) -> io::Result<()> {
        let rules: Vec<Value> = RULES
            .iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "name": r.title,
                    "shortDescription": { "text": r.title },
                    "fullDescription": { "text": r.description },
                    "help": {
                        "text": r.remediation,
                        "markdown": format!("{}\n\n**Fix:** {}", r.description, r.remediation),
                    },
                    "defaultConfiguration": { "level": r.severity.sarif_level() },
                    "properties": {
                        "security-severity": r.severity.security_score(),
                        "tags": ["security", "kubernetes"],
                        "precision": "high",
                    },
                })
            })
            .collect();

        let results: Vec<Value> = report.findings.iter().map(result).collect();

        let doc = json!({
            "$schema": SCHEMA,
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": {
                    "name": "kubesieve",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": INFO_URI,
                    "rules": rules,
                }},
                "results": results,
            }],
        });
        serde_json::to_writer_pretty(&mut *out, &doc)?;
        writeln!(out)
    }
}

fn result(f: &Finding) -> Value {
    let l = &f.location;
    let qualified = match &l.namespace {
        Some(ns) => format!("{}/{ns}/{}", l.kind, l.name),
        None => format!("{}/{}", l.kind, l.name),
    };
    json!({
        "ruleId": f.rule_id,
        "ruleIndex": RULES.iter().position(|r| r.id == f.rule_id),
        "level": f.severity.sarif_level(),
        "message": { "text": format!("{qualified}: {} (at {})", f.message, l.path) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": l.file },
                "region": { "startLine": l.line.max(1) },
            },
            "logicalLocations": [{ "fullyQualifiedName": qualified, "kind": "resource" }],
        }],
        // Lets code scanning recognise the same alert across commits even if lines move.
        "partialFingerprints": {
            "kubesieve/v1": format!("{:016x}", fnv1a(&[f.rule_id, &qualified, &l.path]))
        },
    })
}

/// FNV-1a: tiny, dependency-free and — unlike `std`'s `DefaultHasher` — stable across
/// Rust versions, which a fingerprint stored by GitHub needs to be.
fn fnv1a(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.bytes().chain(std::iter::once(0)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::fnv1a;

    #[test]
    fn fingerprint_is_stable_and_separates_parts() {
        assert_eq!(fnv1a(&[]), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(&["a", "b"]), fnv1a(&["a", "b"]));
        assert_ne!(fnv1a(&["ab", ""]), fnv1a(&["a", "b"]));
    }
}
