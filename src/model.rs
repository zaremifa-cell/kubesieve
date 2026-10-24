//! Core data types shared by the scanner, the rules and the reporters.

use serde::Serialize;
use std::fmt;

/// How serious a finding is. The derive order matters: `Info < Low < … < Critical`,
/// so severities can be compared directly (`finding.severity >= Severity::High`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// SARIF only knows three result levels.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    /// Numeric score GitHub code scanning uses to bucket alerts (CVSS-like, 0.0–10.0).
    pub fn security_score(self) -> &'static str {
        match self {
            Severity::Critical => "9.5",
            Severity::High => "8.0",
            Severity::Medium => "5.5",
            Severity::Low => "3.0",
            Severity::Info => "1.0",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where in the input a finding points.
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    /// File the resource came from (`<stdin>` for piped input).
    pub file: String,
    /// 1-based line on which the YAML document of the resource starts.
    pub line: usize,
    pub kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Dotted path to the offending field, e.g. `spec.template.spec.containers[0].image`.
    pub path: String,
}

/// One problem found by one rule in one resource.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub message: String,
    pub remediation: &'static str,
    pub location: Location,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
        let mut v = vec![Severity::Low, Severity::Critical, Severity::Info];
        v.sort();
        assert_eq!(v, vec![Severity::Info, Severity::Low, Severity::Critical]);
    }
}
