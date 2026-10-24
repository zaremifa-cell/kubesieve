use super::Reporter;
use crate::model::Severity;
use crate::scan::ScanReport;
use serde_json::{Map, Value, json};
use std::io::{self, Write};

pub struct Json;

impl Reporter for Json {
    fn render(&self, report: &ScanReport, out: &mut dyn Write) -> io::Result<()> {
        let by_severity: Map<String, Value> = Severity::ALL
            .iter()
            .map(|s| (s.to_string(), json!(report.count(*s))))
            .collect();
        let doc = json!({
            "tool": "kubesieve",
            "version": env!("CARGO_PKG_VERSION"),
            "summary": {
                "files": report.files,
                "resources": report.resources,
                "findings": report.findings.len(),
                "suppressed": report.suppressed,
                "by_severity": by_severity,
            },
            "findings": report.findings,
            "errors": report.errors,
        });
        serde_json::to_writer_pretty(&mut *out, &doc)?;
        writeln!(out)
    }
}
