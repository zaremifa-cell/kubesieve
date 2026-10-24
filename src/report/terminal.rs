use super::Reporter;
use crate::model::{Finding, Severity};
use crate::scan::ScanReport;
use owo_colors::{OwoColorize, Style};
use std::fmt::Display;
use std::io::{self, Write};

pub struct Terminal {
    pub color: bool,
}

impl Terminal {
    fn paint(&self, text: impl Display, style: Style) -> String {
        if self.color {
            text.style(style).to_string()
        } else {
            text.to_string()
        }
    }

    fn badge(&self, severity: Severity) -> String {
        let label = format!("{:<8}", severity.as_str().to_ascii_uppercase());
        let style = match severity {
            Severity::Critical => Style::new().white().on_red().bold(),
            Severity::High => Style::new().red().bold(),
            Severity::Medium => Style::new().yellow().bold(),
            Severity::Low => Style::new().blue(),
            Severity::Info => Style::new().dimmed(),
        };
        self.paint(label, style)
    }

    fn header(&self, f: &Finding, out: &mut dyn Write) -> io::Result<()> {
        let l = &f.location;
        let name = match &l.namespace {
            Some(ns) => format!("{ns}/{}", l.name),
            None => l.name.clone(),
        };
        writeln!(
            out,
            "{}  {} {}",
            self.paint(format!("{}:{}", l.file, l.line), Style::new().underline()),
            self.paint(&l.kind, Style::new().bold()),
            name
        )
    }
}

impl Reporter for Terminal {
    fn render(&self, report: &ScanReport, out: &mut dyn Write) -> io::Result<()> {
        let dim = Style::new().dimmed();
        let mut current: Option<(&str, usize)> = None;

        for f in &report.findings {
            let key = (f.location.file.as_str(), f.location.line);
            if current != Some(key) {
                if current.is_some() {
                    writeln!(out)?;
                }
                self.header(f, out)?;
                current = Some(key);
            }
            writeln!(
                out,
                "  {} {}  {}",
                self.badge(f.severity),
                self.paint(f.rule_id, dim),
                self.paint(f.title, Style::new().bold())
            )?;
            writeln!(out, "             {}", f.message)?;
            writeln!(
                out,
                "             {} {}",
                self.paint("at", dim),
                self.paint(&f.location.path, dim)
            )?;
            writeln!(
                out,
                "             {} {}",
                self.paint("fix", Style::new().cyan()),
                f.remediation
            )?;
        }

        if !report.findings.is_empty() {
            writeln!(out)?;
        }
        let scope = format!(
            "{} resource{} in {} file{}",
            report.resources,
            plural(report.resources),
            report.files,
            plural(report.files)
        );
        if report.findings.is_empty() {
            writeln!(
                out,
                "{} No findings · {scope}",
                self.paint("✓", Style::new().green().bold())
            )?;
        } else {
            let counts: Vec<String> = Severity::ALL
                .iter()
                .filter(|s| report.count(**s) > 0)
                .map(|s| format!("{} {s}", report.count(*s)))
                .collect();
            writeln!(
                out,
                "{} finding{} ({}) · {scope}",
                self.paint(report.findings.len(), Style::new().bold()),
                plural(report.findings.len()),
                counts.join(", ")
            )?;
        }
        if report.suppressed > 0 {
            writeln!(
                out,
                "{}",
                self.paint(
                    format!(
                        "{} finding{} suppressed by the kubesieve.io/ignore annotation",
                        report.suppressed,
                        plural(report.suppressed)
                    ),
                    dim
                )
            )?;
        }
        Ok(())
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
