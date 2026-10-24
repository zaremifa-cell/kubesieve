//! Output formats. Each one implements [`Reporter`]; `main` picks one at runtime.

mod json;
mod sarif;
mod terminal;

use crate::scan::ScanReport;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Human-readable, coloured when writing to a terminal.
    Terminal,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0, for GitHub code scanning and other CI tools.
    Sarif,
}

pub trait Reporter {
    fn render(&self, report: &ScanReport, out: &mut dyn Write) -> io::Result<()>;
}

pub fn reporter(format: Format, color: bool) -> Box<dyn Reporter> {
    match format {
        Format::Terminal => Box::new(terminal::Terminal { color }),
        Format::Json => Box::new(json::Json),
        Format::Sarif => Box::new(sarif::Sarif),
    }
}
