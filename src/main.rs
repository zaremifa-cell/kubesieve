use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use kubesieve::loader::load_paths;
use kubesieve::model::Severity;
use kubesieve::report::{self, Format};
use kubesieve::rules::{self, RULES};
use kubesieve::scan::{ScanOptions, scan};
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// Static security scanner for Kubernetes manifests.
#[derive(Parser)]
#[command(name = "kubesieve", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan manifest files or directories. Use `-` to read from stdin.
    Scan(ScanArgs),
    /// List every rule with its id and severity.
    Rules {
        /// Print the rules as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Files or directories to scan (directories are searched for *.yaml / *.yml).
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Hide findings below this severity.
    #[arg(long, value_enum, default_value_t = Severity::Low)]
    min_severity: Severity,

    /// Exit with code 1 if any finding is at or above this severity.
    #[arg(long, value_enum, default_value_t = Severity::High)]
    fail_on: Severity,

    /// Always exit with code 0 when the scan itself succeeds.
    #[arg(long)]
    no_fail: bool,

    /// Comma-separated rule ids to disable, e.g. `--skip KS013,KS015`.
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,

    /// When to use colours.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            // `kubesieve scan … | head` closes the pipe early; that is not an error.
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("kubesieve: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Rules { json } => {
            print_rules(json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<ExitCode> {
    for id in &args.skip {
        if rules::find(id).is_none() {
            bail!("unknown rule id `{id}` in --skip (run `kubesieve rules` to list them)");
        }
    }

    let loaded = load_paths(&args.paths)?;
    let report = scan(
        loaded,
        &ScanOptions {
            min_severity: args.min_severity,
            skip: args.skip,
        },
    );

    for e in &report.errors {
        eprintln!("kubesieve: {}:{}: {}", e.source, e.line, e.message);
    }

    let color = match args.color {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            args.output.is_none()
                && io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none()
        }
    };
    let reporter = report::reporter(args.format, color);

    match &args.output {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
            let mut w = BufWriter::new(file);
            reporter.render(&report, &mut w)?;
            w.flush()?;
        }
        None => {
            let mut w = io::stdout().lock();
            reporter.render(&report, &mut w)?;
        }
    }

    // Exit codes: 2 = the input could not be fully read, 1 = policy violated, 0 = clean.
    if !report.errors.is_empty() {
        Ok(ExitCode::from(2))
    } else if !args.no_fail && report.has_at_least(args.fail_on) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn print_rules(json: bool) -> Result<()> {
    let mut out = io::stdout().lock();
    if json {
        let list: Vec<_> = RULES
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "description": r.description,
                    "remediation": r.remediation,
                })
            })
            .collect();
        serde_json::to_writer_pretty(&mut out, &list)?;
        writeln!(out)?;
    } else {
        writeln!(out, "{:<7} {:<9} TITLE", "ID", "SEVERITY")?;
        for r in RULES {
            writeln!(out, "{:<7} {:<9} {}", r.id, r.severity, r.title)?;
        }
    }
    Ok(())
}
