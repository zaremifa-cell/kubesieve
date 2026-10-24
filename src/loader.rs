//! Reading YAML from files, directories and stdin and turning it into Kubernetes resources.
//!
//! A manifest file often holds several YAML documents separated by `---`. We split them
//! ourselves (instead of letting the YAML library do it) so we know the line each document
//! starts on — reports and SARIF output point people to that line.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// One Kubernetes object, with the metadata every rule needs and the raw YAML tree.
#[derive(Debug, Clone)]
pub struct Resource {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub annotations: BTreeMap<String, String>,
    pub source: String,
    pub line: usize,
    pub raw: Value,
}

impl Resource {
    /// `namespace/name`, or just `name` when no namespace is set.
    pub fn display_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        }
    }
}

/// A problem with the input itself (unreadable YAML, unexpected shape).
#[derive(Debug, Clone, Serialize)]
pub struct LoadError {
    pub source: String,
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Loaded {
    pub resources: Vec<Resource>,
    pub errors: Vec<LoadError>,
    pub files: usize,
}

/// Just enough of an object to classify it; everything else stays in `raw`.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Header {
    api_version: Option<String>,
    kind: Option<String>,
    metadata: Option<Metadata>,
    items: Option<Vec<Value>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Metadata {
    name: Option<String>,
    generate_name: Option<String>,
    namespace: Option<String>,
    annotations: Option<BTreeMap<String, Value>>,
}

/// Load every path. Directories are walked recursively for `.yaml`/`.yml` files;
/// `-` reads from stdin (handy for `helm template … | kubesieve scan -`).
pub fn load_paths(paths: &[PathBuf]) -> Result<Loaded> {
    let mut out = Loaded::default();
    for path in paths {
        if path.as_os_str() == "-" {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("reading manifests from stdin")?;
            out.files += 1;
            parse_text("<stdin>", &text, &mut out);
        } else if path.is_dir() {
            let walker = WalkDir::new(path)
                .sort_by_file_name()
                .into_iter()
                // Skip hidden directories such as .git, but never the root we were given.
                .filter_entry(|e| {
                    e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.')
                });
            for entry in walker {
                match entry {
                    Ok(e) if e.file_type().is_file() && is_yaml(e.path()) => {
                        load_file(e.path(), &mut out)?;
                    }
                    Ok(_) => {}
                    Err(err) => out.errors.push(LoadError {
                        source: path.display().to_string(),
                        line: 0,
                        message: err.to_string(),
                    }),
                }
            }
        } else {
            load_file(path, &mut out)?;
        }
    }
    Ok(out)
}

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    )
}

fn load_file(path: &Path, out: &mut Loaded) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    out.files += 1;
    let source = path.to_string_lossy().replace('\\', "/");
    let source = source.strip_prefix("./").unwrap_or(&source).to_owned();
    parse_text(&source, &text, out);
    Ok(())
}

/// Parse one file's worth of text into resources, collecting errors instead of stopping,
/// so one broken document does not hide problems in the others.
pub fn parse_text(source: &str, text: &str, out: &mut Loaded) {
    for (line, doc) in split_documents(text) {
        match serde_yaml::from_str::<Value>(&doc) {
            Ok(Value::Null) => {}
            Ok(value) => push_resources(source, line, value, out),
            Err(err) => out.errors.push(LoadError {
                source: source.to_owned(),
                line: line + err.location().map_or(0, |l| l.line().saturating_sub(1)),
                message: format!("invalid YAML: {err}"),
            }),
        }
    }
}

fn push_resources(source: &str, line: usize, value: Value, out: &mut Loaded) {
    // Documents that are not Kubernetes objects (Helm values files, plain lists…) are skipped.
    let Ok(header) = serde_yaml::from_value::<Header>(value.clone()) else {
        return;
    };
    let (Some(api_version), Some(kind)) = (header.api_version, header.kind) else {
        return;
    };

    // `kubectl get -o yaml` produces `kind: List` with the real objects under `items`.
    if kind.ends_with("List")
        && let Some(items) = header.items
    {
        for item in items {
            push_resources(source, line, item, out);
        }
        return;
    }

    let meta = header.metadata.unwrap_or_default();
    let annotations = meta
        .annotations
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, v)| match v {
            Value::String(s) => Some((k, s)),
            _ => None,
        })
        .collect();

    out.resources.push(Resource {
        api_version,
        kind,
        name: meta
            .name
            .or(meta.generate_name)
            .unwrap_or_else(|| "<unnamed>".to_owned()),
        namespace: meta.namespace,
        annotations,
        source: source.to_owned(),
        line,
        raw: value,
    });
}

/// Split a multi-document YAML stream on `---` lines.
/// Returns `(start_line, text)` where `start_line` is the first line with real content.
pub fn split_documents(text: &str) -> Vec<(usize, String)> {
    fn flush(docs: &mut Vec<(usize, String)>, current: &mut String, start: &mut Option<usize>) {
        if let Some(line) = start.take() {
            docs.push((line, std::mem::take(current)));
        } else {
            current.clear();
        }
    }

    let mut docs = Vec::new();
    let mut current = String::new();
    let mut start: Option<usize> = None;

    for (index, line) in text.lines().enumerate() {
        let lineno = index + 1;
        let trimmed = line.trim_end();

        if is_separator(trimmed) {
            flush(&mut docs, &mut current, &mut start);
            // `--- key: value` is legal YAML: keep what follows the marker.
            let rest = trimmed[3..].trim();
            if !rest.is_empty() && !rest.starts_with('#') {
                current.push_str(rest);
                current.push('\n');
                start = Some(lineno);
            }
            continue;
        }
        if trimmed == "..." {
            flush(&mut docs, &mut current, &mut start);
            continue;
        }
        if start.is_none() {
            let content = trimmed.trim_start();
            if !content.is_empty() && !content.starts_with('#') && !content.starts_with('%') {
                start = Some(lineno);
            }
        }
        if !trimmed.starts_with('%') {
            current.push_str(line);
            current.push('\n');
        }
    }
    flush(&mut docs, &mut current, &mut start);
    docs
}

fn is_separator(line: &str) -> bool {
    line.starts_with("---") && line[3..].chars().next().is_none_or(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_documents_and_tracks_lines() {
        let text = "# header comment\napiVersion: v1\nkind: A\n---\n\n# note\nkind: B\n---\n---\nkind: C\n";
        let docs = split_documents(text);
        let lines: Vec<usize> = docs.iter().map(|(l, _)| *l).collect();
        assert_eq!(lines, vec![2, 7, 10]);
        assert!(docs[1].1.contains("kind: B"));
    }

    #[test]
    fn dashes_inside_values_are_not_separators() {
        let docs = split_documents("a: |\n  ---\n  text\nb: ----x\n");
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn expands_lists_and_skips_non_kubernetes_documents() {
        let mut out = Loaded::default();
        let text = r#"
replicaCount: 3
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata: {name: a}
  - apiVersion: v1
    kind: Service
    metadata: {name: b, namespace: prod}
"#;
        parse_text("x.yaml", text, &mut out);
        assert!(out.errors.is_empty());
        let names: Vec<String> = out.resources.iter().map(Resource::display_name).collect();
        assert_eq!(names, vec!["a", "prod/b"]);
    }

    #[test]
    fn reports_invalid_yaml_with_line() {
        let mut out = Loaded::default();
        parse_text("bad.yaml", "kind: Pod\n---\nkind: [unclosed\n", &mut out);
        assert_eq!(out.resources.len(), 0);
        assert_eq!(out.errors.len(), 1);
        assert!(out.errors[0].line >= 3);
    }
}
