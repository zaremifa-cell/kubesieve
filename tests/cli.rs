//! End-to-end tests: run the real binary the way CI would.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn kubesieve() -> Command {
    Command::cargo_bin("kubesieve").unwrap()
}

fn json_output(args: &[&str]) -> Value {
    let out = kubesieve()
        .args(args)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).expect("valid JSON")
}

#[test]
fn hardened_example_passes() {
    kubesieve()
        .args(["scan", "examples/hardened", "--min-severity", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No findings"));
}

#[test]
fn insecure_example_fails_with_exit_code_1() {
    kubesieve()
        .args(["scan", "examples/insecure", "--color", "never"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("KS001"))
        .stdout(predicate::str::contains("examples/insecure/app.yaml:2"))
        .stdout(predicate::str::contains("s3cr3t").not());
}

#[test]
fn fail_on_threshold_and_no_fail() {
    // RBAC example has critical findings only at/above medium; fail-on critical still fails.
    kubesieve()
        .args([
            "scan",
            "examples/insecure/rbac.yaml",
            "--fail-on",
            "critical",
        ])
        .assert()
        .code(1);
    kubesieve()
        .args(["scan", "examples/insecure", "--no-fail"])
        .assert()
        .success();
}

#[test]
fn json_summary_counts_add_up() {
    let doc = json_output(&["scan", "examples/insecure"]);
    let summary = &doc["summary"];
    assert_eq!(summary["files"], 3);
    let total = summary["findings"].as_u64().unwrap();
    let by_sev: u64 = summary["by_severity"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(total, by_sev);
    assert_eq!(total as usize, doc["findings"].as_array().unwrap().len());
}

#[test]
fn sarif_is_well_formed() {
    let out = kubesieve()
        .args(["scan", "examples/insecure", "--format", "sarif"])
        .output()
        .unwrap();
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    for result in run["results"].as_array().unwrap() {
        let index = result["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[index]["id"], result["ruleId"]);
        assert!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }
}

#[test]
fn reads_stdin() {
    kubesieve()
        .args(["scan", "-", "--color", "never"])
        .write_stdin("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: c, image: x, securityContext: {privileged: true}}]\n")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("<stdin>:1"))
        .stdout(predicate::str::contains("Privileged container"));
}

#[test]
fn writes_report_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.sarif");
    kubesieve()
        .args(["scan", "examples/hardened", "--format", "sarif", "--output"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
    assert!(std::fs::read_to_string(path).unwrap().contains("\"2.1.0\""));
}

#[test]
fn invalid_yaml_exits_with_2() {
    kubesieve()
        .args(["scan", "-"])
        .write_stdin("apiVersion: v1\nkind: [broken\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid YAML"));
}

#[test]
fn unknown_skip_id_is_rejected() {
    kubesieve()
        .args(["scan", "examples/hardened", "--skip", "KS999"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule id"));
}

#[test]
fn missing_file_is_an_error() {
    kubesieve()
        .args(["scan", "does/not/exist.yaml"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn rules_command_lists_all_rules() {
    kubesieve()
        .args(["rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("KS001").and(predicate::str::contains("KS202")));
}
