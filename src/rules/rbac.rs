//! Rules for Role-Based Access Control objects.

use super::{Ctx, Emitter, Rule};
use crate::model::Severity;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RoleDoc {
    rules: Option<Vec<PolicyRule>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PolicyRule {
    resources: Vec<String>,
    verbs: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BindingDoc {
    role_ref: RoleRef,
    subjects: Option<Vec<Subject>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RoleRef {
    name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Subject {
    kind: String,
    name: String,
    namespace: Option<String>,
}

fn role_rules(ctx: &Ctx<'_>) -> Vec<PolicyRule> {
    if !matches!(ctx.res.kind.as_str(), "Role" | "ClusterRole") {
        return Vec::new();
    }
    serde_yaml::from_value::<RoleDoc>(ctx.res.raw.clone())
        .ok()
        .and_then(|d| d.rules)
        .unwrap_or_default()
}

fn has(list: &[String], item: &str) -> bool {
    list.iter().any(|x| x == item)
}

pub const WILDCARD_PERMISSIONS: Rule = Rule {
    id: "KS101",
    title: "Wildcard RBAC permissions",
    severity: Severity::High,
    description: "`*` in verbs or resources grants everything, including permissions added to the API \
                  in the future.",
    remediation: "List the exact resources and verbs the subject needs.",
    check: wildcard_permissions,
};

fn wildcard_permissions(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    for (i, rule) in role_rules(ctx).iter().enumerate() {
        let all_verbs = has(&rule.verbs, "*");
        let all_resources = has(&rule.resources, "*");
        let path = format!("rules[{i}]");
        match (all_verbs, all_resources) {
            (true, true) => emit.report_with(
                Severity::Critical,
                path,
                None,
                format!("{} grants every verb on every resource", ctx.res.kind),
            ),
            (true, false) => emit.report(
                path,
                None,
                format!("grants every verb on {}", rule.resources.join(", ")),
            ),
            (false, true) => emit.report(
                path,
                None,
                format!("grants {} on every resource", rule.verbs.join(", ")),
            ),
            (false, false) => {}
        }
    }
}

pub const CLUSTER_ADMIN_BINDING: Rule = Rule {
    id: "KS102",
    title: "Binding to cluster-admin",
    severity: Severity::Critical,
    description: "cluster-admin can do anything in every namespace. Whoever is bound to it owns the cluster.",
    remediation: "Bind a narrowly scoped Role instead, in the namespace where access is needed.",
    check: cluster_admin_binding,
};

fn cluster_admin_binding(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    if !matches!(ctx.res.kind.as_str(), "RoleBinding" | "ClusterRoleBinding") {
        return;
    }
    let Ok(binding) = serde_yaml::from_value::<BindingDoc>(ctx.res.raw.clone()) else {
        return;
    };
    if binding.role_ref.name != "cluster-admin" {
        return;
    }
    let subjects: Vec<String> = binding
        .subjects
        .unwrap_or_default()
        .iter()
        .map(|s| match &s.namespace {
            Some(ns) => format!("{} {ns}/{}", s.kind, s.name),
            None => format!("{} {}", s.kind, s.name),
        })
        .collect();
    let who = if subjects.is_empty() {
        "no subjects".to_owned()
    } else {
        subjects.join(", ")
    };
    emit.report(
        "roleRef.name",
        None,
        format!("grants cluster-admin to {who}"),
    );
}

pub const SECRETS_ACCESS: Rule = Rule {
    id: "KS103",
    title: "Read access to Secrets",
    severity: Severity::Medium,
    description: "`get`, `list` or `watch` on secrets exposes every credential in scope; `list` alone \
                  returns all secret values.",
    remediation: "Avoid reading secrets through the API; if unavoidable, restrict with `resourceNames`.",
    check: secrets_access,
};

fn secrets_access(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    for (i, rule) in role_rules(ctx).iter().enumerate() {
        // `resources: ["*"]` is already reported by KS101.
        if !has(&rule.resources, "secrets") {
            continue;
        }
        let verbs: Vec<&str> = rule
            .verbs
            .iter()
            .map(String::as_str)
            .filter(|v| matches!(*v, "get" | "list" | "watch" | "*"))
            .collect();
        if !verbs.is_empty() {
            emit.report(
                format!("rules[{i}]"),
                None,
                format!("allows {} on secrets", verbs.join(", ")),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Severity;
    use crate::rules::testutil::findings;

    #[test]
    fn rbac_rules() {
        let yaml = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: too-much}
rules:
  - {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
  - {apiGroups: [""], resources: [secrets, configmaps], verbs: [get, list]}
  - {apiGroups: [""], resources: [pods], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: ServiceAccount, name: deployer, namespace: ci}
"#;
        let f = findings(yaml);
        let summary: Vec<_> = f
            .iter()
            .map(|f| (f.rule_id, f.severity, f.location.path.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("KS101", Severity::Critical, "rules[0]"),
                ("KS103", Severity::Medium, "rules[1]"),
                ("KS102", Severity::Critical, "roleRef.name"),
            ]
        );
        assert!(f[2].message.contains("ServiceAccount ci/deployer"));
    }
}
