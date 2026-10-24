//! Rules about how workloads are exposed on the network.

use super::{Ctx, Emitter, Rule};
use crate::model::Severity;

pub const EXTERNAL_SERVICE: Rule = Rule {
    id: "KS201",
    title: "Service exposed outside the cluster",
    severity: Severity::Low,
    description: "NodePort and LoadBalancer services are reachable from outside the cluster. That is \
                  sometimes intended, but it should never be accidental.",
    remediation: "Use `type: ClusterIP` behind an Ingress or Gateway, or restrict `loadBalancerSourceRanges`.",
    check: external_service,
};

fn external_service(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    if ctx.res.kind != "Service" {
        return;
    }
    let service_type = ctx
        .res
        .raw
        .get("spec")
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str());
    if let Some(t @ ("NodePort" | "LoadBalancer")) = service_type {
        let restricted = ctx
            .res
            .raw
            .get("spec")
            .and_then(|s| s.get("loadBalancerSourceRanges"))
            .and_then(|r| r.as_sequence())
            .is_some_and(|r| !r.is_empty());
        if !restricted {
            emit.report(
                "spec.type",
                None,
                format!("service of type {t} is reachable from outside the cluster"),
            );
        }
    }
}

pub const INGRESS_WITHOUT_TLS: Rule = Rule {
    id: "KS202",
    title: "Ingress without TLS",
    severity: Severity::Medium,
    description: "An Ingress without a `tls` section serves plain HTTP, so credentials and cookies travel unencrypted.",
    remediation: "Add a `spec.tls` entry with a certificate Secret (cert-manager can issue one automatically).",
    check: ingress_without_tls,
};

fn ingress_without_tls(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    if ctx.res.kind != "Ingress" {
        return;
    }
    let has_tls = ctx
        .res
        .raw
        .get("spec")
        .and_then(|s| s.get("tls"))
        .and_then(|t| t.as_sequence())
        .is_some_and(|t| !t.is_empty());
    if !has_tls {
        emit.report("spec.tls", None, "ingress has no TLS configuration");
    }
}

#[cfg(test)]
mod tests {
    use crate::rules::testutil::ids;

    #[test]
    fn network_rules() {
        let yaml = r#"
apiVersion: v1
kind: Service
metadata: {name: public}
spec: {type: LoadBalancer}
---
apiVersion: v1
kind: Service
metadata: {name: restricted}
spec: {type: LoadBalancer, loadBalancerSourceRanges: [10.0.0.0/8]}
---
apiVersion: v1
kind: Service
metadata: {name: internal}
spec: {type: ClusterIP}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web}
spec: {rules: []}
"#;
        assert_eq!(ids(yaml), vec!["KS201", "KS202"]);
    }
}
