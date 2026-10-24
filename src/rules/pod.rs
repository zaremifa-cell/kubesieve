//! Rules for anything that runs pods: Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs.

use super::{Ctx, Emitter, Rule};
use crate::model::Severity;
use crate::workload::ContainerKind;
use regex::Regex;
use std::sync::LazyLock;

pub const PRIVILEGED: Rule = Rule {
    id: "KS001",
    title: "Privileged container",
    severity: Severity::Critical,
    description: "A privileged container gets every Linux capability and access to all host devices. \
                  Breaking out to the node is trivial.",
    remediation: "Remove `privileged: true` and grant only the specific capabilities the process needs.",
    check: privileged,
};

fn privileged(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        if c.sc().and_then(|s| s.privileged) == Some(true) {
            emit.report(
                format!("{}.securityContext.privileged", c.path),
                Some(&c.name),
                format!("container \"{}\" runs privileged", c.name),
            );
        }
    }
}

pub const PRIVILEGE_ESCALATION: Rule = Rule {
    id: "KS002",
    title: "Privilege escalation allowed",
    severity: Severity::High,
    description: "Unless explicitly disabled, a process can gain more privileges than its parent \
                  (for example through setuid binaries).",
    remediation: "Set `securityContext.allowPrivilegeEscalation: false` on every container.",
    check: privilege_escalation,
};

fn privilege_escalation(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        if c.sc().and_then(|s| s.allow_privilege_escalation) != Some(false) {
            emit.report(
                format!("{}.securityContext.allowPrivilegeEscalation", c.path),
                Some(&c.name),
                format!(
                    "container \"{}\" does not set allowPrivilegeEscalation: false (it defaults to true)",
                    c.name
                ),
            );
        }
    }
}

pub const RUN_AS_ROOT: Rule = Rule {
    id: "KS003",
    title: "Container may run as root",
    severity: Severity::High,
    description: "Root inside a container is root on the host if the container is ever escaped, \
                  and many images default to root.",
    remediation: "Set `runAsNonRoot: true` and a non-zero `runAsUser` (pod or container securityContext).",
    check: run_as_root,
};

fn run_as_root(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        match (w.run_as_user(&c), w.run_as_non_root(&c)) {
            (Some(0), _) => emit.report(
                format!("{}.securityContext.runAsUser", c.path),
                Some(&c.name),
                format!("container \"{}\" explicitly runs as UID 0 (root)", c.name),
            ),
            // A non-zero UID, or runAsNonRoot enforced by the kubelet: both fine.
            (Some(_), _) | (None, Some(true)) => {}
            (None, _) => emit.report(
                format!("{}.securityContext.runAsNonRoot", c.path),
                Some(&c.name),
                format!(
                    "container \"{}\" sets neither runAsNonRoot: true nor a non-zero runAsUser",
                    c.name
                ),
            ),
        }
    }
}

pub const HOST_NAMESPACES: Rule = Rule {
    id: "KS004",
    title: "Host namespace shared",
    severity: Severity::High,
    description: "hostNetwork, hostPID and hostIPC remove the isolation between the pod and the node: \
                  the pod can sniff node traffic, see and signal every process, or read shared memory.",
    remediation: "Remove `hostNetwork`, `hostPID` and `hostIPC` unless this is a node-level system agent.",
    check: host_namespaces,
};

fn host_namespaces(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    let flags = [
        (w.spec.host_network, "hostNetwork", "network"),
        (w.spec.host_pid, "hostPID", "process (PID)"),
        (w.spec.host_ipc, "hostIPC", "IPC"),
    ];
    for (enabled, field, what) in flags {
        if enabled {
            emit.report(
                format!("{}.{field}", w.path),
                None,
                format!("pod shares the node's {what} namespace"),
            );
        }
    }
}

pub const HOST_PATH: Rule = Rule {
    id: "KS005",
    title: "hostPath volume",
    severity: Severity::High,
    description: "hostPath volumes expose the node's filesystem to the pod. Mounting the container \
                  runtime socket or system directories gives full control of the node.",
    remediation: "Use emptyDir, a ConfigMap/Secret or a PersistentVolumeClaim instead of hostPath.",
    check: host_path,
};

/// Paths whose exposure amounts to owning the node.
const CRITICAL_HOST_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "/var/lib/kubelet",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
];

fn host_path(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for (i, volume) in w.spec.volumes.iter().enumerate() {
        let Some(hp) = &volume.host_path else {
            continue;
        };
        let normalized = match hp.path.trim_end_matches('/') {
            "" => "/",
            p => p,
        };
        let severity = if CRITICAL_HOST_PATHS.contains(&normalized) {
            Severity::Critical
        } else {
            Severity::High
        };
        emit.report_with(
            severity,
            format!("{}.volumes[{i}].hostPath", w.path),
            None,
            format!("volume \"{}\" mounts host path {}", volume.name, hp.path),
        );
    }
}

pub const DANGEROUS_CAPABILITIES: Rule = Rule {
    id: "KS006",
    title: "Dangerous capability added",
    severity: Severity::High,
    description: "Capabilities such as SYS_ADMIN, NET_ADMIN or SYS_PTRACE are close to full root \
                  and enable well-known container escapes.",
    remediation: "Remove the capability from `securityContext.capabilities.add`; add only narrow ones \
                  such as NET_BIND_SERVICE.",
    check: dangerous_capabilities,
};

const DANGEROUS_CAPS: &[&str] = &[
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "DAC_READ_SEARCH",
    "BPF",
    "PERFMON",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
];

fn dangerous_capabilities(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        let Some(caps) = c.sc().and_then(|s| s.capabilities.as_ref()) else {
            continue;
        };
        for (i, cap) in caps.add.iter().enumerate() {
            let name = cap.to_ascii_uppercase();
            let name = name.trim_start_matches("CAP_");
            if DANGEROUS_CAPS.contains(&name) {
                emit.report(
                    format!("{}.securityContext.capabilities.add[{i}]", c.path),
                    Some(&c.name),
                    format!("container \"{}\" adds capability {name}", c.name),
                );
            }
        }
    }
}

pub const CAPABILITIES_NOT_DROPPED: Rule = Rule {
    id: "KS007",
    title: "Default capabilities not dropped",
    severity: Severity::Medium,
    description: "Container runtimes grant a default set of capabilities (e.g. NET_RAW, which allows \
                  packet spoofing). Most applications need none of them.",
    remediation: "Set `securityContext.capabilities.drop: [\"ALL\"]` and add back only what is required.",
    check: capabilities_not_dropped,
};

fn capabilities_not_dropped(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        let drops_all = c
            .sc()
            .and_then(|s| s.capabilities.as_ref())
            .is_some_and(|caps| caps.drop.iter().any(|d| d.eq_ignore_ascii_case("ALL")));
        if !drops_all {
            emit.report(
                format!("{}.securityContext.capabilities.drop", c.path),
                Some(&c.name),
                format!("container \"{}\" does not drop ALL capabilities", c.name),
            );
        }
    }
}

pub const WRITABLE_ROOT_FS: Rule = Rule {
    id: "KS008",
    title: "Writable root filesystem",
    severity: Severity::Medium,
    description: "A writable root filesystem lets an attacker drop tools or modify binaries inside \
                  the running container.",
    remediation: "Set `readOnlyRootFilesystem: true` and mount an emptyDir for paths that must be writable.",
    check: writable_root_fs,
};

fn writable_root_fs(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        if c.sc().and_then(|s| s.read_only_root_filesystem) != Some(true) {
            emit.report(
                format!("{}.securityContext.readOnlyRootFilesystem", c.path),
                Some(&c.name),
                format!("container \"{}\" has a writable root filesystem", c.name),
            );
        }
    }
}

pub const SECCOMP: Rule = Rule {
    id: "KS009",
    title: "No seccomp profile",
    severity: Severity::Medium,
    description: "Without a seccomp profile every system call is allowed, which widens the kernel \
                  attack surface available to a compromised process.",
    remediation: "Set `securityContext.seccompProfile.type: RuntimeDefault` at pod level.",
    check: seccomp,
};

fn seccomp(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        let problem = match w.seccomp_type(&c) {
            Some("RuntimeDefault" | "Localhost") => continue,
            Some("Unconfined") => "sets seccomp to Unconfined",
            Some(_) => "has an unrecognised seccomp profile type",
            None => "has no seccomp profile",
        };
        emit.report(
            format!("{}.securityContext.seccompProfile", c.path),
            Some(&c.name),
            format!("container \"{}\" {problem}", c.name),
        );
    }
}

pub const SECRET_IN_ENV: Rule = Rule {
    id: "KS010",
    title: "Secret in plain environment variable",
    severity: Severity::High,
    description: "Secrets written directly into a manifest end up in Git history, in `kubectl get -o yaml` \
                  output and in CI logs.",
    remediation: "Store the value in a Secret and reference it with `valueFrom.secretKeyRef`.",
    check: secret_in_env,
};

static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)",
    )
    .expect("valid regex")
});
static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid regex"));

fn secret_in_env(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        for (i, var) in c.env.iter().enumerate() {
            let Some(value) = var.literal() else { continue };
            let path = format!("{}.env[{i}].value", c.path);
            // The value itself is never printed: the report must not leak the secret again.
            if AWS_ACCESS_KEY.is_match(&value) {
                emit.report_with(
                    Severity::Critical,
                    path,
                    Some(&c.name),
                    format!("env var \"{}\" contains what looks like an AWS access key (value redacted)", var.name),
                );
            } else if SECRET_NAME.is_match(&var.name)
                && !matches!(value.trim(), "" | "true" | "false")
            {
                emit.report(
                    path,
                    Some(&c.name),
                    format!("env var \"{}\" holds a literal value that looks like a secret (value redacted)", var.name),
                );
            }
        }
    }
}

pub const SERVICE_ACCOUNT_TOKEN: Rule = Rule {
    id: "KS011",
    title: "Service account token mounted",
    severity: Severity::Low,
    description: "Every pod gets an API token by default. If the application does not talk to the \
                  Kubernetes API, the token is only useful to an attacker.",
    remediation: "Set `automountServiceAccountToken: false` in the pod spec unless the app needs the API.",
    check: service_account_token,
};

fn service_account_token(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    if w.spec.automount_service_account_token != Some(false) {
        emit.report(
            format!("{}.automountServiceAccountToken", w.path),
            None,
            "pod automatically mounts a service account token",
        );
    }
}

pub const IMAGE_TAG: Rule = Rule {
    id: "KS012",
    title: "Mutable image tag",
    severity: Severity::Medium,
    description: "`:latest` (or no tag at all) can point to a different image tomorrow, so what runs \
                  is not what was reviewed.",
    remediation: "Use an explicit version tag, ideally pinned by digest (`image@sha256:…`).",
    check: image_tag,
};

/// Explains what is wrong with an image reference's tag, if anything.
pub fn tag_problem(image: &str) -> Option<&'static str> {
    if image.contains('@') {
        return None; // pinned by digest
    }
    // Look only at the last path segment: `registry:5000/app` has a port, not a tag.
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.split_once(':') {
        None => Some("has no tag, so it resolves to :latest"),
        Some((_, "latest")) => Some("uses the mutable :latest tag"),
        Some(_) => None,
    }
}

fn image_tag(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        let Some(image) = &c.image else { continue };
        if let Some(problem) = tag_problem(image) {
            emit.report(
                format!("{}.image", c.path),
                Some(&c.name),
                format!("image \"{image}\" {problem}"),
            );
        }
    }
}

pub const IMAGE_DIGEST: Rule = Rule {
    id: "KS013",
    title: "Image not pinned by digest",
    severity: Severity::Info,
    description: "Tags can be re-pushed. Only a digest guarantees the exact image bytes.",
    remediation: "Reference the image as `name:tag@sha256:<digest>`.",
    check: image_digest,
};

fn image_digest(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        let Some(image) = &c.image else { continue };
        // Untagged/latest images are already reported by KS012.
        if !image.contains('@') && tag_problem(image).is_none() {
            emit.report(
                format!("{}.image", c.path),
                Some(&c.name),
                format!("image \"{image}\" is not pinned by digest"),
            );
        }
    }
}

pub const MEMORY_LIMIT: Rule = Rule {
    id: "KS014",
    title: "No memory limit",
    severity: Severity::Medium,
    description: "A container without a memory limit can exhaust node memory and get neighbouring \
                  pods evicted — an easy denial of service.",
    remediation: "Set `resources.limits.memory`.",
    check: memory_limit,
};

fn memory_limit(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        // Ephemeral (debug) containers cannot declare resources.
        if c.kind == ContainerKind::Ephemeral {
            continue;
        }
        let has_limit = c
            .resources
            .as_ref()
            .is_some_and(|r| r.limits.contains_key("memory"));
        if !has_limit {
            emit.report(
                format!("{}.resources.limits.memory", c.path),
                Some(&c.name),
                format!("container \"{}\" has no memory limit", c.name),
            );
        }
    }
}

pub const RESOURCE_REQUESTS: Rule = Rule {
    id: "KS015",
    title: "No resource requests",
    severity: Severity::Low,
    description: "Without CPU and memory requests the scheduler cannot place the pod sensibly and it \
                  is the first to be evicted under pressure.",
    remediation: "Set `resources.requests.cpu` and `resources.requests.memory`.",
    check: resource_requests,
};

fn resource_requests(ctx: &Ctx<'_>, emit: &mut Emitter<'_>) {
    let Some(w) = ctx.workload else { return };
    for c in w.containers() {
        if c.kind == ContainerKind::Ephemeral {
            continue;
        }
        let missing: Vec<&str> = ["cpu", "memory"]
            .into_iter()
            .filter(|k| {
                !c.resources
                    .as_ref()
                    .is_some_and(|r| r.requests.contains_key(*k))
            })
            .collect();
        if !missing.is_empty() {
            emit.report(
                format!("{}.resources.requests", c.path),
                Some(&c.name),
                format!(
                    "container \"{}\" has no {} request",
                    c.name,
                    missing.join(" or ")
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tag_problem;
    use crate::rules::testutil::{findings, ids};

    const HARDENED: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: app
          image: ghcr.io/acme/web:1.4.2@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          env:
            - {name: DB_PASSWORD, valueFrom: {secretKeyRef: {name: db, key: password}}}
            - {name: LOG_LEVEL, value: info}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {memory: 256Mi}
"#;

    #[test]
    fn hardened_deployment_is_clean() {
        let f = findings(HARDENED);
        assert!(f.is_empty(), "unexpected findings: {f:#?}");
    }

    #[test]
    fn privileged_root_container_is_flagged() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata: {name: bad}
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
        runAsUser: 0
        capabilities: {add: [SYS_ADMIN, NET_BIND_SERVICE]}
"#;
        let found = ids(yaml);
        for id in [
            "KS001", "KS002", "KS003", "KS004", "KS006", "KS007", "KS008", "KS009", "KS011",
            "KS012", "KS014", "KS015",
        ] {
            assert!(found.contains(&id), "{id} missing from {found:?}");
        }
        let f = findings(yaml);
        assert_eq!(f.iter().filter(|f| f.rule_id == "KS004").count(), 2);
        // NET_BIND_SERVICE is harmless; only SYS_ADMIN is reported.
        assert_eq!(f.iter().filter(|f| f.rule_id == "KS006").count(), 1);
    }

    #[test]
    fn container_settings_override_pod_settings() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: inherits
      image: a:1
    - name: overrides
      image: a:1
      securityContext: {runAsUser: 0}
"#;
        let root: Vec<_> = findings(yaml)
            .into_iter()
            .filter(|f| f.rule_id == "KS003")
            .collect();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].location.container.as_deref(), Some("overrides"));
    }

    #[test]
    fn docker_socket_is_critical() {
        let yaml = r#"
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: agent}
spec:
  template:
    spec:
      containers: [{name: a, image: a:1}]
      volumes:
        - {name: sock, hostPath: {path: /var/run/docker.sock}}
        - {name: logs, hostPath: {path: /var/log/app}}
"#;
        let hp: Vec<_> = findings(yaml)
            .into_iter()
            .filter(|f| f.rule_id == "KS005")
            .map(|f| f.severity)
            .collect();
        use crate::model::Severity::*;
        assert_eq!(hp, vec![Critical, High]);
    }

    #[test]
    fn secrets_are_detected_but_never_printed() {
        let yaml = r#"
apiVersion: batch/v1
kind: CronJob
metadata: {name: backup}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: backup:2
              env:
                - {name: DB_PASSWORD, value: hunter2}
                - {name: AWS_KEY_ID, value: AKIAIOSFODNN7EXAMPLE}
                - {name: TOKEN_REFRESH, value: "true"}
                - {name: PORT, value: 5432}
"#;
        let secrets: Vec<_> = findings(yaml)
            .into_iter()
            .filter(|f| f.rule_id == "KS010")
            .collect();
        assert_eq!(secrets.len(), 2);
        assert!(
            secrets[0]
                .location
                .path
                .starts_with("spec.jobTemplate.spec.template.spec.containers[0].env[")
        );
        for f in &secrets {
            assert!(!f.message.contains("hunter2") && !f.message.contains("AKIA"));
        }
    }

    #[test]
    fn image_tags() {
        assert!(tag_problem("nginx").is_some());
        assert!(tag_problem("nginx:latest").is_some());
        assert!(tag_problem("registry.local:5000/team/app").is_some());
        assert!(tag_problem("registry.local:5000/team/app:2.1").is_none());
        assert!(tag_problem("nginx@sha256:abc").is_none());
    }
}
