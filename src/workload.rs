//! A typed view of the pod specification inside workload resources.
//!
//! Only the fields the rules look at are modelled. Everything is optional or defaulted,
//! so unusual but valid manifests still deserialize; unknown fields are ignored.

use crate::loader::Resource;
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::ops::Deref;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PodSpec {
    pub containers: Vec<Container>,
    pub init_containers: Vec<Container>,
    pub ephemeral_containers: Vec<Container>,
    pub host_network: bool,
    #[serde(rename = "hostPID")]
    pub host_pid: bool,
    #[serde(rename = "hostIPC")]
    pub host_ipc: bool,
    pub volumes: Vec<Volume>,
    pub security_context: Option<PodSecurityContext>,
    pub automount_service_account_token: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PodSecurityContext {
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub seccomp_profile: Option<SeccompProfile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SeccompProfile {
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Volume {
    pub name: String,
    pub host_path: Option<HostPath>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HostPath {
    pub path: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Container {
    pub name: String,
    pub image: Option<String>,
    pub security_context: Option<SecurityContext>,
    pub resources: Option<Resources>,
    pub env: Vec<EnvVar>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecurityContext {
    pub privileged: Option<bool>,
    pub allow_privilege_escalation: Option<bool>,
    pub run_as_non_root: Option<bool>,
    pub run_as_user: Option<i64>,
    pub read_only_root_filesystem: Option<bool>,
    pub capabilities: Option<Capabilities>,
    pub seccomp_profile: Option<SeccompProfile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Capabilities {
    pub add: Vec<String>,
    pub drop: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Resources {
    pub limits: BTreeMap<String, Value>,
    pub requests: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EnvVar {
    pub name: String,
    pub value: Option<Value>,
}

impl EnvVar {
    /// The literal value as text (YAML may have parsed `1234` as a number).
    pub fn literal(&self) -> Option<String> {
        match self.value.as_ref()? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
}

impl Container {
    pub fn sc(&self) -> Option<&SecurityContext> {
        self.security_context.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    App,
    Init,
    Ephemeral,
}

/// A container together with where it lives in the manifest.
pub struct ContainerRef<'a> {
    container: &'a Container,
    pub path: String,
    pub kind: ContainerKind,
}

/// Lets rules write `c.image` instead of `c.container.image`.
impl Deref for ContainerRef<'_> {
    type Target = Container;
    fn deref(&self) -> &Container {
        self.container
    }
}

/// A resource that runs pods, with its pod spec parsed.
#[derive(Debug)]
pub struct Workload {
    pub spec: PodSpec,
    /// Dotted path to the pod spec inside the resource, e.g. `spec.template.spec`.
    pub path: String,
}

/// Where the pod spec lives for each workload kind.
pub fn pod_spec_path(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "Pod" => Some(&["spec"]),
        "PodTemplate" => Some(&["template", "spec"]),
        "Deployment"
        | "StatefulSet"
        | "DaemonSet"
        | "ReplicaSet"
        | "ReplicationController"
        | "Job" => Some(&["spec", "template", "spec"]),
        "CronJob" => Some(&["spec", "jobTemplate", "spec", "template", "spec"]),
        _ => None,
    }
}

/// `None` when the resource does not run pods (or is a partial patch without a pod spec),
/// `Some(Err)` when the pod spec is there but malformed.
pub fn extract(res: &Resource) -> Option<Result<Workload, String>> {
    let segments = pod_spec_path(&res.kind)?;
    let mut node = &res.raw;
    for segment in segments {
        node = node.get(*segment)?;
    }
    let path = segments.join(".");
    Some(
        serde_yaml::from_value::<PodSpec>(node.clone())
            .map(|spec| Workload {
                spec,
                path: path.clone(),
            })
            .map_err(|e| {
                format!(
                    "{} {}: cannot read pod spec at {path}: {e}",
                    res.kind,
                    res.display_name()
                )
            }),
    )
}

impl Workload {
    /// Every container in the pod, including init and ephemeral ones.
    pub fn containers(&self) -> Vec<ContainerRef<'_>> {
        let groups = [
            ("containers", &self.spec.containers, ContainerKind::App),
            (
                "initContainers",
                &self.spec.init_containers,
                ContainerKind::Init,
            ),
            (
                "ephemeralContainers",
                &self.spec.ephemeral_containers,
                ContainerKind::Ephemeral,
            ),
        ];
        groups
            .into_iter()
            .flat_map(|(field, list, kind)| {
                list.iter()
                    .enumerate()
                    .map(move |(i, container)| ContainerRef {
                        container,
                        path: format!("{}.{field}[{i}]", self.path),
                        kind,
                    })
            })
            .collect()
    }

    fn pod_sc(&self) -> Option<&PodSecurityContext> {
        self.spec.security_context.as_ref()
    }

    // Container-level settings override pod-level ones, as in Kubernetes itself.

    pub fn run_as_non_root(&self, c: &Container) -> Option<bool> {
        c.sc()
            .and_then(|s| s.run_as_non_root)
            .or_else(|| self.pod_sc().and_then(|s| s.run_as_non_root))
    }

    pub fn run_as_user(&self, c: &Container) -> Option<i64> {
        c.sc()
            .and_then(|s| s.run_as_user)
            .or_else(|| self.pod_sc().and_then(|s| s.run_as_user))
    }

    /// The result may borrow from the container *or* from the pod, so both inputs
    /// must outlive it — hence the shared lifetime `'a`.
    pub fn seccomp_type<'a>(&'a self, c: &'a Container) -> Option<&'a str> {
        c.sc()
            .and_then(|s| s.seccomp_profile.as_ref())
            .or_else(|| self.pod_sc().and_then(|s| s.seccomp_profile.as_ref()))
            .map(|p| p.kind.as_str())
    }
}
