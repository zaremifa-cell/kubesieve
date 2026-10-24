//! kubesieve — a static security scanner for Kubernetes manifests.
//!
//! The pipeline is: [`loader`] reads YAML into resources → [`scan`] runs every rule from
//! [`rules`] against them → a [`report`] format renders the findings.

pub mod loader;
pub mod model;
pub mod report;
pub mod rules;
pub mod scan;
pub mod workload;
