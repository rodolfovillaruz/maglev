use crate::IpAddressType;
use crate::utils::string_or_vec;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared YAML types
// ---------------------------------------------------------------------------

/// A named group of node names.
///
/// `group_type` must be `"control-plane"` or `"worker"` and determines how
/// `play` treats the nodes in this group.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GroupYaml {
    pub name: String,
    /// Role of every node in this group.  Accepted values: `"control-plane"`,
    /// `"worker"`.
    #[serde(rename = "type")]
    pub group_type: String,
    pub node: Vec<String>,
}

/// A rule maps one or more group names to an ordered list of spec names.
///
/// The specs are merged left-to-right: later entries win for any field both
/// define.  The merged result must satisfy every required field.
///
/// `group` accepts either a YAML scalar (`group: my-group`) or a YAML
/// sequence (`group: [a, b]`) for maximum authoring convenience.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RuleYaml {
    #[serde(deserialize_with = "string_or_vec")]
    pub group: Vec<String>,
    pub specs: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SpecYaml {
    pub name: String,
    pub config: Vec<GenericsConfigYaml>,
}

/// Optional provisioner node configuration for SSH jumphost routing.
///
/// When defined, specifies which node should be used as a jumphost/ProxyJump
/// target for provisioning other nodes (typically nodes with private IPs).
///
/// `type` — `"public"` or `"private"` determines which IP type to use from
/// the provisioner node.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ProvisionerYaml {
    #[serde(rename = "type")]
    pub provisioner_type: String,
    pub node: String,
}

/// A unified spec entry.  All fields are optional so that multiple spec
/// entries can be **merged** by a rule: a base spec (e.g. `cisak`) provides
/// the common fields (user, script, SSH key, machine type, image) while a
/// role-specific spec (e.g. `control-plane-public`) contributes only the
/// fields that differ (disk size, ip-address).
///
/// After merging, every required field must be present or `resolve_rules`
/// returns an error.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GenericsConfigYaml {
    // ── generics-origin fields ──────────────────────────────────────────────
    #[serde(
        rename = "ssh-public-key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssh_public_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Optional stable address for the Kubernetes API server load-balancer.
    /// Format: `<host>` or `<host>:<port>` (port defaults to 6443).
    #[serde(
        rename = "control-plane-endpoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub control_plane_endpoint: Option<String>,

    // ── new ────────────────────────────────────────────────────────────────
    #[serde(rename = "apiServer", default)]
    pub api_server: Option<ApiServerConfigYaml>,

    // ── specs-origin fields ─────────────────────────────────────────────────
    #[serde(
        rename = "machine-type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub machine_type: Option<String>,

    #[serde(
        rename = "boot-disk-image",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_disk_image: Option<String>,

    #[serde(
        rename = "boot-disk-size",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_disk_size: Option<u64>,

    /// When absent, defaults to `private` after merging.
    #[serde(
        rename = "ip-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ip_address: Option<IpAddressType>,
}

// ---------------------------------------------------------------------------
// Unified view of a loaded config (provider-agnostic body + typed creds)
// ---------------------------------------------------------------------------

pub struct CommonConfig {
    pub groups: Vec<GroupYaml>,
    pub specs: Vec<SpecYaml>,
    pub rules: Vec<RuleYaml>,
    pub provisioner: Option<ProvisionerYaml>,
}

#[derive(Debug, Clone, Deserialize, Default, Serialize)]
pub struct ApiServerConfigYaml {
    /// Additional Subject Alternative Names for the API-server TLS certificate.
    #[serde(rename = "certSANs", default)]
    pub cert_sans: Vec<String>,
}

// ---------------------------------------------------------------------------
// Spec merging
// ---------------------------------------------------------------------------

/// The fully resolved, non-optional view of a node's configuration produced
/// by merging one or more [`SpecConfigYaml`] entries left-to-right.
///
/// Every field is required; `merge_spec_configs` returns an error when any
/// mandatory field is absent after the merge pass.
#[derive(Debug, Clone)]
pub struct MergedSpec {
    pub machine_type: String,
    pub boot_disk_image: String,
    pub boot_disk_size: u64,
    /// Defaults to [`IpAddressType::Private`] when no spec sets it.
    pub ip_address: IpAddressType,
    pub ssh_public_key: String,
    pub script: String,
    pub user: String,
    pub control_plane_endpoint: Option<String>,
    /// Union of all `apiServer.certSANs` entries from every spec layer that
    /// contributed to this node.  Order is preserved; duplicates are removed
    /// on first-seen basis.  Empty when no spec defines certSANs.
    pub cert_sans: Vec<String>,
}
