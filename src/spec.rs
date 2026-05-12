use crate::IpAddressType;
use crate::SpecConfigYaml;
use std::collections::HashMap;
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
}

/// Merge `spec_names` (in order) from `specs_map` into a single
/// [`MergedSpec`].  Later entries override earlier ones for any field both
/// define.
pub fn merge_spec_configs(
    spec_names: &[String],
    specs_map: &HashMap<&str, &SpecConfigYaml>,
) -> Result<MergedSpec, Box<dyn std::error::Error>> {
    let mut machine_type: Option<String> = None;
    let mut boot_disk_image: Option<String> = None;
    let mut boot_disk_size: Option<u64> = None;
    let mut ip_address: Option<IpAddressType> = None;
    let mut ssh_public_key: Option<String> = None;
    let mut script: Option<String> = None;
    let mut user: Option<String> = None;
    let mut control_plane_endpoint: Option<String> = None;

    for name in spec_names {
        let cfg = specs_map
            .get(name.as_str())
            .ok_or_else(|| format!("Rule references unknown spec '{name}'"))?;

        if let Some(v) = &cfg.machine_type {
            machine_type = Some(v.clone());
        }
        if let Some(v) = &cfg.boot_disk_image {
            boot_disk_image = Some(v.clone());
        }
        if let Some(v) = cfg.boot_disk_size {
            boot_disk_size = Some(v);
        }
        if let Some(v) = cfg.ip_address {
            ip_address = Some(v);
        }
        if let Some(v) = &cfg.ssh_public_key {
            ssh_public_key = Some(v.clone());
        }
        if let Some(v) = &cfg.script {
            script = Some(v.clone());
        }
        if let Some(v) = &cfg.user {
            user = Some(v.clone());
        }
        if let Some(v) = &cfg.control_plane_endpoint {
            control_plane_endpoint = Some(v.clone());
        }
    }

    Ok(MergedSpec {
        machine_type: machine_type
            .ok_or_else(|| format!("No 'machine-type' found after merging specs {spec_names:?}"))?,
        boot_disk_image: boot_disk_image.ok_or_else(|| {
            format!("No 'boot-disk-image' found after merging specs {spec_names:?}")
        })?,
        boot_disk_size: boot_disk_size.ok_or_else(|| {
            format!("No 'boot-disk-size' found after merging specs {spec_names:?}")
        })?,
        ip_address: ip_address.unwrap_or_default(),
        ssh_public_key: ssh_public_key.ok_or_else(|| {
            format!("No 'ssh-public-key' found after merging specs {spec_names:?}")
        })?,
        script: script
            .ok_or_else(|| format!("No 'script' found after merging specs {spec_names:?}"))?,
        user: user.ok_or_else(|| format!("No 'user' found after merging specs {spec_names:?}"))?,
        control_plane_endpoint,
    })
}
