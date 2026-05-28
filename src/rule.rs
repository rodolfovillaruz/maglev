use crate::GenericsConfigYaml;
use crate::structs::CommonConfig;
use crate::structs::CommonMergedSpec;
use crate::utils::common_merge_spec_configs;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Rule resolution (provider-agnostic)
// ---------------------------------------------------------------------------

/// The fully resolved view of a single rule: group metadata, the ordered list
/// of spec names, all node names collected from the referenced groups, and the
/// merged spec ready for use.
pub struct CommonResolvedRule {
    /// Names of every group referenced by this rule.
    #[allow(dead_code)]
    pub group_names: Vec<String>,
    /// The shared `type` of all groups in this rule (`"control-plane"` /
    /// `"worker"`).
    pub group_type: String,
    /// Names of every spec referenced by this rule (merge order).
    #[allow(dead_code)]
    pub generic_names: Vec<String>,
    /// Every node name collected from all referenced groups.
    pub nodes: Vec<String>,
    /// Result of merging all referenced specs left-to-right.
    pub merged: CommonMergedSpec,
}

pub fn resolve_rules(
    common: &CommonConfig,
) -> Result<Vec<CommonResolvedRule>, Box<dyn std::error::Error>> {
    // Index groups by name → (type, nodes)
    let groups: HashMap<&str, (&str, &[String])> = common
        .groups
        .iter()
        .map(|g| (g.name.as_str(), (g.group_type.as_str(), g.node.as_slice())))
        .collect();

    // Index specs by name → first config entry
    let specs_map: HashMap<&str, &GenericsConfigYaml> = common
        .generics
        .iter()
        .filter_map(|s| s.config.first().map(|c| (s.name.as_str(), c)))
        .collect();

    common
        .rules
        .iter()
        .map(|rule| {
            // Collect nodes and validate that all groups share the same type
            let mut nodes: Vec<String> = Vec::new();
            let mut resolved_type: Option<&str> = None;

            for gname in &rule.group {
                let (gtype, gnodes) = groups
                    .get(gname.as_str())
                    .ok_or_else(|| format!("Rule references unknown group '{gname}'"))?;

                if let Some(existing) = resolved_type {
                    if existing != *gtype {
                        return Err(format!(
                            "Rule mixes groups of different types: \
                             '{existing}' (previous) vs '{gtype}' ('{gname}')"
                        )
                        .into());
                    }
                } else {
                    resolved_type = Some(gtype);
                }

                nodes.extend(gnodes.iter().cloned());
            }

            let group_type = resolved_type
                .ok_or_else(|| "Rule has an empty group list".to_string())?
                .to_string();

            // Merge specs
            let merged = common_merge_spec_configs(&rule.generics, &specs_map)?;

            Ok(CommonResolvedRule {
                group_names: rule.group.clone(),
                group_type,
                generic_names: rule.generics.clone(),
                nodes,
                merged,
            })
        })
        .collect()
}
