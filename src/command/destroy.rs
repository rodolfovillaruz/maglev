use crate::provider::load_provider;
use crate::state::State;
use crate::utils::prompt_yes_no;

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

pub fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    // 1. Load the state to retrieve instance IDs.
    // DigitalOcean requires the Droplet ID (stored in state) disguised as the name to destroy.
    let mut state = State::load(config_path);

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    println!("\n── Instances to destroy ─────────────────────────────────────────────────");

    let mut all_nodes: Vec<(&str, &str, &str)> = Vec::new(); // (group_name, group_type, node)
    for group in &common.groups {
        for node in &group.node {
            println!("  [{}] {}  →  {}", group.group_type, group.name, node);
            all_nodes.push((&group.name, &group.group_type, node));
        }
    }

    let total = all_nodes.len();
    println!();
    println!("⚠  This action is IRREVERSIBLE. All {total} VM instance(s) and their boot");
    println!("   disks will be permanently deleted.");

    if !prompt_yes_no("\nProceed with destroying all VM instances?") {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    let provider = loaded.provider();

    for (group_name, group_type, node) in &all_nodes {
        // Look up the ID in the state file. If present, pass it as the target.
        // Otherwise, fallback to the original node name (e.g., for GCP which doesn't use state IDs).
        let target = match state.instances.get(*node) {
            Some(id) => id.as_str(),
            None => *node,
        };

        match provider.destroy_vm(target) {
            Ok(_) => {
                println!("\n[{group_type}/{group_name}] {node} deleted");
                state.instances.remove(*node);
            }
            Err(e) => {
                // Gracefully handle 404 Not Found (already deleted)
                if e.to_string().contains("404") {
                    println!("\n[{group_type}/{group_name}] {node} not found (already deleted)");
                    state.instances.remove(*node);
                } else {
                    eprintln!("  ✗ Failed to delete {node}: {e}");
                }
            }
        }
    }

    // 2. Save updated state (removing destroyed instances) so apply works cleanly next time
    if let Err(e) = state.save(config_path) {
        eprintln!("\n⚠ Failed to save state file updates: {e}");
    }

    println!("\n✓ Deletion requests submitted. Operations may take a minute to complete.");
    Ok(())
}
