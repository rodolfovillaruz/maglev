use crate::provider::load_provider;
use crate::state::State;
use crate::utils::prompt_yes_no;

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

pub fn destroy_config(
    config_path: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    // 1. Load the state to retrieve instance and disk IDs.
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

    let total_vms = all_nodes.len();
    let total_disks = state.disks.len();

    println!();
    println!("⚠  This action is IRREVERSIBLE. {total_vms} VM instance(s) and {total_disks}");
    println!("   attached disk(s) will be permanently deleted.");

    if !prompt_yes_no(
        "\nProceed with destroying all VM instances and disks?",
        auto_approve,
    ) {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    let provider = loaded.provider();

    if !state.disks.is_empty() {
        println!("\n── Pre-Destruction Checks ───────────────────────────────────────────────");

        let disks_to_delete: Vec<(String, String)> = state.disks.clone().into_iter().collect();
        for (disk_name, disk_id) in disks_to_delete {
            println!("Checking if disk \"{disk_name}\" needs to be detached...");
            if let Ok(Some(attached_instance)) = provider.get_disk_attached_instance(&disk_id) {
                println!(
                    "Disk \"{disk_name}\" is attached to instance ID \"{attached_instance}\"."
                );
                if prompt_yes_no(
                    &format!("Detach disk \"{disk_name}\" from instance \"{attached_instance}\"?"),
                    auto_approve,
                ) {
                    println!("Detaching disk \"{disk_name}\"...");
                    if let Err(e) = provider.detach_disk(&disk_id, &attached_instance) {
                        eprintln!("  ⚠ Failed to detach disk {disk_name}: {e}");
                    } else {
                        println!("Disk \"{disk_name}\" detached.");
                    }
                }
            }
        }
    }

    // 2. Destroy VMs first (This implicitly detaches disks in most cloud providers)
    for (group_name, group_type, node) in &all_nodes {
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
                if e.to_string().contains("404") {
                    println!("\n[{group_type}/{group_name}] {node} not found (already deleted)");
                    state.instances.remove(*node);
                } else {
                    eprintln!("  ✗ Failed to delete {node}: {e}");
                }
            }
        }
    }

    // 3. Destroy Disks tracked in state
    if !state.disks.is_empty() {
        println!("\n── Disks to destroy ─────────────────────────────────────────────────────");

        // Clone into a separate collection so we can mutate `state.disks` during iteration
        let disks_to_delete: Vec<(String, String)> = state.disks.clone().into_iter().collect();

        for (disk_name, disk_id) in disks_to_delete {
            match provider.destroy_disk(&disk_id) {
                Ok(_) => {
                    println!("  [Disk] {disk_name} deleted");
                    state.disks.remove(&disk_name);
                }
                Err(e) => {
                    if e.to_string().contains("404") {
                        println!("  [Disk] {disk_name} not found (already deleted)");
                        state.disks.remove(&disk_name);
                    } else {
                        eprintln!("  ✗ Failed to delete disk {disk_name}: {e}");
                    }
                }
            }
        }
    }

    // 4. Save updated state (removing destroyed instances & disks)
    if let Err(e) = state.save(config_path) {
        eprintln!("\n⚠ Failed to save state file updates: {e}");
    }

    println!("\n✓ Deletion requests submitted. Operations may take a minute to complete.");
    Ok(())
}
