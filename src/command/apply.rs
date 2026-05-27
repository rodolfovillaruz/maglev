use crate::command::play::play_config;
use crate::ip::IpAddressType;
use crate::provider::{LoadedProvider, load_provider};
use crate::rule::resolve_rules;
use crate::state::State;
use crate::utils::{prompt_yes_no, read_ssh_public_key};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

pub fn apply_config(
    config_path: &str,
    play: bool,
    auto_approve: bool,
    force_ha: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    // 1. Load state file for this config
    let mut state = State::load(config_path);

    // Compute desired instances
    let mut desired_instances = HashSet::new();
    for r in &resolved {
        for node in &r.nodes {
            desired_instances.insert(node.clone());
        }
    }

    // Compute desired disks
    let mut desired_disks = HashSet::new();
    if let Some(disks) = &common.disks {
        for disk in disks {
            desired_disks.insert(disk.name.clone());
        }
    }

    // Find instances to delete
    let state_instances: HashSet<String> = state.instances.keys().cloned().collect();
    let mut instances_to_delete: Vec<String> = state_instances
        .difference(&desired_instances)
        .cloned()
        .collect();
    instances_to_delete.sort();

    // Find instances to create
    let mut total_to_create = 0usize;
    for r in &resolved {
        for node in &r.nodes {
            if !state.instances.contains_key(node) {
                total_to_create += 1;
            }
        }
    }

    // Find disks to delete
    let state_disks: HashSet<String> = state.disks.keys().cloned().collect();
    let mut disks_to_delete: Vec<String> =
        state_disks.difference(&desired_disks).cloned().collect();
    disks_to_delete.sort();

    // Find disks to create
    let mut total_disks_to_create = 0usize;
    if let Some(disks) = &common.disks {
        for disk in disks {
            if !state.disks.contains_key(&disk.name) {
                total_disks_to_create += 1;
            }
        }
    }

    println!("\n── Execution Plan ───────────────────────────────────────────────────────");

    let mut has_changes = false;

    if !instances_to_delete.is_empty() {
        println!("Instances to destroy:");
        for node in &instances_to_delete {
            let id = state.instances.get(node).unwrap();
            println!("  - {node} (ID: {id})");
        }
        has_changes = true;
    }

    if total_to_create > 0 {
        println!("Instances to create:");
        for r in &resolved {
            for node in &r.nodes {
                if !state.instances.contains_key(node) {
                    println!(
                        "  + {node} (Type: {}, Image: {})",
                        r.merged.machine_type, r.merged.boot_disk_image
                    );
                }
            }
        }
        has_changes = true;
    }

    if !disks_to_delete.is_empty() {
        println!("Disks to destroy:");
        for disk in &disks_to_delete {
            let id = state.disks.get(disk).unwrap();
            println!("  - {disk} (ID: {id})");
        }
        has_changes = true;
    }

    if total_disks_to_create > 0 {
        println!("Disks to create & attach:");
        if let Some(disks) = &common.disks {
            for disk in disks {
                if !state.disks.contains_key(&disk.name) {
                    println!(
                        "  + {} (Size: {}GB, Node: {})",
                        disk.name, disk.size, disk.node
                    );
                }
            }
        }
        has_changes = true;
    }

    if !has_changes {
        println!("All nodes and disks are already in the desired state. Nothing to do.");
    } else {
        println!(
            "\nSummary: {} instances to create, {} instances to destroy, {} disks to create, {} disks to destroy.",
            total_to_create,
            instances_to_delete.len(),
            total_disks_to_create,
            disks_to_delete.len()
        );

        let prompt_msg = "\nProceed with these changes?";
        if !auto_approve && !prompt_yes_no(prompt_msg, auto_approve) {
            println!("Aborted.");
            return Ok(());
        }
    }

    let provider = loaded.provider();

    // 2. Destroy disks
    if !disks_to_delete.is_empty() {
        println!("\n── Destroying Disks ─────────────────────────────────────────────────────");
        for disk in &disks_to_delete {
            let id = state.disks.get(disk).unwrap();
            println!("Destroying disk \"{disk}\" (ID: {id})...");
            if let Err(e) = provider.destroy_disk(id) {
                eprintln!("  ⚠ Failed to destroy disk {disk}: {e}");
            } else {
                println!("Disk \"{disk}\" destroyed.");
                state.disks.remove(disk);
                state.save(config_path)?;
            }
        }
    }

    // 3. Destroy instances
    if !instances_to_delete.is_empty() {
        println!("\n── Destroying Instances ─────────────────────────────────────────────────");
        for node in &instances_to_delete {
            let id = state.instances.get(node).unwrap();

            // GCP expects the instance name; DigitalOcean expects the droplet ID
            let target = match &loaded {
                LoadedProvider::Gcp { .. } => node,
                LoadedProvider::DigitalOcean { .. } => id,
            };

            println!("Destroying instance \"{node}\"...");
            if let Err(e) = provider.destroy_vm(target) {
                eprintln!("  ⚠ Failed to destroy instance {node}: {e}");
            } else {
                println!("Instance \"{node}\" destroyed.");
                state.instances.remove(node);
                state.save(config_path)?;
            }
        }
    }

    // 4. Create instances
    let mut created_count = 0usize;
    if total_to_create > 0 {
        println!("\n── Creating Instances ───────────────────────────────────────────────────");
        for r in &resolved {
            let ssh_meta = read_ssh_public_key(&r.merged.ssh_public_key)
                .map(|k| format!("{}:{k}", r.merged.user))
                .unwrap_or_else(|e| {
                    eprintln!("  ⚠ Could not read SSH public key: {e}");
                    String::new()
                });

            let assign_public_ip = r.merged.ip_address == IpAddressType::Public;

            for node in &r.nodes {
                if state.instances.contains_key(node) {
                    continue;
                }

                println!("\nCreating instance \"{node}\"...");
                let response = provider.create_vm(
                    node,
                    &r.merged.machine_type,
                    &r.merged.boot_disk_image,
                    &ssh_meta,
                    &r.merged.script,
                    assign_public_ip,
                )?;

                let mut id_str = response.to_string();

                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&id_str) {
                    if let Some(id_val) = parsed.pointer("/droplet/id") {
                        if let Some(num) = id_val.as_u64() {
                            id_str = num.to_string();
                        } else if let Some(s) = id_val.as_str() {
                            id_str = s.to_string();
                        }
                    }
                }

                println!("Instance \"{node}\" created with ID: {}", id_str);

                state.instances.insert(node.clone(), id_str);
                state.save(config_path)?;

                created_count += 1;
            }
        }
        println!("\n✓ {created_count} VM creation request(s) submitted successfully.");
    }

    // 5. Create and attach disks
    if total_disks_to_create > 0 {
        println!("\n── Creating & Attaching Disks ───────────────────────────────────────────");
        let mut created_disks = 0usize;
        if let Some(disks) = &common.disks {
            for disk in disks {
                if state.disks.contains_key(&disk.name) {
                    continue;
                }

                println!("\nCreating disk \"{}\"...", disk.name);
                let disk_id = provider.create_disk(&disk.name, disk.size)?;
                println!("Disk \"{}\" created with ID: {}", disk.name, disk_id);

                state.disks.insert(disk.name.clone(), disk_id.clone());
                state.save(config_path)?;
                created_disks += 1;

                if let Some(instance_id) = state.instances.get(&disk.node) {
                    println!(
                        "Attaching disk \"{}\" to node \"{}\"...",
                        disk.name, disk.node
                    );
                    if let Err(e) = provider.attach_disk(&disk_id, instance_id) {
                        eprintln!("  ⚠ Failed to attach disk \"{}\": {}", disk.name, e);
                    } else {
                        println!("Successfully requested attach for \"{}\".", disk.name);
                    }
                } else {
                    println!(
                        "⚠ Cannot attach disk \"{}\": Target node \"{}\" not found in state.",
                        disk.name, disk.node
                    );
                }
            }
        }
        println!("\n✓ {created_disks} disk(s) created and attachment requested.");
    }

    if play {
        println!("\n── --play flag set: handing off to play ────────────────────────────────");
        play_config(config_path, auto_approve, false, force_ha)?;
    }

    Ok(())
}
