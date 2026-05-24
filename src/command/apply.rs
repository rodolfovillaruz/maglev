use crate::command::play::play_config;
use crate::ip::IpAddressType;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::state::State;
use crate::utils::{prompt_yes_no, read_ssh_public_key};

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

    // 1. Load state file for this config (e.g., digitalocean.yaml.state)
    let mut state = State::load(config_path);

    println!("\n── Nodes to create ──────────────────────────────────────────────────────");
    let mut total_to_create = 0usize;
    for r in &resolved {
        println!(
            "\n  groups: [{}]  type: {}  (specs: [{}])",
            r.group_names.join(", "),
            r.group_type,
            r.generic_names.join(", "),
        );
        println!(
            "    machine-type: {}  image: {}  ip-address: {}",
            r.merged.machine_type, r.merged.boot_disk_image, r.merged.ip_address,
        );
        println!(
            "    user: {}  ssh-public-key: {}",
            r.merged.user, r.merged.ssh_public_key
        );
        for node in &r.nodes {
            // Check state: Skip instances already in state
            if let Some(id) = state.instances.get(node) {
                println!("      • {node} (Skipping: Already exists in state with ID: {id})");
            } else {
                println!("      • {node}");
                total_to_create += 1;
            }
        }
    }

    if total_to_create == 0 {
        println!("\nAll nodes are already present in the state file. Nothing new to create.");
    } else {
        // Updated to respect auto_approve
        let prompt_msg = format!("\nProceed with creating {total_to_create} new VM instance(s)?");
        if !auto_approve && !prompt_yes_no(&prompt_msg, auto_approve) {
            println!("Aborted.");
            return Ok(());
        }
    }

    let provider = loaded.provider();
    let mut created_count = 0usize;

    for r in &resolved {
        if total_to_create == 0 {
            break; // Quick circuit break if nothing to do
        }

        println!(
            "\n── Groups: [{}] ({}) ─────────────────────────────────────────────────────",
            r.group_names.join(", "),
            r.group_type,
        );

        let ssh_meta = read_ssh_public_key(&r.merged.ssh_public_key)
            .map(|k| format!("{}:{k}", r.merged.user))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });

        let assign_public_ip = r.merged.ip_address == IpAddressType::Public;

        for node in &r.nodes {
            // 2. Before creating, check state again to be safe
            if let Some(id) = state.instances.get(node) {
                println!("\nInstance \"{node}\" already created (ID: {id}), skipping.");
                continue;
            }

            // 3. Create the instance.
            // If it exists in DO but not in state, the cloud provider will throw a Conflict Error here (Fulfilling the "throw an error" condition).
            let response = provider.create_vm(
                node,
                &r.merged.machine_type,
                &r.merged.boot_disk_image,
                &ssh_meta,
                &r.merged.script,
                assign_public_ip,
            )?;

            let mut id_str = response.to_string();

            // Try to extract the instance ID if the response is JSON (e.g., DigitalOcean API response)
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&id_str) {
                // Target the specific "droplet.id" field for DigitalOcean
                if let Some(id_val) = parsed.pointer("/droplet/id") {
                    if let Some(num) = id_val.as_u64() {
                        id_str = num.to_string();
                    } else if let Some(s) = id_val.as_str() {
                        id_str = s.to_string();
                    }
                }
            }

            println!("\nInstance \"{node}\" created with ID: {}", id_str);

            // 4. Register mapping immediately and flush to disk
            state.instances.insert(node.clone(), id_str);
            state.save(config_path)?;

            created_count += 1;
        }
    }

    println!("\n✓ {created_count} VM creation request(s) submitted successfully.");

    // 5. Provision and Attach Disks
    if let Some(disks) = &common.disks {
        if !disks.is_empty() {
            println!(
                "\n── Disks to create & attach ──────────────────────────────────────────────"
            );
            let mut total_disks = 0usize;
            for disk in disks {
                if let Some(disk_id) = state.disks.get(&disk.name) {
                    println!(
                        "  • {} (Skipping: Already exists in state with ID: {})",
                        disk.name, disk_id
                    );
                } else {
                    println!(
                        "  • {} (Size: {}GB, Target Node: {})",
                        disk.name, disk.size, disk.node
                    );
                    total_disks += 1;
                }
            }

            if total_disks > 0 {
                let prompt_msg =
                    format!("\nProceed with creating and attaching {total_disks} new disk(s)?");
                if !auto_approve && !prompt_yes_no(&prompt_msg, auto_approve) {
                    println!("Skipping disk creation.");
                } else {
                    let mut created_disks = 0usize;
                    for disk in disks {
                        if state.disks.contains_key(&disk.name) {
                            continue;
                        }

                        // Create
                        println!("\nCreating disk \"{}\"...", disk.name);
                        let disk_id = provider.create_disk(&disk.name, disk.size)?;
                        println!("Disk \"{}\" created with ID: {}", disk.name, disk_id);

                        state.disks.insert(disk.name.clone(), disk_id.clone());
                        state.save(config_path)?;
                        created_disks += 1;

                        // Attach
                        if let Some(instance_id) = state.instances.get(&disk.node) {
                            println!(
                                "Attaching disk \"{}\" to node \"{}\"...",
                                disk.name, disk.node
                            );
                            provider.attach_disk(&disk_id, instance_id)?;
                            println!("Successfully requested attach for \"{}\".", disk.name);
                        } else {
                            println!(
                                "⚠ Cannot attach disk \"{}\": Target node \"{}\" not found in state.",
                                disk.name, disk.node
                            );
                        }
                    }
                    println!("\n✓ {created_disks} disk(s) created and attachment requested.");
                }
            } else {
                println!("\nAll disks are already present in the state file.");
            }
        }
    }

    if play {
        println!("\n── --play flag set: handing off to play ────────────────────────────────");
        // Pass force_ha down to play_config
        play_config(config_path, auto_approve, false, force_ha)?;
    }

    Ok(())
}
