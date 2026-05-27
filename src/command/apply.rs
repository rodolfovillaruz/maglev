use crate::command::play::play_config;
use crate::cp::{ADMIN_KUBECONFIG, ensure_cp_endpoint_resolves};
use crate::ip::IpAddressType;
use crate::provider::{LoadedProvider, load_provider};
use crate::rule::resolve_rules;
use crate::ssh::{ssh_capture, ssh_run};
use crate::state::State;
use crate::utils::{expand_tilde, prompt_yes_no, read_ssh_public_key};
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

    let provider = loaded.provider();

    // Find CP nodes to compute cp_endpoint and primary_cp_ip
    let mut first_cp_merged = None;
    let mut cp_entries: Vec<(String, bool)> = Vec::new();

    for rule in &resolved {
        let prefer_public = rule.merged.ip_address == IpAddressType::Public;
        if rule.group_type == "control-plane" {
            if first_cp_merged.is_none() {
                first_cp_merged = Some(&rule.merged);
            }
            for node in &rule.nodes {
                cp_entries.push((node.clone(), prefer_public));
            }
        }
    }

    let mut primary_cp_name = String::new();
    let mut primary_cp_ip = String::new();

    if let Some((name, prefer_public)) = cp_entries.first() {
        primary_cp_name = name.clone();
        let identifier = state
            .instances
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or(name.as_str());
        if let Ok(ip) = provider.get_vm_ip(identifier, *prefer_public) {
            primary_cp_ip = ip;
        }
    }

    let cp_endpoint = if let Some(merged) = first_cp_merged {
        match &merged.control_plane_endpoint {
            Some(ep) if !ep.trim().is_empty() => {
                let ep = ep.trim().to_string();
                if ep.contains(':') {
                    ep
                } else {
                    format!("{ep}:6443")
                }
            }
            _ => format!("{primary_cp_ip}:6443"),
        }
    } else {
        String::new()
    };

    // Look up provisioner details for Kubernetes node validation and deletion
    let mut provisioner_ip = String::new();
    let mut provisioner_user = String::new();
    let mut provisioner_priv_key = String::new();
    let mut provisioner_node_name = String::new();

    if let Some(prov) = &common.provisioner {
        for r in &resolved {
            if r.nodes.contains(&prov.node) {
                let prefer_public = prov.provisioner_type == "public";
                let target = match &loaded {
                    LoadedProvider::Gcp { .. } => prov.node.as_str(),
                    LoadedProvider::DigitalOcean { .. } => state
                        .instances
                        .get(&prov.node)
                        .map(|s| s.as_str())
                        .unwrap_or(prov.node.as_str()),
                };

                if let Ok(ip) = provider.get_vm_ip(target, prefer_public) {
                    provisioner_ip = ip;
                }
                provisioner_user = r.merged.user.clone();
                provisioner_priv_key = expand_tilde(&r.merged.ssh_public_key.replace(".pub", ""));
                provisioner_node_name = prov.node.clone();
                break;
            }
        }
    } else {
        if let Some(merged) = first_cp_merged {
            provisioner_ip = primary_cp_ip.clone();
            provisioner_user = merged.user.clone();
            provisioner_priv_key = expand_tilde(&merged.ssh_public_key.replace(".pub", ""));
            provisioner_node_name = primary_cp_name.clone();
        }
    }

    if !instances_to_delete.is_empty() || !disks_to_delete.is_empty() {
        println!("\n── Pre-Destruction Checks ───────────────────────────────────────────────");

        // Sync /etc/hosts for the provisioner so it can reach the cluster
        if !provisioner_ip.is_empty() && !cp_endpoint.is_empty() && !primary_cp_ip.is_empty() {
            if let Err(e) = ensure_cp_endpoint_resolves(
                &provisioner_node_name,
                &cp_endpoint,
                &primary_cp_ip,
                auto_approve,
                |cmd| {
                    ssh_capture(
                        &provisioner_ip,
                        &provisioner_user,
                        &provisioner_priv_key,
                        cmd,
                    )
                },
                |cmd| {
                    ssh_run(
                        &provisioner_ip,
                        &provisioner_user,
                        &provisioner_priv_key,
                        cmd,
                    )
                },
            ) {
                eprintln!("  ⚠ Could not synchronize /etc/hosts on provisioner: {e}");
            }
        }

        for node in &instances_to_delete {
            if !provisioner_ip.is_empty() {
                println!("Verifying if node \"{node}\" is connected to the cluster...");
                let check_cmd = format!(
                    "kubectl --kubeconfig {} get node {}",
                    ADMIN_KUBECONFIG, node
                );

                if ssh_capture(
                    &provisioner_ip,
                    &provisioner_user,
                    &provisioner_priv_key,
                    &check_cmd,
                )
                .is_ok()
                {
                    println!("  ✓ Node \"{node}\" is connected to the cluster.");

                    if prompt_yes_no(&format!("Cordon node \"{node}\"?"), auto_approve) {
                        let cordon_cmd =
                            format!("kubectl --kubeconfig {} cordon {}", ADMIN_KUBECONFIG, node);
                        if let Err(e) = ssh_run(
                            &provisioner_ip,
                            &provisioner_user,
                            &provisioner_priv_key,
                            &cordon_cmd,
                        ) {
                            eprintln!("  ⚠ Failed to cordon node \"{node}\": {}", e);
                        }
                    }

                    if prompt_yes_no(&format!("Drain node \"{node}\"?"), auto_approve) {
                        let drain_cmd = format!(
                            "kubectl --kubeconfig {} drain {} --ignore-daemonsets --delete-emptydir-data --force",
                            ADMIN_KUBECONFIG, node
                        );
                        if let Err(e) = ssh_run(
                            &provisioner_ip,
                            &provisioner_user,
                            &provisioner_priv_key,
                            &drain_cmd,
                        ) {
                            eprintln!("  ⚠ Failed to drain node \"{node}\": {}", e);
                        }
                    }

                    if prompt_yes_no(
                        &format!("Delete node \"{node}\" from the cluster?"),
                        auto_approve,
                    ) {
                        let del_cmd = format!(
                            "kubectl --kubeconfig {} delete node {}",
                            ADMIN_KUBECONFIG, node
                        );
                        if let Err(e) = ssh_run(
                            &provisioner_ip,
                            &provisioner_user,
                            &provisioner_priv_key,
                            &del_cmd,
                        ) {
                            eprintln!(
                                "  ⚠ Failed to delete node \"{node}\" from Kubernetes: {}",
                                e
                            );
                        }
                    }
                } else {
                    println!(
                        "  Node \"{node}\" is not connected to the cluster. Proceeding destructively."
                    );
                }
            }
        }

        for disk in &disks_to_delete {
            if let Some(id) = state.disks.get(disk) {
                println!("Checking if disk \"{disk}\" needs to be detached...");
                if let Ok(Some(attached_instance)) = provider.get_disk_attached_instance(id) {
                    println!("Disk \"{disk}\" is attached to instance ID \"{attached_instance}\".");
                    if prompt_yes_no(
                        &format!("Detach disk \"{disk}\" from instance \"{attached_instance}\"?"),
                        auto_approve,
                    ) {
                        println!("Detaching disk \"{disk}\"...");
                        if let Err(e) = provider.detach_disk(id, &attached_instance) {
                            eprintln!("  ⚠ Failed to detach disk {disk}: {e}");
                        } else {
                            println!("Disk \"{disk}\" detached.");
                        }
                    }
                }
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
