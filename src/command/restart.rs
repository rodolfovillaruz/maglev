use crate::ip::IpAddressType;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::ssh::{ssh_run, ssh_run_jump};
use crate::state::State;
use crate::utils::{expand_tilde, prompt_yes_no};
use std::thread;

// ---------------------------------------------------------------------------
// `restart` subcommand
// ---------------------------------------------------------------------------

pub fn restart_config(
    config_path: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Restart ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    // Load state to map node names to instance IDs
    let state = State::load(config_path);

    // Collect all nodes (both control-plane and worker)
    let mut all_nodes: Vec<(String, bool)> = Vec::new(); // (node_name, prefer_public)

    for rule in &resolved {
        let prefer_public = rule.merged.ip_address == IpAddressType::Public;
        for node in &rule.nodes {
            all_nodes.push((node.clone(), prefer_public));
        }
    }

    if all_nodes.is_empty() {
        println!("  No nodes found in config.");
        return Ok(());
    }

    // Get SSH credentials from the first control-plane rule
    let first_cp_spec = resolved
        .iter()
        .find(|r| r.group_type == "control-plane")
        .ok_or("No control-plane rules found in config")?
        .merged
        .clone();

    let ssh_user = first_cp_spec.user.clone();
    let ssh_pub_path = first_cp_spec.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    // Fetch IPs
    println!("\n── Nodes to restart ─────────────────────────────────────────────────────");
    println!("Fetching IPs …\n");

    let nodes_with_ips: Vec<(String, String, bool)> = all_nodes
        .iter()
        .map(|(name, prefer_public)| {
            let instance_id = state.instances.get(name).ok_or_else(|| {
                format!(
                    "No instance ID found for node '{}' in state. Run 'apply' first.",
                    name
                )
            })?;
            let ip = provider.get_vm_ip(instance_id, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip, *prefer_public))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    println!("\n  SSH user: {ssh_user}  private key: {ssh_priv_path}");
    println!("⚠  All nodes will be rebooted. Services will be temporarily unavailable.");

    if !prompt_yes_no("\nProceed with restarting all nodes?", auto_approve) {
        println!("Aborted.");
        return Ok(());
    }

    // Determine primary control-plane IP for jumphost usage
    let primary_cp_ip = nodes_with_ips
        .iter()
        .find(|(_, _, pp)| *pp)
        .map(|(_, ip, _)| ip.clone())
        .or_else(|| nodes_with_ips.first().map(|(_, ip, _)| ip.clone()))
        .ok_or("No nodes available")?;

    // Precompute whether any node has a public IP (needed for jump logic)
    let has_public_node = nodes_with_ips.iter().any(|(_, _, pp)| *pp);

    // Restart all nodes in parallel
    println!("\nSending reboot signals to all nodes in parallel …");

    thread::scope(|s| {
        let handles: Vec<_> = nodes_with_ips
            .iter()
            .map(|(name, ip, prefer_public)| {
                let name = name.clone();
                let ip = ip.clone();
                let ssh_user = ssh_user.clone();
                let ssh_priv_path = ssh_priv_path.clone();
                let primary_cp_ip = primary_cp_ip.clone();
                s.spawn(move || {
                    let needs_jump = !prefer_public && has_public_node;
                    let result = if needs_jump {
                        ssh_run_jump(
                            &primary_cp_ip,
                            &ssh_user,
                            &ip,
                            &ssh_user,
                            &ssh_priv_path,
                            "sudo reboot",
                        )
                    } else {
                        ssh_run(&ip, &ssh_user, &ssh_priv_path, "sudo reboot")
                    };
                    (name, result.map_err(|e| e.to_string()))
                })
            })
            .collect();

        for handle in handles {
            let (name, result) = handle.join().unwrap();
            match result {
                Ok(()) => println!("  ✓ {name} reboot initiated."),
                Err(e) if e.contains("status") || e.contains("exited") => {
                    println!("  ✓ {name} reboot initiated (connection closed).")
                }
                Err(e) => eprintln!("  ✗ Failed to restart {name}: {e}"),
            }
        }
    });

    println!("\n✓ Restart signals sent to all nodes.");
    println!("  Nodes will be available again in 1-2 minutes.");
    Ok(())
}
