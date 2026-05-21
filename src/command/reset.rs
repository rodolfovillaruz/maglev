use crate::ip::IpAddressType;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::ssh::{ssh_run, ssh_run_jump};
use crate::utils::{expand_tilde, prompt_yes_no};

// ---------------------------------------------------------------------------
// `reset` subcommand
// ---------------------------------------------------------------------------

pub fn reset_config(
    config_path: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Reset ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

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

    let ssh_user = &first_cp_spec.user;
    let ssh_pub_path = first_cp_spec.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    // Fetch IPs
    println!("\n── Nodes to reset ───────────────────────────────────────────────────────");
    println!("Fetching IPs …\n");

    let nodes_with_ips: Vec<(String, String, bool)> = all_nodes
        .iter()
        .map(|(name, prefer_public)| {
            let ip = provider.get_vm_ip(name, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip, *prefer_public))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    println!("\n  SSH user: {ssh_user}  private key: {ssh_priv_path}");
    println!("\n⚠  This will reset kubeadm state on all nodes. Any clusters will be destroyed.");

    if !prompt_yes_no("\nProceed with kubeadm reset on all nodes?", auto_approve) {
        println!("Aborted.");
        return Ok(());
    }

    let primary_cp_ip = nodes_with_ips
        .iter()
        .find(|(_, _, pp)| *pp)
        .map(|(_, ip, _)| ip.clone())
        .or_else(|| nodes_with_ips.first().map(|(_, ip, _)| ip.clone()))
        .ok_or("No nodes available")?;

    // Reset each node
    for (idx, (name, ip, prefer_public)) in nodes_with_ips.iter().enumerate() {
        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, nodes_with_ips.len());

        if !prompt_yes_no(&format!("  Reset {name}?"), auto_approve) {
            println!("  Skipped.");
            continue;
        }

        let needs_jump = !prefer_public && nodes_with_ips.iter().find(|(_, _, pp)| *pp).is_some();

        let reset_cmd = "sudo kubeadm reset -f && \
                        sudo rm -rf /etc/cni /etc/kubernetes /var/lib/etcd /var/lib/kubelet";

        println!("  Running kubeadm reset …");
        let result = if needs_jump {
            ssh_run_jump(
                &primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                reset_cmd,
            )
        } else {
            ssh_run(ip, ssh_user, &ssh_priv_path, reset_cmd)
        };

        match result {
            Ok(()) => println!("  ✓ {name} reset."),
            Err(e) => eprintln!("  ✗ Failed to reset {name}: {e}"),
        }
    }

    println!("\n✓ Reset complete. All nodes have been reset to clean state.");
    Ok(())
}
