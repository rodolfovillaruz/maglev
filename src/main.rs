mod cp;
mod ip;
mod play;
mod provider;
mod rule;
mod spec;
mod ssh;
mod utils;
mod yaml;

use ip::IpAddressType;
use play::play_config;
use rule::resolve_rules;
use ssh::{ssh_capture, ssh_capture_jump, ssh_run, ssh_run_jump};
use yaml::{SpecConfigYaml, SpecYaml};

use clap::{Parser, Subcommand};

use cp::{provision_cilium, provision_control_plane_node};
use provider::{gcp::print_build_credential, load_provider};

use utils::{expand_tilde, prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Maglev — multi-cloud Kubernetes cluster manager
#[derive(Parser)]
#[command(
    name = "maglev",
    version,
    about = "Provision and manage cloud-backed Kubernetes clusters"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create VM instances described by a provider YAML config
    Apply {
        /// Path to the YAML config file (gcp.yaml or digitalocean.yaml)
        config: String,
    },
    /// Permanently delete VM instances described by a provider YAML config
    Destroy {
        /// Path to the YAML config file
        config: String,
    },
    /// Provision Kubernetes on control-plane nodes and join workers
    Play {
        /// Path to the YAML config file
        config: String,
    },
    /// Reset kubeadm state on all nodes
    Reset {
        /// Path to the YAML config file
        config: String,
    },
    /// Restart (reboot) all nodes
    Restart {
        /// Path to the YAML config file
        config: String,
    },
    /// Run the interactive GCP credential builder
    Print,
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    println!("\n── Nodes to create ──────────────────────────────────────────────────────");
    let mut total = 0usize;
    for r in &resolved {
        println!(
            "\n  groups: [{}]  type: {}  (specs: [{}])",
            r.group_names.join(", "),
            r.group_type,
            r.spec_names.join(", "),
        );
        println!(
            "    machine-type: {}  image: {}  disk: {} GB  ip-address: {}",
            r.merged.machine_type,
            r.merged.boot_disk_image,
            r.merged.boot_disk_size,
            r.merged.ip_address,
        );
        println!(
            "    user: {}  ssh-public-key: {}",
            r.merged.user, r.merged.ssh_public_key
        );
        for node in &r.nodes {
            println!("      • {node}");
            total += 1;
        }
    }

    if !prompt_yes_no(&format!("\nProceed with creating {total} VM instance(s)?")) {
        println!("Aborted.");
        return Ok(());
    }

    let provider = loaded.provider();

    for r in &resolved {
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
            println!("\n  ── Creating instance: {node} ──");
            let resp = provider.create_vm(
                node,
                &r.merged.machine_type,
                &r.merged.boot_disk_image,
                r.merged.boot_disk_size,
                &ssh_meta,
                &r.merged.script,
                assign_public_ip,
            )?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    println!("\n✓ All {total} VM creation request(s) submitted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

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
        println!("\n  ── Deleting [{group_type}/{group_name}] {node} ──");
        match provider.destroy_vm(node) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {node}: {e}"),
        }
    }

    println!("\n✓ Deletion requests submitted. Operations may take a minute to complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Apply { config } => apply_config(&config),
        Commands::Destroy { config } => destroy_config(&config),
        Commands::Play { config } => play_config(&config),
        Commands::Reset { config } => reset_config(&config),
        Commands::Restart { config } => restart_config(&config),
        Commands::Print => print_build_credential(),
    }
}

// ---------------------------------------------------------------------------
// Control-plane endpoint guard
// ---------------------------------------------------------------------------

fn verify_control_plane_endpoint(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    expected_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Verifying controlPlaneEndpoint in kubeadm-config …");

    let script = "sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf \
        get configmap kubeadm-config -n kube-system \
        -o jsonpath='{.data.ClusterConfiguration}' 2>/dev/null \
        | grep 'controlPlaneEndpoint' || true";

    let output = ssh_capture(cp_ip, ssh_user, ssh_priv_path, script).unwrap_or_default();

    let stored_endpoint = output
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if stored_endpoint.is_empty() {
        return Err(format!(
            "Cluster on {cp_name} has no controlPlaneEndpoint stored in kubeadm-config.\n\
             \n\
             This happens when the node was initialised without --control-plane-endpoint.\n\
             \n\
             Remediation — on every control-plane and worker node run:\n\
             \n\
             \tsudo kubeadm reset -f\n\
             \tsudo rm -rf /etc/cni /etc/kubernetes /var/lib/etcd /var/lib/kubelet\n\
             \n\
             Then re-run 'maglev play'.  Maglev will call:\n\
             \n\
             \tsudo kubeadm init \
             --control-plane-endpoint {expected_endpoint} --upload-certs\n\
             \n\
             To use a dedicated load-balancer address instead of the primary \
             node's IP, add 'control-plane-endpoint' to the relevant spec block \
             in your config."
        )
        .into());
    }

    println!("  ✓ controlPlaneEndpoint: {stored_endpoint}");

    let stored_normalised = if stored_endpoint.contains(':') {
        stored_endpoint.clone()
    } else {
        format!("{stored_endpoint}:6443")
    };

    if stored_normalised != expected_endpoint {
        eprintln!(
            "  ⚠  controlPlaneEndpoint in kubeadm-config ({stored_normalised}) \
             differs from the value in your config ({expected_endpoint}).\n\
             The join command will target the stored endpoint — this is \
             correct behaviour. Update your config if needed."
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Control-plane-endpoint DNS guard
// ---------------------------------------------------------------------------

/// Verify that the hostname inside `cp_endpoint` resolves on a remote node.
///
/// * Skipped when `cp_endpoint` is already a bare IP address.
/// * When the hostname is **unresolvable** the user is offered two choices:
///   - Let maglev append a temporary `/etc/hosts` line right now.
///   - Abort, with exact copy-paste instructions for a manual fix.
///
/// `capture` / `run` are thin closures over either the direct or the
/// ProxyJump SSH helpers so the same logic works for every node type.
fn ensure_cp_endpoint_resolves(
    node_name: &str,
    cp_endpoint: &str,
    fallback_ip: &str,
    capture: impl Fn(&str) -> Result<String, Box<dyn std::error::Error>>,
    run: impl Fn(&str) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = cp_endpoint.split(':').next().unwrap_or(cp_endpoint);

    // Nothing to do when the endpoint is already an IP address.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    println!("  Checking if '{host}' resolves on {node_name} …");

    let result = capture(&format!(
        "getent hosts {host} >/dev/null 2>&1 && echo ok || echo fail"
    ))?;

    if result.trim() == "ok" {
        println!("  ✓ '{host}' resolves.");
        return Ok(());
    }

    eprintln!(
        "\n  ⚠  '{host}' does NOT resolve on {node_name}.\n\
         \n\
         kubeadm will fail unless the name is resolvable before it starts.\n\
         \n\
         Long-term fix: provision a load-balancer, point DNS '{host}' at it,\n\
         then remove the /etc/hosts workaround from every node.\n\
         \n\
         Short-term: maglev can add  {fallback_ip}  {host}\n\
         to /etc/hosts on this node right now (idempotent — skipped if already present)."
    );

    if prompt_yes_no(&format!(
        "  Add '{fallback_ip}  {host}' to /etc/hosts on {node_name}?"
    )) {
        run(&format!(
            "grep -qF '{host}' /etc/hosts \
             || echo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts"
        ))?;
        println!(
            "  ✓ Added '{fallback_ip}  {host}' to /etc/hosts on {node_name}.\n\
             \n\
             ℹ  This is a temporary placeholder pointing at the primary control-plane IP.\n\
             ℹ  Once your load-balancer is live, run on EVERY node:\n\
             \n\
             \t  sudo sed -i '/{host}/d' /etc/hosts\n\
             \n\
             ℹ  Then ensure DNS resolves '{host}' to the LB address."
        );
    } else {
        return Err(format!(
            "DNS resolution for '{host}' is required before kubeadm can run.\n\
             \n\
             Add the following line to /etc/hosts on EVERY cluster node\n\
             (all control-plane + worker nodes) before re-running 'maglev play':\n\
             \n\
             \t{fallback_ip}  {host}\n\
             \n\
             Example (run on each node):\n\
             \n\
             \techo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts\n\
             \n\
             Once a real load-balancer is provisioned, update the entry to point\n\
             to the LB address, or delete it and let DNS handle resolution:\n\
             \n\
             \tsudo sed -i '/{host}/d' /etc/hosts"
        )
        .into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `reset` subcommand
// ---------------------------------------------------------------------------

fn reset_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    if !prompt_yes_no("\nProceed with kubeadm reset on all nodes?") {
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

        if !prompt_yes_no(&format!("  Reset {name}?")) {
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

// ---------------------------------------------------------------------------
// `restart` subcommand
// ---------------------------------------------------------------------------

fn restart_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Restart ===\n");
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
    println!("\n── Nodes to restart ─────────────────────────────────────────────────────");
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
    println!("\n⚠  All nodes will be rebooted. Services will be temporarily unavailable.");

    if !prompt_yes_no("\nProceed with restarting all nodes?") {
        println!("Aborted.");
        return Ok(());
    }

    let primary_cp_ip = nodes_with_ips
        .iter()
        .find(|(_, _, pp)| *pp)
        .map(|(_, ip, _)| ip.clone())
        .or_else(|| nodes_with_ips.first().map(|(_, ip, _)| ip.clone()))
        .ok_or("No nodes available")?;

    // Restart each node
    for (idx, (name, ip, prefer_public)) in nodes_with_ips.iter().enumerate() {
        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, nodes_with_ips.len());

        if !prompt_yes_no(&format!("  Restart {name}?")) {
            println!("  Skipped.");
            continue;
        }

        let needs_jump = !prefer_public && nodes_with_ips.iter().find(|(_, _, pp)| *pp).is_some();

        println!("  Sending reboot signal …");
        let result = if needs_jump {
            ssh_run_jump(
                &primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                "sudo reboot",
            )
        } else {
            ssh_run(ip, ssh_user, &ssh_priv_path, "sudo reboot")
        };

        match result {
            Ok(()) => println!("  ✓ {name} reboot initiated."),
            Err(e) => {
                // Reboot may close connection immediately, so connection errors are acceptable
                if e.to_string().contains("status") || e.to_string().contains("exited") {
                    println!("  ✓ {name} reboot initiated (connection closed).");
                } else {
                    eprintln!("  ✗ Failed to restart {name}: {e}");
                }
            }
        }
    }

    println!("\n✓ Restart signals sent to all nodes.");
    println!("  Nodes will be available again in 1-2 minutes.");
    Ok(())
}
