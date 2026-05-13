use crate::ip::IpAddressType;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::utils::{prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

pub fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
