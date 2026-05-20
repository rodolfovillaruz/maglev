use crate::command::play::play_config;
use crate::ip::IpAddressType;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::utils::{prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

pub fn apply_config(
    config_path: &str,
    play: bool,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
            let _ = provider.create_vm(
                node,
                &r.merged.machine_type,
                &r.merged.boot_disk_image,
                &ssh_meta,
                &r.merged.script,
                assign_public_ip,
            )?;
            println!("\nInstance \"{node}\" created");
        }
    }

    println!("\n✓ All {total} VM creation request(s) submitted successfully.");

    if play {
        println!("\n── --play flag set: handing off to play ────────────────────────────────");
        // no_wait=false so the play step will poll until containerd is ready
        play_config(config_path, auto_approve, false)?;
    }

    Ok(())
}
