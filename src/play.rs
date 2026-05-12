use crate::IpAddressType;
use crate::cp::{ensure_cp_endpoint_resolves, verify_control_plane_endpoint};
use crate::expand_tilde;
use crate::prompt_yes_no;
use crate::provider::load_provider;
use crate::provision_cilium;
use crate::provision_control_plane_node;
use crate::rule::resolve_rules;
use crate::spec::MergedSpec;
use crate::ssh_capture;
use crate::ssh_capture_jump;
use crate::ssh_run;
use crate::ssh_run_jump;

// ---------------------------------------------------------------------------
// `play` subcommand
// ---------------------------------------------------------------------------

pub fn play_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    // ── Partition resolved rules into CP and worker node lists ────────────────
    //
    // Each entry carries:  (node_name, prefer_public)
    // The SSH config (user, key, control-plane-endpoint) is taken from the
    // first control-plane rule's merged spec — all rules in the example share
    // the same `cisak` base spec so these values are identical across the
    // cluster.
    let mut cp_entries: Vec<(String, bool)> = Vec::new();
    let mut worker_entries: Vec<(String, bool)> = Vec::new();
    let mut first_cp_merged: Option<&MergedSpec> = None;

    for rule in &resolved {
        let prefer_public = rule.merged.ip_address == IpAddressType::Public;
        match rule.group_type.as_str() {
            "control-plane" => {
                if first_cp_merged.is_none() {
                    first_cp_merged = Some(&rule.merged);
                }
                for node in &rule.nodes {
                    cp_entries.push((node.clone(), prefer_public));
                }
            }
            "worker" => {
                for node in &rule.nodes {
                    worker_entries.push((node.clone(), prefer_public));
                }
            }
            other => {
                eprintln!("  ⚠ Unknown group type '{other}' — skipping in play.");
            }
        }
    }

    let first_cp_merged = first_cp_merged.ok_or("No control-plane rules found in config")?;

    let ssh_user = &first_cp_merged.user;
    let ssh_pub_path = first_cp_merged.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    // ── Cluster-size checks ───────────────────────────────────────────────────
    let cp_count = cp_entries.len();
    if cp_count == 0 {
        return Err("No control-plane nodes found in config.".into());
    }
    if cp_count == 1 {
        println!(
            "\n  ℹ  INFO: Single control-plane node — this cluster will \
             not be highly available."
        );
    } else if cp_count % 2 == 0 {
        eprintln!(
            "\n  ⚠  WARNING: Even number of control-plane nodes ({cp_count}) detected. \
             An odd count (e.g. 3 or 5) is strongly recommended for proper \
             etcd quorum. Proceed with caution."
        );
    }

    let is_ha = cp_count >= 3;

    // Primary CP node is the first one in document order.
    let primary_cp_prefer_public = cp_entries[0].1;

    // A worker whose own IP is private and whose reachability depends on
    // tunnelling through the (public) primary CP node needs ProxyJump.
    let any_worker_needs_jump =
        worker_entries.iter().any(|(_, pp)| !pp) && primary_cp_prefer_public;

    if any_worker_needs_jump {
        println!(
            "\n  ℹ  Some workers have private IPs and the primary control-plane has a \
             public IP. Private-worker SSH will be routed through the primary \
             control-plane node via ProxyJump."
        );
    }

    // ── Resolve provisioner node (if configured) ──────────────────────────────
    let provisioner_spec = loaded.provisioner();
    let provisioner_node_info: Option<(String, String, bool)> = if let Some(p) = provisioner_spec {
        println!(
            "\n  Provisioner node configured: {} ({})",
            p.node, p.provisioner_type
        );
        let pref_pub = p.provisioner_type == "public";
        let ip = provider.get_vm_ip(&p.node, pref_pub)?;
        println!("    IP: {ip}");
        Some((p.node.clone(), ip, pref_pub))
    } else {
        None
    };

    // ── Resolve IPs ───────────────────────────────────────────────────────────
    println!("\n  Fetching IPs …");

    let cp_with_ips: Vec<(String, String)> = cp_entries
        .iter()
        .map(|(name, prefer_public)| {
            let ip = provider.get_vm_ip(name, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    let worker_with_ips: Vec<(String, String)> = worker_entries
        .iter()
        .map(|(name, prefer_public)| {
            let ip = provider.get_vm_ip(name, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    println!("  SSH user: {ssh_user}  private key: {ssh_priv_path}");

    let (primary_cp_name, primary_cp_ip) = cp_with_ips
        .first()
        .ok_or("No control-plane nodes available")?;

    // Determine jumphost: use provisioner if configured, otherwise use primary CP
    let (jumphost_name, jumphost_ip, jumphost_is_public) =
        if let Some((name, ip, is_public)) = provisioner_node_info {
            (name, ip, is_public)
        } else {
            (
                primary_cp_name.clone(),
                primary_cp_ip.clone(),
                primary_cp_prefer_public,
            )
        };

    // Determine if any worker needs jumphost routing
    let any_worker_needs_jump = worker_entries.iter().any(|(_, pp)| !pp) && jumphost_is_public;

    if any_worker_needs_jump {
        println!(
            "\n  ℹ  Some workers have private IPs. SSH to these nodes will be routed \
         through {jumphost_name} ({jumphost_ip}) via ProxyJump."
        );
    }

    // ── Determine the stable control-plane endpoint ───────────────────────────
    let cp_endpoint: String = match &first_cp_merged.control_plane_endpoint {
        Some(ep) if !ep.trim().is_empty() => {
            let ep = ep.trim().to_string();
            if ep.contains(':') {
                ep
            } else {
                format!("{ep}:6443")
            }
        }
        _ => format!("{primary_cp_ip}:6443"),
    };

    println!("\n  control-plane-endpoint: {cp_endpoint}");

    if is_ha && cp_endpoint.starts_with(primary_cp_ip.as_str()) {
        eprintln!(
            "\n  ⚠  WARNING: control-plane-endpoint is set to the primary node's own \
             IP ({cp_endpoint}).\n\
             This works but is not truly highly available — if that node is lost \
             the API server becomes unreachable.\n\
             Consider adding a load-balancer and setting 'control-plane-endpoint' \
             in the relevant spec block of your config."
        );
    }

    // ── Step 1 / 3 — Primary control-plane ───────────────────────────────────
    println!("\n━━ Step 1 / 3 — Primary control-plane init ({primary_cp_name}) ━━━━━━━━━━━━");
    println!("\n  [{primary_cp_name}]  ({primary_cp_ip})");

    if prompt_yes_no(&format!("  SSH-check and provision {primary_cp_name}?")) {
        ensure_cp_endpoint_resolves(
            primary_cp_name,
            &cp_endpoint,
            primary_cp_ip,
            |cmd| match any_worker_needs_jump {
                true => ssh_capture_jump(
                    &jumphost_ip,
                    ssh_user,
                    primary_cp_ip,
                    ssh_user,
                    &ssh_priv_path,
                    cmd,
                ),
                false => ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
            },
            |cmd| match any_worker_needs_jump {
                true => ssh_run_jump(
                    &jumphost_ip,
                    ssh_user,
                    primary_cp_ip,
                    ssh_user,
                    &ssh_priv_path,
                    cmd,
                ),
                false => ssh_run(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
            },
        )?;

        let already_init = if any_worker_needs_jump {
            ssh_capture_jump(
                &jumphost_ip,
                ssh_user,
                primary_cp_ip,
                ssh_user,
                &ssh_priv_path,
                "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
            )?
        } else {
            ssh_capture(
                primary_cp_ip,
                ssh_user,
                &ssh_priv_path,
                "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
            )?
        };

        if already_init.trim() == "yes" {
            println!("  ✓ {primary_cp_name} already initialised — skipping kubeadm init.");
            if is_ha {
                verify_control_plane_endpoint(
                    primary_cp_ip,
                    primary_cp_name,
                    ssh_user,
                    &ssh_priv_path,
                    &cp_endpoint,
                    any_worker_needs_jump,
                    &jumphost_ip,
                )?;
            }
            provision_cilium(
                primary_cp_ip,
                primary_cp_name,
                ssh_user,
                &ssh_priv_path,
                any_worker_needs_jump,
                &jumphost_ip,
            )?;
        } else {
            provision_control_plane_node(
                primary_cp_ip,
                primary_cp_name,
                ssh_user,
                &ssh_priv_path,
                &cp_endpoint,
                is_ha,
                any_worker_needs_jump,
                &jumphost_ip,
            )?;
        }
    } else {
        println!("  Skipped.");
    }

    // ── Step 2 / 3 — Additional control-plane nodes (HA join) ────────────────
    if is_ha && cp_with_ips.len() > 1 {
        println!(
            "\n━━ Step 2 / 3 — Additional control-plane nodes ({} nodes) ━━━━━━━━━━━━━━",
            cp_with_ips.len() - 1
        );

        let cp_join_script = "\
            CERT_KEY=$(sudo kubeadm certs certificate-key) && \
            sudo kubeadm init phase upload-certs \
                --upload-certs --certificate-key \"$CERT_KEY\" \
                >/dev/null 2>&1 && \
            BASE=$(sudo kubeadm token create --print-join-command) && \
            echo \"$BASE --control-plane --certificate-key $CERT_KEY\"";

        let cp_join_cmd = match ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cp_join_script)
        {
            Ok(cmd) if !cmd.is_empty() => cmd,
            Ok(_) => {
                eprintln!(
                    "  ✗ Empty control-plane join command from {primary_cp_name} \
                     — is it fully up?"
                );
                String::new()
            }
            Err(e) => {
                eprintln!("  ✗ Could not fetch control-plane join command: {e}");
                String::new()
            }
        };

        // cp_entries[1..] parallel-tracks cp_with_ips[1..]
        for (idx, ((name, ip), (_, prefer_public))) in cp_with_ips
            .iter()
            .skip(1)
            .zip(cp_entries.iter().skip(1))
            .enumerate()
        {
            println!("\n  [{}/{}] {name}  ({ip})", idx + 2, cp_with_ips.len());

            if !prompt_yes_no(&format!("  Check and join {name} as control-plane?")) {
                println!("  Skipped.");
                continue;
            }

            // Additional CP nodes that have private IPs are assumed to be
            // reachable directly (VPN / internal routing).  If they are not,
            // the operator will see an SSH timeout here.
            let _ = prefer_public; // used only to choose ip — already reflected in `ip`
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            )?;

            let already_joined = ssh_capture(
                ip,
                ssh_user,
                &ssh_priv_path,
                "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
            )?;

            if already_joined.trim() == "yes" {
                println!("  ✓ {name} already part of the control-plane — skipping.");
                continue;
            }

            if cp_join_cmd.is_empty() {
                eprintln!("  ✗ No join command available — skipping {name}.");
                continue;
            }

            println!("  Join command: {cp_join_cmd}");
            if prompt_yes_no("  Run join command?") {
                println!("\n  Joining {name} as control-plane node …\n");
                ssh_run(ip, ssh_user, &ssh_priv_path, &format!("sudo {cp_join_cmd}"))?;
                println!("\n  ✓ {name} joined as control-plane.");
            } else {
                println!("  Skipped.");
            }
        }
    } else if !is_ha {
        println!("\n━━ Step 2 / 3 — Additional control-plane nodes ━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Single-node cluster — no additional control-plane nodes to join.");
    }

    // ── Step 3 / 3 — Join workers ─────────────────────────────────────────────
    println!(
        "\n━━ Step 3 / 3 — Join workers ({} nodes) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        worker_with_ips.len()
    );

    let worker_join_cmd = match ssh_capture(
        primary_cp_ip,
        ssh_user,
        &ssh_priv_path,
        "sudo kubeadm token create --print-join-command",
    ) {
        Ok(cmd) if !cmd.is_empty() => cmd,
        Ok(_) => {
            eprintln!("  ✗ Empty worker join command from {primary_cp_name} — is it fully up?");
            String::new()
        }
        Err(e) => {
            eprintln!("  ✗ Could not fetch worker join command: {e}");
            String::new()
        }
    };

    // worker_entries[i] and worker_with_ips[i] are aligned
    for (idx, ((name, ip), (_, prefer_public))) in worker_with_ips
        .iter()
        .zip(worker_entries.iter())
        .enumerate()
    {
        let needs_jump = !prefer_public && jumphost_is_public;

        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, worker_with_ips.len());

        if needs_jump {
            println!("    (routing through {jumphost_name} @ {jumphost_ip} via ProxyJump)");
        }

        if !prompt_yes_no("  Fetch join command and join?") {
            println!("  Skipped.");
            continue;
        }

        // DNS guard — use the appropriate SSH path per worker topology
        if needs_jump {
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                &jumphost_ip,
                |cmd| ssh_capture_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
            )?;
        } else {
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            )?;
        }

        if worker_join_cmd.is_empty() {
            eprintln!("  ✗ No join command available — skipping {name}.");
            continue;
        }

        println!("  Join command: {worker_join_cmd}");

        let already_joined = if needs_jump {
            ssh_capture_jump(
                primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                "systemctl is-active kubelet 2>/dev/null && echo yes || echo no",
            )
        } else {
            ssh_capture(
                ip,
                ssh_user,
                &ssh_priv_path,
                "systemctl is-active kubelet 2>/dev/null && echo yes || echo no",
            )
        };

        match already_joined {
            Ok(ref s) if s.trim() == "yes" => {
                println!("  ✓ {name} already has kubelet active — skipping.");
                continue;
            }
            _ => {}
        }

        println!("\n  Joining {name} …\n");
        let join_full = format!("sudo {worker_join_cmd}");

        let result = if needs_jump {
            ssh_run_jump(
                primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                &join_full,
            )
        } else {
            ssh_run(ip, ssh_user, &ssh_priv_path, &join_full)
        };

        match result {
            Ok(()) => println!("\n  ✓ {name} joined."),
            Err(e) => eprintln!("  ✗ Failed to join {name}: {e}"),
        }
    }

    println!("\n✓ Cluster provisioning complete!");
    println!("\n  Verify from the primary control-plane:");
    println!("    ssh -i {ssh_priv_path} {ssh_user}@{primary_cp_ip}");
    println!("    kubectl get nodes -o wide");

    Ok(())
}
