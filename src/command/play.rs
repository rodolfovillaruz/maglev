use crate::IpAddressType;
use crate::cp::{
    cilium::provision_cilium, ensure_cp_endpoint_resolves, provision_control_plane_node,
    verify_control_plane_endpoint,
};
use crate::expand_tilde;
use crate::prompt_yes_no;
use crate::provider::load_provider;
use crate::rule::resolve_rules;
use crate::state::State;
use crate::structs::CommonMergedSpec;
use crate::utils::approve_pending_csrs;
use crate::utils::check_containerd_running;
use crate::utils::wait_for_containerd;
use crate::{ssh_capture, ssh_capture_jump, ssh_run, ssh_run_jump};

// ---------------------------------------------------------------------------
// `play` subcommand
// ---------------------------------------------------------------------------

pub fn play_config(
    config_path: &str,
    auto_approve: bool,
    no_wait: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    // Load state so we can pass instance IDs to the provider instead of raw names
    let state = State::load(config_path);

    let mut cp_entries: Vec<(String, bool)> = Vec::new();
    let mut worker_entries: Vec<(String, bool)> = Vec::new();
    let mut first_cp_merged: Option<&CommonMergedSpec> = None;

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
    // Collect certSANs from the primary control-plane spec (already unioned
    // across all spec layers by merge_spec_configs).
    let cert_sans: Vec<String> = first_cp_merged.cert_sans.clone();

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
    let primary_cp_prefer_public = cp_entries[0].1;

    println!("\n  Fetching IPs (waiting for assignments if necessary) …");

    // Helper to retry fetching the IP address, handling DigitalOcean's asynchronous IP assignment
    let fetch_ip_with_retry = |name: &str,
                               prefer_public: bool|
     -> Result<String, Box<dyn std::error::Error>> {
        let identifier = state
            .instances
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or(name);
        let max_attempts = 30; // 30 attempts * 2 seconds = 60 seconds timeout
        for _ in 0..max_attempts {
            match provider.get_vm_ip(identifier, prefer_public) {
                Ok(ip) if !ip.trim().is_empty() && ip.to_lowercase() != "null" => return Ok(ip),
                _ => std::thread::sleep(std::time::Duration::from_secs(2)),
            }
        }
        // Final attempt that will safely bubble up the error if it's still missing
        provider.get_vm_ip(identifier, prefer_public)
    };

    let cp_with_ips: Vec<(String, String)> = cp_entries
        .iter()
        .map(|(name, prefer_public)| {
            let ip = fetch_ip_with_retry(name, *prefer_public)?;
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
            let ip = fetch_ip_with_retry(name, *prefer_public)?;
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

    let (jumphost_name, jumphost_ip, jumphost_is_public) = if let Some(p) = &common.provisioner {
        println!(
            "\n  Provisioner node configured: {} ({})",
            p.node, p.provisioner_type
        );
        let pref_pub = p.provisioner_type == "public";
        // Also use the retry logic for the provisioner jump-host
        let ip = fetch_ip_with_retry(&p.node, pref_pub)?;
        println!("    IP: {ip}");
        (p.node.clone(), ip, pref_pub)
    } else {
        (
            primary_cp_name.clone(),
            primary_cp_ip.clone(),
            primary_cp_prefer_public,
        )
    };

    let jumphost_accessible = common.provisioner.is_some() && jumphost_is_public;

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

    if !cert_sans.is_empty() {
        println!("  apiServer certSANs:");
        for san in &cert_sans {
            println!("    - {san}");
        }
    }

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

    // ── Preflight check ──────────────────────────────────────────────────────
    println!("\n━━ Preflight check — Verifying containerd on all nodes ━━━━━━━━━━━━━━");

    let wait_or_check = |ip: &str,
                         name: &str,
                         needs_jump: bool|
     -> Result<(), Box<dyn std::error::Error>> {
        if no_wait {
            check_containerd_running(ip, name, ssh_user, &ssh_priv_path, needs_jump, &jumphost_ip)
        } else {
            wait_for_containerd(ip, name, ssh_user, &ssh_priv_path, needs_jump, &jumphost_ip)
        }
    };

    println!("\n  Control-plane nodes:");
    for (name, ip) in &cp_with_ips {
        let needs_jump = cp_entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, pub_)| !pub_ && jumphost_is_public)
            .unwrap_or(false);
        wait_or_check(ip, name, needs_jump)?;
        println!("    ✓ {name}");
    }

    println!("\n  Worker nodes:");
    for (name, ip) in &worker_with_ips {
        let needs_jump = worker_entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, pub_)| !pub_ && jumphost_is_public)
            .unwrap_or(false);
        wait_or_check(ip, name, needs_jump)?;
        println!("    ✓ {name}");
    }

    println!("\n  ✓ All nodes ready for provisioning.\n");

    // ── Step 1 / 3 — Primary control-plane ───────────────────────────────────
    println!("\n━━ Step 1 / 3 — Primary control-plane init ({primary_cp_name}) ━━━━━━━━━━━━");
    println!("\n  [{primary_cp_name}]  ({primary_cp_ip})");

    if prompt_yes_no(
        &format!("  SSH-check and provision {primary_cp_name}?"),
        auto_approve,
    ) {
        ensure_cp_endpoint_resolves(
            primary_cp_name,
            &cp_endpoint,
            primary_cp_ip,
            auto_approve,
            |cmd| match jumphost_accessible {
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
            |cmd| match jumphost_accessible {
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

        let already_init = if jumphost_accessible {
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
                    jumphost_accessible,
                    &jumphost_ip,
                )?;
            }
            provision_cilium(
                primary_cp_ip,
                primary_cp_name,
                ssh_user,
                &ssh_priv_path,
                jumphost_accessible,
                &jumphost_ip,
                auto_approve,
            )?;
        } else {
            provision_control_plane_node(
                primary_cp_ip,
                primary_cp_name,
                ssh_user,
                &ssh_priv_path,
                &cp_endpoint,
                is_ha,
                jumphost_accessible,
                &jumphost_ip,
                auto_approve,
                &cert_sans,
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

        let cp_join_cmd = {
            let cmd_result = if jumphost_accessible {
                ssh_capture_jump(
                    &jumphost_ip,
                    ssh_user,
                    primary_cp_ip,
                    ssh_user,
                    &ssh_priv_path,
                    cp_join_script,
                )
            } else {
                ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cp_join_script)
            };

            match cmd_result {
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
            }
        };

        for (idx, ((name, ip), (_, prefer_public))) in cp_with_ips
            .iter()
            .skip(1)
            .zip(cp_entries.iter().skip(1))
            .enumerate()
        {
            println!("\n  [{}/{}] {name}  ({ip})", idx + 2, cp_with_ips.len());

            if !prompt_yes_no(
                &format!("  Check and join {name} as control-plane?"),
                auto_approve,
            ) {
                println!("  Skipped.");
                continue;
            }

            let cp_needs_jump = !prefer_public && jumphost_is_public;

            if cp_needs_jump {
                println!("    (routing through {jumphost_name} @ {jumphost_ip} via ProxyJump)");
            }

            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                auto_approve,
                |cmd| match cp_needs_jump {
                    true => {
                        ssh_capture_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd)
                    }
                    false => ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                },
                |cmd| match cp_needs_jump {
                    true => ssh_run_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
                    false => ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
                },
            )?;

            let already_joined = if cp_needs_jump {
                ssh_capture_jump(
                    &jumphost_ip,
                    ssh_user,
                    ip,
                    ssh_user,
                    &ssh_priv_path,
                    "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
                )
            } else {
                ssh_capture(
                    ip,
                    ssh_user,
                    &ssh_priv_path,
                    "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
                )
            };

            match already_joined {
                Ok(ref s) if s.trim() == "yes" => {
                    println!("  ✓ {name} already part of the control-plane — skipping.");
                    continue;
                }
                Err(e) => {
                    eprintln!("  ✗ Could not check join status on {name}: {e}");
                    continue;
                }
                _ => {}
            }

            if cp_join_cmd.is_empty() {
                eprintln!("  ✗ No join command available — skipping {name}.");
                continue;
            }

            println!("  Join command: {cp_join_cmd}");
            if prompt_yes_no("  Run join command?", auto_approve) {
                println!("\n  Joining {name} as control-plane node …\n");
                let join_full = format!("sudo {cp_join_cmd}");
                let result = if cp_needs_jump {
                    ssh_run_jump(
                        &jumphost_ip,
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
                    Ok(()) => println!("\n  ✓ {name} joined as control-plane."),
                    Err(e) => eprintln!("\n  ✗ Failed to join {name}: {e}"),
                }
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

    let primary_ca_fingerprint: Option<String> = {
        let cmd = "sudo openssl x509 -noout -fingerprint -sha256 \
                   -in /etc/kubernetes/pki/ca.crt 2>/dev/null \
                   | cut -d= -f2";
        let result = if jumphost_accessible {
            ssh_capture_jump(
                &jumphost_ip,
                ssh_user,
                primary_cp_ip,
                ssh_user,
                &ssh_priv_path,
                cmd,
            )
        } else {
            ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cmd)
        };
        match result {
            Ok(fp) if !fp.trim().is_empty() => {
                let fp = fp.trim().to_string();
                println!("  Cluster CA fingerprint (SHA-256): {fp}");
                Some(fp)
            }
            Ok(_) => {
                eprintln!(
                    "  ⚠  Could not determine cluster CA fingerprint from \
                     {primary_cp_name} — membership verification will be skipped."
                );
                None
            }
            Err(e) => {
                eprintln!(
                    "  ⚠  Could not determine cluster CA fingerprint: {e} \
                     — membership verification will be skipped."
                );
                None
            }
        }
    };

    let worker_join_cmd = {
        let cmd_result = if jumphost_accessible {
            ssh_capture_jump(
                &jumphost_ip,
                ssh_user,
                primary_cp_ip,
                ssh_user,
                &ssh_priv_path,
                "sudo kubeadm token create --print-join-command",
            )
        } else {
            ssh_capture(
                primary_cp_ip,
                ssh_user,
                &ssh_priv_path,
                "sudo kubeadm token create --print-join-command",
            )
        };

        match cmd_result {
            Ok(cmd) if !cmd.is_empty() => cmd,
            Ok(_) => {
                eprintln!("  ✗ Empty worker join command from {primary_cp_name} — is it fully up?");
                String::new()
            }
            Err(e) => {
                eprintln!("  ✗ Could not fetch worker join command: {e}");
                String::new()
            }
        }
    };

    for (idx, ((name, ip), (_, prefer_public))) in worker_with_ips
        .iter()
        .zip(worker_entries.iter())
        .enumerate()
    {
        let worker_needs_jump = !prefer_public && jumphost_is_public;

        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, worker_with_ips.len());

        if worker_needs_jump {
            println!("    (routing through {jumphost_name} @ {jumphost_ip} via ProxyJump)");
        }

        if !prompt_yes_no("  Check and join?", auto_approve) {
            println!("  Skipped.");
            continue;
        }

        let join_check_cmd =
            "test -f /etc/kubernetes/kubelet.conf && echo joined || echo not-joined";

        let join_status = if worker_needs_jump {
            ssh_capture_jump(
                &jumphost_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                join_check_cmd,
            )
        } else {
            ssh_capture(ip, ssh_user, &ssh_priv_path, join_check_cmd)
        };

        match join_status {
            Ok(ref s) if s.trim() == "joined" => match &primary_ca_fingerprint {
                Some(expected_fp) => {
                    let worker_fp_cmd = "sudo awk '/certificate-authority-data/{print $2; exit}' \
                             /etc/kubernetes/kubelet.conf \
                             | base64 -d \
                             | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
                             | cut -d= -f2";

                    let worker_fp = if worker_needs_jump {
                        ssh_capture_jump(
                            &jumphost_ip,
                            ssh_user,
                            ip,
                            ssh_user,
                            &ssh_priv_path,
                            worker_fp_cmd,
                        )
                    } else {
                        ssh_capture(ip, ssh_user, &ssh_priv_path, worker_fp_cmd)
                    };

                    match worker_fp {
                        Ok(ref fp) if fp.trim() == expected_fp.as_str() => {
                            println!(
                                "  ✓ {name} already joined to this cluster \
                                     (CA fingerprint verified) — skipping."
                            );
                            continue;
                        }
                        Ok(ref fp) if !fp.trim().is_empty() => {
                            eprintln!(
                                "  ✗ {name} is joined to a DIFFERENT cluster!\n\
                                     Expected CA fingerprint : {expected_fp}\n\
                                     Node CA fingerprint     : {}\n\
                                     Refusing to re-join — manual intervention required \
                                     (reset the node with `sudo kubeadm reset` first).",
                                fp.trim()
                            );
                            continue;
                        }
                        Ok(_) => {
                            eprintln!(
                                "  ⚠  {name} has kubelet.conf but the CA fingerprint \
                                     could not be extracted — skipping to avoid \
                                     overwriting an existing cluster member."
                            );
                            continue;
                        }
                        Err(e) => {
                            eprintln!(
                                "  ⚠  {name} has kubelet.conf but CA fingerprint \
                                     verification failed ({e}) — skipping to avoid \
                                     overwriting an existing cluster member."
                            );
                            continue;
                        }
                    }
                }
                None => {
                    println!(
                        "  ✓ {name} already has kubelet.conf — skipping \
                             (CA fingerprint verification unavailable)."
                    );
                    continue;
                }
            },
            Err(e) => {
                eprintln!("  ⚠  Could not check join status on {name}: {e}");
            }
            _ => {}
        }

        ensure_cp_endpoint_resolves(
            name,
            &cp_endpoint,
            primary_cp_ip,
            auto_approve,
            |cmd| match worker_needs_jump {
                true => ssh_capture_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
                false => ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
            },
            |cmd| match worker_needs_jump {
                true => ssh_run_jump(&jumphost_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
                false => ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            },
        )?;

        if worker_join_cmd.is_empty() {
            eprintln!("  ✗ No join command available — skipping {name}.");
            continue;
        }

        println!("  Join command: {worker_join_cmd}");
        println!("\n  Joining {name} …\n");

        let join_full = format!("sudo {worker_join_cmd}");
        let result = if worker_needs_jump {
            ssh_run_jump(
                &jumphost_ip,
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

    // ── Final step — Approve any pending CSRs from worker nodes ────────────────
    println!("\n━━ Final step — Approve pending CSRs from worker nodes ━━━━━━━━━━━━━━━━━━");

    approve_pending_csrs(
        primary_cp_ip,
        ssh_user,
        &ssh_priv_path,
        jumphost_accessible,
        &jumphost_ip,
        auto_approve,
    )?;

    println!("\n✓ Cluster provisioning complete!");
    println!("\n  Verify from the primary control-plane:");

    let primary_id = state
        .instances
        .get(primary_cp_name)
        .map(|s| s.as_str())
        .unwrap_or(primary_cp_name.as_str());
    let alt_ip = if primary_cp_prefer_public {
        provider.get_vm_ip(primary_id, false).ok()
    } else {
        provider.get_vm_ip(primary_id, true).ok()
    };

    let (primary_label, primary_ip_to_show, alt_label, alt_ip_to_show) = if primary_cp_prefer_public
    {
        (
            "public",
            primary_cp_ip.clone(),
            "private",
            alt_ip.unwrap_or_else(|| "<private-ip>".to_string()),
        )
    } else {
        (
            "private",
            primary_cp_ip.clone(),
            "public",
            alt_ip.unwrap_or_else(|| "<public-ip>".to_string()),
        )
    };

    println!("\n  Using {primary_label} IP:");
    println!("    ssh -i {ssh_priv_path} {ssh_user}@{primary_ip_to_show} \\");
    println!("      sudo kubectl --kubeconfig /etc/kubernetes/admin.conf get po -A -o wide");

    println!("\n  Using {alt_label} IP:");
    println!("    ssh -i {ssh_priv_path} {ssh_user}@{alt_ip_to_show} \\");
    println!("      sudo kubectl --kubeconfig /etc/kubernetes/admin.conf get po -A -o wide");

    Ok(())
}
