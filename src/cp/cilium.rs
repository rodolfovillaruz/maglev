use crate::cp::ADMIN_KUBECONFIG;
use crate::{prompt_yes_no, ssh_run, ssh_run_jump};
use crate::{ssh_capture, ssh_capture_jump};

// ---------------------------------------------------------------------------
// Cilium provisioning steps (Steps B + B.5 + C)
// ---------------------------------------------------------------------------

pub fn provision_cilium(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    any_worker_needs_jump: bool,
    jumphost_ip: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // When --auto-approve is set every interactive gate is bypassed.
    let confirm = |question: &str| -> bool {
        if auto_approve {
            println!("{question} [auto-approved]");
            true
        } else {
            prompt_yes_no(question)
        }
    };

    // ── Step B: cilium install ────────────────────────────────────────────────

    // Check if Cilium is already installed
    let check_cilium_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} get daemonset -n kube-system cilium \
         >/dev/null 2>&1 && echo installed || echo not_installed"
    );

    let cilium_status = if any_worker_needs_jump {
        ssh_capture_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &check_cilium_cmd,
        )
        .unwrap_or_default()
    } else {
        ssh_capture(cp_ip, ssh_user, ssh_priv_path, &check_cilium_cmd).unwrap_or_default()
    };

    let cilium_already_installed = cilium_status.trim() == "installed";

    if cilium_already_installed {
        println!("\n  → Step B: Cilium CNI already deployed (idempotent skip)");
    } else {
        let cilium_install_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} install");

        println!("\n  → Step B: deploy Cilium CNI");
        println!("    $ {cilium_install_cmd}");

        if !confirm("  Run cilium install?") {
            println!("  Skipped — Cilium CNI will not be deployed.");
            return Ok(());
        }

        let result = if any_worker_needs_jump {
            ssh_run_jump(
                jumphost_ip,
                ssh_user,
                cp_ip,
                ssh_user,
                ssh_priv_path,
                &cilium_install_cmd,
            )
        } else {
            ssh_run(cp_ip, ssh_user, ssh_priv_path, &cilium_install_cmd)
        };

        match result {
            Ok(()) => {}
            Err(e) => {
                eprintln!("  ⚠ cilium install failed ({e}) — retrying with sudo …");
                let sudo_cmd = format!("sudo {cilium_install_cmd}");
                println!("    $ {sudo_cmd}");
                if any_worker_needs_jump {
                    ssh_run_jump(
                        jumphost_ip,
                        ssh_user,
                        cp_ip,
                        ssh_user,
                        ssh_priv_path,
                        &sudo_cmd,
                    )?;
                } else {
                    ssh_run(cp_ip, ssh_user, ssh_priv_path, &sudo_cmd)?;
                }
            }
        }
        println!("\n  ✓ Cilium CNI installed.");
    }

    // ── Step B.5: approve pending kubelet-serving CSRs ────────────────────────
    //
    // When serverTLSBootstrap is enabled in the KubeletConfiguration, each
    // kubelet generates a CSR for its serving certificate.  Those CSRs land
    // in "Pending" state and must be manually approved (or handled by an
    // auto-approver).  We surface them here so the operator can bulk-approve
    // before waiting for Cilium to become ready, avoiding a deadlock where
    // pods stay NotReady because their node's kubelet-serving cert is missing.
    approve_pending_csrs(
        cp_ip,
        ssh_user,
        ssh_priv_path,
        any_worker_needs_jump,
        jumphost_ip,
        auto_approve,
    )?;

    // ── Step C: cilium status --wait ──────────────────────────────────────────
    let cilium_status_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} status --wait");

    println!("\n  → Step C: wait for Cilium to become ready");
    println!("    $ {cilium_status_cmd}");

    if !confirm("  Run cilium status --wait?") {
        println!("  Skipped — continuing without confirming Cilium health.");
        return Ok(());
    }

    let result = if any_worker_needs_jump {
        ssh_run_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &cilium_status_cmd,
        )
    } else {
        ssh_run(cp_ip, ssh_user, ssh_priv_path, &cilium_status_cmd)
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("  ⚠ cilium status --wait failed ({e}) — retrying with sudo …");
            let sudo_cmd = format!("sudo {cilium_status_cmd}");
            println!("    $ {sudo_cmd}");
            if any_worker_needs_jump {
                ssh_run_jump(
                    jumphost_ip,
                    ssh_user,
                    cp_ip,
                    ssh_user,
                    ssh_priv_path,
                    &sudo_cmd,
                )?;
            } else {
                ssh_run(cp_ip, ssh_user, ssh_priv_path, &sudo_cmd)?;
            }
        }
    }
    println!("\n  ✓ Cilium is ready.");

    println!("\n  ✓ {cp_name} control-plane provisioning complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Pending CSR approval helper
// ---------------------------------------------------------------------------

/// List every CSR whose final column is `Pending`, print an aggregated
/// summary, and offer the operator a single prompt to approve them all.
///
/// Uses `$NF` (last field) so the check is stable regardless of whether the
/// optional *REQUESTEDNAME* column is populated in the `kubectl get csr`
/// output.
fn approve_pending_csrs(
    cp_ip: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    any_worker_needs_jump: bool,
    jumphost_ip: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // When --auto-approve is set every interactive gate is bypassed.
    let confirm = |question: &str| -> bool {
        if auto_approve {
            println!("{question} [auto-approved]");
            true
        } else {
            prompt_yes_no(question)
        }
    };

    println!("\n  → Step B.5: approve pending kubelet-serving CSRs");

    // Collect the names of every CSR currently in Pending state.
    let list_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} get csr --no-headers 2>/dev/null \
         | awk '$NF == \"Pending\" {{print $1}}'"
    );

    let raw = if any_worker_needs_jump {
        ssh_capture_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &list_cmd,
        )
        .unwrap_or_default()
    } else {
        ssh_capture(cp_ip, ssh_user, ssh_priv_path, &list_cmd).unwrap_or_default()
    };

    let pending: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if pending.is_empty() {
        println!("  No pending CSRs found — skipping.");
        return Ok(());
    }

    println!(
        "\n  Found {} pending CSR(s) waiting for approval:\n",
        pending.len()
    );
    for name in &pending {
        println!("    • {name}");
    }
    println!();

    if !confirm(&format!(
        "  Approve all {} pending CSR(s) now?",
        pending.len()
    )) {
        println!(
            "  Skipped — CSRs remain pending.\n\
             \n\
             ℹ  You can approve them later with:\n\
             \n\
             \t  kubectl --kubeconfig {ADMIN_KUBECONFIG} get csr \\\n\
             \t    --no-headers | awk '$NF == \"Pending\" {{print $1}}' \\\n\
             \t    | xargs -r kubectl --kubeconfig {ADMIN_KUBECONFIG} certificate approve"
        );
        return Ok(());
    }

    // Build a single `certificate approve` call with all names on one line
    // to avoid spawning one SSH session per CSR.
    let approve_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} certificate approve {}",
        pending.join(" ")
    );
    println!("    $ {approve_cmd}");

    let result = if any_worker_needs_jump {
        ssh_run_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &approve_cmd,
        )
    } else {
        ssh_run(cp_ip, ssh_user, ssh_priv_path, &approve_cmd)
    };

    match result {
        Ok(()) => println!("  ✓ All {} pending CSR(s) approved.", pending.len()),
        Err(e) => eprintln!(
            "  ⚠ Failed to approve CSRs ({e}).\n\
             Cilium may still become healthy — continuing."
        ),
    }

    Ok(())
}
