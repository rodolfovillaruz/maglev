use crate::cp::ADMIN_KUBECONFIG;
use crate::utils::approve_pending_csrs;
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
    primary_cp_needs_jump: bool,
    jumphost_ip: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Step B: cilium install ────────────────────────────────────────────────

    // Check if Cilium is already installed
    let check_cilium_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} get daemonset -n kube-system cilium \
         >/dev/null 2>&1 && echo installed || echo not_installed"
    );

    let cilium_status = if primary_cp_needs_jump {
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

        if !prompt_yes_no("  Run cilium install?", auto_approve) {
            println!("  Skipped — Cilium CNI will not be deployed.");
            return Ok(());
        }

        let result = if primary_cp_needs_jump {
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
                if primary_cp_needs_jump {
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
        primary_cp_needs_jump,
        jumphost_ip,
        auto_approve,
    )?;

    // ── Step C: cilium status --wait ──────────────────────────────────────────
    let cilium_status_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} status --wait");

    println!("\n  → Step C: wait for Cilium to become ready");
    println!("    $ {cilium_status_cmd}");

    if !prompt_yes_no("  Run cilium status --wait?", auto_approve) {
        println!("  Skipped — continuing without confirming Cilium health.");
        return Ok(());
    }

    let result = if primary_cp_needs_jump {
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
            if primary_cp_needs_jump {
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
