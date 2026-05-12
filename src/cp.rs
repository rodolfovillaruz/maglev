use crate::ssh::{ssh_run, ssh_run_jump};
use crate::utils::prompt_yes_no;

// ---------------------------------------------------------------------------
// Control-plane provisioning steps
// ---------------------------------------------------------------------------

const ADMIN_KUBECONFIG: &str = "/etc/kubernetes/admin.conf";

pub fn provision_control_plane_node(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    cp_endpoint: &str,
    is_ha: bool,
    any_worker_needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Step A: kubeadm init ──────────────────────────────────────────────────
    // Create kubeadm config with serverTLSBootstrap enabled
    let kubeadm_config = if is_ha {
        format!(
            r#"apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
controlPlaneEndpoint: {cp_endpoint}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
serverTLSBootstrap: true
"#
        )
    } else {
        r#"apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
serverTLSBootstrap: true
"#
        .to_string()
    };

    // Write config to remote node
    let config_script = format!(
        "cat > /tmp/kubeadm-config.yaml <<'KUBEADM_CONFIG_EOF'\n{}\nKUBEADM_CONFIG_EOF",
        kubeadm_config
    );
    if any_worker_needs_jump {
        ssh_run_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &config_script,
        )?;
    } else {
        ssh_run(cp_ip, ssh_user, ssh_priv_path, &config_script)?;
    }

    // Build kubeadm init command using the config file
    let kubeadm_init_cmd = if is_ha {
        "sudo kubeadm init --config /tmp/kubeadm-config.yaml --upload-certs"
    } else {
        "sudo kubeadm init --config /tmp/kubeadm-config.yaml"
    };

    println!("\n  → Step A: initialise the cluster with kubeadm");
    println!("    $ {kubeadm_init_cmd}");

    if !prompt_yes_no("  Run kubeadm init?") {
        println!("  Skipped — aborting control-plane provisioning for {cp_name}.");
        return Ok(());
    }

    println!("\n  Running kubeadm init — this may take several minutes …\n");
    if any_worker_needs_jump {
        ssh_run_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            &kubeadm_init_cmd,
        )?;
    } else {
        ssh_run(cp_ip, ssh_user, ssh_priv_path, &kubeadm_init_cmd)?;
    }
    println!("\n  ✓ kubeadm init complete.");

    provision_cilium(
        cp_ip,
        cp_name,
        ssh_user,
        ssh_priv_path,
        any_worker_needs_jump,
        jumphost_ip,
    )
}

// ---------------------------------------------------------------------------
// Cilium provisioning steps (Steps B + C)
// ---------------------------------------------------------------------------

pub fn provision_cilium(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    any_worker_needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Step B: cilium install ────────────────────────────────────────────────
    let cilium_install_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} install");

    println!("\n  → Step B: deploy Cilium CNI");
    println!("    $ {cilium_install_cmd}");

    if !prompt_yes_no("  Run cilium install?") {
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

    // ── Step C: cilium status --wait ──────────────────────────────────────────
    let cilium_status_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} status --wait");

    println!("\n  → Step C: wait for Cilium to become ready");
    println!("    $ {cilium_status_cmd}");

    if !prompt_yes_no("  Run cilium status --wait?") {
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
