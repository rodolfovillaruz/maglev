use crate::ssh::{ssh_run, ssh_run_jump};
use crate::ssh_capture;
use crate::ssh_capture_jump;
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

// ---------------------------------------------------------------------------
// Control-plane endpoint guard
// ---------------------------------------------------------------------------

pub fn verify_control_plane_endpoint(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    expected_endpoint: &str,
    any_worker_needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Verifying controlPlaneEndpoint in kubeadm-config …");

    let script = "sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf \
        get configmap kubeadm-config -n kube-system \
        -o jsonpath='{.data.ClusterConfiguration}' 2>/dev/null \
        | grep 'controlPlaneEndpoint' || true";

    let output = if any_worker_needs_jump {
        ssh_capture_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            script,
        )
        .unwrap_or_default()
    } else {
        ssh_capture(cp_ip, ssh_user, ssh_priv_path, script).unwrap_or_default()
    };

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
pub fn ensure_cp_endpoint_resolves(
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
