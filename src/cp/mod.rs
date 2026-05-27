use crate::ssh::{ssh_run, ssh_run_jump};
use crate::ssh_capture;
use crate::ssh_capture_jump;
use crate::utils::prompt_yes_no;
use cilium::provision_cilium;

pub mod cilium;

// ---------------------------------------------------------------------------
// Control-plane provisioning steps
// ---------------------------------------------------------------------------

pub const ADMIN_KUBECONFIG: &str = "/etc/kubernetes/admin.conf";

pub fn provision_control_plane_node(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    cp_endpoint: &str,
    is_ha: bool,
    primary_cp_needs_jump: bool,
    jumphost_ip: &str,
    auto_approve: bool,
    cert_sans: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Build optional apiServer.certSANs block ───────────────────────────────
    //
    // Produces (when SANs are present):
    //
    //   apiServer:
    //     certSANs:
    //     - 192.168.1.100
    //     - api.example.com
    //
    // The trailing newline means it can be concatenated directly into the
    // YAML document without further spacing adjustments.
    let api_server_block = if cert_sans.is_empty() {
        String::new()
    } else {
        let items = cert_sans
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("apiServer:\n  certSANs:\n{items}\n")
    };
    // ── Step A: kubeadm init ──────────────────────────────────────────────────
    // Create kubeadm config with serverTLSBootstrap enabled and kube-proxy disabled.
    //
    // Configuration reference:
    //   https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/
    let kubeadm_config = if is_ha {
        format!(
            "apiVersion: kubeadm.k8s.io/v1beta4\n\
             kind: InitConfiguration\n\
             skipPhases:\n\
               - addon/kube-proxy\n\
             ---\n\
             apiVersion: kubeadm.k8s.io/v1beta4\n\
             kind: ClusterConfiguration\n\
             controlPlaneEndpoint: {cp_endpoint}\n\
             {api_server_block}\
             ---\n\
             apiVersion: kubelet.config.k8s.io/v1beta1\n\
             kind: KubeletConfiguration\n\
             serverTLSBootstrap: true\n"
        )
    } else {
        format!(
            "apiVersion: kubeadm.k8s.io/v1beta4\n\
             kind: InitConfiguration\n\
             skipPhases:\n\
               - addon/kube-proxy\n\
             ---\n\
             apiVersion: kubeadm.k8s.io/v1beta4\n\
             kind: ClusterConfiguration\n\
             {api_server_block}\
             ---\n\
             apiVersion: kubelet.config.k8s.io/v1beta1\n\
             kind: KubeletConfiguration\n\
             serverTLSBootstrap: true\n"
        )
    };

    // Write config to remote node.
    let config_script = format!(
        "cat > /tmp/kubeadm-config.yaml <<'KUBEADM_CONFIG_EOF'\n{kubeadm_config}\nKUBEADM_CONFIG_EOF"
    );
    if primary_cp_needs_jump {
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

    // Build kubeadm init command using the config file.
    let kubeadm_init_cmd = if is_ha {
        "sudo kubeadm init --config /tmp/kubeadm-config.yaml --upload-certs"
    } else {
        "sudo kubeadm init --config /tmp/kubeadm-config.yaml"
    };

    println!("\n  → Step A: initialise the cluster with kubeadm");
    println!("    $ {kubeadm_init_cmd}");

    if !prompt_yes_no("  Run kubeadm init?", auto_approve) {
        println!("  Skipped — aborting control-plane provisioning for {cp_name}.");
        return Ok(());
    }

    println!("\n  Running kubeadm init — this may take several minutes …\n");
    if primary_cp_needs_jump {
        ssh_run_jump(
            jumphost_ip,
            ssh_user,
            cp_ip,
            ssh_user,
            ssh_priv_path,
            kubeadm_init_cmd,
        )?;
    } else {
        ssh_run(cp_ip, ssh_user, ssh_priv_path, kubeadm_init_cmd)?;
    }
    println!("\n  ✓ kubeadm init complete.");

    provision_cilium(
        cp_ip,
        cp_name,
        ssh_user,
        ssh_priv_path,
        primary_cp_needs_jump,
        jumphost_ip,
        auto_approve,
    )
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
    primary_cp_needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Verifying controlPlaneEndpoint in kubeadm-config …");

    let script = "sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf \
        get configmap kubeadm-config -n kube-system \
        -o jsonpath='{.data.ClusterConfiguration}' 2>/dev/null \
        | grep 'controlPlaneEndpoint' || true";

    let output = if primary_cp_needs_jump {
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
    auto_approve: bool,
    capture: impl Fn(&str) -> Result<String, Box<dyn std::error::Error>>,
    run: impl Fn(&str) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = cp_endpoint.split(':').next().unwrap_or(cp_endpoint);

    // Nothing to do when the endpoint is already an IP address.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    println!("  Checking if '{host}' resolves on {node_name} …");

    let resolve_cmd = format!("getent hosts {host} 2>/dev/null | awk '{{ print $1 }}' || echo ''");
    let resolved_ip = capture(&resolve_cmd)?.trim().to_string();

    if !resolved_ip.is_empty() {
        if resolved_ip == fallback_ip {
            println!("  ✓ '{host}' resolves to {resolved_ip}.");
            return Ok(());
        } else {
            eprintln!(
                "\n  ⚠  '{host}' currently resolves to {resolved_ip} on {node_name},\n\
                 but it should resolve to {fallback_ip}.\n\
                 \n\
                 kubeadm will fail or connect to the wrong endpoint.\n\
                 \n\
                 maglev will update /etc/hosts to fix this."
            );

            if prompt_yes_no(
                &format!("  Update '{host}' in /etc/hosts to {fallback_ip} on {node_name}?"),
                auto_approve,
            ) {
                run(&format!(
                    "sudo sed -i '/[[:space:]]{host}[[:space:]]*$/d' /etc/hosts && \
                     echo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts"
                ))?;
                println!(
                    "  ✓ Updated '{host}' in /etc/hosts to {fallback_ip} on {node_name}.\n\
                     \n\
                     ℹ  This is a temporary placeholder.\n\
                     ℹ  Once your load-balancer is live, run on EVERY node:\n\
                     \n\
                     \t  sudo sed -i '/{host}/d' /etc/hosts\n\
                     \n\
                     ℹ  Then ensure DNS resolves '{host}' to the LB address."
                );
                return Ok(());
            } else {
                return Err(format!(
                    "DNS resolution mismatch for '{host}'.\n\
                     \n\
                     Currently resolves to: {resolved_ip}\n\
                     Expected to resolve to: {fallback_ip}\n\
                     \n\
                     Update the entry in /etc/hosts on EVERY cluster node\n\
                     (all control-plane + worker nodes) before re-running 'maglev play':\n\
                     \n\
                     \tsudo sed -i '/[[:space:]]{host}[[:space:]]*$/d' /etc/hosts && \
                     echo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts\n\
                     \n\
                     Once a real load-balancer is provisioned, update the entry to point\n\
                     to the LB address, or delete it and let DNS handle resolution:\n\
                     \n\
                     \tsudo sed -i '/{host}/d' /etc/hosts"
                )
                .into());
            }
        }
    } else {
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

        if prompt_yes_no(
            &format!("  Add '{fallback_ip}  {host}' to /etc/hosts on {node_name}?"),
            auto_approve,
        ) {
            run(&format!(
                "grep -qF '{host}' /etc/hosts \
                 || echo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts"
            ))?;
            println!(
                "  ✓ Added '{fallback_ip}  {host}' to /etc/hosts on {node_name}.\n\
                 \n\
                 ℹ  This is a temporary placeholder.\n\
                 ℹ  Once your load-balancer is live, run on EVERY node:\n\
                 \n\
                 \t  sudo sed -i '/{host}/d' /etc/hosts\n\
                 \n\
                 ℹ  Then ensure DNS resolves '{host}' to the LB address."
            );
            return Ok(());
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
    }
}
