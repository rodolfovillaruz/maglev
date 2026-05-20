use crate::GenericsConfigYaml;
use crate::GenericsYaml;
use crate::IpAddressType;
use crate::cp::ADMIN_KUBECONFIG;
use crate::structs::CommonMergedSpec;
use crate::{ssh_capture, ssh_capture_jump, ssh_run, ssh_run_jump};
use std::collections::HashMap;
use std::env;
use std::fs::read_to_string;
use std::io::{BufRead, Write, stdin, stdout};
use std::{thread, time::Duration};

// ---------------------------------------------------------------------------
// Custom YAML deserializer: scalar string  OR  sequence of strings
// ---------------------------------------------------------------------------

pub fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or a sequence of strings")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(Visitor)
}

// ---------------------------------------------------------------------------
// SSH public-key helper
// ---------------------------------------------------------------------------

pub fn read_ssh_public_key(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(path);
    let content = read_to_string(&expanded)
        .map_err(|e| format!("Cannot read SSH public key from '{expanded}': {e}"))?;
    Ok(content.trim().to_string())
}

// ---------------------------------------------------------------------------
// Tilde expansion
// ---------------------------------------------------------------------------

pub fn expand_tilde(path: &str) -> String {
    let after_tilde = if path == "~" {
        ""
    } else if path.starts_with("~/") || path.starts_with("~\\") {
        &path[1..]
    } else {
        return path.to_string();
    };

    let home = home_dir().unwrap_or_else(|| ".".to_string());
    format!("{}{}", home, after_tilde)
}

fn home_dir() -> Option<String> {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .ok()
        .or_else(|| {
            let drive = env::var("HOMEDRIVE").ok()?;
            let path = env::var("HOMEPATH").ok()?;
            Some(format!("{}{}", drive, path))
        })
}

// ---------------------------------------------------------------------------
// Interactive yes/no prompt
// ---------------------------------------------------------------------------

pub fn prompt_yes_no(question: &str) -> bool {
    print!("{question} [y/N]: ");
    stdout().flush().expect("Failed to flush stdout");

    let mut line = String::new();
    stdin()
        .lock()
        .read_line(&mut line)
        .expect("Failed to read input");

    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

// ---------------------------------------------------------------------------
// Spec validation (pre-merge, informational only)
// ---------------------------------------------------------------------------

pub fn validate_specs(specs: &[GenericsYaml]) -> Result<(), Box<dyn std::error::Error>> {
    for spec in specs {
        for (i, cfg) in spec.config.iter().enumerate() {
            let ip_str = cfg
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "private (default)".to_string());
            println!("  spec '{}' [{}]: ip-address = {}", spec.name, i, ip_str);
        }
    }
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
pub fn approve_pending_csrs(
    cp_ip: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    jumphost_accessible: bool,
    jumphost_ip: &str,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let confirm = |question: &str| -> bool {
        if auto_approve {
            println!("{question} [auto-approved]");
            true
        } else {
            prompt_yes_no(question)
        }
    };

    println!("\n  → Step B.5: approve pending kubelet-serving CSRs");

    // Collect CSR names and requestors. Handles both cases:
    // - No REQUESTEDNAME column: condition is $NF
    // - With REQUESTEDNAME column: condition is $(NF-1), name is $NF
    let list_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} get csr --no-headers 2>/dev/null \
         | awk '$NF == \"Pending\" || $(NF-1) == \"Pending\" {{ \
             if ($(NF-1) == \"Pending\") print $1, $NF; \
             else print $1 \
         }}'"
    );

    let raw = if jumphost_accessible {
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

    // Parse: name and optional requestor
    let pending: Vec<(String, String)> = raw
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.len() {
                0 => (String::new(), String::new()),
                1 => (parts[0].to_string(), String::new()),
                _ => (parts[0].to_string(), parts[1].to_string()),
            }
        })
        .collect();

    if pending.is_empty() {
        println!("  No pending CSRs found — skipping.");
        return Ok(());
    }

    println!(
        "\n  Found {} pending CSR(s) waiting for approval:\n",
        pending.len()
    );
    for (name, requestor) in &pending {
        if requestor.is_empty() {
            println!("    • {name}");
        } else {
            println!("    • {name} (requestor: {requestor})");
        }
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

    let approve_cmd = format!(
        "kubectl --kubeconfig {ADMIN_KUBECONFIG} certificate approve {}",
        pending
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("    $ {approve_cmd}");

    let result = if jumphost_accessible {
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

// ─────────────────────────────────────────────────────────────────────────
// Helper: Check containerd status
// ─────────────────────────────────────────────────────────────────────────

pub fn check_containerd_running(
    ip: &str,
    name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = if needs_jump {
        ssh_capture_jump(
            jumphost_ip,
            ssh_user,
            ip,
            ssh_user,
            ssh_priv_path,
            "systemctl is-active --quiet containerd && echo ok || echo failed",
        )?
    } else {
        ssh_capture(
            ip,
            ssh_user,
            ssh_priv_path,
            "systemctl is-active --quiet containerd && echo ok || echo failed",
        )?
    };

    if status.trim() == "ok" {
        Ok(())
    } else {
        Err(format!(
            "✗ containerd is not running on {name} ({ip})\n  \
             Cloud-init may still be installing packages. \
             Please wait a moment and try again, or manually run:\n  \
             sudo systemctl restart containerd"
        )
        .into())
    }
}

/// Merge `spec_names` (in order) from `specs_map` into a single
/// [`MergedSpec`].  Later entries override earlier ones for scalar fields.
/// For `cert_sans` all layers are unioned and deduplicated (first-seen wins
/// on collision) so that a base spec can supply cluster-wide SANs while a
/// derived spec adds node-specific ones.
pub fn common_merge_spec_configs(
    spec_names: &[String],
    specs_map: &HashMap<&str, &GenericsConfigYaml>,
) -> Result<CommonMergedSpec, Box<dyn std::error::Error>> {
    let mut machine_type: Option<String> = None;
    let mut boot_disk_image: Option<String> = None;
    let mut ip_address: Option<IpAddressType> = None;
    let mut ssh_public_key: Option<String> = None;
    let mut script: Option<String> = None;
    let mut user: Option<String> = None;
    let mut control_plane_endpoint: Option<String> = None;
    // Accumulated across all layers; duplicates are skipped.
    let mut cert_sans: Vec<String> = Vec::new();

    for name in spec_names {
        let cfg = specs_map
            .get(name.as_str())
            .ok_or_else(|| format!("Rule references unknown spec '{name}'"))?;

        if let Some(v) = &cfg.machine_type {
            machine_type = Some(v.clone());
        }
        if let Some(v) = &cfg.boot_disk_image {
            boot_disk_image = Some(v.clone());
        }
        if let Some(v) = cfg.ip_address {
            ip_address = Some(v);
        }
        if let Some(v) = &cfg.ssh_public_key {
            ssh_public_key = Some(v.clone());
        }
        if let Some(v) = &cfg.script {
            script = Some(v.clone());
        }
        if let Some(v) = &cfg.user {
            user = Some(v.clone());
        }
        if let Some(v) = &cfg.control_plane_endpoint {
            control_plane_endpoint = Some(v.clone());
        }
        // Union certSANs from this layer, skipping entries already present.
        if let Some(api) = &cfg.api_server {
            for san in &api.cert_sans {
                if !cert_sans.contains(san) {
                    cert_sans.push(san.clone());
                }
            }
        }
    }

    Ok(CommonMergedSpec {
        machine_type: machine_type
            .ok_or_else(|| format!("No 'machine-type' found after merging specs {spec_names:?}"))?,
        boot_disk_image: boot_disk_image.ok_or_else(|| {
            format!("No 'boot-disk-image' found after merging specs {spec_names:?}")
        })?,
        ip_address: ip_address.unwrap_or_default(),
        ssh_public_key: ssh_public_key.ok_or_else(|| {
            format!("No 'ssh-public-key' found after merging specs {spec_names:?}")
        })?,
        script: script
            .ok_or_else(|| format!("No 'script' found after merging specs {spec_names:?}"))?,
        user: user.ok_or_else(|| format!("No 'user' found after merging specs {spec_names:?}"))?,
        control_plane_endpoint,
        cert_sans,
    })
}

/// Polls every 15 s for up to 10 minutes until containerd is active,
/// then delegates to `check_containerd_running` for the final assertion.
pub fn wait_for_containerd(
    ip: &str,
    name: &str,
    user: &str,
    priv_key: &str,
    needs_jump: bool,
    jumphost_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const INTERVAL: Duration = Duration::from_secs(15);
    const MAX_ATTEMPTS: u32 = 40; // 40 × 15 s = 10 min

    println!("  ⏳ Waiting for containerd on {name} …");

    for attempt in 1..=MAX_ATTEMPTS {
        let result = check_containerd_running(ip, name, user, priv_key, needs_jump, jumphost_ip);
        if result.is_ok() {
            return Ok(());
        }
        println!(
            "    [{attempt}/{MAX_ATTEMPTS}] not ready yet — retrying in {}s …",
            INTERVAL.as_secs()
        );
        thread::sleep(INTERVAL);
    }

    Err(format!("containerd on {name} did not become ready within the timeout").into())
}
