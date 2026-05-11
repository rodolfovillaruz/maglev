mod provider;
mod utils;

use std::collections::HashMap;
use std::env;
use std::fs;

use clap::{Parser, Subcommand};

use provider::{
    Provider,
    gcp::{GcpCredentials, GcpProvider, print_build_credential},
};
use utils::{expand_tilde, prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Maglev — GCP Kubernetes cluster manager
#[derive(Parser)]
#[command(
    name = "maglev",
    version,
    about = "Provision and manage GCP-backed Kubernetes clusters"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a config/gcp.yaml from environment variables
    Generate {
        /// Output path (default: config/gcp.yaml)
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
        /// Overwrite if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Create VM instances described by a config/gcp.yaml
    Apply {
        /// Path to the YAML config file
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Permanently delete VM instances described by a config/gcp.yaml
    Destroy {
        /// Path to the YAML config file
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Provision Kubernetes on control-plane nodes and join workers
    Play {
        /// Path to the YAML config file
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Run the interactive credential builder
    Print,
}

// ---------------------------------------------------------------------------
// YAML config types  (mirror config/gcp.yaml)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct YamlRoot {
    gcp: GcpYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpYaml {
    group: Vec<GroupYaml>,
    generics: Vec<GenericYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: CredentialsYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GroupYaml {
    name: String,
    node: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenericYaml {
    name: String,
    config: Vec<GenericConfigYaml>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenericConfigYaml {
    #[serde(rename = "ssh-public-key")]
    ssh_public_key: String,
    script: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecYaml {
    name: String,
    config: Vec<SpecConfigYaml>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecConfigYaml {
    #[serde(rename = "machine-type")]
    machine_type: String,
    #[serde(rename = "boot-disk-image")]
    boot_disk_image: String,
    #[serde(rename = "boot-disk-size")]
    boot_disk_size: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RuleYaml {
    group: String,
    generics: String,
    specs: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct CredentialsYaml {
    #[serde(rename = "client-email")]
    client_email: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "project-id")]
    project_id: String,
    zone: String,
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn load_yaml(path: &str) -> Result<YamlRoot, Box<dyn std::error::Error>> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read config file '{path}': {e}"))?;
    serde_yaml::from_str(&content).map_err(|e| format!("YAML parse error in '{path}': {e}").into())
}

/// Resolve a rule into its concrete (nodes, generic_config, spec_config) triple.
struct ResolvedRule<'a> {
    nodes: &'a [String],
    generic: &'a GenericConfigYaml,
    spec: &'a SpecConfigYaml,
}

fn resolve_rules<'a>(
    cfg: &'a GcpYaml,
) -> Result<Vec<ResolvedRule<'a>>, Box<dyn std::error::Error>> {
    let groups: HashMap<&str, &[String]> = cfg
        .group
        .iter()
        .map(|g| (g.name.as_str(), g.node.as_slice()))
        .collect();

    let generics: HashMap<&str, &GenericConfigYaml> = cfg
        .generics
        .iter()
        .filter_map(|g| g.config.first().map(|c| (g.name.as_str(), c)))
        .collect();

    let specs: HashMap<&str, &SpecConfigYaml> = cfg
        .specs
        .iter()
        .filter_map(|s| s.config.first().map(|c| (s.name.as_str(), c)))
        .collect();

    cfg.rules
        .iter()
        .map(|rule| {
            let nodes = *groups
                .get(rule.group.as_str())
                .ok_or_else(|| format!("Rule references unknown group '{}'", rule.group))?;
            let generic = *generics
                .get(rule.generics.as_str())
                .ok_or_else(|| format!("Rule references unknown generics '{}'", rule.generics))?;
            let spec = *specs
                .get(rule.specs.as_str())
                .ok_or_else(|| format!("Rule references unknown specs '{}'", rule.specs))?;
            Ok(ResolvedRule {
                nodes,
                generic,
                spec,
            })
        })
        .collect()
}

fn credentials_from_yaml(c: &CredentialsYaml) -> GcpCredentials {
    GcpCredentials {
        client_email: c.client_email.clone(),
        private_key_path: expand_tilde(&c.private_key),
        project_id: c.project_id.clone(),
        zone: c.zone.clone(),
    }
}

// ---------------------------------------------------------------------------
// `generate` subcommand
// ---------------------------------------------------------------------------

fn env_list(var: &str) -> Option<Vec<String>> {
    env::var(var).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn generate_config(config_path: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    if !force && Path::new(config_path).exists() {
        eprintln!("error: '{config_path}' already exists");
        eprintln!("  Use -f / --force to overwrite.");
        std::process::exit(1);
    }

    if let Some(parent) = Path::new(config_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create directories for '{config_path}': {e}"))?;
        }
    }

    // ── Credentials ──────────────────────────────────────────────────────────
    let client_email = env::var("MAGLEV_CLIENT_EMAIL")
        .map_err(|_| "MAGLEV_CLIENT_EMAIL environment variable is not set")?;

    let derived_project = client_email
        .split('@')
        .nth(1)
        .and_then(|d| d.split('.').next())
        .unwrap_or("my-project")
        .to_string();

    let project_id = env::var("MAGLEV_PROJECT_ID").unwrap_or(derived_project);
    let private_key =
        env::var("MAGLEV_PRIVATE_KEY").unwrap_or_else(|_| "path/to/private-key.pem".to_string());
    let zone = env::var("MAGLEV_ZONE").unwrap_or_else(|_| "us-central1-a".to_string());

    // ── Node names ────────────────────────────────────────────────────────────
    let cp_names = env_list("MAGLEV_CP_INSTANCES").unwrap_or_else(|| {
        vec![
            "maglev-cp-alpha".to_string(),
            "maglev-cp-beta".to_string(),
            "maglev-cp-gamma".to_string(),
        ]
    });

    let worker_names = env_list("MAGLEV_WORKER_INSTANCES").unwrap_or_else(|| {
        vec![
            "maglev-worker-alpha".to_string(),
            "maglev-worker-beta".to_string(),
            "maglev-worker-gamma".to_string(),
        ]
    });

    // ── SSH key / startup script ──────────────────────────────────────────────
    let ssh_public_key = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
        .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());

    let default_script = "#!/bin/bash\n\
        set -e\n\n\
        apt-get update\n\
        curl -fsSL https://github.com/rodolfovillaruz/cisak/releases/download/v0.1.11/\
        cisak-v0.1.11-linux-amd64.tar.gz | tar -xz\n\
        install -m 755 -o root -g root cisak /usr/local/bin/cisak\n\
        cisak generate\n\
        cisak install -y"
        .to_string();
    let script = env::var("MAGLEV_STARTUP_SCRIPT").unwrap_or(default_script);

    // ── Machine specs ─────────────────────────────────────────────────────────
    let cp_machine_type =
        env::var("MAGLEV_CP_MACHINE_TYPE").unwrap_or_else(|_| "e2-standard-2".to_string());
    let cp_boot_disk_image = env::var("MAGLEV_CP_BOOT_DISK_IMAGE")
        .unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());
    let cp_boot_disk_size: u64 = env::var("MAGLEV_CP_BOOT_DISK_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let worker_machine_type =
        env::var("MAGLEV_MACHINE_TYPE").unwrap_or_else(|_| "e2-standard-2".to_string());
    let worker_boot_disk_image =
        env::var("MAGLEV_BOOT_DISK_IMAGE").unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());
    let worker_boot_disk_size: u64 = env::var("MAGLEV_BOOT_DISK_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    // ── Build YAML structure ──────────────────────────────────────────────────
    let root = YamlRoot {
        gcp: GcpYaml {
            group: vec![
                GroupYaml {
                    name: "control-plane".to_string(),
                    node: cp_names.clone(),
                },
                GroupYaml {
                    name: "worker".to_string(),
                    node: worker_names.clone(),
                },
            ],
            generics: vec![GenericYaml {
                name: "default".to_string(),
                config: vec![GenericConfigYaml {
                    ssh_public_key: ssh_public_key.clone(),
                    script,
                }],
            }],
            specs: vec![
                SpecYaml {
                    name: "control-plane".to_string(),
                    config: vec![SpecConfigYaml {
                        machine_type: cp_machine_type,
                        boot_disk_image: cp_boot_disk_image,
                        boot_disk_size: cp_boot_disk_size,
                    }],
                },
                SpecYaml {
                    name: "worker".to_string(),
                    config: vec![SpecConfigYaml {
                        machine_type: worker_machine_type,
                        boot_disk_image: worker_boot_disk_image,
                        boot_disk_size: worker_boot_disk_size,
                    }],
                },
            ],
            rules: vec![
                RuleYaml {
                    group: "control-plane".to_string(),
                    generics: "default".to_string(),
                    specs: "control-plane".to_string(),
                },
                RuleYaml {
                    group: "worker".to_string(),
                    generics: "default".to_string(),
                    specs: "worker".to_string(),
                },
            ],
            credentials: CredentialsYaml {
                client_email,
                private_key,
                project_id,
                zone,
            },
        },
    };

    let yaml_text = serde_yaml::to_string(&root)?;
    fs::write(config_path, &yaml_text)
        .map_err(|e| format!("Cannot write config to '{config_path}': {e}"))?;

    println!("✓ Config written to: {config_path}");
    println!("  control-plane nodes : {}", cp_names.join(", "));
    println!("  worker nodes        : {}", worker_names.join(", "));

    Ok(())
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let root = load_yaml(config_path)?;
    let cfg = &root.gcp;
    let creds = credentials_from_yaml(&cfg.credentials);

    println!("\n── GCP settings ─────────────────────────────────────────────────────────");
    println!("  Project:         {}", creds.project_id);
    println!("  Zone:            {}", creds.zone);
    println!("  Service account: {}", creds.client_email);

    let resolved = resolve_rules(cfg)?;

    println!("\n── Nodes to create ──────────────────────────────────────────────────────");
    let mut total = 0usize;
    for (rule_idx, r) in resolved.iter().enumerate() {
        let rule = &cfg.rules[rule_idx];
        println!(
            "\n  group: {}  (generics: {}, specs: {})",
            rule.group, rule.generics, rule.specs
        );
        println!(
            "    machine-type: {}  image: {}  disk: {} GB",
            r.spec.machine_type, r.spec.boot_disk_image, r.spec.boot_disk_size
        );
        println!("    ssh-public-key: {}", r.generic.ssh_public_key);
        for node in r.nodes {
            println!("      • {node}");
            total += 1;
        }
    }

    if !prompt_yes_no(&format!("\nProceed with creating {total} VM instance(s)?")) {
        println!("Aborted.");
        return Ok(());
    }

    let provider = GcpProvider::new(&creds)?;

    for (rule_idx, r) in resolved.iter().enumerate() {
        let rule = &cfg.rules[rule_idx];
        println!(
            "\n── Group: {} ─────────────────────────────────────────────────────",
            rule.group
        );

        let ssh_meta = read_ssh_public_key(&r.generic.ssh_public_key)
            .map(|k| format!("ubuntu:{k}"))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });

        for node in r.nodes {
            println!("\n  ── Creating instance: {node} ──");
            let resp = provider.create_vm(
                node,
                &r.spec.machine_type,
                &r.spec.boot_disk_image,
                r.spec.boot_disk_size,
                &ssh_meta,
                &r.generic.script,
            )?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    println!("\n✓ All {total} VM creation request(s) submitted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let root = load_yaml(config_path)?;
    let cfg = &root.gcp;
    let creds = credentials_from_yaml(&cfg.credentials);

    println!("\n── Instances to destroy ─────────────────────────────────────────────────");
    println!("  Project:         {}", creds.project_id);
    println!("  Zone:            {}", creds.zone);
    println!("  Service account: {}", creds.client_email);
    println!();

    let mut all_nodes: Vec<(&str, &str)> = Vec::new(); // (group_name, instance_name)
    for group in &cfg.group {
        for node in &group.node {
            println!("  {}  →  {}", group.name, node);
            all_nodes.push((&group.name, node));
        }
    }

    let total = all_nodes.len();
    println!();
    println!("⚠  This action is IRREVERSIBLE. All {total} VM instance(s) and their boot");
    println!("   disks will be permanently deleted.");

    if !prompt_yes_no("\nProceed with destroying all VM instances?") {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    let provider = GcpProvider::new(&creds)?;

    for (group_name, node) in &all_nodes {
        println!("\n  ── Deleting [{group_name}] {node} ──");
        match provider.destroy_vm(node) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {node}: {e}"),
        }
    }

    println!("\n✓ Deletion requests submitted. GCP operations may take a minute to complete.");
    println!("  Track progress:");
    println!(
        "    gcloud compute operations list --filter=\"zone:{}\" --project={}",
        creds.zone, creds.project_id
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// `play` subcommand
// ---------------------------------------------------------------------------

fn ssh_capture(
    ip: &str,
    user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "LogLevel=ERROR",
            &format!("{user}@{ip}"),
            command,
        ])
        .output()
        .map_err(|e| format!("Failed to spawn ssh: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ssh exited {} — stderr: {stderr}",
            out.status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn ssh_run(
    ip: &str,
    user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "LogLevel=ERROR",
            "-t",
            &format!("{user}@{ip}"),
            command,
        ])
        .status()
        .map_err(|e| format!("Failed to spawn ssh: {e}"))?;

    if !status.success() {
        return Err(format!("Remote command exited {}", status.code().unwrap_or(-1)).into());
    }
    Ok(())
}

fn play_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
    println!("Reading config: {config_path}");

    let root = load_yaml(config_path)?;
    let cfg = &root.gcp;
    let creds = credentials_from_yaml(&cfg.credentials);

    let ssh_user = env::var("MAGLEV_SSH_USER").unwrap_or_else(|_| "ubuntu".to_string());

    // Find the ssh public-key path from the "default" generics config.
    let ssh_pub_path = cfg
        .generics
        .iter()
        .find(|g| g.name == "default")
        .and_then(|g| g.config.first())
        .map(|c| c.ssh_public_key.as_str())
        .unwrap_or("~/.ssh/id_ed25519.pub");

    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    let provider = GcpProvider::new(&creds)?;

    println!("\n  Fetching IPs from Compute Engine API …");

    // Identify control-plane and worker groups from rules.
    let cp_nodes: Vec<&str> = cfg
        .rules
        .iter()
        .find(|r| r.group == "control-plane")
        .and_then(|r| cfg.group.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let worker_nodes: Vec<&str> = cfg
        .rules
        .iter()
        .find(|r| r.group == "worker")
        .and_then(|r| cfg.group.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let resolve_ips =
        |nodes: &[&str]| -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
            nodes
                .iter()
                .map(|&name| {
                    let ip = provider.get_vm_ip(name)?;
                    println!("  {name:<30} →  {ip}");
                    Ok((name.to_string(), ip)) // owned String, no lifetime problem
                })
                .collect()
        };

    let cp_with_ips: Vec<(String, String)> = resolve_ips(&cp_nodes)?;
    let worker_with_ips: Vec<(String, String)> = resolve_ips(&worker_nodes)?;

    println!("  SSH user: {ssh_user}  private key: {ssh_priv_path}");

    // ── Step 1: provision control-plane nodes ─────────────────────────────────
    println!(
        "\n━━ Step 1 / 2 — Control-plane provisioning ({} nodes) ━━━━━━━━━━━━━━━━━",
        cp_with_ips.len()
    );

    for (idx, (name, ip)) in cp_with_ips.iter().enumerate() {
        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, cp_with_ips.len());
        if !prompt_yes_no(&format!("  SSH-check and provision {name}?")) {
            println!("  Skipped.");
            continue;
        }

        let check = ssh_capture(
            ip,
            &ssh_user,
            &ssh_priv_path,
            "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
        )?;

        if check.trim() == "yes" {
            println!("  ✓ Already provisioned — skipping.");
            continue;
        }

        if !prompt_yes_no("  Run: sudo cisak install --control-plane -y ?") {
            println!("  Skipped.");
            continue;
        }

        println!("\n  Provisioning — this may take several minutes …\n");
        ssh_run(
            ip,
            &ssh_user,
            &ssh_priv_path,
            "sudo cisak install --control-plane -y",
        )?;
        println!("\n  ✓ {name} provisioned.");
    }

    // ── Step 2: join workers ──────────────────────────────────────────────────
    println!(
        "\n━━ Step 2 / 2 — Join workers ({} nodes) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        worker_with_ips.len()
    );

    let (primary_cp_name, primary_cp_ip) = cp_with_ips
        .first()
        .ok_or("No control-plane nodes available")?;

    for (idx, (name, ip)) in worker_with_ips.iter().enumerate() {
        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, worker_with_ips.len());
        if !prompt_yes_no("  Fetch join command and join?") {
            println!("  Skipped.");
            continue;
        }

        let join_cmd = ssh_capture(
            primary_cp_ip,
            &ssh_user,
            &ssh_priv_path,
            "sudo kubeadm token create --print-join-command",
        )?;

        if join_cmd.is_empty() {
            eprintln!("  ✗ Empty join command from {primary_cp_name} — is it fully up?");
            continue;
        }

        println!("  Join command: {join_cmd}");
        println!("\n  Joining {name} …\n");
        ssh_run(ip, &ssh_user, &ssh_priv_path, &format!("sudo {join_cmd}"))?;
        println!("\n  ✓ {name} joined.");
    }

    println!("\n✓ Cluster provisioning complete!");
    println!("\n  Verify from the primary control-plane:");
    println!("    ssh -i {ssh_priv_path} {ssh_user}@{primary_cp_ip}");
    println!("    kubectl get nodes -o wide");

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { config, force } => generate_config(&config, force),
        Commands::Apply { config } => apply_config(&config),
        Commands::Destroy { config } => destroy_config(&config),
        Commands::Play { config } => play_config(&config),
        Commands::Print => print_build_credential(),
    }
}
