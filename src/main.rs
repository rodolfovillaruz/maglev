mod provider;
mod utils;

use std::collections::HashMap;
use std::fs;

use clap::{Parser, Subcommand};

use provider::{
    Provider,
    digitalocean::{DigitalOceanCredentials, DigitalOceanProvider},
    gcp::{GcpCredentials, GcpProvider, print_build_credential},
};
use utils::{expand_tilde, prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Maglev — multi-cloud Kubernetes cluster manager
#[derive(Parser)]
#[command(
    name = "maglev",
    version,
    about = "Provision and manage cloud-backed Kubernetes clusters"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create VM instances described by a provider YAML config
    Apply {
        /// Path to the YAML config file (gcp.yaml or digitalocean.yaml)
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Permanently delete VM instances described by a provider YAML config
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
    /// Run the interactive GCP credential builder
    Print,
}

// ---------------------------------------------------------------------------
// ip-address field type
// ---------------------------------------------------------------------------

/// Validated value for `ip-address` in a spec config block.
///
/// Accepted YAML values: `"public"` or `"private"`.
/// Omitting the field is equivalent to `"private"`.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum IpAddressType {
    Public,
    Private,
}

impl Default for IpAddressType {
    fn default() -> Self {
        IpAddressType::Private
    }
}

impl std::fmt::Display for IpAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddressType::Public => write!(f, "public"),
            IpAddressType::Private => write!(f, "private"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared YAML types (identical structure across providers)
// ---------------------------------------------------------------------------

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
    user: String,
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
    /// Controls whether a public IP is assigned/used.
    /// Accepts `"public"` or `"private"` only; defaults to `"private"`.
    #[serde(rename = "ip-address", default)]
    ip_address: IpAddressType,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RuleYaml {
    group: String,
    generics: String,
    specs: String,
}

// ---------------------------------------------------------------------------
// Provider-specific credential types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpCredentialsYaml {
    #[serde(rename = "client-email")]
    client_email: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "project-id")]
    project_id: String,
    zone: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoCredentialsYaml {
    token: String,
    region: String,
}

// ---------------------------------------------------------------------------
// Per-provider YAML roots
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpRoot {
    gcp: GcpYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpYaml {
    group: Vec<GroupYaml>,
    generics: Vec<GenericYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: GcpCredentialsYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoRoot {
    digitalocean: DoYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoYaml {
    group: Vec<GroupYaml>,
    generics: Vec<GenericYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: DoCredentialsYaml,
}

// ---------------------------------------------------------------------------
// Unified view of a loaded config (provider-agnostic body + typed creds)
// ---------------------------------------------------------------------------

struct CommonConfig {
    groups: Vec<GroupYaml>,
    generics: Vec<GenericYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
}

enum LoadedProvider {
    Gcp {
        common: CommonConfig,
        location: String,
        identity: String,
        provider: GcpProvider,
    },
    DigitalOcean {
        common: CommonConfig,
        location: String,
        provider: DigitalOceanProvider,
    },
}

impl LoadedProvider {
    fn common(&self) -> &CommonConfig {
        match self {
            LoadedProvider::Gcp { common, .. } => common,
            LoadedProvider::DigitalOcean { common, .. } => common,
        }
    }

    fn provider(&self) -> &dyn Provider {
        match self {
            LoadedProvider::Gcp { provider, .. } => provider,
            LoadedProvider::DigitalOcean { provider, .. } => provider,
        }
    }

    fn describe(&self) {
        match self {
            LoadedProvider::Gcp {
                location, identity, ..
            } => {
                println!("  Provider:        GCP");
                println!("  Zone:            {location}");
                println!("  Service account: {identity}");
            }
            LoadedProvider::DigitalOcean { location, .. } => {
                println!("  Provider:        DigitalOcean");
                println!("  Region:          {location}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config loading + provider detection
// ---------------------------------------------------------------------------

fn load_provider(path: &str) -> Result<LoadedProvider, Box<dyn std::error::Error>> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read config file '{path}': {e}"))?;

    let raw: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| format!("YAML parse error in '{path}': {e}"))?;

    if raw.get("gcp").is_some() {
        let root: GcpRoot = serde_yaml::from_str(&content)
            .map_err(|e| format!("GCP YAML parse error in '{path}': {e}"))?;
        let yaml = root.gcp;

        validate_specs(&yaml.specs)?;

        let creds = GcpCredentials {
            client_email: yaml.credentials.client_email.clone(),
            private_key_path: expand_tilde(&yaml.credentials.private_key),
            project_id: yaml.credentials.project_id.clone(),
            zone: yaml.credentials.zone.clone(),
        };

        let location = creds.zone.clone();
        let identity = creds.client_email.clone();
        let provider = GcpProvider::new(&creds)?;

        Ok(LoadedProvider::Gcp {
            common: CommonConfig {
                groups: yaml.group,
                generics: yaml.generics,
                specs: yaml.specs,
                rules: yaml.rules,
            },
            location,
            identity,
            provider,
        })
    } else if raw.get("digitalocean").is_some() {
        let root: DoRoot = serde_yaml::from_str(&content)
            .map_err(|e| format!("DigitalOcean YAML parse error in '{path}': {e}"))?;
        let yaml = root.digitalocean;

        validate_specs(&yaml.specs)?;

        let creds = DigitalOceanCredentials {
            token: yaml.credentials.token.clone(),
            region: yaml.credentials.region.clone(),
        };

        let location = creds.region.clone();
        let provider = DigitalOceanProvider::new(&creds)?;

        Ok(LoadedProvider::DigitalOcean {
            common: CommonConfig {
                groups: yaml.group,
                generics: yaml.generics,
                specs: yaml.specs,
                rules: yaml.rules,
            },
            location,
            provider,
        })
    } else {
        Err(format!(
            "Cannot detect provider in '{path}': \
             YAML must have a top-level 'gcp' or 'digitalocean' key"
        )
        .into())
    }
}

// ---------------------------------------------------------------------------
// Spec validation
// ---------------------------------------------------------------------------

/// Walk every `SpecConfigYaml` block and reject any `ip-address` value that
/// is not `"public"` or `"private"`.
///
/// Serde already rejects unknown enum variants, so by the time this function
/// is called the only possible values are the two valid ones.  The function
/// serves as an explicit audit point and prints a clear summary of what was
/// found.
fn validate_specs(specs: &[SpecYaml]) -> Result<(), Box<dyn std::error::Error>> {
    for spec_yaml in specs {
        for (i, cfg) in spec_yaml.config.iter().enumerate() {
            // IpAddressType only has Public/Private variants; serde rejects
            // anything else at deserialization time, so this match is
            // exhaustive and always succeeds.  We keep it explicit so that
            // adding a third variant in the future forces a conscious update
            // here.
            match cfg.ip_address {
                IpAddressType::Public | IpAddressType::Private => {}
            }

            println!(
                "  spec '{}' [{}]: ip-address = {}",
                spec_yaml.name, i, cfg.ip_address
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rule resolution (provider-agnostic)
// ---------------------------------------------------------------------------

struct ResolvedRule<'a> {
    group_name: &'a str,
    generics_name: &'a str,
    specs_name: &'a str,
    nodes: &'a [String],
    generic: &'a GenericConfigYaml,
    spec: &'a SpecConfigYaml,
}

fn resolve_rules<'a>(
    common: &'a CommonConfig,
) -> Result<Vec<ResolvedRule<'a>>, Box<dyn std::error::Error>> {
    let groups: HashMap<&str, &[String]> = common
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.node.as_slice()))
        .collect();

    let generics: HashMap<&str, &GenericConfigYaml> = common
        .generics
        .iter()
        .filter_map(|g| g.config.first().map(|c| (g.name.as_str(), c)))
        .collect();

    let specs: HashMap<&str, &SpecConfigYaml> = common
        .specs
        .iter()
        .filter_map(|s| s.config.first().map(|c| (s.name.as_str(), c)))
        .collect();

    common
        .rules
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
                group_name: &rule.group,
                generics_name: &rule.generics,
                specs_name: &rule.specs,
                nodes,
                generic,
                spec,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
            "\n  group: {}  (generics: {}, specs: {})",
            r.group_name, r.generics_name, r.specs_name
        );
        println!(
            "    machine-type: {}  image: {}  disk: {} GB  ip-address: {}",
            r.spec.machine_type, r.spec.boot_disk_image, r.spec.boot_disk_size, r.spec.ip_address
        );
        println!(
            "    user: {}  ssh-public-key: {}",
            r.generic.user, r.generic.ssh_public_key
        );
        for node in r.nodes {
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
            "\n── Group: {} ─────────────────────────────────────────────────────",
            r.group_name
        );

        let ssh_meta = read_ssh_public_key(&r.generic.ssh_public_key)
            .map(|k| format!("{}:{k}", r.generic.user))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });

        let assign_public_ip = r.spec.ip_address == IpAddressType::Public;

        for node in r.nodes {
            println!("\n  ── Creating instance: {node} ──");
            let resp = provider.create_vm(
                node,
                &r.spec.machine_type,
                &r.spec.boot_disk_image,
                r.spec.boot_disk_size,
                &ssh_meta,
                &r.generic.script,
                assign_public_ip,
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

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    println!("\n── Instances to destroy ─────────────────────────────────────────────────");

    let mut all_nodes: Vec<(&str, &str)> = Vec::new();
    for group in &common.groups {
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

    let provider = loaded.provider();

    for (group_name, node) in &all_nodes {
        println!("\n  ── Deleting [{group_name}] {node} ──");
        match provider.destroy_vm(node) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {node}: {e}"),
        }
    }

    println!("\n✓ Deletion requests submitted. Operations may take a minute to complete.");
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

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    let default_generic = common
        .generics
        .iter()
        .find(|g| g.name == "default")
        .and_then(|g| g.config.first())
        .ok_or("No 'default' generics entry found in config")?;

    let ssh_user = &default_generic.user;

    let ssh_pub_path = default_generic.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    // ── Build a map from group name → prefer_public ──────────────────────────
    //
    // For each rule, look up the spec it references and read the ip-address
    // field.  This drives both the IP-lookup call and the SSH target address.
    let group_prefer_public: HashMap<&str, bool> = common
        .rules
        .iter()
        .filter_map(|rule| {
            let ip_type = common
                .specs
                .iter()
                .find(|s| s.name == rule.specs)
                .and_then(|s| s.config.first())
                .map(|c| c.ip_address)
                .unwrap_or(IpAddressType::Private);
            Some((rule.group.as_str(), ip_type == IpAddressType::Public))
        })
        .collect();

    let cp_prefer_public = *group_prefer_public.get("control-plane").unwrap_or(&false);
    let worker_prefer_public = *group_prefer_public.get("worker").unwrap_or(&false);

    println!("\n  Fetching IPs …");
    println!(
        "  control-plane ip-address: {}",
        if cp_prefer_public {
            "public"
        } else {
            "private"
        }
    );
    println!(
        "  worker        ip-address: {}",
        if worker_prefer_public {
            "public"
        } else {
            "private"
        }
    );

    let cp_nodes: Vec<&str> = common
        .rules
        .iter()
        .find(|r| r.group == "control-plane")
        .and_then(|r| common.groups.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let worker_nodes: Vec<&str> = common
        .rules
        .iter()
        .find(|r| r.group == "worker")
        .and_then(|r| common.groups.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    // Resolve IPs using the preference dictated by ip-address in each group's
    // spec.  When prefer_public is true the provider returns the external IP;
    // when false it returns the internal/private IP.
    let resolve_ips = |nodes: &[&str],
                       prefer_public: bool|
     -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        nodes
            .iter()
            .map(|&name| {
                let ip = provider.get_vm_ip(name, prefer_public)?;
                println!(
                    "  {name:<30} →  {ip}  ({})",
                    if prefer_public { "public" } else { "private" }
                );
                Ok((name.to_string(), ip))
            })
            .collect()
    };

    let cp_with_ips: Vec<(String, String)> = resolve_ips(&cp_nodes, cp_prefer_public)?;
    let worker_with_ips: Vec<(String, String)> = resolve_ips(&worker_nodes, worker_prefer_public)?;

    println!("  SSH user: {ssh_user}  private key: {ssh_priv_path}");

    // ── Step 1: provision control-plane nodes ────────────────────────────────
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
            ssh_user,
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
            ssh_user,
            &ssh_priv_path,
            "sudo cisak install --control-plane -y",
        )?;
        println!("\n  ✓ {name} provisioned.");
    }

    // ── Step 2: join workers ─────────────────────────────────────────────────
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
            ssh_user,
            &ssh_priv_path,
            "sudo kubeadm token create --print-join-command",
        )?;

        if join_cmd.is_empty() {
            eprintln!("  ✗ Empty join command from {primary_cp_name} — is it fully up?");
            continue;
        }

        println!("  Join command: {join_cmd}");
        println!("\n  Joining {name} …\n");
        ssh_run(ip, ssh_user, &ssh_priv_path, &format!("sudo {join_cmd}"))?;
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
        Commands::Apply { config } => apply_config(&config),
        Commands::Destroy { config } => destroy_config(&config),
        Commands::Play { config } => play_config(&config),
        Commands::Print => print_build_credential(),
    }
}
