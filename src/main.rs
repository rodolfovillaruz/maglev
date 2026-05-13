mod command;
mod cp;
mod ip;
mod provider;
mod rule;
mod spec;
mod ssh;
mod utils;
mod yaml;

use clap::{Parser, Subcommand};
use command::apply::apply_config;
use command::destroy::destroy_config;
use command::play::play_config;
use command::reset::reset_config;
use command::restart::restart_config;
use cp::provision_control_plane_node;
use ip::IpAddressType;
use provider::gcp::print_build_credential;
use ssh::{ssh_capture, ssh_capture_jump, ssh_run, ssh_run_jump};
use utils::{expand_tilde, prompt_yes_no};
use yaml::{SpecConfigYaml, SpecYaml};

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
        config: String,
    },
    /// Permanently delete VM instances described by a provider YAML config
    Destroy {
        /// Path to the YAML config file
        config: String,
    },
    /// Provision Kubernetes on control-plane nodes and join workers
    Play {
        /// Path to the YAML config file
        config: String,
        /// Assume "yes" to every interactive prompt
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
    },
    /// Reset kubeadm state on all nodes
    Reset {
        /// Path to the YAML config file
        config: String,
    },
    /// Restart (reboot) all nodes
    Restart {
        /// Path to the YAML config file
        config: String,
    },
    /// Run the interactive GCP credential builder
    Print,
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
        Commands::Play {
            config,
            auto_approve,
        } => play_config(&config, auto_approve),
        Commands::Reset { config } => reset_config(&config),
        Commands::Restart { config } => restart_config(&config),
        Commands::Print => print_build_credential(),
    }
}
