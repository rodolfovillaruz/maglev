mod command;
mod cp;
mod ip;
mod provider;
mod rule;
mod ssh;
mod state;
mod structs;
mod utils;

use clap::{Parser, Subcommand};
use command::apply::apply_config;
use command::destroy::destroy_config;
use command::play::play_config;
use command::reset::reset_config;
use command::restart::restart_config;
use ip::IpAddressType;
use provider::gcp::print_build_credential;
use ssh::{ssh_capture, ssh_capture_jump, ssh_run, ssh_run_jump};
use structs::{GenericsConfigYaml, GenericsYaml};
use utils::{expand_tilde, prompt_yes_no};

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
    Apply {
        config: String,
        /// Also run the play step after instances are created
        #[arg(long, default_value_t = false)]
        play: bool,
        /// Assume "yes" to every interactive prompt (only meaningful with --play)
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
        /// Force highly-available setup (useful for < 3 nodes)
        #[arg(long, default_value_t = false)]
        single_node: bool,
    },
    Destroy {
        config: String,
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
    },
    Play {
        config: String,
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
        /// Skip waiting for containerd; fail immediately if it is not ready
        /// Force highly-available setup (useful for < 3 nodes)
        #[arg(long, default_value_t = false)]
        single_node: bool,
    },
    Reset {
        config: String,
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
    },
    Restart {
        config: String,
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
    },
    Print,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;
    let cli = Cli::parse();
    match cli.command {
        Commands::Apply {
            config,
            play,
            auto_approve,
            single_node,
        } => apply_config(&config, play, auto_approve, single_node),
        Commands::Destroy {
            config,
            auto_approve,
        } => destroy_config(&config, auto_approve),
        Commands::Play {
            config,
            auto_approve,
            single_node,
        } => play_config(&config, auto_approve, single_node),
        Commands::Reset {
            config,
            auto_approve,
        } => reset_config(&config, auto_approve),
        Commands::Restart {
            config,
            auto_approve,
        } => restart_config(&config, auto_approve),
        Commands::Print => print_build_credential(),
    }
}
