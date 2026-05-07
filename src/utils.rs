use std::env;
use std::fs::read_to_string;
use std::io::{BufRead, Write, stdin, stdout};

use crate::provider::gcp::GcpEntry;

// ---------------------------------------------------------------------------
// SSH key / startup-script helpers
// ---------------------------------------------------------------------------

pub fn read_ssh_public_key(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(path);
    let content = read_to_string(&expanded)
        .map_err(|e| format!("Cannot read SSH public key from '{expanded}': {e}"))?;
    Ok(content.trim().to_string())
}

pub fn read_startup_script(path: &str) -> String {
    let expanded = expand_tilde(path);
    read_to_string(&expanded).unwrap_or_else(|_| {
        "#!/bin/bash\nset -e\napt-get update\n\
         curl -fsSL https://github.com/rodolfovillaruz/cisak/releases/download/v0.1.11/\
         cisak-v0.1.11-linux-amd64.tar.gz | tar -xz\n\
         install -m 755 -o root -g root cisak /usr/local/bin/cisak\n\
         cisak generate\ncisak install -y"
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Shared: load GCP private key from config
// ---------------------------------------------------------------------------

pub fn load_gcp_private_key(gcp: &GcpEntry) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(&gcp.private_key);
    read_to_string(&expanded)
        .map_err(|e| format!("Cannot read GCP private key from '{expanded}': {e}").into())
}

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

pub fn prompt_yes_no(question: &str) -> bool {
    print!("{question} [y/N]: ");
    stdout().flush().expect("Failed to flush stdout");

    let stdin = stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .expect("Failed to read input");

    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}
