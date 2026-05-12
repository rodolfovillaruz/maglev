use crate::SpecYaml;
use std::env;
use std::fs::read_to_string;
use std::io::{BufRead, Write, stdin, stdout};

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

pub fn validate_specs(specs: &[SpecYaml]) -> Result<(), Box<dyn std::error::Error>> {
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
