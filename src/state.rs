use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct State {
    pub instances: HashMap<String, String>,
}

impl State {
    /// Loads the `.state` file if it exists, otherwise creates an empty state.
    pub fn load(config_path: &str) -> Self {
        let path = Self::file_path(config_path);
        if Path::new(&path).exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str(&content) {
                    return state;
                }
            }
        }
        Self::default()
    }

    /// Saves the current mappings to the `.state` file.
    pub fn save(&self, config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::file_path(config_path);
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    fn file_path(config_path: &str) -> String {
        format!("{}.state", config_path)
    }
}
