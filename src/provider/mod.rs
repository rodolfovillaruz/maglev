pub mod digitalocean;
pub mod gcp;

/// Cloud-provider abstraction.
///
/// Each implementation holds its own authentication context and exposes the
/// three lifecycle operations Maglev needs.
pub trait Provider {
    fn create_vm(
        &self,
        instance_name: &str,
        machine_type: &str,
        boot_disk_image: &str,
        boot_disk_size_gb: u64,
        ssh_keys_metadata: &str,
        startup_script: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    fn destroy_vm(
        &self,
        instance_name: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    /// Return the best reachable IP for `instance_name` (private preferred).
    fn get_vm_ip(&self, instance_name: &str) -> Result<String, Box<dyn std::error::Error>>;
}
