pub mod digitalocean;
pub mod gcp;

/// Cloud-provider abstraction.
///
/// Each implementation is responsible for holding its own authentication
/// context (project, zone / region, access token, …) and exposing the two
/// lifecycle operations that Maglev needs.
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
}
