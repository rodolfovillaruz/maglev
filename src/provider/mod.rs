pub mod digitalocean;
pub mod gcp;

/// Cloud-provider abstraction.
///
/// Each implementation holds its own authentication context and exposes the
/// three lifecycle operations Maglev needs.
pub trait Provider {
    /// Create a VM instance.
    ///
    /// `assign_public_ip` — when `true` the provider should attach an
    /// external/public IP to the new instance.  When `false` (or when the
    /// provider always assigns a public IP by default, as DigitalOcean does)
    /// the parameter may be ignored.
    fn create_vm(
        &self,
        instance_name: &str,
        machine_type: &str,
        boot_disk_image: &str,
        boot_disk_size_gb: u64,
        ssh_keys_metadata: &str,
        startup_script: &str,
        assign_public_ip: bool,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    fn destroy_vm(
        &self,
        instance_name: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    /// Return the IP for `instance_name`.
    ///
    /// `prefer_public` — when `true` the external/public IP is returned;
    /// when `false` the internal/private IP is preferred (falling back to
    /// public only if no private address exists).
    fn get_vm_ip(
        &self,
        instance_name: &str,
        prefer_public: bool,
    ) -> Result<String, Box<dyn std::error::Error>>;
}
