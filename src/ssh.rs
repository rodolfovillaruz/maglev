pub fn ssh_capture(
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

pub fn ssh_run(
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

// ---------------------------------------------------------------------------
// SSH helpers — via ProxyCommand (jump_host → target)
// ---------------------------------------------------------------------------

pub fn ssh_capture_jump(
    jump_ip: &str,
    jump_user: &str,
    target_ip: &str,
    target_user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Explicitly pass the bypass flags and key to the jump host connection.
    // Note: We wrap the private_key_path in single quotes in case it contains spaces.
    let proxy_cmd = format!(
        "ssh -W %h:%p -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i '{}' {}@{}",
        private_key_path, jump_user, jump_ip
    );

    let out = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "LogLevel=ERROR",
            "-o",
            &format!("ProxyCommand={proxy_cmd}"),
            &format!("{target_user}@{target_ip}"),
            command,
        ])
        .output()
        .map_err(|e| format!("Failed to spawn ssh (jump): {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ssh (jump) exited {} — stderr: {stderr}",
            out.status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn ssh_run_jump(
    jump_ip: &str,
    jump_user: &str,
    target_ip: &str,
    target_user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_cmd = format!(
        "ssh -W %h:%p -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i '{}' {}@{}",
        private_key_path, jump_user, jump_ip
    );

    let status = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "LogLevel=ERROR",
            "-t",
            "-o",
            &format!("ProxyCommand={proxy_cmd}"),
            &format!("{target_user}@{target_ip}"),
            command,
        ])
        .status()
        .map_err(|e| format!("Failed to spawn ssh (jump): {e}"))?;

    if !status.success() {
        return Err(format!(
            "Remote command (jump) exited {}",
            status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(())
}
