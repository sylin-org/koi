use std::path::Path;
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::model::NodeSpec;

pub struct PuttyTransport {
    password: Option<String>,
}

impl PuttyTransport {
    pub fn from_environment() -> Self {
        Self {
            password: std::env::var("KOI_LAB_PASSWORD").ok(),
        }
    }

    pub fn run(&self, node: &NodeSpec, remote_command: &str) -> Result<Output> {
        if remote_command.contains('\0') {
            bail!("remote command contains a NUL byte");
        }
        let password = self.resolved_password(node)?;
        let (address, user, host_key) = remote_details(node)?;
        // Force POSIX sh regardless of the account's login shell (a
        // workstation may run fish/zsh): every lab snippet is written for sh,
        // so the transport pins the interpreter instead of assuming one.
        let remote = format!("sh -c '{}'", remote_command.replace('\'', "'\\''"));
        let output = Command::new("plink")
            .args([
                "-batch",
                "-ssh",
                "-hostkey",
                host_key,
                "-pw",
                &password,
                &format!("{user}@{address}"),
                &remote,
            ])
            .output()
            .with_context(|| format!("failed to start plink for node {}", node.id()))?;
        Ok(output)
    }

    pub fn run_checked(&self, node: &NodeSpec, remote_command: &str) -> Result<String> {
        let output = self.run(node, remote_command)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            bail!(
                "remote command failed on {} (exit {}): {}",
                node.id(),
                output.status.code().unwrap_or(-1),
                stderr
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("node {} returned non-UTF-8 output", node.id()))
    }

    pub fn copy_to(&self, node: &NodeSpec, local: &Path, remote_path: &str) -> Result<()> {
        if !local.is_file() {
            bail!("local artifact does not exist: {}", local.display());
        }
        if remote_path
            .chars()
            .any(|c| matches!(c, '\r' | '\n' | '\0' | ' ' | '\'' | '"'))
        {
            bail!("unsafe remote copy path {remote_path:?}");
        }
        let password = self.resolved_password(node)?;
        let (address, user, host_key) = remote_details(node)?;
        let destination = format!("{user}@{address}:{remote_path}");
        let output = Command::new("pscp")
            .args(["-batch", "-q", "-hostkey", host_key, "-pw", &password])
            .arg(local)
            .arg(destination)
            .output()
            .with_context(|| format!("failed to start pscp for node {}", node.id()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            bail!(
                "artifact copy failed for {} (exit {}): {}",
                node.id(),
                output.status.code().unwrap_or(-1),
                stderr
            );
        }
        Ok(())
    }

    pub fn copy_from(&self, node: &NodeSpec, remote_path: &str, local: &Path) -> Result<()> {
        if remote_path
            .chars()
            .any(|c| matches!(c, '\r' | '\n' | '\0' | ' ' | '\'' | '"'))
        {
            bail!("unsafe remote copy path {remote_path:?}");
        }
        if local.exists() {
            bail!("local copy destination already exists: {}", local.display());
        }
        let parent = local
            .parent()
            .context("local copy destination has no parent")?;
        if !parent.is_dir() {
            bail!(
                "local copy destination parent does not exist: {}",
                parent.display()
            );
        }
        let password = self.resolved_password(node)?;
        let (address, user, host_key) = remote_details(node)?;
        let source = format!("{user}@{address}:{remote_path}");
        let output = Command::new("pscp")
            .args(["-batch", "-q", "-hostkey", host_key, "-pw", &password])
            .arg(source)
            .arg(local)
            .output()
            .with_context(|| format!("failed to start pscp for node {}", node.id()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            bail!(
                "artifact download failed for {} (exit {}): {}",
                node.id(),
                output.status.code().unwrap_or(-1),
                stderr
            );
        }
        Ok(())
    }

    /// Per-machine credential resolution (catalog-driven, schema 2): a node's
    /// `password_env` names the environment variable holding ITS password;
    /// machines without one share the global `KOI_LAB_PASSWORD`.
    fn resolved_password(&self, node: &NodeSpec) -> Result<String> {
        if let Some(env_name) = node.password_env() {
            let password = std::env::var(env_name).map_err(|_| {
                anyhow::anyhow!(
                    "{env_name} is required for remote operations on {}",
                    node.id()
                )
            })?;
            Self::validate_password(&password, env_name)?;
            return Ok(password);
        }
        let password = self
            .password
            .as_deref()
            .context("KOI_LAB_PASSWORD is required for remote lab operations")?;
        Self::validate_password(password, "KOI_LAB_PASSWORD")?;
        Ok(password.to_owned())
    }

    fn validate_password(password: &str, source: &str) -> Result<()> {
        if password.is_empty() || password.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
            bail!("{source} contains an invalid value");
        }
        Ok(())
    }
}

fn remote_details(node: &NodeSpec) -> Result<(&str, &str, &str)> {
    match node {
        NodeSpec::PuttyLinux {
            address,
            user,
            host_key,
            ..
        } => Ok((address, user, host_key)),
        NodeSpec::LocalWindows { .. } => bail!("{} is not a PuTTY node", node.id()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_nodes_are_rejected_by_the_remote_transport() {
        let node = NodeSpec::LocalWindows {
            id: "windows".into(),
            hostname: "stone-leaded-sparkle".into(),
            address: "192.168.1.138".into(),
            http_port: 18541,
            mtls_port: 18542,
            acme_port: 18543,
            proxy_port: 18544,
            dns_port: 18553,
            fixture_port: 18554,
            container_port: 18555,
            roles: Vec::new(),
            mutations: Vec::new(),
            privilege: "workstation".into(),
        };
        assert!(remote_details(&node).is_err());
    }
}
