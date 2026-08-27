use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RUN_OUTPUT_DIR: &str = ".lab-runs";
const RUN_ID_PREFIX: &str = "v1-";

#[derive(Clone, Debug, Deserialize)]
pub struct LabConfig {
    pub schema: u32,
    pub artifact: ArtifactSpec,
    pub nodes: Vec<NodeSpec>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ArtifactSpec {
    pub target: String,
    pub package: String,
    pub relative_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeSpec {
    LocalWindows {
        id: String,
        hostname: String,
        address: String,
        http_port: u16,
        mtls_port: u16,
        acme_port: u16,
        proxy_port: u16,
        dns_port: u16,
        fixture_port: u16,
        container_port: u16,
        /// What this machine may run in generated assignments.
        #[serde(default)]
        roles: Vec<String>,
        /// What may be mutated on it (trust-store, systemd). Empty = never
        /// assigned a mutating lane, even with the operator flag present.
        #[serde(default)]
        mutations: Vec<String>,
        /// `dedicated-box` or `workstation`. Workstations are daily-driver
        /// machines: every lane stays run-scoped and exactly restored.
        #[serde(default = "default_privilege")]
        privilege: String,
    },
    PuttyLinux {
        id: String,
        hostname: String,
        address: String,
        user: String,
        host_key: String,
        architecture: String,
        remote_root: String,
        http_port: u16,
        mtls_port: u16,
        acme_port: u16,
        proxy_port: u16,
        dns_port: u16,
        fixture_port: u16,
        container_port: u16,
        #[serde(default)]
        roles: Vec<String>,
        #[serde(default)]
        mutations: Vec<String>,
        #[serde(default = "default_privilege")]
        privilege: String,
        /// Environment variable holding this machine's SSH password. Falls
        /// back to the shared `KOI_LAB_PASSWORD` when absent — credentials
        /// live in the environment, never in the catalog file.
        #[serde(default)]
        password_env: Option<String>,
    },
}

fn default_privilege() -> String {
    "dedicated-box".to_string()
}

impl NodeSpec {
    pub fn password_env(&self) -> Option<&str> {
        match self {
            Self::PuttyLinux { password_env, .. } => password_env.as_deref(),
            Self::LocalWindows { .. } => None,
        }
    }

    /// Whether this machine may play `role` in a generated assignment.
    /// Machines with an empty role list are legacy entries: they opt into
    /// nothing and the planner will not schedule them.
    pub fn supports_role(&self, role: &str) -> bool {
        match self {
            Self::PuttyLinux { roles, .. } | Self::LocalWindows { roles, .. } => {
                roles.iter().any(|r| r == role)
            }
        }
    }

    /// Whether `op` (e.g. `trust-store`, `systemd`) may be mutated here.
    pub fn allows_mutation(&self, op: &str) -> bool {
        match self {
            Self::PuttyLinux { mutations, .. } | Self::LocalWindows { mutations, .. } => {
                mutations.iter().any(|m| m == op)
            }
        }
    }

    pub fn privilege(&self) -> &str {
        match self {
            Self::PuttyLinux { privilege, .. } | Self::LocalWindows { privilege, .. } => privilege,
        }
    }
}

/// Named V1-02 role rotations. Node assignment lives here so scenario code
/// consumes roles rather than scattering fixed host IDs through each check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum TrustRotation {
    LinuxForward,
    LinuxReverse,
    WindowsClient,
}

/// Operator-facing hardware execution policies. Scenario membership is owned
/// by the profile orchestrator; this enum is only the stable CLI/report name.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum LabProfile {
    Smoke,
    Certmesh,
    Full,
    /// Every `full` case that runs on the two Linux hosts — the Windows
    /// workstation's native-trust lane is excluded, so the profile is runnable
    /// from an unelevated controller session.
    Linux,
    Soak,
}

impl LabProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Certmesh => "certmesh",
            Self::Full => "full",
            Self::Linux => "linux",
            Self::Soak => "soak",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertmeshRoles {
    pub ca: &'static str,
    pub service: &'static str,
    pub client: &'static str,
}

impl TrustRotation {
    pub fn roles(self) -> CertmeshRoles {
        match self {
            Self::LinuxForward => CertmeshRoles {
                ca: "brook",
                service: "granite",
                client: "brook",
            },
            Self::LinuxReverse => CertmeshRoles {
                ca: "granite",
                service: "brook",
                client: "granite",
            },
            Self::WindowsClient => CertmeshRoles {
                ca: "brook",
                service: "granite",
                client: "windows",
            },
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxForward => "linux-forward",
            Self::LinuxReverse => "linux-reverse",
            Self::WindowsClient => "windows-client",
        }
    }
}

impl LabConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("could not open lab config {}", path.display()))?;
        let config: Self = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("could not parse lab config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 2 {
            bail!("unsupported lab config schema {}", self.schema);
        }
        if self.artifact.target != "x86_64-unknown-linux-musl" {
            bail!("the physical lab requires the x86_64 musl artifact target");
        }
        if self.artifact.package != "koi-net" {
            bail!("the physical lab artifact package must be koi-net");
        }
        if self.nodes.len() < 3 {
            bail!("the lab inventory requires one local Windows node and at least two Linux nodes");
        }

        let mut ids = HashSet::new();
        let mut addresses = HashSet::new();
        let mut local_count = 0;
        let mut remote_count = 0;
        let mut ports = HashSet::new();
        for node in &self.nodes {
            let id = node.id();
            validate_identifier(id, "node id")?;
            if !ids.insert(id) {
                bail!("duplicate node id {id}");
            }
            let address = node.address();
            address
                .parse::<IpAddr>()
                .with_context(|| format!("node {id} has invalid address {address}"))?;
            if !addresses.insert(address) {
                bail!("duplicate node address {address}");
            }

            match node {
                NodeSpec::LocalWindows {
                    hostname,
                    http_port,
                    mtls_port,
                    acme_port,
                    proxy_port,
                    dns_port,
                    fixture_port,
                    container_port,
                    ..
                } => {
                    local_count += 1;
                    validate_hostname(hostname)?;
                    for port in [
                        http_port,
                        mtls_port,
                        acme_port,
                        proxy_port,
                        dns_port,
                        fixture_port,
                        container_port,
                    ] {
                        if *port < 1024 || !ports.insert(*port) {
                            bail!("node {id} has an unsafe or duplicate lab port {port}");
                        }
                    }
                }
                NodeSpec::PuttyLinux {
                    hostname,
                    user,
                    host_key,
                    architecture,
                    remote_root,
                    http_port,
                    mtls_port,
                    acme_port,
                    proxy_port,
                    dns_port,
                    fixture_port,
                    container_port,
                    ..
                } => {
                    remote_count += 1;
                    validate_hostname(hostname)?;
                    validate_identifier(user, "SSH user")?;
                    if !host_key.starts_with("SHA256:") || host_key.len() < 24 {
                        bail!("node {id} does not have a pinned SHA-256 SSH host key");
                    }
                    if architecture != "x86_64" {
                        bail!("node {id} must be x86_64, got {architecture}");
                    }
                    validate_remote_root(remote_root)?;
                    for port in [
                        http_port,
                        mtls_port,
                        acme_port,
                        proxy_port,
                        dns_port,
                        fixture_port,
                        container_port,
                    ] {
                        if *port < 1024 || !ports.insert(*port) {
                            bail!("node {id} has an unsafe or duplicate lab port {port}");
                        }
                    }
                }
            }
        }
        if local_count != 1 || remote_count < 2 {
            bail!("the lab requires one local Windows node and at least two PuTTY Linux nodes");
        }
        Ok(())
    }

    pub fn local(&self) -> Result<&NodeSpec> {
        self.nodes
            .iter()
            .find(|node| matches!(node, NodeSpec::LocalWindows { .. }))
            .context("validated lab config has no local Windows node")
    }

    pub fn node(&self, id: &str) -> Result<&NodeSpec> {
        self.nodes
            .iter()
            .find(|node| node.id() == id)
            .with_context(|| format!("validated lab config has no node {id}"))
    }

    pub fn remotes(&self) -> impl Iterator<Item = &NodeSpec> {
        self.nodes
            .iter()
            .filter(|node| matches!(node, NodeSpec::PuttyLinux { .. }))
    }
}

impl NodeSpec {
    pub fn id(&self) -> &str {
        match self {
            Self::LocalWindows { id, .. } | Self::PuttyLinux { id, .. } => id,
        }
    }

    pub fn hostname(&self) -> &str {
        match self {
            Self::LocalWindows { hostname, .. } | Self::PuttyLinux { hostname, .. } => hostname,
        }
    }

    pub fn address(&self) -> &str {
        match self {
            Self::LocalWindows { address, .. } | Self::PuttyLinux { address, .. } => address,
        }
    }

    pub fn remote_root(&self) -> Result<&str> {
        match self {
            Self::PuttyLinux { remote_root, .. } => Ok(remote_root),
            Self::LocalWindows { .. } => bail!("{} is not a remote node", self.id()),
        }
    }

    pub fn remote_user(&self) -> Result<&str> {
        match self {
            Self::PuttyLinux { user, .. } => Ok(user),
            Self::LocalWindows { .. } => bail!("{} is not a remote node", self.id()),
        }
    }

    pub fn lock_dir(&self) -> Result<String> {
        Ok(format!("{}/.koi-lab-lock", self.remote_root()?))
    }

    pub fn run_dir(&self, run_id: &RunId) -> Result<String> {
        Ok(format!("{}/runs/{}", self.remote_root()?, run_id.as_str()))
    }

    pub fn lab_ports(&self) -> Result<LabPorts> {
        match self {
            Self::LocalWindows {
                http_port,
                mtls_port,
                acme_port,
                proxy_port,
                dns_port,
                fixture_port,
                container_port,
                ..
            }
            | Self::PuttyLinux {
                http_port,
                mtls_port,
                acme_port,
                proxy_port,
                dns_port,
                fixture_port,
                container_port,
                ..
            } => Ok(LabPorts {
                http: *http_port,
                mtls: *mtls_port,
                acme: *acme_port,
                proxy: *proxy_port,
                dns: *dns_port,
                fixture: *fixture_port,
                container: *container_port,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabPorts {
    pub http: u16,
    pub mtls: u16,
    pub acme: u16,
    pub proxy: u16,
    pub dns: u16,
    pub fixture: u16,
    pub container: u16,
}

impl LabPorts {
    pub fn all(self) -> [u16; 7] {
        [
            self.http,
            self.mtls,
            self.acme,
            self.proxy,
            self.dns,
            self.fixture,
            self.container,
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RunId(String);

impl<'de> Deserialize<'de> for RunId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl RunId {
    pub fn generate() -> Self {
        let now = Utc::now();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seed = format!("{nanos}-{}", std::process::id());
        let digest = Sha256::digest(seed.as_bytes());
        let suffix = hex_prefix(&digest, 4);
        Self(format!(
            "{RUN_ID_PREFIX}{}-{suffix}",
            now.format("%Y%m%dT%H%M%SZ")
        ))
    }

    pub fn parse(value: &str) -> Result<Self> {
        if !value.starts_with(RUN_ID_PREFIX)
            || value.len() > 40
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("invalid run id {value:?}");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactIdentity {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildReport {
    pub linux: ArtifactIdentity,
    pub windows: ArtifactIdentity,
}

impl ArtifactIdentity {
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("could not open artifact {}", path.display()))?;
        let size_bytes = file
            .metadata()
            .with_context(|| format!("could not stat artifact {}", path.display()))?
            .len();
        if size_bytes == 0 {
            bail!("artifact {} is empty", path.display());
        }
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let sha256 = hex_prefix(&hasher.finalize(), 32);
        Ok(Self {
            path: path.to_path_buf(),
            size_bytes,
            sha256,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeSnapshot {
    pub id: String,
    pub expected_hostname: String,
    pub observed_hostname: String,
    pub address: String,
    pub operating_system: String,
    pub architecture: String,
    /// Catalog metadata (schema 2): what the machine may run, what may be
    /// mutated on it, and its privilege class. Surfaced so operators see the
    /// planner's grants at a glance.
    #[serde(default)]
    pub catalog_roles: Vec<String>,
    #[serde(default)]
    pub catalog_mutations: Vec<String>,
    #[serde(default)]
    pub catalog_privilege: String,
    pub utc_epoch: i64,
    pub clock_skew_seconds: i64,
    pub clock_probe_span_seconds: i64,
    pub sudo_non_interactive: bool,
    pub tools: BTreeMap<String, bool>,
    pub services: BTreeMap<String, ServiceSnapshot>,
    pub listening_sockets: Vec<String>,
    pub remote_root_present: bool,
    pub existing_artifact_sha256: Option<String>,
    pub existing_artifact_version: Option<String>,
    pub deploy_ready: bool,
    pub scenario_ready: bool,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceSnapshot {
    pub active: String,
    pub enabled: String,
    pub exec_start: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreflightReport {
    pub schema: u32,
    pub created_at: DateTime<Utc>,
    pub git_commit: String,
    pub local: NodeSnapshot,
    pub remotes: Vec<NodeSnapshot>,
    pub deploy_ready: bool,
    pub scenario_ready: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeploymentManifest {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub git_commit: String,
    pub artifact: ArtifactIdentity,
    pub nodes: Vec<DeployedNode>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeployedNode {
    pub id: String,
    pub address: String,
    pub run_dir: String,
    pub artifact_sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupPlan {
    pub run_id: RunId,
    pub nodes: Vec<NodeCleanupPlan>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeCleanupPlan {
    pub id: String,
    pub lock_dir: String,
    pub run_dir: String,
    pub lock_present: bool,
    pub owner_matches: bool,
    pub run_dir_present: bool,
    pub disposition: CleanupDisposition,
    pub files: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupDisposition {
    Owned,
    Absent,
    Conflict,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertmeshSmokeReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub ca_node: String,
    pub member_node: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeTrustReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub ca_node: String,
    pub service_node: String,
    pub client_node: String,
    pub ca_fingerprint: String,
    pub checks: Vec<CheckResult>,
    pub system_trust_restored: bool,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertmeshLifecycleReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub ca_node: String,
    pub member_node: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertmeshRecoveryReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub ca_node: String,
    pub member_node: String,
    pub ca_fingerprint: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapabilityStoryReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub primary_node: String,
    pub observer_node: String,
    pub covered_acts: Vec<u8>,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeReconnectReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub primary_node: String,
    pub observer_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct WebhookFanoutReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub primary_node: String,
    pub sink_node: String,
    pub artifact_sha256: String,
    pub deliveries_captured: u32,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct MgmtPrincipalReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub rotation: TrustRotation,
    pub primary_node: String,
    pub probe_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W4 (ADR-032) Windows-hosted CA rotation: the CA daemon runs on this
/// workstation and a physical Linux member enrolls, renews, and is revoked
/// over the real LAN.
#[derive(Clone, Debug, Serialize)]
pub struct WindowsCaReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub ca_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W6+W9 (ADR-032): Windows-hosted serving lane — DNS on the standard port
/// verified cross-host and via the native resolver, plus cross-host health
/// checks in both directions, over the real LAN.
#[derive(Clone, Debug, Serialize)]
pub struct WindowsBreadthReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub windows_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W5 (ADR-032): mDNS announce/browse from Windows over the real LAN, both
/// directions (Windows announces → member discovers; member announces →
/// Windows discovers).
#[derive(Clone, Debug, Serialize)]
pub struct WindowsMdnsReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub windows_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W7 (ADR-032): TLS proxy serving ON Windows, verified by Schannel AND
/// openssl from the Linux CA host, with a certmesh-sourced leaf.
#[derive(Clone, Debug, Serialize)]
pub struct WindowsProxyReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub windows_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W8 (ADR-032): webhook origin ON Windows, sink on the Linux member, HMAC
/// verified at receive.
#[derive(Clone, Debug, Serialize)]
pub struct WindowsWebhookReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub windows_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

/// W12 (ADR-032): ACME dns-01 with the Windows daemon as the RFC 8555 server,
/// TXT served through its own DNS runtime, cross-host observed.
#[derive(Clone, Debug, Serialize)]
pub struct WindowsAcmeReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub windows_node: String,
    pub member_node: String,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceLifecycleWindowsReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub artifact_sha256: String,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceLifecycleReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub service_node: String,
    pub observer_node: String,
    pub unit_name: String,
    pub artifact_sha256: String,
    pub initial_pid: u32,
    pub restarted_pid: u32,
    pub restart_count: u64,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SoakIterationReport {
    pub iteration: u32,
    pub duration_ms: u64,
    pub restarted_from_pid: Option<u32>,
    pub restarted_to_pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BoundedSoakReport {
    pub schema: u32,
    pub run_id: RunId,
    pub created_at: DateTime<Utc>,
    pub primary_node: String,
    pub observer_node: String,
    pub artifact_sha256: String,
    pub target_iterations: u32,
    pub completed_iterations: u32,
    pub max_minutes: u32,
    pub restart_every: u32,
    pub termination: String,
    pub elapsed_ms: u64,
    pub iterations: Vec<SoakIterationReport>,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileCaseReport {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    pub deployment_passed: bool,
    pub scenario_passed: bool,
    pub cleanup_passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileReport {
    pub schema: u32,
    pub execution_id: RunId,
    pub created_at: DateTime<Utc>,
    pub git_commit: String,
    pub profile: LabProfile,
    pub cases: Vec<ProfileCaseReport>,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileRecoveryReport {
    pub schema: u32,
    pub execution_id: RunId,
    pub created_at: DateTime<Utc>,
    pub git_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<LabProfile>,
    pub recovered_runs: Vec<RunId>,
    pub checks: Vec<CheckResult>,
    pub secrets_redacted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

pub trait EvidenceReport: Serialize {
    fn checks(&self) -> &[CheckResult];
    fn secrets_redacted(&self) -> bool;
}

macro_rules! impl_evidence_report {
    ($($report:ty),+ $(,)?) => {
        $(
            impl EvidenceReport for $report {
                fn checks(&self) -> &[CheckResult] {
                    &self.checks
                }

                fn secrets_redacted(&self) -> bool {
                    self.secrets_redacted
                }
            }
        )+
    };
}

impl_evidence_report!(
    CertmeshSmokeReport,
    NativeTrustReport,
    CertmeshLifecycleReport,
    CertmeshRecoveryReport,
    CapabilityStoryReport,
    RuntimeReconnectReport,
    WebhookFanoutReport,
    MgmtPrincipalReport,
    ServiceLifecycleWindowsReport,
    WindowsCaReport,
    WindowsBreadthReport,
    WindowsMdnsReport,
    WindowsProxyReport,
    WindowsWebhookReport,
    WindowsAcmeReport,
    ServiceLifecycleReport,
    BoundedSoakReport,
    ProfileReport,
    ProfileRecoveryReport,
);

pub fn output_path(name: &str) -> PathBuf {
    Path::new(RUN_OUTPUT_DIR).join(name)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid {label} {value:?}");
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        bail!("invalid hostname {value:?}");
    }
    Ok(())
}

fn validate_remote_root(value: &str) -> Result<()> {
    if !value.starts_with("/home/")
        || !value.ends_with("/koi-test")
        || value.contains("..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
    {
        bail!("unsafe remote root {value:?}");
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    let mut output = String::with_capacity(count * 2);
    for byte in bytes.iter().take(count) {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_path_safe_and_parseable() {
        let run_id = RunId::generate();
        assert_eq!(RunId::parse(run_id.as_str()).unwrap(), run_id);
        assert!(RunId::parse("../../other").is_err());
        assert!(RunId::parse("v1-space here").is_err());
    }

    #[test]
    fn trust_rotations_centralize_the_three_role_assignments() {
        assert_eq!(
            TrustRotation::LinuxForward.roles(),
            CertmeshRoles {
                ca: "brook",
                service: "granite",
                client: "brook"
            }
        );
        assert_eq!(
            TrustRotation::LinuxReverse.roles(),
            CertmeshRoles {
                ca: "granite",
                service: "brook",
                client: "granite"
            }
        );
        assert_eq!(
            TrustRotation::WindowsClient.roles(),
            CertmeshRoles {
                ca: "brook",
                service: "granite",
                client: "windows"
            }
        );
    }

    #[test]
    fn remote_roots_are_narrow() {
        assert!(validate_remote_root("/home/stone/koi-test").is_ok());
        assert!(validate_remote_root("/").is_err());
        assert!(validate_remote_root("/home/stone/../other/koi-test").is_err());
        assert!(validate_remote_root("/tmp/koi-test").is_err());
    }

    #[test]
    fn derived_paths_stay_below_the_configured_root() {
        let node = NodeSpec::PuttyLinux {
            id: "brook".into(),
            hostname: "stone-platinum-brook".into(),
            address: "192.168.1.44".into(),
            user: "stone".into(),
            host_key: "SHA256:abcdefghijklmnopqrstuvwxyz".into(),
            architecture: "x86_64".into(),
            remote_root: "/home/stone/koi-test".into(),
            http_port: 16541,
            mtls_port: 16542,
            acme_port: 16543,
            proxy_port: 16544,
            dns_port: 16553,
            fixture_port: 16554,
            container_port: 16555,
            roles: Vec::new(),
            mutations: Vec::new(),
            privilege: "dedicated-box".into(),
            password_env: None,
        };
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        assert_eq!(
            node.run_dir(&run_id).unwrap(),
            "/home/stone/koi-test/runs/v1-20260719T000000Z-deadbeef"
        );
        assert_eq!(
            node.lock_dir().unwrap(),
            "/home/stone/koi-test/.koi-lab-lock"
        );
        assert_eq!(node.lab_ports().unwrap().dns, 16553);
        assert_eq!(node.lab_ports().unwrap().fixture, 16554);
        assert_eq!(node.lab_ports().unwrap().container, 16555);
    }
}
