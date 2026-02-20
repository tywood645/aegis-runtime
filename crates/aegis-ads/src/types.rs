use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level Agent Definition Spec parsed from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDefinition {
    pub agent: AgentMeta,

    #[serde(default)]
    pub capabilities: Capabilities,

    #[serde(default)]
    pub resources: ResourceLimits,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub checkpoint: CheckpointConfig,

    #[serde(default)]
    pub compliance: ComplianceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeta {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_framework")]
    pub framework: AgentFramework,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default = "default_restart_policy")]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub max_runtime: Option<String>,
    #[serde(default = "default_trust_level")]
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AgentFramework { OpenClaw, CrewAI, AutoGPT, LangChain, Custom }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy { Never, OnFailure, Always }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel { Trusted, SemiTrusted, Untrusted }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub filesystem: FilesystemCapabilities,
    #[serde(default)]
    pub network: NetworkCapabilities,
    #[serde(default)]
    pub exec: ExecCapabilities,
    #[serde(default)]
    pub api: HashMap<String, ApiScope>,
    #[serde(default)]
    pub skills: SkillsCapabilities,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemCapabilities {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCapabilities {
    #[serde(default)]
    pub allow_egress: Vec<String>,
    #[serde(default = "default_deny_all")]
    pub deny_egress: Vec<String>,
    #[serde(default)]
    pub allow_ingress: bool,
    #[serde(default = "default_dns_policy")]
    pub dns_policy: DnsPolicy,
}

impl Default for NetworkCapabilities {
    fn default() -> Self {
        Self {
            allow_egress: Vec::new(),
            deny_egress: vec!["*".to_string()],
            allow_ingress: false,
            dns_policy: DnsPolicy::Restricted,
        }
    }
}


#[serde(rename_all = "lowercase")]
pub enum DnsPolicy { Restricted, Open }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCapabilities {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow_subprocess: bool,
    #[serde(default)]
    pub allow_dynamic_code: bool,
    #[serde(default)]
    pub deny_dynamic_imports: Vec<String>,
}

impl Default for ExecCapabilities {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: vec!["bash".into(), "sh".into(), "zsh".into(), "nc".into(), "ncat".into(), "wget".into(), "curl".into(), "ssh".into(), "scp".into()],
            allow_subprocess: false,
            allow_dynamic_code: false,
            deny_dynamic_imports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiScope {
    pub scopes: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<String>,
    #[serde(flatten)]
    pub constraints: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillsCapabilities {
    #[serde(default)]
    pub allow_skills: Vec<String>,
    #[serde(default)]
    pub deny_skills: Vec<String>,
    #[serde(default)]
    pub require_signature: bool,
    #[serde(default = "default_skill_sandbox")]
    pub skill_sandbox: SkillSandboxLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SkillSandboxLevel { None, Basic, #[default] Strict }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    #[serde(default = "default_cpu_shares")]
    pub cpu_shares: u64,
    #[serde(default = "default_memory_limit")]
    pub memory_limit: String,
    #[serde(default)]
    pub memory_swap: Option<String>,
    #[serde(default = "default_io_weight")]
    pub io_weight: u64,
    #[serde(default = "default_pids_limit")]
    pub pids_limit: u64,
    #[serde(default)]
    pub tmp_size: Option<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { cpu_shares: 256, memory_limit: "512M".to_string(), memory_swap: None, io_weight: 100, pids_limit: 64, tmp_size: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_log_level")]
    pub log_level: AuditLogLevel,
    #[serde(default = "default_retention")]
    pub retention: String,
    #[serde(default)]
    pub hash_chain: bool,
    #[serde(default)]
    pub export: Vec<AuditExport>,
    #[serde(default)]
    pub siem_endpoint: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { log_level: AuditLogLevel::Actions, retention: "90d".to_string(), hash_chain: true, export: vec![AuditExport::File], siem_endpoint: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogLevel { All, Actions, Errors }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditExport { File, Siem, Stdout }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointConfig {
    #[serde(default = "default_checkpoint_interval")]
    pub interval: String,
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: u32,
    #[serde(default)]
    pub before_high_risk: bool,
    #[serde(default)]
    pub rollback_triggers: Vec<String>,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self { interval: "30m".to_string(), max_snapshots: 10, before_high_risk: true, rollback_triggers: Vec::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub review_interval: Option<String>,
}

fn default_version() -> String { "0.1.0".to_string() }
fn default_framework() -> AgentFramework { AgentFramework::Custom }
fn default_restart_policy() -> RestartPolicy { RestartPolicy::Never }
fn default_trust_level() -> TrustLevel { TrustLevel::Untrusted }
fn default_deny_all() -> Vec<String> { vec!["*".to_string()] }
fn default_dns_policy() -> DnsPolicy { DnsPolicy::Restricted }
fn default_skill_sandbox() -> SkillSandboxLevel { SkillSandboxLevel::Strict }
fn default_cpu_shares() -> u64 { 256 }
fn default_memory_limit() -> String { "512M".to_string() }
fn default_io_weight() -> u64 { 100 }
fn default_pids_limit() -> u64 { 64 }
fn default_log_level() -> AuditLogLevel { AuditLogLevel::Actions }
fn default_retention() -> String { "90d".to_string() }
fn default_checkpoint_interval() -> String { "30m".to_string() }
fn default_max_snapshots() -> u32 { 10 }
