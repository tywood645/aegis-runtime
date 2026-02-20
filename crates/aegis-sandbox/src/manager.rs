use aegis_ads::types::{AgentDefinition, TrustLevel};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::fs_policy::{FsPolicy, FsDecision};

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("filesystem policy error: {0}")]
    FsPolicy(#[from] crate::fs_policy::FsPolicyError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sandbox setup failed: {0}")]
    Setup(String),
    #[error("agent '{0}' is not running")]
    NotRunning(String),
    #[error("agent '{0}' is already running")]
    AlreadyRunning(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentState {
    Stopped, Running, Paused, Failed { reason: String },
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Stopped => write!(f, "stopped"),
            AgentState::Running => write!(f, "running"),
            AgentState::Paused => write!(f, "paused"),
            AgentState::Failed { reason } => write!(f, "failed: {}", reason),
        }
    }
}

#[derive(Debug)]
pub struct AgentRuntime {
    pub runtime_id: String,
    pub definition: AgentDefinition,
    pub state: AgentState,
    pub fs_policy: FsPolicy,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub workspace: PathBuf,
    pub audit_log_path: PathBuf,
    pub violation_count: u64,
    pub pid: Option<u32>,
}

pub struct SandboxManager {
    base_dir: PathBuf,
    agents: HashMap<String, AgentRuntime>,
}

impl SandboxManager {
    pub fn new(base_dir: &Path) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(base_dir)?;
        std::fs::create_dir_all(base_dir.join("workspaces"))?;
        std::fs::create_dir_all(base_dir.join("audit"))?;
        Ok(Self { base_dir: base_dir.to_path_buf(), agents: HashMap::new() })
    }

    pub fn register(&mut self, def: AgentDefinition) -> Result<&AgentRuntime, SandboxError> {
        let name = def.agent.name.clone();
        if self.agents.contains_key(&name) { return Err(SandboxError::AlreadyRunning(name)); }
        let workspace = self.base_dir.join("workspaces").join(&name);
        let audit_log_path = self.base_dir.join("audit").join(format!("{}.jsonl", &name));
        std::fs::create_dir_all(&workspace)?;
        let fs_policy = FsPolicy::compile(&def.capabilities.filesystem)?;
        let runtime = AgentRuntime {
            runtime_id: Uuid::new_v4().to_string(), definition: def, state: AgentState::Stopped,
            fs_policy, created_at: Utc::now(), started_at: None, workspace, audit_log_path,
            violation_count: 0, pid: None,
        };
        self.agents.insert(name.clone(), runtime);
        Ok(self.agents.get(&name).unwrap())
    }

    pub fn check_fs_read(&mut self, agent_name: &str, path: &Path) -> Result<FsDecision, SandboxError> {
        let runtime = self.agents.get_mut(agent_name).ok_or_else(|| SandboxError::NotRunning(agent_name.to_string()))?;
        let decision = runtime.fs_policy.check_read(path);
        let effective = match (&decision, &runtime.definition.agent.trust_level) {
            (FsDecision::NotCovered, TrustLevel::Untrusted) => FsDecision::Deny { reason: format!("path '{}' not in any allow list (untrusted agent)", path.display()) },
            _ => decision,
        };
        if matches!(&effective, FsDecision::Deny { .. }) { runtime.violation_count += 1; }
        Ok(effective)
    }

    pub fn check_fs_write(&mut self, agent_name: &str, path: &Path) -> Result<FsDecision, SandboxError> {
        let runtime = self.agents.get_mut(agent_name).ok_or_else(|| SandboxError::NotRunning(agent_name.to_string()))?;
        let decision = runtime.fs_policy.check_write(path);
        let effective = match (&decision, &runtime.definition.agent.trust_level) {
            (FsDecision::NotCovered, TrustLevel::Untrusted | TrustLevel::SemiTrusted) => FsDecision::Deny { reason: format!("path '{}' not in write allow list", path.display()) },
            _ => decision,
        };
        if matches!(&effective, FsDecision::Deny { .. }) { runtime.violation_count += 1; }
        Ok(effective)
    }

    pub fn get_agent(&self, name: &str) -> Option<&AgentRuntime> { self.agents.get(name) }
    pub fn list_agents(&self) -> Vec<(&str, &AgentRuntime)> { self.agents.iter().map(|(k, v)| (k.as_str(), v)).collect() }
    pub fn violation_count(&self, name: &str) -> Option<u64> { self.agents.get(name).map(|r| r.violation_count) }
    pub fn base_dir(&self) -> &Path { &self.base_dir }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ads::parse_str;

    const TEST_ADS: &str = r#"
[agent]
name = "test-agent"
trust_level = "untrusted"
[capabilities.filesystem]
read = ["/home/user/mail/**", "/tmp/aegis/test-agent/**"]
write = ["/tmp/aegis/test-agent/**"]
deny = ["/etc/**", "/home/user/.ssh/**", "**/*.key"]
"#;

    fn setup() -> (SandboxManager, AgentDefinition) {
        let dir = std::env::temp_dir().join(format!("aegis-test-{}", Uuid::new_v4()));
        (SandboxManager::new(&dir).unwrap(), parse_str(TEST_ADS).unwrap())
    }

    #[test] fn register_agent() { let (mut m, d) = setup(); let r = m.register(d).unwrap(); assert_eq!(r.state, AgentState::Stopped); assert!(r.workspace.exists()); }
    #[test] fn reject_duplicate() { let (mut m, d) = setup(); m.register(d.clone()).unwrap(); assert!(m.register(d).is_err()); }
    #[test] fn allow_read() { let (mut m, d) = setup(); m.register(d).unwrap(); assert_eq!(m.check_fs_read("test-agent", Path::new("/home/user/mail/inbox/msg.eml")).unwrap(), FsDecision::Allow); }
    #[test] fn deny_read() { let (mut m, d) = setup(); m.register(d).unwrap(); assert!(matches!(m.check_fs_read("test-agent", Path::new("/etc/shadow")).unwrap(), FsDecision::Deny { .. })); }
    #[test] fn deny_uncovered() { let (mut m, d) = setup(); m.register(d).unwrap(); assert!(matches!(m.check_fs_read("test-agent", Path::new("/opt/random")).unwrap(), FsDecision::Deny { .. })); }
    #[test] fn deny_write_readonly() { let (mut m, d) = setup(); m.register(d).unwrap(); assert!(matches!(m.check_fs_write("test-agent", Path::new("/home/user/mail/inbox/msg.eml")).unwrap(), FsDecision::Deny { .. })); }
    #[test] fn allow_write() { let (mut m, d) = setup(); m.register(d).unwrap(); assert_eq!(m.check_fs_write("test-agent", Path::new("/tmp/aegis/test-agent/out.json")).unwrap(), FsDecision::Allow); }
    #[test] fn deny_key_in_writable() { let (mut m, d) = setup(); m.register(d).unwrap(); assert!(matches!(m.check_fs_read("test-agent", Path::new("/tmp/aegis/test-agent/stolen.key")).unwrap(), FsDecision::Deny { .. })); }
    #[test] fn track_violations() { let (mut m, d) = setup(); m.register(d).unwrap(); m.check_fs_read("test-agent", Path::new("/etc/passwd")).unwrap(); m.check_fs_read("test-agent", Path::new("/etc/shadow")).unwrap(); assert_eq!(m.violation_count("test-agent"), Some(2)); }
}
