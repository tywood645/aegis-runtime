use aegis_ads::parse_file;
use aegis_audit::{ActionType, AuditLog, PolicyResult};
use aegis_sandbox::{FsDecision, SandboxManager};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

const AEGIS_DIR: &str = "/var/lib/aegis";
const SOCKET_PATH: &str = "/var/run/aegis/aegisd.sock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum DaemonRequest {
    #[serde(rename = "register")]  Register { ads_path: String },
    #[serde(rename = "start")]     Start { agent_name: String },
    #[serde(rename = "stop")]      Stop { agent_name: String },
    #[serde(rename = "status")]    Status,
    #[serde(rename = "agent_status")] AgentStatus { agent_name: String },
    #[serde(rename = "check_fs")]  CheckFs { agent_name: String, operation: String, path: String },
    #[serde(rename = "violations")] Violations { agent_name: String },
    #[serde(rename = "capabilities")] Capabilities { agent_name: String },
    #[serde(rename = "verify_audit")] VerifyAudit { agent_name: String },
    #[serde(rename = "ping")]      Ping,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl DaemonResponse {
    fn ok(msg: impl Into<String>) -> Self { Self { success: true, message: msg.into(), data: None } }
    fn ok_data(msg: impl Into<String>, data: serde_json::Value) -> Self { Self { success: true, message: msg.into(), data: Some(data) } }
    fn err(msg: impl Into<String>) -> Self { Self { success: false, message: msg.into(), data: None } }
}

struct Daemon { sandbox: SandboxManager, audit_logs: std::collections::HashMap<String, AuditLog>, base_dir: PathBuf }

impl Daemon {
    fn new(base_dir: &Path) -> Result<Self> {
        Ok(Self { sandbox: SandboxManager::new(base_dir).context("sandbox init failed")?, audit_logs: std::collections::HashMap::new(), base_dir: base_dir.to_path_buf() })
    }

    fn handle(&mut self, req: DaemonRequest) -> DaemonResponse {
        match req {
            DaemonRequest::Ping => DaemonResponse::ok("pong"),
            DaemonRequest::Register { ads_path } => self.h_register(&ads_path),
            DaemonRequest::Start { agent_name } => self.h_start(&agent_name),
            DaemonRequest::Stop { agent_name } => self.h_stop(&agent_name),
            DaemonRequest::Status => self.h_status(),
            DaemonRequest::AgentStatus { agent_name } => self.h_agent_status(&agent_name),
            DaemonRequest::CheckFs { agent_name, operation, path } => self.h_check_fs(&agent_name, &operation, &path),
            DaemonRequest::Violations { agent_name } => self.h_violations(&agent_name),
            DaemonRequest::Capabilities { agent_name } => self.h_capabilities(&agent_name),
            DaemonRequest::VerifyAudit { agent_name } => self.h_verify_audit(&agent_name),
        }
    }

    fn h_register(&mut self, ads_path: &str) -> DaemonResponse {
        let def = match parse_file(Path::new(ads_path)) { Ok(d) => d, Err(e) => return DaemonResponse::err(format!("parse failed: {}", e)) };
        let name = def.agent.name.clone();
        let audit_path = self.base_dir.join("audit").join(format!("{}.jsonl", &name));
        match AuditLog::open(&audit_path) { Ok(l) => { self.audit_logs.insert(name.clone(), l); } Err(e) => return DaemonResponse::err(format!("audit log: {}", e)) }
        match self.sandbox.register(def) {
            Ok(r) => { info!(agent = %name, "registered"); DaemonResponse::ok(format!("agent '{}' registered (state: {})", name, r.state)) }
            Err(e) => DaemonResponse::err(format!("register failed: {}", e)),
        }
    }

    fn h_start(&mut self, name: &str) -> DaemonResponse {
        if let Some(log) = self.audit_logs.get_mut(name) { let _ = log.record(name, ActionType::AgentStart, "started", PolicyResult::Allow); }
        info!(agent = %name, "start (Phase 0: policy only)");
        DaemonResponse::ok(format!("agent '{}' started (Phase 0: policy enforcement active)", name))
    }

    fn h_stop(&mut self, name: &str) -> DaemonResponse {
        if let Some(log) = self.audit_logs.get_mut(name) { let _ = log.record(name, ActionType::AgentStop, "stopped", PolicyResult::Allow); }
        DaemonResponse::ok(format!("agent '{}' stopped", name))
    }

    fn h_status(&self) -> DaemonResponse {
        let agents = self.sandbox.list_agents();
        if agents.is_empty() { return DaemonResponse::ok("no agents registered"); }
        let data: Vec<serde_json::Value> = agents.iter().map(|(n, r)| serde_json::json!({"name": n, "state": format!("{}", r.state), "trust_level": format!("{:?}", r.definition.agent.trust_level), "violations": r.violation_count, "created_at": r.created_at.to_rfc3339()})).collect();
        DaemonResponse::ok_data(format!("{} agent(s)", data.len()), serde_json::json!(data))
    }

    fn h_agent_status(&self, name: &str) -> DaemonResponse {
        match self.sandbox.get_agent(name) {
            Some(r) => DaemonResponse::ok_data(format!("agent '{}'", name), serde_json::json!({"name": name, "state": format!("{}", r.state), "trust_level": format!("{:?}", r.definition.agent.trust_level), "violations": r.violation_count, "workspace": r.workspace.display().to_string()})),
            None => DaemonResponse::err(format!("agent '{}' not found", name)),
        }
    }

    fn h_check_fs(&mut self, name: &str, op: &str, path_str: &str) -> DaemonResponse {
        let path = Path::new(path_str);
        let decision = match op {
            "read" => self.sandbox.check_fs_read(name, path),
            "write" => self.sandbox.check_fs_write(name, path),
            _ => return DaemonResponse::err(format!("unknown op '{}' (use read/write)", op)),
        };
        match decision {
            Ok(FsDecision::Allow) => {
                if let Some(log) = self.audit_logs.get_mut(name) { let a = if op == "read" { ActionType::FsRead } else { ActionType::FsWrite }; let _ = log.record(name, a, path_str, PolicyResult::Allow); }
                DaemonResponse::ok_data(format!("{} {} -> ALLOW", op, path_str), serde_json::json!({"decision": "allow", "operation": op, "path": path_str}))
            }
            Ok(FsDecision::Deny { reason }) => {
                if let Some(log) = self.audit_logs.get_mut(name) { let _ = log.record(name, ActionType::FsDeny, &format!("{} ({})", path_str, reason), PolicyResult::Deny); }
                DaemonResponse::ok_data(format!("{} {} -> DENY: {}", op, path_str, reason), serde_json::json!({"decision": "deny", "operation": op, "path": path_str, "reason": reason}))
            }
            Ok(FsDecision::NotCovered) => DaemonResponse::ok_data(format!("{} {} -> NOT COVERED", op, path_str), serde_json::json!({"decision": "not_covered"})),
            Err(e) => DaemonResponse::err(format!("check failed: {}", e)),
        }
    }

    fn h_violations(&self, name: &str) -> DaemonResponse {
        match self.sandbox.violation_count(name) {
            Some(c) => DaemonResponse::ok_data(format!("{} violation(s)", c), serde_json::json!({"agent": name, "violations": c})),
            None => DaemonResponse::err(format!("agent '{}' not found", name)),
        }
    }

    fn h_capabilities(&self, name: &str) -> DaemonResponse {
        match self.sandbox.get_agent(name) {
            Some(r) => {
                let p = aegis_ads::effective_permissions(&r.definition);
                DaemonResponse::ok_data(format!("capabilities for '{}'", name), serde_json::json!({"agent": name, "trust_level": format!("{:?}", p.trust_level), "filesystem": {"read": p.fs_readable, "write": p.fs_writable, "deny": p.fs_denied}, "network": {"egress": p.net_egress_allowed, "ingress": p.net_ingress}, "exec": {"allow": p.exec_allowed, "deny": p.exec_denied}, "api_scopes": p.api_scopes, "resources": {"memory": p.resource_memory, "pids": p.resource_pids}}))
            }
            None => DaemonResponse::err(format!("agent '{}' not found", name)),
        }
    }

    fn h_verify_audit(&self, name: &str) -> DaemonResponse {
        match self.audit_logs.get(name) {
            Some(log) => match log.verify() {
                Ok(c) => DaemonResponse::ok_data(format!("verified: {} entries, chain intact", c), serde_json::json!({"entries": c, "integrity": "valid"})),
                Err(e) => DaemonResponse::ok_data(format!("INTEGRITY VIOLATION: {}", e), serde_json::json!({"integrity": "violated", "error": e.to_string()})),
            }
            None => DaemonResponse::err(format!("no audit log for '{}'", name)),
        }
    }
}

async fn handle_conn(stream: UnixStream, daemon: &mut Daemon) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 { break; }
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let resp = match serde_json::from_str::<DaemonRequest>(trimmed) {
            Ok(req) => daemon.handle(req),
            Err(e) => DaemonResponse::err(format!("bad request: {}", e)),
        };
        writer.write_all(serde_json::to_string(&resp)?.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "aegisd=info".into())).with_target(false).init();
    let base_dir = PathBuf::from(std::env::var("AEGIS_DIR").unwrap_or_else(|_| AEGIS_DIR.to_string()));
    let socket_path = PathBuf::from(std::env::var("AEGIS_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string()));
    if let Some(p) = socket_path.parent() { std::fs::create_dir_all(p)?; }
    if socket_path.exists() { std::fs::remove_file(&socket_path)?; }
    info!(base_dir = %base_dir.display(), socket = %socket_path.display(), "aegisd starting");
    let mut daemon = Daemon::new(&base_dir)?;
    let listener = UnixListener::bind(&socket_path)?;
    info!("listening on {}", socket_path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if let Err(e) = handle_conn(stream, &mut daemon).await {
                    error!("conn error: {}", e);
                }
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }
}
