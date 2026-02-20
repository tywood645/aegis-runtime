use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("integrity violation at entry {index}: expected hash {expected}, got {actual}")]
    IntegrityViolation { index: u64, expected: String, actual: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    FsRead, FsWrite, FsDeny, NetEgress, NetEgressDeny, ExecAllow, ExecDeny,
    ApiCall, ApiDeny, AgentStart, AgentStop, AgentKill,
    CheckpointCreate, CheckpointRollback, PolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyResult { Allow, Deny, Audit }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub entry_id: String,
    pub agent_id: String,
    pub action: ActionType,
    pub detail: String,
    pub result: PolicyResult,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEntry {
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.agent_id.as_bytes());
        hasher.update(serde_json::to_string(&self.action).unwrap_or_default().as_bytes());
        hasher.update(self.detail.as_bytes());
        hasher.update(serde_json::to_string(&self.result).unwrap_or_default().as_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
}

pub struct AuditLog {
    path: PathBuf,
    next_index: u64,
    last_hash: String,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let (next_index, last_hash) = if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut last_index = 0u64;
            let mut last_hash = String::new();
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() { continue; }
                let entry: AuditEntry = serde_json::from_str(&line)?;
                last_index = entry.index;
                last_hash = entry.hash.clone();
            }
            if last_hash.is_empty() { (0, String::new()) } else { (last_index + 1, last_hash) }
        } else {
            (0, String::new())
        };
        Ok(Self { path: path.to_path_buf(), next_index, last_hash })
    }

    pub fn record(&mut self, agent_id: &str, action: ActionType, detail: &str, result: PolicyResult) -> Result<AuditEntry, AuditError> {
        let mut entry = AuditEntry {
            index: self.next_index, timestamp: Utc::now(), entry_id: Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(), action, detail: detail.to_string(), result,
            prev_hash: self.last_hash.clone(), hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let line = serde_json::to_string(&entry)?;
        writeln!(file, "{}", line)?;
        file.flush()?;
        self.last_hash = entry.hash.clone();
        self.next_index += 1;
        Ok(entry)
    }

    pub fn verify(&self) -> Result<u64, AuditError> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut prev_hash = String::new();
        let mut count = 0u64;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            let entry: AuditEntry = serde_json::from_str(&line)?;
            if entry.prev_hash != prev_hash {
                return Err(AuditError::IntegrityViolation { index: entry.index, expected: prev_hash, actual: entry.prev_hash });
            }
            let computed = entry.compute_hash();
            if entry.hash != computed {
                return Err(AuditError::IntegrityViolation { index: entry.index, expected: computed, actual: entry.hash });
            }
            prev_hash = entry.hash.clone();
            count += 1;
        }
        Ok(count)
    }

    pub fn path(&self) -> &Path { &self.path }
    pub fn entry_count(&self) -> u64 { self.next_index }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log_path() -> PathBuf {
        let dir = std::env::temp_dir().join("aegis-test");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("audit-{}.jsonl", Uuid::new_v4()))
    }

    #[test]
    fn create_and_record() {
        let path = temp_log_path();
        let mut log = AuditLog::open(&path).unwrap();
        let entry = log.record("test-agent", ActionType::FsRead, "/tmp/test/file.txt", PolicyResult::Allow).unwrap();
        assert_eq!(entry.index, 0);
        assert!(!entry.hash.is_empty());
        assert!(entry.prev_hash.is_empty());
    }

    #[test]
    fn hash_chain_integrity() {
        let path = temp_log_path();
        let mut log = AuditLog::open(&path).unwrap();
        log.record("a", ActionType::AgentStart, "started", PolicyResult::Allow).unwrap();
        log.record("a", ActionType::FsRead, "/tmp/ok", PolicyResult::Allow).unwrap();
        log.record("a", ActionType::FsDeny, "/etc/passwd", PolicyResult::Deny).unwrap();
        assert_eq!(log.verify().unwrap(), 3);
    }

    #[test]
    fn detect_tampering() {
        let path = temp_log_path();
        let mut log = AuditLog::open(&path).unwrap();
        log.record("a", ActionType::AgentStart, "started", PolicyResult::Allow).unwrap();
        log.record("a", ActionType::FsDeny, "/etc/shadow", PolicyResult::Deny).unwrap();
        drop(log);
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("/etc/shadow", "/tmp/innocent");
        std::fs::write(&path, tampered).unwrap();
        let log = AuditLog::open(&path).unwrap();
        assert!(log.verify().is_err());
    }

    #[test]
    fn reopen_and_continue() {
        let path = temp_log_path();
        { let mut log = AuditLog::open(&path).unwrap();
          log.record("a", ActionType::AgentStart, "started", PolicyResult::Allow).unwrap();
          log.record("a", ActionType::FsRead, "/tmp/f", PolicyResult::Allow).unwrap(); }
        { let mut log = AuditLog::open(&path).unwrap();
          assert_eq!(log.entry_count(), 2);
          log.record("a", ActionType::AgentStop, "stopped", PolicyResult::Allow).unwrap(); }
        let log = AuditLog::open(&path).unwrap();
        assert_eq!(log.verify().unwrap(), 3);
    }
}
