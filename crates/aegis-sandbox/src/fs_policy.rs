use aegis_ads::types::FilesystemCapabilities;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsPolicyError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob { pattern: String, source: globset::Error },
}

pub struct FsPolicy {
    read_set: GlobSet,
    write_set: GlobSet,
    deny_set: GlobSet,
    read_patterns: Vec<String>,
    write_patterns: Vec<String>,
    deny_patterns: Vec<String>,
}

impl std::fmt::Debug for FsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsPolicy")
            .field("read_patterns", &self.read_patterns)
            .field("write_patterns", &self.write_patterns)
            .field("deny_patterns", &self.deny_patterns)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FsDecision {
    Allow,
    Deny { reason: String },
    NotCovered,
}

impl FsPolicy {
    pub fn compile(caps: &FilesystemCapabilities) -> Result<Self, FsPolicyError> {
        Ok(Self {
            read_set: build_globset(&caps.read)?,
            write_set: build_globset(&caps.write)?,
            deny_set: build_globset(&caps.deny)?,
            read_patterns: caps.read.clone(),
            write_patterns: caps.write.clone(),
            deny_patterns: caps.deny.clone(),
        })
    }

    pub fn check_read(&self, path: &Path) -> FsDecision {
        if self.deny_set.is_match(path) {
            return FsDecision::Deny { reason: format!("path '{}' matches deny pattern", path.display()) };
        }
        if self.read_set.is_match(path) || self.write_set.is_match(path) {
            return FsDecision::Allow;
        }
        FsDecision::NotCovered
    }

    pub fn check_write(&self, path: &Path) -> FsDecision {
        if self.deny_set.is_match(path) {
            return FsDecision::Deny { reason: format!("path '{}' matches deny pattern", path.display()) };
        }
        if self.write_set.is_match(path) {
            return FsDecision::Allow;
        }
        if self.read_set.is_match(path) {
            return FsDecision::Deny { reason: format!("path '{}' is read-only", path.display()) };
        }
        FsDecision::NotCovered
    }

    pub fn summary(&self) -> FsPolicySummary {
        FsPolicySummary {
            read_patterns: self.read_patterns.clone(),
            write_patterns: self.write_patterns.clone(),
            deny_patterns: self.deny_patterns.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsPolicySummary {
    pub read_patterns: Vec<String>,
    pub write_patterns: Vec<String>,
    pub deny_patterns: Vec<String>,
}

fn build_globset(patterns: &[String]) -> Result<GlobSet, FsPolicyError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(|e| FsPolicyError::InvalidGlob { pattern: pattern.clone(), source: e })?);
    }
    builder.build().map_err(|e| FsPolicyError::InvalidGlob { pattern: "(combined)".to_string(), source: e })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_caps() -> FilesystemCapabilities {
        FilesystemCapabilities {
            read: vec!["/home/user/mail/**".into(), "/tmp/aegis/inbox-manager/**".into()],
            write: vec!["/tmp/aegis/inbox-manager/**".into()],
            deny: vec!["/etc/**".into(), "/home/user/.ssh/**".into(), "**/*.key".into(), "**/*.pem".into()],
        }
    }

    #[test] fn allow_read_on_readable_path() { assert_eq!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/home/user/mail/inbox/msg1.eml")), FsDecision::Allow); }
    #[test] fn allow_read_on_writable_path() { assert_eq!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/tmp/aegis/inbox-manager/cache.json")), FsDecision::Allow); }
    #[test] fn allow_write_on_writable_path() { assert_eq!(FsPolicy::compile(&test_caps()).unwrap().check_write(Path::new("/tmp/aegis/inbox-manager/output.txt")), FsDecision::Allow); }
    #[test] fn deny_write_on_read_only() { assert!(matches!(FsPolicy::compile(&test_caps()).unwrap().check_write(Path::new("/home/user/mail/inbox/msg1.eml")), FsDecision::Deny { .. })); }
    #[test] fn deny_overrides_read() { assert!(matches!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/etc/passwd")), FsDecision::Deny { .. })); }
    #[test] fn deny_ssh_keys() { assert!(matches!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/home/user/.ssh/id_rsa")), FsDecision::Deny { .. })); }
    #[test] fn deny_key_files_anywhere() { assert!(matches!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/tmp/aegis/inbox-manager/secret.key")), FsDecision::Deny { .. })); }
    #[test] fn not_covered_path() { assert_eq!(FsPolicy::compile(&test_caps()).unwrap().check_read(Path::new("/opt/something/random.txt")), FsDecision::NotCovered); }
}
