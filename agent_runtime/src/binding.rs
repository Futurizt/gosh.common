// SPDX-License-Identifier: MIT
//
// Runtime memory binding schema and local registry.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use parking_lot::RwLock;
use serde::Deserialize;
use serde::Serialize;

use crate::join_token::JoinToken;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuntimeBindingKey {
    pub memory_url: String,
    pub key: String,
    pub swarm_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBinding {
    pub memory_url: String,
    pub key: String,
    pub swarm_id: String,
    pub principal_id: String,
    pub principal_token: String,
    #[serde(default)]
    pub transport_token: Option<String>,
    #[serde(default)]
    pub tls_ca: Option<String>,
    #[serde(default, alias = "fingerprint")]
    pub tls_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeBindingsFile {
    #[serde(default)]
    bindings: Vec<RuntimeBinding>,
}

#[derive(Clone, Default)]
pub struct RuntimeBindingRegistry {
    inner: Arc<RwLock<HashMap<RuntimeBindingKey, RuntimeBinding>>>,
}

impl RuntimeBindingKey {
    pub fn new(memory_url: &str, key: &str, swarm_id: &str) -> Result<Self> {
        let memory_url = normalize_memory_url(memory_url)?;
        let key = require_non_empty("key", key)?;
        let swarm_id = require_non_empty("swarm_id", swarm_id)?;
        Ok(Self {
            memory_url,
            key,
            swarm_id,
        })
    }
}

impl RuntimeBinding {
    pub fn normalize(mut self) -> Result<Self> {
        self.memory_url = normalize_memory_url(&self.memory_url)?;
        self.key = require_non_empty("key", &self.key)?;
        self.swarm_id = require_non_empty("swarm_id", &self.swarm_id)?;
        self.principal_id = require_non_empty("principal_id", &self.principal_id)?;
        self.principal_token = require_non_empty("principal_token", &self.principal_token)?;
        self.transport_token = normalize_optional(self.transport_token);
        self.tls_ca = normalize_optional(self.tls_ca);
        self.tls_fingerprint = normalize_optional(self.tls_fingerprint);
        if self.tls_fingerprint.is_some() {
            bail!("tls_fingerprint pinning is not supported for runtime bindings yet");
        }
        Ok(self)
    }

    pub fn identity(&self) -> Result<RuntimeBindingKey> {
        RuntimeBindingKey::new(&self.memory_url, &self.key, &self.swarm_id)
    }

    pub fn to_join_token(&self) -> JoinToken {
        JoinToken {
            url: self.memory_url.clone(),
            transport_token: self.transport_token.clone(),
            principal_id: Some(self.principal_id.clone()),
            principal_token: Some(self.principal_token.clone()),
            key: Some(self.key.clone()),
            swarm_id: Some(self.swarm_id.clone()),
            fingerprint: self.tls_fingerprint.clone(),
            ca: self.tls_ca.clone(),
        }
    }
}

impl RuntimeBindingRegistry {
    pub fn add(&self, binding: RuntimeBinding) -> Result<bool> {
        let binding = binding.normalize()?;
        let key = binding.identity()?;
        let mut guard = self.inner.write();
        Ok(guard.insert(key, binding).is_some())
    }

    pub fn get_exact(&self, memory_url: &str, key: &str, swarm_id: &str) -> Option<RuntimeBinding> {
        let binding_key = RuntimeBindingKey::new(memory_url, key, swarm_id).ok()?;
        self.inner.read().get(&binding_key).cloned()
    }

    pub fn remove_exact(
        &self,
        memory_url: &str,
        key: &str,
        swarm_id: &str,
    ) -> Result<Option<RuntimeBinding>> {
        let binding_key = RuntimeBindingKey::new(memory_url, key, swarm_id)?;
        Ok(self.inner.write().remove(&binding_key))
    }

    pub fn find_for_request(
        &self,
        memory_url: Option<&str>,
        default_memory_url: &str,
        key: &str,
        swarm_id: &str,
    ) -> Option<RuntimeBinding> {
        if let Some(memory_url) = memory_url.filter(|value| !value.trim().is_empty()) {
            return self.get_exact(memory_url, key, swarm_id);
        }
        if let Some(binding) = self.get_exact(default_memory_url, key, swarm_id) {
            return Some(binding);
        }

        let guard = self.inner.read();
        let mut matches = guard
            .values()
            .filter(|binding| binding.key == key && binding.swarm_id == swarm_id)
            .cloned();
        let first = matches.next()?;
        if matches.next().is_none() {
            Some(first)
        } else {
            None
        }
    }

    pub fn list(&self) -> Vec<RuntimeBinding> {
        let mut bindings: Vec<_> = self.inner.read().values().cloned().collect();
        bindings.sort_by(|a, b| {
            (&a.memory_url, &a.key, &a.swarm_id).cmp(&(&b.memory_url, &b.key, &b.swarm_id))
        });
        bindings
    }

    pub fn load_file(&self, path: &Path) -> Result<usize> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let file: RuntimeBindingsFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing runtime bindings {}", path.display()))?;
        let count = file.bindings.len();
        for binding in file.bindings {
            self.add(binding)?;
        }
        Ok(count)
    }

    pub fn save_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = serde_json::to_string_pretty(&RuntimeBindingsFile {
            bindings: self.list(),
        })
        .context("serialising runtime bindings")?;
        let tmp = path.with_extension("json.tmp");
        write_secret_file(&tmp, &text).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

pub fn normalize_memory_url(value: &str) -> Result<String> {
    let mut trimmed = require_non_empty("memory_url", value)?;
    while trimmed.ends_with('/') {
        trimmed.pop();
    }
    if let Some(stripped) = trimmed.strip_suffix("/mcp") {
        trimmed = stripped.trim_end_matches('/').to_string();
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        bail!("memory_url must use http:// or https://");
    }
    Ok(trimmed)
}

fn write_secret_file(path: &Path, text: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)?;
    }
    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn require_non_empty(name: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{name} must be non-empty");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(memory_url: &str, key: &str, swarm_id: &str) -> RuntimeBinding {
        RuntimeBinding {
            memory_url: memory_url.to_string(),
            key: key.to_string(),
            swarm_id: swarm_id.to_string(),
            principal_id: "agent:researcher".to_string(),
            principal_token: "principal-token".to_string(),
            transport_token: None,
            tls_ca: None,
            tls_fingerprint: None,
        }
    }

    #[test]
    fn registry_uses_exact_memory_key_swarm_identity() {
        let registry = RuntimeBindingRegistry::default();
        registry
            .add(binding("http://mem.local/mcp/", "project", "swarm-a"))
            .unwrap();
        registry
            .add(binding("http://other.local", "project", "swarm-a"))
            .unwrap();

        let exact = registry
            .find_for_request(
                Some("http://mem.local"),
                "http://mem.local",
                "project",
                "swarm-a",
            )
            .expect("exact binding");
        assert_eq!(exact.memory_url, "http://mem.local");

        assert!(
            registry
                .find_for_request(None, "http://missing.local", "project", "swarm-a")
                .is_none(),
            "ambiguous key/swarm without memory_url must not pick arbitrarily"
        );
    }

    #[test]
    fn registry_removes_exact_binding_identity() {
        let registry = RuntimeBindingRegistry::default();
        registry
            .add(binding("http://mem.local", "project", "swarm-a"))
            .unwrap();
        registry
            .add(binding("http://mem.local", "other", "swarm-a"))
            .unwrap();

        let removed = registry
            .remove_exact("http://mem.local/mcp", "project", "swarm-a")
            .unwrap();

        assert!(removed.is_some());
        assert!(registry
            .get_exact("http://mem.local", "project", "swarm-a")
            .is_none());
        assert!(registry
            .get_exact("http://mem.local", "other", "swarm-a")
            .is_some());
    }

    #[test]
    fn registry_roundtrips_file_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime_bindings.json");
        let registry = RuntimeBindingRegistry::default();
        registry
            .add(binding("http://mem.local", "project", "swarm-a"))
            .unwrap();
        registry.save_file(&path).unwrap();

        let loaded = RuntimeBindingRegistry::default();
        assert_eq!(loaded.load_file(&path).unwrap(), 1);
        assert!(loaded
            .get_exact("http://mem.local", "project", "swarm-a")
            .is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
