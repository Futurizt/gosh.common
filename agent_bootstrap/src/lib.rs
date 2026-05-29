// SPDX-License-Identifier: MIT
//
// Bootstrap/binding payload helpers.

use anyhow::Result;
use base64::Engine;
use serde::Deserialize;
use serde::Serialize;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use gosh_agent_runtime::binding::RuntimeBinding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKeypair {
    pub secret_key_b64: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapBundle {
    pub join_token: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBindingEnvelope {
    pub schema_version: u32,
    pub kind: String,
    pub binding: RuntimeBinding,
}

pub fn generate_agent_keypair() -> AgentKeypair {
    let secret_key = StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
    let public_key = PublicKey::from(&secret_key);
    AgentKeypair {
        secret_key_b64: base64::engine::general_purpose::STANDARD.encode(secret_key.to_bytes()),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes()),
    }
}

pub fn build_bootstrap_bundle(
    binding: &RuntimeBinding,
    secret_key_b64: String,
) -> Result<BootstrapBundle> {
    Ok(BootstrapBundle {
        join_token: binding.to_join_token().encode()?,
        secret_key: secret_key_b64,
    })
}

impl RuntimeBindingEnvelope {
    pub fn new(binding: RuntimeBinding) -> Self {
        Self {
            schema_version: 1,
            kind: "runtime_binding".to_string(),
            binding,
        }
    }
}

#[cfg(test)]
mod tests {
    use gosh_agent_runtime::join_token::JoinToken;

    use super::*;

    #[test]
    fn bootstrap_bundle_uses_runtime_binding_schema() {
        let binding = RuntimeBinding {
            memory_url: "http://memory.local".to_string(),
            key: "project".to_string(),
            swarm_id: "research".to_string(),
            principal_id: "agent:researcher".to_string(),
            principal_token: "principal-token".to_string(),
            transport_token: Some("server-token".to_string()),
            tls_ca: None,
            tls_fingerprint: None,
        }
        .normalize()
        .unwrap();

        let bundle = build_bootstrap_bundle(&binding, "secret-key".to_string()).unwrap();
        let decoded = JoinToken::decode(&bundle.join_token).unwrap();

        assert_eq!(decoded.url, "http://memory.local");
        assert_eq!(decoded.key.as_deref(), Some("project"));
        assert_eq!(decoded.swarm_id.as_deref(), Some("research"));
        assert_eq!(bundle.secret_key, "secret-key");
    }

    #[test]
    fn generated_agent_keypair_is_base64_x25519_material() {
        let keypair = generate_agent_keypair();
        let secret = base64::engine::general_purpose::STANDARD
            .decode(keypair.secret_key_b64)
            .unwrap();
        let public = base64::engine::general_purpose::STANDARD
            .decode(keypair.public_key_b64)
            .unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);
    }
}
