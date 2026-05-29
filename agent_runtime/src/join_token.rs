// SPDX-License-Identifier: MIT
//
// Join token encode/decode helpers.

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use serde::Deserialize;
use serde::Serialize;

const PREFIX: &str = "gosh_join_";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinToken {
    pub url: String,
    #[serde(default, alias = "token")]
    pub transport_token: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default, alias = "principal_auth_token")]
    pub principal_token: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub swarm_id: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
}

impl JoinToken {
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let json = serde_json::to_vec(self)?;
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }

    pub fn decode(input: &str) -> Result<Self> {
        let b64 = input
            .strip_prefix(PREFIX)
            .context("join token must start with 'gosh_join_'")?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .context("invalid base64 in join token")?;
        let token: Self = serde_json::from_slice(&json).context("invalid JSON in join token")?;
        token.validate()?;
        Ok(token)
    }

    pub fn validate(&self) -> Result<()> {
        if self.url.trim().is_empty() {
            bail!("join token has empty url");
        }
        if !self.url.starts_with("https://") && !self.url.starts_with("http://") {
            bail!(
                "join token URL must use http:// or https:// (got: {})",
                self.url
            );
        }
        let has_transport = self
            .transport_token
            .as_deref()
            .is_some_and(|v| !v.is_empty());
        let has_principal = self
            .principal_token
            .as_deref()
            .is_some_and(|v| !v.is_empty());
        if !has_transport && !has_principal {
            bail!("join token must include transport_token or principal_token");
        }
        Ok(())
    }
}

pub fn decode(token: &str) -> Result<JoinToken> {
    JoinToken::decode(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_token_roundtrip_preserves_runtime_fields() {
        let token = JoinToken {
            url: "http://memory.local".to_string(),
            transport_token: Some("server-token".to_string()),
            principal_id: Some("agent:worker".to_string()),
            principal_token: Some("agent-token".to_string()),
            key: Some("project-key".to_string()),
            swarm_id: Some("team-alpha".to_string()),
            fingerprint: None,
            ca: Some("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----".to_string()),
        };

        let encoded = token.encode().unwrap();
        let decoded = JoinToken::decode(&encoded).unwrap();

        assert_eq!(decoded, token);
    }

    #[test]
    fn join_token_accepts_legacy_principal_auth_alias() {
        let raw = serde_json::json!({
            "url": "http://memory.local",
            "principal_auth_token": "agent-token"
        });
        let encoded = format!(
            "gosh_join_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.to_string())
        );

        let decoded = JoinToken::decode(&encoded).unwrap();

        assert_eq!(decoded.principal_token.as_deref(), Some("agent-token"));
    }
}
