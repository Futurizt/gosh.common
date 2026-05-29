// SPDX-License-Identifier: MIT
//
// Sealed-box decryption for memory secret/runtime binding delivery.

use std::fs;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::AeadCore;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

const ENVELOPE_MAGIC_V1: &[u8; 4] = b"GMS1";
const ENVELOPE_MAGIC_V2: &[u8; 4] = b"GMS2";
const SECRET_INFO_V1: &[u8] = b"gosh.memory/agent-secrets/v1";
const SECRET_INFO_V2: &[u8] = b"gosh.memory/namespace-secret-delivery/v1";

pub fn load_secret_key(path: &Path) -> Result<StaticSecret> {
    let bytes =
        fs::read(path).with_context(|| format!("reading secret key: {}", path.display()))?;
    if bytes.len() != 32 {
        bail!(
            "secret key file must be exactly 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let key = StaticSecret::from(arr);
    arr.zeroize();
    Ok(key)
}

pub fn decrypt_agent_secret(private_key: &StaticSecret, ciphertext_b64: &str) -> Result<String> {
    use base64::Engine;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .context("base64 decode of sealed secret")?;

    if envelope.len() < 64 {
        bail!("sealed envelope too short: {} bytes", envelope.len());
    }
    let secret_info = match &envelope[..4] {
        magic if magic == ENVELOPE_MAGIC_V1 => SECRET_INFO_V1,
        magic if magic == ENVELOPE_MAGIC_V2 => SECRET_INFO_V2,
        _ => bail!("invalid envelope magic: expected GMS1 or GMS2"),
    };

    let ephemeral_public_bytes: [u8; 32] = envelope[4..36].try_into().unwrap();
    let nonce_bytes: [u8; 12] = envelope[36..48].try_into().unwrap();
    let ciphertext = &envelope[48..];
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    let shared_secret = private_key.diffie_hellman(&ephemeral_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(secret_info, &mut aes_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {e}"))?;
    aes_key.zeroize();
    let nonce = <Aes256Gcm as AeadCore>::NonceSize::default();
    let _ = nonce;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: secret_info,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed"))?;

    String::from_utf8(plaintext).context("decrypted secret is not valid UTF-8")
}

pub fn save_secret_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(key)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_for_test_with(
        agent_public: &PublicKey,
        plaintext: &str,
        magic: &[u8; 4],
        info: &[u8],
    ) -> String {
        use aes_gcm::aead::OsRng;
        use base64::Engine;

        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(agent_public);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(info, &mut aes_key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext.as_bytes(),
            aad: info,
        };
        let ciphertext = cipher.encrypt(&nonce, payload).unwrap();

        let mut envelope = Vec::with_capacity(4 + 32 + 12 + ciphertext.len());
        envelope.extend_from_slice(magic);
        envelope.extend_from_slice(ephemeral_public.as_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        base64::engine::general_purpose::STANDARD.encode(&envelope)
    }

    fn encrypt_for_test(agent_public: &PublicKey, plaintext: &str) -> String {
        encrypt_for_test_with(agent_public, plaintext, ENVELOPE_MAGIC_V1, SECRET_INFO_V1)
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        use aes_gcm::aead::OsRng;
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        let ciphertext_b64 = encrypt_for_test(&public, "agent-secret-roundtrip-fixture");

        let decrypted = decrypt_agent_secret(&private, &ciphertext_b64).unwrap();

        assert_eq!(decrypted, "agent-secret-roundtrip-fixture");
    }

    #[test]
    fn decrypts_namespace_secret_delivery_v2_envelope() {
        let private = StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
        let public = PublicKey::from(&private);
        let ciphertext =
            encrypt_for_test_with(&public, "runtime-secret", ENVELOPE_MAGIC_V2, SECRET_INFO_V2);

        let decrypted = decrypt_agent_secret(&private, &ciphertext).unwrap();

        assert_eq!(decrypted, "runtime-secret");
    }

    #[test]
    fn wrong_key_fails() {
        use aes_gcm::aead::OsRng;
        let private1 = StaticSecret::random_from_rng(OsRng);
        let public1 = PublicKey::from(&private1);
        let private2 = StaticSecret::random_from_rng(OsRng);
        let ciphertext_b64 = encrypt_for_test(&public1, "secret");

        let result = decrypt_agent_secret(&private2, &ciphertext_b64);

        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_key_roundtrip() {
        use aes_gcm::aead::OsRng;
        let secret = StaticSecret::random_from_rng(OsRng);
        let bytes: [u8; 32] = secret.to_bytes();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");

        save_secret_key(&path, &bytes).unwrap();
        let loaded = load_secret_key(&path).unwrap();

        assert_eq!(
            PublicKey::from(&secret).as_bytes(),
            PublicKey::from(&loaded).as_bytes()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
