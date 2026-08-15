//! Verify the signed authority receipt before native execution.
//!
//! The launcher receives the receipt and the authorityd public key through
//! already-open file descriptors.  It never trusts a Python object, SQLite
//! row, pathname, or a public key supplied as a command argument.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{FromRawFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const AUTHORITY_TIMESTAMP_SCALE: f64 = 1000.0;
const MAX_WIRE_TIMESTAMP: u64 = (1_u64 << 53) - 1;

pub fn verify_from_fds_bound(
    receipt_fd: RawFd,
    public_key_fd: RawFd,
    now: Option<f64>,
    expected_operation: &str,
    expected_resource_digest: &str,
) -> io::Result<()> {
    let receipt = read_fd(receipt_fd, MAX_RECEIPT_BYTES)?;
    let public_key = read_fd(public_key_fd, 4096)?;
    verify_json_bound(
        &receipt,
        &public_key,
        now,
        Some(expected_operation),
        Some(expected_resource_digest),
    )
}

fn verify_json_bound(
    receipt: &[u8],
    public_key: &[u8],
    now: Option<f64>,
    expected_operation: Option<&str>,
    expected_resource_digest: Option<&str>,
) -> io::Result<()> {
    let mut value: Value =
        serde_json::from_slice(receipt).map_err(|error| invalid(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid("authorization receipt must be an object"))?;
    let signature = object
        .remove("signature")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid("authorization receipt signature is missing"))?;
    let algorithm = object
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("authorization receipt algorithm is missing"))?;
    if algorithm != "Ed25519" {
        return Err(invalid("authorization receipt algorithm is unsupported"));
    }
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(invalid("authorization receipt schema is unsupported"));
    }
    for field in [
        "principal_id",
        "project_id",
        "runtime_id",
        "task_id",
        "workspace_id",
        "operation",
        "resource_digest",
        "policy_digest",
        "nonce",
        "audit_intent_digest",
        "issuer_id",
    ] {
        let text = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("authorization receipt {field} is missing")))?;
        if text.is_empty() || text.len() > 512 || text.contains('\0') {
            return Err(invalid(format!("authorization receipt {field} is invalid")));
        }
    }
    if object
        .get("authorization_epoch")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(invalid("authorization receipt epoch is invalid"));
    }
    let expires_at = receipt_timestamp(object, "expires_at")?;
    let issued_at = receipt_timestamp(object, "issued_at")?;
    if expires_at <= issued_at || expires_at - issued_at > 300.0 {
        return Err(invalid("authorization receipt expiry is invalid"));
    }
    if let Some(expected_operation) = expected_operation {
        if object.get("operation").and_then(Value::as_str) != Some(expected_operation) {
            return Err(invalid(
                "authorization receipt operation is outside authority",
            ));
        }
    }
    if let Some(expected_resource_digest) = expected_resource_digest {
        if object.get("resource_digest").and_then(Value::as_str) != Some(expected_resource_digest) {
            return Err(invalid(
                "authorization receipt resource is not bound to the native launch",
            ));
        }
    }
    let current = now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs_f64())
            .unwrap_or(f64::INFINITY)
    });
    if current >= expires_at {
        return Err(invalid("authorization receipt has expired"));
    }
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature.as_bytes())
        .map_err(|error| invalid(error.to_string()))?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|error| invalid(error.to_string()))?;
    let public_key_bytes = if public_key.len() == 32 {
        public_key.to_vec()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .map_err(|error| invalid(error.to_string()))?
    };
    let key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("authorityd public key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|error| invalid(error.to_string()))?;
    let canonical = canonical_json(&value);
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|error| invalid(error.to_string()))
}

fn receipt_timestamp(object: &Map<String, Value>, field: &str) -> io::Result<f64> {
    let encoded = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("authorization receipt {field} is invalid")))?;
    if encoded > MAX_WIRE_TIMESTAMP {
        return Err(invalid(format!("authorization receipt {field} is invalid")));
    }
    Ok(encoded as f64 / AUTHORITY_TIMESTAMP_SCALE)
}

fn read_fd(fd: RawFd, max_bytes: usize) -> io::Result<Vec<u8>> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take((max_bytes + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(invalid("authority receipt exceeds its bound"));
    }
    Ok(bytes)
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect::<Map<_, _>>())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

pub(crate) fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonical(value)).expect("JSON canonicalization cannot fail")
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn rejects_tampered_receipt() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let mut value = serde_json::json!({
            "algorithm": "Ed25519",
            "issued_at": 1_000_000,
            "expires_at": 1_100_000,
            "operation": "git.workspace"
        });
        let signature = signing.sign(canonical_json(&value).as_bytes());
        value["signature"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
        value["operation"] = Value::String("git.update-ref".to_owned());
        let public =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        assert!(verify_json_bound(
            value.to_string().as_bytes(),
            public.as_bytes(),
            Some(1050.0),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn accepts_complete_signed_receipt() {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let mut value = serde_json::json!({
            "schema_version": 1,
            "algorithm": "Ed25519",
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "operation": "exec.host",
            "resource_digest": "resource",
            "policy_digest": "policy",
            "nonce": "nonce",
            "authorization_epoch": 1,
            "expires_at": 1_100_000,
            "audit_intent_digest": "audit",
            "issuer_id": "authorityd",
            "issued_at": 1_000_000
        });
        let signature = signing.sign(canonical_json(&value).as_bytes());
        value["signature"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
        let public = signing.verifying_key().to_bytes();
        assert!(verify_json_bound(
            value.to_string().as_bytes(),
            &public,
            Some(1050.0),
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn accepts_python_signed_receipt_with_integer_timestamps() {
        // This vector is signed by Python's authorityd protocol canonicalizer.
        // It protects the actual Python -> Rust production boundary rather
        // than only testing Rust against its own serializer.
        let receipt = br#"{"algorithm":"Ed25519","audit_intent_digest":"audit","authorization_epoch":7,"expires_at":2000000300000,"issued_at":2000000000000,"issuer_id":"authorityd-python-fixture","nonce":"nonce-python-fixture","operation":"exec.host","policy_digest":"policy","principal_id":"agent","project_id":"project","resource_digest":"resource","runtime_id":"runtime","schema_version":1,"signature":"sPkdS7jVnKCqFC5NsW3m2pyxHuM7WatlzNd/saRaFvZBJ8znYiPdolSsQw+VxmOyu/HACauFuJjkiwWOQz94AQ==","task_id":"task","workspace_id":"workspace"}"#;
        let public = [
            0x91, 0xa2, 0x8a, 0x0b, 0x74, 0x38, 0x15, 0x93, 0xa4, 0xd9, 0x46, 0x95, 0x79, 0x20,
            0x89, 0x26, 0xaf, 0xc8, 0xad, 0x82, 0xc8, 0x83, 0x9b, 0x76, 0x44, 0x35, 0x9b, 0x9e,
            0xba, 0x9a, 0x4b, 0x3a,
        ];
        assert!(verify_json_bound(
            receipt,
            &public,
            Some(2_000_000_100.0),
            Some("exec.host"),
            Some("resource"),
        )
        .is_ok());
    }
}
