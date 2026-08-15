use std::collections::{BTreeMap, HashSet};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::{Map, Value, json};

use super::JwtMintPlugin;

const ED_PRIV: &str = include_str!("testdata/ed25519_priv.pem");
const ED_PUB: &str = include_str!("testdata/ed25519_pub.pem");
const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");

const HS_SECRET: &str = "0123456789abcdef-shared-secret";

fn build(cfg: Value) -> JwtMintPlugin {
    JwtMintPlugin::from_config_json(&cfg.to_string())
}

fn issue(
    p: &JwtMintPlugin,
    id: &PluginIdentity,
    target: &str,
) -> Result<IssuedCredential, CredentialError> {
    SyncCredentialIssuer::issue(p, id, target, &json!({}))
}

fn verified(subject: &str, roles: &[&str], groups: &[&str]) -> PluginIdentity {
    PluginIdentity {
        kind: "verified".into(),
        trust_level: "verified".into(),
        subject_id: Some(subject.into()),
        auth_provider: Some("oidc".into()),
        issuer: Some("https://idp.example".into()),
        roles: roles.iter().map(|s| (*s).to_owned()).collect(),
        groups: groups.iter().map(|s| (*s).to_owned()).collect(),
        scopes: vec!["read".into(), "write".into()],
        attributes: BTreeMap::from([("tenant".to_owned(), "acme".to_owned())]),
    }
}

fn at_trust(trust: &str, subject: &str) -> PluginIdentity {
    PluginIdentity {
        kind: trust.into(),
        trust_level: trust.into(),
        subject_id: Some(subject.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: BTreeMap::new(),
    }
}

/// Decode + verify a token's signature; return its claims. `validate_aud` is
/// off so tests assert `aud` shape directly.
fn decode(token: &str, alg: Algorithm, key: &DecodingKey) -> Map<String, Value> {
    let mut v = Validation::new(alg);
    v.validate_aud = false;
    v.required_spec_claims = HashSet::new();
    jsonwebtoken::decode::<Map<String, Value>>(token, key, &v)
        .expect("token must verify + decode")
        .claims
}

#[test]
fn mints_hs256_token_and_verifies() {
    let p = build(json!({
        "targets": {
            "svc": {
                "algorithm": "HS256",
                "signing_key": HS_SECRET,
                "issuer": "mcpg",
                "audience": ["orders"]
            }
        }
    }));
    let cred = issue(&p, &verified("alice", &[], &[]), "svc").unwrap();
    let token = cred.value.as_deref().unwrap();
    let claims = decode(
        token,
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    assert_eq!(claims["iss"], json!("mcpg"));
    assert_eq!(claims["aud"], json!("orders"));
    assert_eq!(claims["sub"], json!("alice"));
    assert!(claims.contains_key("exp"));
    assert_eq!(cred.metadata.get("jwt.alg").unwrap(), "HS256");
}

#[test]
fn mints_eddsa_token_and_verifies() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "EdDSA", "signing_key": ED_PRIV } }
    }));
    let token = issue(&p, &verified("bob", &[], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::EdDSA,
        &DecodingKey::from_ed_pem(ED_PUB.as_bytes()).unwrap(),
    );
    assert_eq!(claims["sub"], json!("bob"));
}

#[test]
fn mints_rs256_token_and_verifies() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "RS256", "signing_key": RSA_PRIV } }
    }));
    let token = issue(&p, &verified("carol", &[], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::RS256,
        &DecodingKey::from_rsa_pem(RSA_PUB.as_bytes()).unwrap(),
    );
    assert_eq!(claims["sub"], json!("carol"));
}

#[test]
fn include_subject_false_omits_sub() {
    let p = build(json!({
        "targets": {
            "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "include_subject": false }
        }
    }));
    let token = issue(&p, &verified("alice", &[], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    assert!(!claims.contains_key("sub"));
}

#[test]
fn extra_claims_present_in_payload() {
    let p = build(json!({
        "targets": {
            "svc": {
                "algorithm": "HS256", "signing_key": HS_SECRET,
                "extra_claims": { "tenant": "globex", "tier": 3 }
            }
        }
    }));
    let token = issue(&p, &verified("alice", &[], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    assert_eq!(claims["tenant"], json!("globex"));
    assert_eq!(claims["tier"], json!(3));
}

#[test]
fn claim_mapping_projects_roles_and_attributes() {
    let p = build(json!({
        "targets": {
            "svc": {
                "algorithm": "HS256", "signing_key": HS_SECRET,
                "claim_mappings": { "roles": "roles", "tenant": "attributes.tenant" }
            }
        }
    }));
    let token = issue(&p, &verified("alice", &["admin", "dev"], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    assert_eq!(claims["roles"], json!(["admin", "dev"]));
    assert_eq!(claims["tenant"], json!("acme"));
}

#[test]
fn aud_single_string_vs_array() {
    let one = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "audience": ["a"] } }
    }));
    let two = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "audience": ["a", "b"] } }
    }));
    let dk = DecodingKey::from_secret(HS_SECRET.as_bytes());
    let c1 = decode(
        &issue(&one, &verified("u", &[], &[]), "svc")
            .unwrap()
            .value
            .unwrap(),
        Algorithm::HS256,
        &dk,
    );
    let c2 = decode(
        &issue(&two, &verified("u", &[], &[]), "svc")
            .unwrap()
            .value
            .unwrap(),
        Algorithm::HS256,
        &dk,
    );
    assert_eq!(c1["aud"], json!("a"), "single aud is a JSON string");
    assert_eq!(c2["aud"], json!(["a", "b"]), "multi aud is a JSON array");
}

#[test]
fn no_aud_when_empty() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    let token = issue(&p, &verified("u", &[], &[]), "svc")
        .unwrap()
        .value
        .unwrap();
    let claims = decode(
        &token,
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    assert!(!claims.contains_key("aud"));
}

#[test]
fn kid_in_header_and_metadata() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "kid": "key-2026" } }
    }));
    let cred = issue(&p, &verified("u", &[], &[]), "svc").unwrap();
    assert_eq!(cred.metadata.get("jwt.kid").unwrap(), "key-2026");
    let header = jsonwebtoken::decode_header(cred.value.as_deref().unwrap()).unwrap();
    assert_eq!(header.kid.as_deref(), Some("key-2026"));
}

#[test]
fn unknown_target_returns_misconfigured() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    let err = issue(&p, &verified("u", &[], &[]), "missing").unwrap_err();
    assert!(matches!(err, CredentialError::Misconfigured { .. }));
}

#[test]
fn any_rule_rejects_anonymous_caller() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    assert!(matches!(
        issue(&p, &at_trust("anonymous", "x"), "svc").unwrap_err(),
        CredentialError::NotAuthorized { .. }
    ));
    // header_asserted meets the default floor.
    assert!(issue(&p, &at_trust("header_asserted", "x"), "svc").is_ok());
}

#[test]
fn roles_rule_requires_verified_trust() {
    let p = build(json!({
        "targets": {
            "svc": {
                "algorithm": "HS256", "signing_key": HS_SECRET,
                "authorize": { "kind": "roles", "roles": ["admin"] }
            }
        }
    }));
    // A header-asserted caller carrying no verified roles is rejected.
    let mut ha = at_trust("header_asserted", "x");
    ha.roles = vec!["admin".into()];
    assert!(matches!(
        issue(&p, &ha, "svc").unwrap_err(),
        CredentialError::NotAuthorized { .. }
    ));
    // Verified + role → allowed.
    assert!(issue(&p, &verified("x", &["admin"], &[]), "svc").is_ok());
    // Verified without the role → rejected.
    assert!(matches!(
        issue(&p, &verified("x", &["dev"], &[]), "svc").unwrap_err(),
        CredentialError::NotAuthorized { .. }
    ));
}

#[test]
fn subjects_rule_rejects_header_asserted_subject() {
    let p = build(json!({
        "targets": {
            "svc": {
                "algorithm": "HS256", "signing_key": HS_SECRET,
                "authorize": { "kind": "subjects", "subjects": ["alice"] }
            }
        }
    }));
    assert!(matches!(
        issue(&p, &at_trust("header_asserted", "alice"), "svc").unwrap_err(),
        CredentialError::NotAuthorized { .. }
    ));
    assert!(issue(&p, &verified("alice", &[], &[]), "svc").is_ok());
}

#[test]
fn ttl_reflected_in_credential_and_exp() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "ttl_seconds": 120 } }
    }));
    let cred = issue(&p, &verified("u", &[], &[]), "svc").unwrap();
    assert_eq!(cred.ttl_seconds, 120);
    let claims = decode(
        cred.value.as_deref().unwrap(),
        Algorithm::HS256,
        &DecodingKey::from_secret(HS_SECRET.as_bytes()),
    );
    let iat = claims["iat"].as_i64().unwrap();
    let exp = claims["exp"].as_i64().unwrap();
    assert_eq!(exp - iat, 120);
}

#[test]
fn jti_is_unique_per_call() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    let dk = DecodingKey::from_secret(HS_SECRET.as_bytes());
    let a = decode(
        &issue(&p, &verified("u", &[], &[]), "svc")
            .unwrap()
            .value
            .unwrap(),
        Algorithm::HS256,
        &dk,
    );
    let b = decode(
        &issue(&p, &verified("u", &[], &[]), "svc")
            .unwrap()
            .value
            .unwrap(),
        Algorithm::HS256,
        &dk,
    );
    assert_ne!(a["jti"], b["jti"]);
    assert!(a["jti"].as_str().unwrap().starts_with("jwt_"));
}

#[test]
fn issued_at_is_rfc3339() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    let cred = issue(&p, &verified("u", &[], &[]), "svc").unwrap();
    assert!(cred.issued_at.len() >= 20);
    assert!(cred.issued_at.contains('T'));
}

#[test]
fn revoke_is_noop() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET } }
    }));
    assert!(SyncCredentialIssuer::revoke(&p, "any-lease").is_ok());
}

#[tokio::test]
async fn async_and_sync_issue_agree() {
    let p = build(json!({
        "targets": { "svc": { "algorithm": "HS256", "signing_key": HS_SECRET, "issuer": "mcpg" } }
    }));
    let id = verified("dave", &[], &[]);
    let sync_tok = SyncCredentialIssuer::issue(&p, &id, "svc", &json!({}))
        .unwrap()
        .value
        .unwrap();
    let async_tok = CredentialIssuer::issue(&p, &id, "svc", &json!({}))
        .await
        .unwrap()
        .value
        .unwrap();
    let dk = DecodingKey::from_secret(HS_SECRET.as_bytes());
    let cs = decode(&sync_tok, Algorithm::HS256, &dk);
    let ca = decode(&async_tok, Algorithm::HS256, &dk);
    assert_eq!(cs["sub"], ca["sub"]);
    assert_eq!(cs["iss"], ca["iss"]);
}

#[test]
#[should_panic(expected = "jwt-mint config parse failed")]
fn from_config_json_panics_on_malformed_json() {
    JwtMintPlugin::from_config_json("{ not json");
}

#[test]
#[should_panic(expected = "jwt-mint config parse failed")]
fn from_config_json_panics_on_bad_eddsa_key() {
    // PEM marker present (passes structural validation) but bytes are garbage,
    // so the EdDSA key load fails at compile time → fail closed.
    JwtMintPlugin::from_config_json(
        &json!({
            "targets": {
                "svc": {
                    "algorithm": "EdDSA",
                    "signing_key": "-----BEGIN PRIVATE KEY-----\nZ===\n-----END PRIVATE KEY-----"
                }
            }
        })
        .to_string(),
    );
}
