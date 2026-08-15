//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.jwt-mint`.
//!
//! Pure serde + structural validation; the actual signing-key parsing (which
//! needs `jsonwebtoken`) happens in `lib.rs` at compile time.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// JWT registered claims an operator may not overwrite via `extra_claims` or
/// `claim_mappings` — the plugin owns them so a minted token can't be forged
/// with a wrong issuer / no expiry / a foreign subject.
pub const RESERVED_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtMintConfig {
    /// Per-target minting profiles. Key is the `<target>` operators reference
    /// via `cred://dev.mcpg.credential.jwt-mint/<target>`.
    pub targets: BTreeMap<String, TargetEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    /// Signing algorithm.
    pub algorithm: Alg,
    /// The signing key. HS256 = the raw shared secret (UTF-8). RS256 = a
    /// PKCS#1/PKCS#8 RSA private key PEM. EdDSA = a PKCS#8 Ed25519 private key
    /// PEM. Operators populate via `${env.VAR}` (the gateway resolves it at
    /// config-load time; the plugin receives the literal).
    pub signing_key: String,
    /// JWT `iss` claim (optional).
    #[serde(default)]
    pub issuer: Option<String>,
    /// JWT `aud` claim. Serialised as a string for one value, an array for
    /// many, omitted when empty (RFC 7519).
    #[serde(default)]
    pub audience: Vec<String>,
    /// Token lifetime; `exp = iat + ttl_seconds` and the cache TTL. Must be > 0.
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    /// When true (default), the caller's `subject_id` becomes the `sub` claim.
    #[serde(default = "default_include_subject")]
    pub include_subject: bool,
    /// JWT header `kid` (optional, for downstream JWKS / key rotation).
    #[serde(default)]
    pub kid: Option<String>,
    /// Static operator-supplied claims merged into every token (e.g. `tenant`).
    /// May not collide with a reserved registered claim.
    #[serde(default)]
    pub extra_claims: BTreeMap<String, Value>,
    /// Map a caller identity field into a named claim. The value selects the
    /// source: `subject_id`, `issuer`, `auth_provider`, `trust_level`, `kind`,
    /// `roles`, `groups`, `scopes`, or `attributes.<key>`. The key (claim name)
    /// may not collide with a reserved registered claim.
    #[serde(default)]
    pub claim_mappings: BTreeMap<String, String>,
    /// Identity authorization rule. Default `any` (any caller at or above
    /// header_asserted trust). The `roles`/`groups`/`subjects` rules
    /// additionally require a cryptographically Verified identity.
    #[serde(default)]
    pub authorize: Authorize,
    /// Free-form metadata surfaced via the issued credential.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_ttl() -> u64 {
    3600
}
fn default_include_subject() -> bool {
    true
}

/// Signing algorithm. `HS256` / `RS256` / `EdDSA` only — PS/ES are out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Alg {
    Hs256,
    Rs256,
    #[serde(rename = "EdDSA")]
    Eddsa,
}

impl Alg {
    /// The canonical wire name used in the `alg` header and metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Hs256 => "HS256",
            Alg::Rs256 => "RS256",
            Alg::Eddsa => "EdDSA",
        }
    }
    /// PEM-keyed algorithms require a `-----BEGIN` marker in `signing_key`;
    /// HS256 takes a raw secret.
    pub fn is_pem_keyed(self) -> bool {
        matches!(self, Alg::Rs256 | Alg::Eddsa)
    }
}

/// Per-target identity-authorisation rule (parity with `credential.static`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Authorize {
    /// Any caller at or above header_asserted trust (anonymous is refused).
    #[default]
    Any,
    /// Caller must hold at least one of the listed roles (Verified-only).
    Roles { roles: Vec<String> },
    /// Caller must be in at least one of the listed groups (Verified-only).
    Groups { groups: Vec<String> },
    /// Caller's `subject_id` must be in the allowlist (Verified-only).
    Subjects { subjects: Vec<String> },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.jwt-mint config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.jwt-mint: `targets` must be non-empty")]
    EmptyTargets,
    #[error("credential.jwt-mint: target `{target}`: ttl_seconds must be > 0")]
    InvalidTtl { target: String },
    #[error("credential.jwt-mint: target `{target}`: signing_key must be non-empty")]
    EmptySigningKey { target: String },
    #[error(
        "credential.jwt-mint: target `{target}`: {alg} signing_key must be a PEM \
         (missing -----BEGIN marker)"
    )]
    NotPem { target: String, alg: &'static str },
    #[error(
        "credential.jwt-mint: target `{target}`: {source_kind} maps reserved claim \
         `{claim}` (reserved: iss/sub/aud/exp/nbf/iat/jti)"
    )]
    ReservedClaim {
        target: String,
        source_kind: &'static str,
        claim: String,
    },
    #[error("credential.jwt-mint: target `{target}`: authorize.{rule} list cannot be empty")]
    EmptyAuthorizeList { target: String, rule: &'static str },
}

impl JwtMintConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        for (target, entry) in &self.targets {
            if entry.ttl_seconds == 0 {
                return Err(ConfigError::InvalidTtl {
                    target: target.clone(),
                });
            }
            if entry.signing_key.is_empty() {
                return Err(ConfigError::EmptySigningKey {
                    target: target.clone(),
                });
            }
            if entry.algorithm.is_pem_keyed() && !entry.signing_key.contains("-----BEGIN") {
                return Err(ConfigError::NotPem {
                    target: target.clone(),
                    alg: entry.algorithm.as_str(),
                });
            }
            for claim in entry.extra_claims.keys() {
                reject_reserved(target, "extra_claims", claim)?;
            }
            for claim in entry.claim_mappings.keys() {
                reject_reserved(target, "claim_mappings", claim)?;
            }
            match &entry.authorize {
                Authorize::Roles { roles } if roles.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "roles",
                    });
                }
                Authorize::Groups { groups } if groups.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "groups",
                    });
                }
                Authorize::Subjects { subjects } if subjects.is_empty() => {
                    return Err(ConfigError::EmptyAuthorizeList {
                        target: target.clone(),
                        rule: "subjects",
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn reject_reserved(
    target: &str,
    source_kind: &'static str,
    claim: &str,
) -> Result<(), ConfigError> {
    if RESERVED_CLAIMS.contains(&claim) {
        return Err(ConfigError::ReservedClaim {
            target: target.to_owned(),
            source_kind,
            claim: claim.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_hs256_config() {
        let cfg = JwtMintConfig::parse(
            &json!({
                "targets": {
                    "downstream": { "algorithm": "HS256", "signing_key": "0123456789abcdef" }
                }
            })
            .to_string(),
        )
        .unwrap();
        let t = cfg.targets.get("downstream").unwrap();
        assert_eq!(t.algorithm, Alg::Hs256);
        assert_eq!(t.ttl_seconds, 3600);
        assert!(t.include_subject);
    }

    #[test]
    fn rejects_empty_targets() {
        let err = JwtMintConfig::parse(&json!({ "targets": {} }).to_string()).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyTargets));
    }

    #[test]
    fn rejects_zero_ttl() {
        let err = JwtMintConfig::parse(
            &json!({
                "targets": { "t": { "algorithm": "HS256", "signing_key": "k", "ttl_seconds": 0 } }
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTtl { .. }));
    }

    #[test]
    fn rejects_empty_signing_key() {
        let err = JwtMintConfig::parse(
            &json!({ "targets": { "t": { "algorithm": "HS256", "signing_key": "" } } }).to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::EmptySigningKey { .. }));
    }

    #[test]
    fn rejects_rs256_without_pem_marker() {
        let err = JwtMintConfig::parse(
            &json!({ "targets": { "t": { "algorithm": "RS256", "signing_key": "not-a-pem" } } })
                .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::NotPem { .. }));
    }

    #[test]
    fn rejects_unknown_field() {
        let err = JwtMintConfig::parse(
            &json!({ "targets": { "t": { "algorithm": "HS256", "signing_key": "k", "bogus": 1 } } })
                .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidJson(_)));
    }

    #[test]
    fn rejects_extra_claim_colliding_with_reserved() {
        let err = JwtMintConfig::parse(
            &json!({
                "targets": {
                    "t": { "algorithm": "HS256", "signing_key": "k", "extra_claims": { "exp": 1 } }
                }
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::ReservedClaim { .. }));
    }

    #[test]
    fn rejects_claim_mapping_colliding_with_reserved() {
        let err = JwtMintConfig::parse(
            &json!({
                "targets": {
                    "t": {
                        "algorithm": "HS256", "signing_key": "k",
                        "claim_mappings": { "sub": "subject_id" }
                    }
                }
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::ReservedClaim { .. }));
    }

    #[test]
    fn rejects_empty_roles_authorize() {
        let err = JwtMintConfig::parse(
            &json!({
                "targets": {
                    "t": {
                        "algorithm": "HS256", "signing_key": "k",
                        "authorize": { "kind": "roles", "roles": [] }
                    }
                }
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::EmptyAuthorizeList { .. }));
    }

    #[test]
    fn eddsa_alg_round_trips_wire_name() {
        let cfg = JwtMintConfig::parse(
            &json!({
                "targets": {
                    "t": { "algorithm": "EdDSA", "signing_key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }
                }
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(cfg.targets.get("t").unwrap().algorithm.as_str(), "EdDSA");
    }
}
