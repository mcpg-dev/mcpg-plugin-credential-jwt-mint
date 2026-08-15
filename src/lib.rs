//! `dev.mcpg.credential.jwt-mint` — config-driven JWT-minting
//! credential_issuer plugin.
//!
//! For each operator-defined target the plugin mints a freshly-signed JWT per
//! request, asserting the caller's identity to a downstream service. Pure CPU
//! crypto, fully offline (no outbound network). Supports HS256 / RS256 / EdDSA.
//! Signing keys are parsed ONCE at boot; per-request `issue()` does zero key
//! parsing. Fails closed: a bad config or an unloadable signing key refuses to
//! register.
//!
//! Minted tokens are stateless (like STS), so there is no lease and `revoke`
//! is a no-op.

pub mod config;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::manifest::PluginClass;
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use config::{Alg, Authorize, ConfigError, JwtMintConfig, TargetEntry};

const PLUGIN_ID: &str = "dev.mcpg.credential.jwt-mint";

pub struct JwtMintPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    targets: BTreeMap<String, CompiledTarget>,
}

/// A target with its signing key already parsed, so `issue()` is pure assembly.
struct CompiledTarget {
    alg: Algorithm,
    alg_str: &'static str,
    encoding_key: EncodingKey,
    kid: Option<String>,
    issuer: Option<String>,
    audience: Vec<String>,
    ttl_seconds: u64,
    include_subject: bool,
    extra_claims: BTreeMap<String, Value>,
    claim_mappings: BTreeMap<String, String>,
    authorize: Authorize,
    metadata: BTreeMap<String, String>,
}

fn to_jwt_alg(a: Alg) -> Algorithm {
    match a {
        Alg::Hs256 => Algorithm::HS256,
        Alg::Rs256 => Algorithm::RS256,
        Alg::Eddsa => Algorithm::EdDSA,
    }
}

impl Inner {
    /// Compile a validated config: parse every signing key into an
    /// `EncodingKey`. Returns a message on the first unloadable key.
    fn compile(cfg: JwtMintConfig) -> Result<Self, String> {
        let mut targets = BTreeMap::new();
        for (name, entry) in cfg.targets {
            let encoding_key = match entry.algorithm {
                Alg::Hs256 => EncodingKey::from_secret(entry.signing_key.as_bytes()),
                Alg::Rs256 => EncodingKey::from_rsa_pem(entry.signing_key.as_bytes())
                    .map_err(|e| format!("target `{name}`: invalid RS256 signing key: {e}"))?,
                Alg::Eddsa => EncodingKey::from_ed_pem(entry.signing_key.as_bytes())
                    .map_err(|e| format!("target `{name}`: invalid EdDSA signing key: {e}"))?,
            };
            targets.insert(
                name,
                CompiledTarget {
                    alg: to_jwt_alg(entry.algorithm),
                    alg_str: entry.algorithm.as_str(),
                    encoding_key,
                    kid: entry.kid,
                    issuer: entry.issuer,
                    audience: entry.audience,
                    ttl_seconds: entry.ttl_seconds,
                    include_subject: entry.include_subject,
                    extra_claims: entry.extra_claims,
                    claim_mappings: entry.claim_mappings,
                    authorize: entry.authorize,
                    metadata: entry.metadata,
                },
            );
        }
        Ok(Inner {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "JWT Minting Credential Issuer".into(),
                plugin_class: PluginClass::CredentialIssuer,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            targets,
        })
    }
}

impl JwtMintPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = JwtMintConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "credential.jwt-mint: config parse failed; refusing to register"
            );
            panic!(
                "credential.jwt-mint config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        let inner = Inner::compile(cfg).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "credential.jwt-mint: signing-key load failed; refusing to register"
            );
            panic!(
                "credential.jwt-mint config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        tracing::info!(
            plugin_id = PLUGIN_ID,
            targets_loaded = inner.targets.len(),
            "credential.jwt-mint: registry compiled"
        );
        Self {
            inner: Arc::new(inner),
        }
    }
}

/// Identity trust-floor check — identical policy to `credential.static`.
/// Minting a token that asserts the caller's identity to a downstream is an
/// impersonation primitive, so a spoofable header-asserted identity must never
/// satisfy a subject/role/group allowlist.
fn check_authorization(
    target: &str,
    rule: &Authorize,
    identity: &PluginIdentity,
) -> Result<(), CredentialError> {
    use mcpg_plugin_protocol::catalog::{
        TRUST_LEVEL_HEADER_ASSERTED, TRUST_LEVEL_VERIFIED, trust_level_meets,
    };
    let trust = identity.trust_level.as_str();
    let authorized = match rule {
        Authorize::Any => trust_level_meets(trust, TRUST_LEVEL_HEADER_ASSERTED),
        Authorize::Roles { roles } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && roles.iter().any(|r| identity.roles.contains(r))
        }
        Authorize::Groups { groups } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && groups.iter().any(|g| identity.groups.contains(g))
        }
        Authorize::Subjects { subjects } => {
            trust_level_meets(trust, TRUST_LEVEL_VERIFIED)
                && identity
                    .subject_id
                    .as_ref()
                    .is_some_and(|s| subjects.iter().any(|allowed| allowed == s))
        }
    };
    if authorized {
        Ok(())
    } else {
        Err(CredentialError::NotAuthorized {
            reason: format!("identity not permitted to issue target `{target}`"),
        })
    }
}

/// Project a `claim_mappings` source string onto an identity field.
fn map_identity_field(identity: &PluginIdentity, source: &str) -> Option<Value> {
    let strs = |v: &[String]| Value::Array(v.iter().cloned().map(Value::String).collect());
    match source {
        "subject_id" => identity.subject_id.clone().map(Value::String),
        "issuer" => identity.issuer.clone().map(Value::String),
        "auth_provider" => identity.auth_provider.clone().map(Value::String),
        "trust_level" => Some(Value::String(identity.trust_level.clone())),
        "kind" => Some(Value::String(identity.kind.clone())),
        "roles" => Some(strs(&identity.roles)),
        "groups" => Some(strs(&identity.groups)),
        "scopes" => Some(strs(&identity.scopes)),
        other => other
            .strip_prefix("attributes.")
            .and_then(|k| identity.attributes.get(k))
            .cloned()
            .map(Value::String),
    }
}

fn issue_for(
    inner: &Inner,
    identity: &PluginIdentity,
    target: &str,
) -> Result<IssuedCredential, CredentialError> {
    let ct = inner
        .targets
        .get(target)
        .ok_or_else(|| CredentialError::Misconfigured {
            reason: format!("unknown target `{target}` in credential.jwt-mint plugin"),
        })?;
    check_authorization(target, &ct.authorize, identity)?;

    let now = OffsetDateTime::now_utc();
    let now_unix = now.unix_timestamp();
    let exp = now_unix + ct.ttl_seconds as i64;

    let mut claims: Map<String, Value> = Map::new();
    claims.insert("iat".into(), Value::from(now_unix));
    claims.insert("nbf".into(), Value::from(now_unix));
    claims.insert("exp".into(), Value::from(exp));
    claims.insert(
        "jti".into(),
        Value::from(format!("jwt_{}", uuid::Uuid::now_v7().simple())),
    );
    if let Some(iss) = &ct.issuer {
        claims.insert("iss".into(), Value::from(iss.clone()));
    }
    if ct.include_subject
        && let Some(sub) = &identity.subject_id
    {
        claims.insert("sub".into(), Value::from(sub.clone()));
    }
    match ct.audience.len() {
        0 => {}
        1 => {
            claims.insert("aud".into(), Value::from(ct.audience[0].clone()));
        }
        _ => {
            claims.insert(
                "aud".into(),
                Value::Array(ct.audience.iter().cloned().map(Value::from).collect()),
            );
        }
    }
    for (k, v) in &ct.extra_claims {
        claims.insert(k.clone(), v.clone());
    }
    for (claim_name, source) in &ct.claim_mappings {
        if let Some(v) = map_identity_field(identity, source) {
            claims.insert(claim_name.clone(), v);
        }
    }

    let mut header = Header::new(ct.alg);
    header.kid = ct.kid.clone();
    let token = jsonwebtoken::encode(&header, &claims, &ct.encoding_key).map_err(|e| {
        // An encode failure here is an operator key-config problem, not a
        // transient upstream — surface it as Misconfigured (500), not Backend.
        CredentialError::Misconfigured {
            reason: format!("jwt encode failed for target `{target}`: {e}"),
        }
    })?;

    let issued_at = now.format(&Rfc3339).unwrap_or_default();
    let mut metadata = ct.metadata.clone();
    metadata.insert("jwt.alg".into(), ct.alg_str.to_owned());
    if let Some(kid) = &ct.kid {
        metadata.insert("jwt.kid".into(), kid.clone());
    }

    Ok(IssuedCredential {
        value: Some(token),
        parts: BTreeMap::new(),
        ttl_seconds: ct.ttl_seconds,
        lease_id: None,
        issued_at,
        metadata,
    })
}

#[async_trait]
impl CredentialIssuer for JwtMintPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_for(&self.inner, identity, target)
    }

    // Minted JWTs are stateless — no lease, no revocation.
}

impl SyncCredentialIssuer for JwtMintPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_for(&self.inner, identity, target)
    }
}

declare_plugin! {
    plugin_id: "dev.mcpg.credential.jwt-mint",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: JwtMintPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> JwtMintPlugin {
                JwtMintPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests;
