# JWT Minting Credential Issuer (`dev.mcpg.credential.jwt-mint`)

A **credential_issuer** that mints a freshly-signed **JWT per request** to assert
the caller's identity to a downstream service. Operators declare per-target
minting profiles keyed on the `cred://` target string; the gateway resolves
`cred://dev.mcpg.credential.jwt-mint/<target>` and hands the minted token to the
bound backend.

Pure CPU crypto, fully **offline** — no outbound network. Signing keys are
parsed **once at boot**; each call is pure claim assembly + signing. The plugin
**fails closed**: a bad config or an unloadable signing key refuses to register.
Minted tokens are stateless (like STS) — no lease, `revoke` is a no-op.

Supported algorithms: **HS256** (shared secret), **RS256** (RSA PEM), **EdDSA**
(Ed25519 PEM). Crypto runs on `aws-lc-rs` (rustls-clean — no OpenSSL).

## Configuration

Top-level: `targets` — a non-empty map of `<target>` → minting profile.

| Field | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `HS256` \| `RS256` \| `EdDSA` | *(required)* | Signing algorithm. |
| `signing_key` | string | *(required)* | HS256 = raw shared secret. RS256 = RSA private-key PEM. EdDSA = PKCS#8 Ed25519 private-key PEM. Populate via `${env.VAR}`. |
| `issuer` | string | *(none)* | `iss` claim. |
| `audience` | array of string | `[]` | `aud` claim — a string for one value, an array for many, omitted when empty (RFC 7519). |
| `ttl_seconds` | int > 0 | `3600` | Token lifetime; `exp = iat + ttl_seconds` and the cache TTL. |
| `include_subject` | bool | `true` | When true, the caller's `subject_id` becomes the `sub` claim. |
| `kid` | string | *(none)* | JWT header `kid` (for downstream JWKS / key rotation). |
| `extra_claims` | object | `{}` | Static operator claims merged into every token. |
| `claim_mappings` | map of claim→source | `{}` | Project an identity field into a named claim (see below). |
| `authorize` | rule | `{kind: any}` | Who may mint this target (see below). |
| `metadata` | map | `{}` | Surfaced via the issued credential's metadata. |

`extra_claims` and `claim_mappings` may **not** target a reserved registered
claim (`iss` `sub` `aud` `exp` `nbf` `iat` `jti`) — rejected at load so an
operator can't forge a non-expiring or wrong-issuer token. Unknown fields are
rejected (`deny_unknown_fields`).

### `claim_mappings` sources

The value selects a caller-identity field: `subject_id`, `issuer`,
`auth_provider`, `trust_level`, `kind`, `roles`, `groups`, `scopes`, or
`attributes.<key>`. Optional fields are emitted only when present.

```yaml
claim_mappings:
  roles: roles            # -> "roles": ["admin", "dev"]
  tenant: attributes.tenant
```

### `authorize`

Identity trust-floor gate, identical to `credential.static`:

- `{kind: any}` (default) — any caller at or above **header_asserted** trust
  (anonymous is refused).
- `{kind: roles, roles: [...]}` / `{kind: groups, groups: [...]}` /
  `{kind: subjects, subjects: [...]}` — additionally require a cryptographically
  **Verified** identity. A spoofable header-asserted identity can never satisfy
  one of these allowlists (minting a token for it would be an impersonation
  primitive).

## Example

```yaml
plugins:
  - id: dev.mcpg.credential.jwt-mint
    class: credential_issuer
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/credential-jwt-mint:protocol-1" }
    config:
      targets:
        partner-api:
          algorithm: EdDSA
          signing_key: ${env.PARTNER_JWT_ED25519_PEM}
          issuer: https://gateway.mcpg.dev
          audience: ["https://partner.example/api"]
          ttl_seconds: 300
          kid: partner-2026
          claim_mappings:
            roles: roles
            tenant: attributes.tenant
          authorize: { kind: roles, roles: ["partner"] }
```

A backend binds `cred://dev.mcpg.credential.jwt-mint/partner-api`; each request
from a Verified caller holding the `partner` role gets a 5-minute EdDSA JWT
carrying their `sub`, `roles`, and `tenant`.

## Notes

- Distinct from `dev.mcpg.identity.jwt`, which **verifies** inbound JWTs to
  establish identity; this plugin **mints** outbound JWTs from an established
  identity.
- `jti` is a fresh UUIDv7 per call; `iat`/`nbf`/`exp` are set automatically.
- Pure-Rust (`jsonwebtoken` on `aws-lc-rs`, MIT/Apache-2.0), rustls-clean,
  `default-members`. No host capabilities required.

## Building and testing

```sh
cargo build --release   # builds the plugin cdylib into target/release/
cargo test
```
