use super::types::ArchiveIdentity;
use crate::settings::ArchiveOidcSettings;
use jsonwebtoken::jwk::{JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Clone)]
pub struct ArchiveAuthService {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

#[derive(Clone)]
struct CachedJwks {
    fetched_at: Instant,
    set: JwkSet,
}

impl ArchiveAuthService {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn validate(
        &self,
        token: &str,
        settings: &ArchiveOidcSettings,
    ) -> Result<ArchiveIdentity, String> {
        validate_oidc_settings(settings)?;
        let header = decode_header(token).map_err(|_| "Bearer JWT 格式无效".to_string())?;
        let kid = header
            .kid
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "Bearer JWT 缺少 kid".to_string())?;
        if !algorithm_allowed(header.alg, &settings.allowed_algorithms) {
            return Err("Bearer JWT 使用了未允许的签名算法".to_string());
        }
        let jwk = match self.cached_key(&settings.jwks_url, kid).await {
            Some(value) => value,
            None => {
                self.refresh(&settings.jwks_url).await?;
                self.cached_key(&settings.jwks_url, kid)
                    .await
                    .ok_or_else(|| "JWKS 中不存在 JWT 指定的 kid".to_string())?
            }
        };
        if jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| !matches!(usage, PublicKeyUse::Signature))
        {
            return Err("JWT 指定的 JWK 不允许用于签名验证".to_string());
        }
        if jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                !operations
                    .iter()
                    .any(|operation| matches!(operation, KeyOperations::Verify))
            })
        {
            return Err("JWT 指定的 JWK 不允许 verify 操作".to_string());
        }
        if jwk.common.key_algorithm.is_some_and(|algorithm| {
            !algorithm
                .to_string()
                .eq_ignore_ascii_case(algorithm_label(header.alg))
        }) {
            return Err("JWT header 与 JWK 的签名算法不匹配".to_string());
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| "JWKS 公钥格式不受支持".to_string())?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[settings.issuer.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_SECONDS;
        let claims = decode::<Value>(token, &key, &validation)
            .map_err(|_| "Bearer JWT 签名或标准 Claims 校验失败".to_string())?
            .claims;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "Bearer JWT 缺少 sub".to_string())?;
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|value| value == &settings.issuer)
            .ok_or_else(|| "Bearer JWT issuer 不匹配".to_string())?;
        Ok(ArchiveIdentity {
            issuer,
            subject,
            name: claim_string(&claims, &settings.name_claim),
            email: claim_string(&claims, &settings.email_claim),
            organization: claim_string(&claims, &settings.organization_claim),
        })
    }

    pub async fn check_jwks(&self, settings: &ArchiveOidcSettings) -> Result<(), String> {
        validate_oidc_settings(settings)?;
        self.refresh(&settings.jwks_url).await
    }

    async fn cached_key(&self, url: &str, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        let cache = self.cache.read().await;
        let entry = cache.get(url)?;
        if entry.fetched_at.elapsed() > JWKS_CACHE_TTL {
            return None;
        }
        entry
            .set
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid))
            .cloned()
    }

    async fn refresh(&self, url: &str) -> Result<(), String> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| "无法获取 OIDC JWKS".to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "OIDC JWKS 返回 HTTP {}",
                response.status().as_u16()
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "读取 OIDC JWKS 失败".to_string())?;
        if bytes.len() > 1024 * 1024 {
            return Err("OIDC JWKS 响应过大".to_string());
        }
        let set: JwkSet =
            serde_json::from_slice(&bytes).map_err(|_| "OIDC JWKS JSON 格式无效".to_string())?;
        if set.keys.is_empty() {
            return Err("OIDC JWKS 不包含公钥".to_string());
        }
        self.cache.write().await.insert(
            url.to_string(),
            CachedJwks {
                fetched_at: Instant::now(),
                set,
            },
        );
        Ok(())
    }
}

impl Default for ArchiveAuthService {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_oidc_settings(settings: &ArchiveOidcSettings) -> Result<(), String> {
    if settings.issuer.trim().is_empty()
        || settings.audience.trim().is_empty()
        || settings.jwks_url.trim().is_empty()
    {
        return Err("OIDC 尚未完整配置".to_string());
    }
    Ok(())
}

fn algorithm_allowed(algorithm: Algorithm, allowed: &[String]) -> bool {
    let label = algorithm_label(algorithm);
    if label.is_empty() {
        return false;
    }
    allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(label))
}

fn algorithm_label(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::EdDSA => "EDDSA",
        _ => "",
    }
}

fn claim_string(claims: &Value, path: &str) -> Option<String> {
    if path.trim().is_empty() {
        return None;
    }
    let mut value = claims;
    for segment in path.split('.') {
        value = value.get(segment)?;
    }
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => {
            let values = values.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.join(", "))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    // Intentionally public, test-only fixture. It never signs production data
    // and exists solely to exercise local JWKS signature verification.
    const TEST_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCybVhV+VGqEqVl
xUmYRVTDRNBzTocnF6CZb5A1UJHNZFOS7ZrkdbJcYdnb+o0pdHHNbim0HYbw6etn
cwJJe2ji4fv7i1eYyQFDhIqeRyll47Fjc5F7hADn/VdAxwidVFgaSj6UnWaViRbh
39105ZHCrrq1QbjAytNG4pDwXyUADVY2vVMKV/iBF3xpFrgr+1OC/wu8kvHHShrH
y0ONxhIpsZeGuAY/39K2iEpCMVXcBm0vI2i4EF/nEZFNQTyUZ6IqPOOEPzIRV4Sa
mDVS7WgdZpTV7ZyXrjWsG6213Sy5MlY+apgj2c7iybxSr948kPZlNtzFitxMaPxE
Q6DFHhCTAgMBAAECggEATIL1GVDjQwHh6QUzrNc2JNHybS+kZxALryAW/7XAAApg
iCXZgNQzmsffCySiub8UOdpeib0Lq20zo9W+ilIgRQJQ8qnq8zpmj1RbuMmdJ/L+
kz3wib2uQczySHXQ7N5JNWTW9xWT8tWpeUxtA36aBZi1uZooJowTE1d+fYTfMejM
X5k1KBg54C8L9SFUvIFWlBo2Y5aQLuSwq0FMwFfdAItMtAG4OnlAYgKXXyqinfNM
799Mbl2JkyZkI77pas6A5wtgAuSXEXi1aB08qIby+sKCjVUt3GsuZ+DnmIXXFuk/
2nRl2w444cqa/Y3tacCDZx43Y8JWj419/KGdb87M2QKBgQD8Bz6Qt679S6DEI3p2
Ebq0jABYG2V0jaDZq/PCJFaPQ9cCOOfSy2qV1vtHPpMBcp+bPB07CoYuJMxHxMd/
zbRtYBWt3XwdGEXCCI8ymOiniaQ42BFNv4cL57L9x+Q4KVt2g5aUXRKg99no6AHr
K1si7S8Xvq2Bma69uts9uScSnwKBgQC1PSwOurZx9rN4APyuj1firgDt0moF2ijv
WAAPbgoRBKiuEcm2hw4MZBLoFs/Sonad40fx9cb49LDyru9KxCHE3gJOniFINA3v
atmbkL9oQ8P8sOqW9SXMYK1Nuhc9AsKB8VFpRMl1D8VE2p2r3xm0PtFo1ycCcqI3
0BvpznvRjQKBgQDNY5YAWEFamWSWE5e8Wux+MM4i/4ip+LXKTtDjObv1G0NAw2Fh
r3bYUBAN2pfxCRm7Z70mnYgGWOTF5D71D43nyPNB8wsvptVKsLEKegS4bHqR/Lv1
UY3cDOIY4etCPaoVJl3z4PnKhtJmdZUCsx2dlA/Z2QILaVQ3uOztG1QVXwKBgCcd
TKThJv7xf0om7GHADfeeFhU9lCQvMSZ2l4y88u85Ui4/KIl8HEwQTQRJ6BBNf8wT
gTN3F7ojFQ1LM9mu+prCTz0oY4ZxtZA2P0CTvLuD5IhkpjxuK/ov4zcjMmC4d8IT
kr5lWhUpkimKBP1S6Pk9lXRK+uBMXTYuc9fB+HcBAoGBAMA5LgpfvuyuuqX9/RNk
B8gOBH9xZY870JBG/WNmV3nOc33O0EQIA+u/XYIxnhUyhWc2tHqfO3LCQDpg9QfR
PFQt9azGRk7huYjra4wtnY88YYRO7syI8qCo8jdppef5CzJ6t2BL06oBP/2X5Ukr
Ne7N4XTGo07QSftcVZlTQsTs
-----END PRIVATE KEY-----"#;

    const TEST_MODULUS: &str = "sm1YVflRqhKlZcVJmEVUw0TQc06HJxegmW-QNVCRzWRTku2a5HWyXGHZ2_qNKXRxzW4ptB2G8OnrZ3MCSXto4uH7-4tXmMkBQ4SKnkcpZeOxY3ORe4QA5_1XQMcInVRYGko-lJ1mlYkW4d_ddOWRwq66tUG4wMrTRuKQ8F8lAA1WNr1TClf4gRd8aRa4K_tTgv8LvJLxx0oax8tDjcYSKbGXhrgGP9_StohKQjFV3AZtLyNouBBf5xGRTUE8lGeiKjzjhD8yEVeEmpg1Uu1oHWaU1e2cl641rButtd0suTJWPmqYI9nO4sm8Uq_ePJD2ZTbcxYrcTGj8REOgxR4Qkw";

    #[test]
    fn resolves_nested_and_array_claims() {
        let claims = json!({"sub":"u1", "realm":{"orgs":["a", "b"]}});
        assert_eq!(claim_string(&claims, "sub").as_deref(), Some("u1"));
        assert_eq!(claim_string(&claims, "realm.orgs").as_deref(), Some("a, b"));
    }

    #[test]
    fn rejects_symmetric_algorithms() {
        assert!(!algorithm_allowed(Algorithm::HS256, &["HS256".to_string()]));
        assert!(algorithm_allowed(Algorithm::RS256, &["RS256".to_string()]));
    }

    #[tokio::test]
    async fn validates_signature_and_standard_claims_against_jwks() {
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "RS256",
                "kid": "archive-test-key",
                "n": TEST_MODULUS,
                "e": "AQAB"
            }]
        });
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let value = jwks.clone();
                async move { Json(value) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let settings = ArchiveOidcSettings {
            issuer: "https://issuer.example".to_string(),
            audience: "token-manager-team".to_string(),
            jwks_url: format!("http://{address}/jwks"),
            allowed_algorithms: vec!["RS256".to_string()],
            name_claim: "profile.name".to_string(),
            email_claim: "email".to_string(),
            organization_claim: "organizations".to_string(),
        };
        let service = ArchiveAuthService::new();
        let now = chrono::Utc::now().timestamp();
        let valid_claims = json!({
            "iss": settings.issuer,
            "aud": settings.audience,
            "sub": "user-42",
            "exp": now + 300,
            "nbf": now - 1,
            "profile": {"name": "Alice"},
            "email": "alice@example.com",
            "organizations": ["engineering", "security"]
        });

        let valid = sign(&valid_claims, "archive-test-key");
        let identity = service.validate(&valid, &settings).await.unwrap();
        assert_eq!(identity.subject, "user-42");
        assert_eq!(identity.name.as_deref(), Some("Alice"));
        assert_eq!(
            identity.organization.as_deref(),
            Some("engineering, security")
        );

        for invalid_claims in [
            json!({"iss": settings.issuer, "aud": settings.audience, "sub": "user-42", "exp": now - 60}),
            json!({"iss": "https://wrong.example", "aud": settings.audience, "sub": "user-42", "exp": now + 300}),
            json!({"iss": settings.issuer, "aud": "wrong-audience", "sub": "user-42", "exp": now + 300}),
            json!({"iss": settings.issuer, "aud": settings.audience, "exp": now + 300}),
            json!({"iss": settings.issuer, "aud": settings.audience, "sub": 42, "exp": now + 300}),
            json!({"iss": settings.issuer, "aud": settings.audience, "sub": "user-42", "exp": now + 300, "nbf": now + 300}),
        ] {
            assert!(service
                .validate(&sign(&invalid_claims, "archive-test-key"), &settings)
                .await
                .is_err());
        }
        assert!(service
            .validate(&sign(&valid_claims, "unknown-key"), &settings)
            .await
            .is_err());
        server.abort();
    }

    fn sign(claims: &Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }
}
