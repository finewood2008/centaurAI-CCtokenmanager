use super::types::NormalizedAttachment;
use crate::settings::ArchiveRedactionRule;
use base64::Engine;
use regex::{Captures, Regex};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static PEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("valid PEM regex")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
        .expect("valid JWT regex")
});
static API_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:sk|rk|pk|api|key|token|gh[pousr])[-_][A-Za-z0-9_-]{16,}\b|\bAKIA[A-Z0-9]{16}\b|\bAIza[A-Za-z0-9_-]{30,}\b",
    )
    .expect("valid API key regex")
});
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}").expect("valid bearer regex")
});
static HEADER_CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-goog-api-key)\s*:\s*[^\r\n]+",
    )
    .expect("valid credential header regex")
});
static PASSWORD_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(password|passwd|pwd|client[_-]?secret|secret[_-]?access[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]\s*([^\s,;\"']+)"#)
        .expect("valid password regex")
});
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"']+"#).expect("valid URL regex")
});

#[derive(Debug)]
struct CompiledRule {
    name: String,
    regex: Regex,
}

#[derive(Debug, Default)]
pub struct Redactor {
    rules: Vec<CompiledRule>,
}

impl Redactor {
    pub fn new(rules: &[ArchiveRedactionRule]) -> Result<Self, String> {
        let rules = rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                Regex::new(&rule.pattern)
                    .map(|regex| CompiledRule {
                        name: sanitize_label(&rule.name),
                        regex,
                    })
                    .map_err(|e| format!("脱敏规则“{}”无效: {e}", rule.name))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules })
    }

    pub fn redact_json(&self, value: &mut Value) -> Vec<NormalizedAttachment> {
        let mut attachments = Vec::new();
        self.redact_value(None, value, &mut attachments);
        attachments
    }

    pub fn redact_text(&self, input: &str) -> String {
        let mut output = PEM_RE
            .replace_all(input, "[REDACTED:PRIVATE_KEY]")
            .into_owned();
        output = JWT_RE.replace_all(&output, "[REDACTED:JWT]").into_owned();
        output = BEARER_RE
            .replace_all(&output, "Bearer [REDACTED:AUTHORIZATION]")
            .into_owned();
        output = HEADER_CREDENTIAL_RE
            .replace_all(&output, |captures: &Captures<'_>| {
                let name = captures.get(1).map_or("credential", |value| value.as_str());
                let kind = if name.to_ascii_lowercase().contains("cookie") {
                    "COOKIE"
                } else if name.to_ascii_lowercase().contains("authorization") {
                    "AUTHORIZATION"
                } else {
                    "API_KEY"
                };
                format!("{name}: [REDACTED:{kind}]")
            })
            .into_owned();
        output = API_KEY_RE
            .replace_all(&output, "[REDACTED:API_KEY]")
            .into_owned();
        output = PASSWORD_ASSIGNMENT_RE
            .replace_all(&output, |captures: &Captures<'_>| {
                format!("{}=[REDACTED:CREDENTIAL]", &captures[1])
            })
            .into_owned();
        output = URL_RE
            .replace_all(&output, |captures: &Captures<'_>| {
                redact_url(captures.get(0).map_or("", |value| value.as_str()))
            })
            .into_owned();
        for rule in &self.rules {
            let placeholder = format!("[REDACTED:CUSTOM:{}]", rule.name);
            output = rule.regex.replace_all(&output, placeholder).into_owned();
        }
        output
    }

    fn redact_value(
        &self,
        key: Option<&str>,
        value: &mut Value,
        attachments: &mut Vec<NormalizedAttachment>,
    ) {
        if key.is_some_and(is_sensitive_key) {
            *value = Value::String(sensitive_placeholder(key.unwrap_or_default()).to_string());
            return;
        }

        match value {
            Value::String(text) => {
                *text = self.redact_text(text);
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value(None, item, attachments);
                }
            }
            Value::Object(object) => {
                if is_attachment_object(object) {
                    if let Some(mut attachment) = sanitize_attachment_object(object) {
                        attachment.mime_type = attachment
                            .mime_type
                            .as_deref()
                            .map(|value| self.redact_text(value));
                        attachment.file_name = attachment
                            .file_name
                            .as_deref()
                            .map(|value| self.redact_text(value));
                        attachments.push(attachment);
                    }
                }
                for (child_key, child_value) in object.iter_mut() {
                    self.redact_value(Some(child_key), child_value, attachments);
                }
            }
            _ => {}
        }
    }
}

fn sanitize_label(value: &str) -> String {
    let label: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        .take(40)
        .collect();
    if label.is_empty() {
        "RULE".to_string()
    } else {
        label.to_ascii_uppercase()
    }
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "xapikey"
            | "apikey"
            | "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "clientsecret"
            | "privatekey"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "bearertoken"
            | "token"
            | "sessiontoken"
            | "secretaccesskey"
            | "awssecretaccesskey"
            | "credentials"
    ) || normalized.ends_with("apikey")
        || normalized.ends_with("password")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("idtoken")
        || normalized.ends_with("privatekey")
        || normalized.ends_with("clientsecret")
        || normalized.ends_with("secretaccesskey")
}

fn sensitive_placeholder(key: &str) -> &'static str {
    match normalize_key(key).as_str() {
        "authorization" | "proxyauthorization" | "bearertoken" => "[REDACTED:AUTHORIZATION]",
        "cookie" | "setcookie" => "[REDACTED:COOKIE]",
        "password" | "passwd" | "pwd" => "[REDACTED:PASSWORD]",
        "privatekey" => "[REDACTED:PRIVATE_KEY]",
        "accesstoken" | "refreshtoken" | "idtoken" | "token" => "[REDACTED:TOKEN]",
        _ => "[REDACTED:API_KEY]",
    }
}

fn redact_url(raw: &str) -> String {
    let Ok(parsed) = url::Url::parse(raw) else {
        return raw.to_string();
    };
    let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
    let has_query = parsed.query().is_some();
    if !has_credentials && !has_query {
        return raw.to_string();
    }
    let mut safe = format!("{}://", parsed.scheme());
    if let Some(host) = parsed.host_str() {
        safe.push_str(host);
    }
    if let Some(port) = parsed.port() {
        safe.push(':');
        safe.push_str(&port.to_string());
    }
    safe.push_str(parsed.path());
    if has_credentials || has_query {
        safe.push_str("?[REDACTED:URL_CREDENTIALS]");
    }
    safe
}

fn is_attachment_object(object: &Map<String, Value>) -> bool {
    let object_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        object_type.as_str(),
        "image"
            | "image_url"
            | "input_image"
            | "file"
            | "input_file"
            | "document"
            | "inline_data"
            | "audio"
            | "input_audio"
    ) || object.contains_key("inlineData")
        || object.contains_key("inline_data")
        || object.contains_key("fileData")
        || object.contains_key("file_data")
        || object.contains_key("input_audio")
        || (object.contains_key("data")
            && (object.contains_key("mime_type") || object.contains_key("mimeType")))
}

fn sanitize_attachment_object(object: &mut Map<String, Value>) -> Option<NormalizedAttachment> {
    let mime_type = object
        .get("mime_type")
        .or_else(|| object.get("mimeType"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            object
                .get("source")
                .and_then(Value::as_object)
                .and_then(|source| source.get("media_type"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            nested_string(
                object,
                &["inlineData", "inline_data"],
                &["mimeType", "mime_type"],
            )
        })
        .or_else(|| {
            nested_string(
                object,
                &["fileData", "file_data"],
                &["mimeType", "mime_type"],
            )
        })
        .or_else(|| {
            nested_string(
                object,
                &["input_audio"],
                &["mimeType", "mime_type", "format"],
            )
        });
    let file_name = object
        .get("filename")
        .or_else(|| object.get("file_name"))
        .or_else(|| object.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);

    if let Some(source) = object.get_mut("source").and_then(Value::as_object_mut) {
        if let Some(data) = source.get_mut("data") {
            return sanitize_binary_value(
                data,
                "inline_base64",
                mime_type.clone(),
                file_name.clone(),
            );
        }
        for key in ["url", "file_uri", "fileUri", "uri", "file_id", "fileId"] {
            if let Some(reference) = source.get_mut(key) {
                return sanitize_reference_value(
                    reference,
                    key,
                    mime_type.clone(),
                    file_name.clone(),
                );
            }
        }
    }
    for key in ["inlineData", "inline_data", "input_audio"] {
        if let Some(inline) = object.get_mut(key).and_then(Value::as_object_mut) {
            let nested_mime = inline
                .get("mimeType")
                .or_else(|| inline.get("mime_type"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| mime_type.clone());
            if let Some(data) = inline.get_mut("data") {
                return sanitize_binary_value(
                    data,
                    "inline_base64",
                    nested_mime,
                    file_name.clone(),
                );
            }
        }
    }
    for key in ["fileData", "file_data"] {
        if let Some(file_data) = object.get_mut(key).and_then(Value::as_object_mut) {
            if let Some(data) = file_data.get_mut("data") {
                return sanitize_binary_value(
                    data,
                    "inline_base64",
                    mime_type.clone(),
                    file_name.clone(),
                );
            }
            for reference_key in ["fileUri", "file_uri", "uri", "url", "fileId", "file_id"] {
                if let Some(reference) = file_data.get_mut(reference_key) {
                    return sanitize_reference_value(
                        reference,
                        reference_key,
                        mime_type.clone(),
                        file_name.clone(),
                    );
                }
            }
        }
    }
    for key in ["file_data", "data", "bytes", "blob", "content"] {
        if object.get(key).is_some_and(Value::is_string) {
            if let Some(data) = object.get_mut(key) {
                return sanitize_binary_value(
                    data,
                    "inline_base64",
                    mime_type.clone(),
                    file_name.clone(),
                );
            }
        }
    }
    for key in [
        "image_url",
        "file_url",
        "url",
        "uri",
        "file_uri",
        "fileUri",
        "file_id",
        "fileId",
    ] {
        if let Some(reference) = object.get_mut(key) {
            if let Some(attachment) =
                sanitize_reference_value(reference, key, mime_type.clone(), file_name.clone())
            {
                return Some(attachment);
            }
        }
    }
    None
}

fn nested_string(object: &Map<String, Value>, parents: &[&str], keys: &[&str]) -> Option<String> {
    parents.iter().find_map(|parent| {
        let nested = object.get(*parent)?.as_object()?;
        keys.iter()
            .find_map(|key| nested.get(*key).and_then(Value::as_str).map(str::to_string))
    })
}

fn sanitize_reference_value(
    value: &mut Value,
    key: &str,
    mime_type: Option<String>,
    file_name: Option<String>,
) -> Option<NormalizedAttachment> {
    if let Value::Object(map) = value {
        for nested_key in ["url", "uri", "file_uri", "fileUri", "file_id", "fileId"] {
            if let Some(nested) = map.get_mut(nested_key) {
                return sanitize_reference_value(nested, nested_key, mime_type, file_name);
            }
        }
        return None;
    }
    let raw = value.as_str()?.to_string();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("data:") {
        return sanitize_binary_value(value, "inline_base64", mime_type, file_name);
    }
    let sha256 = sha256_hex(raw.as_bytes());
    *value = Value::String(format!("[ATTACHMENT_REFERENCE:{sha256}]"));
    Some(NormalizedAttachment {
        reference_type: if matches!(key, "file_id" | "fileId") {
            "provider_file_id".to_string()
        } else {
            "remote_url".to_string()
        },
        mime_type,
        file_name,
        size_bytes: 0,
        sha256,
    })
}

fn sanitize_binary_value(
    value: &mut Value,
    reference_type: &str,
    mime_type: Option<String>,
    file_name: Option<String>,
) -> Option<NormalizedAttachment> {
    let raw = value.as_str()?.to_string();
    let (encoded, inferred_mime) = if let Some(rest) = raw.strip_prefix("data:") {
        match rest.split_once(",") {
            Some((meta, encoded)) => (
                encoded,
                meta.split(';')
                    .next()
                    .filter(|v| !v.is_empty())
                    .map(str::to_string),
            ),
            None => (raw.as_str(), None),
        }
    } else {
        (raw.as_str(), None)
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .unwrap_or_else(|_| encoded.as_bytes().to_vec());
    let sha256 = sha256_hex(&decoded);
    let size_bytes = decoded.len() as u64;
    *value = Value::String(format!("[ATTACHMENT:{sha256}]"));
    Some(NormalizedAttachment {
        reference_type: reference_type.to_string(),
        mime_type: mime_type.or(inferred_mime),
        file_name,
        size_bytes,
        sha256,
    })
}

pub fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn removes_structured_and_text_secrets() {
        let redactor = Redactor::default();
        let mut value = json!({
            "authorization": "Bearer secret-token-value",
            "message": "password=hunter2 sk-example123456789012345 https://alice:pw@example.com/a?token=x postgres://dbuser:dbpass@db.example/app\nCookie: session=never-store-this\nAuthorization: Basic never-store-that"
        });
        redactor.redact_json(&mut value);
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("hunter2"));
        assert!(!encoded.contains("example123"));
        assert!(!encoded.contains("alice"));
        assert!(!encoded.contains("dbpass"));
        assert!(!encoded.contains("never-store"));
        assert!(!encoded.contains("secret-token"));
    }

    #[test]
    fn replaces_inline_attachment_and_keeps_only_metadata() {
        let redactor = Redactor::default();
        let mut value = json!({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "aGVsbG8="}
        });
        let attachments = redactor.redact_json(&mut value);
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].size_bytes, 5);
        assert!(!serde_json::to_string(&value).unwrap().contains("aGVsbG8"));
    }

    #[test]
    fn removes_nested_gemini_file_reference_and_common_secret_fields() {
        let redactor = Redactor::default();
        let mut value = json!({
            "parts": [{
                "fileData": {
                    "mimeType": "application/pdf",
                    "fileUri": "https://files.example/private/report.pdf?signature=secret"
                }
            }],
            "awsSecretAccessKey": "should-never-be-stored",
            "serviceApiKey": "also-never-stored"
        });
        let attachments = redactor.redact_json(&mut value);
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].reference_type, "remote_url");
        assert_eq!(attachments[0].mime_type.as_deref(), Some("application/pdf"));
        assert!(!encoded.contains("report.pdf"));
        assert!(!encoded.contains("should-never"));
        assert!(!encoded.contains("also-never"));
    }
}
