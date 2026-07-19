use super::database::ArchiveDatabase;
use super::normalize::{extract_stream_event_text, normalize_request, normalize_response};
use super::redaction::Redactor;
use super::types::CaptureHandle;
use crate::proxy::server::ProxyState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;

const CONVERSATION_HEADER: &str = "x-tokenmanager-conversation-id";
const MAX_ARCHIVE_BODY_BYTES: usize = 200 * 1024 * 1024;

pub async fn local_archive_middleware(
    State(state): State<ProxyState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.archive.is_enabled() || !is_capture_path(request.uri().path(), request.method()) {
        return next.run(request).await;
    }
    let database = match state.archive.ensure_local_ready() {
        Ok(database) => database,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_unavailable",
                &error,
            )
        }
    };
    let identity = match state.archive.local_identity() {
        Ok(identity) => identity,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_unavailable",
                &error,
            )
        }
    };
    let redactor = match state.archive.redactor() {
        Ok(redactor) => redactor,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_unavailable",
                &error,
            )
        }
    };
    let path = request.uri().path().to_string();
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_ARCHIVE_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return archive_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "请求体无效或超过 200 MiB",
            )
        }
    };
    let raw_payload: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(_) => {
            return archive_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "归档代理请求体必须是 JSON",
            )
        }
    };
    let normalized = match normalize_request(&path, &raw_payload, &redactor) {
        Ok(normalized) => normalized,
        Err(error) => return archive_error(StatusCode::BAD_REQUEST, "invalid_request", &error),
    };
    let external_conversation_id = if parts.headers.contains_key(CONVERSATION_HEADER) {
        match conversation_id(&parts.headers) {
            Ok(value) => value,
            Err(error) => return archive_error(StatusCode::BAD_REQUEST, "invalid_request", &error),
        }
    } else {
        let client_format = match normalized.provider.as_str() {
            "claude" => "claude",
            "openai_chat" => "openai",
            "openai_responses" => "codex",
            "gemini" => "gemini",
            _ => "unknown",
        };
        let extracted =
            crate::proxy::extract_session_id(&parts.headers, &raw_payload, client_format);
        if extracted.client_provided {
            extracted.session_id
        } else {
            let first_user = normalized
                .messages
                .iter()
                .find(|message| message.role == "user")
                .map(|message| message.content.as_str())
                .unwrap_or(&extracted.session_id);
            let digest = super::redaction::sha256_hex(
                format!(
                    "{}\u{1f}{}\u{1f}{}",
                    normalized.provider,
                    normalized.model.as_deref().unwrap_or_default(),
                    first_user
                )
                .as_bytes(),
            );
            format!("local-{}", &digest[..32])
        }
    };
    let capture = match database.capture_request(
        &identity,
        &external_conversation_id,
        "local_proxy",
        &normalized,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_write_failed",
                &error,
            )
        }
    };
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = next.run(request).await;
    let is_stream = normalized.stream
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"));
    if is_stream {
        if let Err(error) = database.begin_stream_response(&capture, response.status().as_u16()) {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_write_failed",
                &error,
            );
        }
        wrap_streaming_response(response, database, capture, redactor)
    } else {
        persist_non_stream_response(response, database, capture, redactor).await
    }
}

pub async fn team_archive_middleware(
    State(state): State<ProxyState>,
    mut request: Request,
    next: Next,
) -> Response {
    let bearer = match extract_bearer(request.headers()) {
        Ok(value) => value,
        Err(error) => {
            return archive_error(StatusCode::UNAUTHORIZED, "authentication_error", &error)
        }
    };
    if !state.archive.is_enabled() {
        return archive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "archive_unavailable",
            "团队对话归档尚未启用",
        );
    }
    let mut identity = match state.archive.validate_token(&bearer).await {
        Ok(identity) => identity,
        Err(error) => {
            return archive_error(StatusCode::UNAUTHORIZED, "authentication_error", &error)
        }
    };

    let path = request.uri().path().to_string();
    if !is_capture_path(&path, request.method()) {
        strip_team_credentials(request.headers_mut());
        strip_sensitive_query(request.uri_mut());
        return next.run(request).await;
    }
    let conversation_id = match conversation_id(request.headers()) {
        Ok(value) => value,
        Err(error) => return archive_error(StatusCode::BAD_REQUEST, "invalid_request", &error),
    };
    let database = match state.archive.ensure_team_ready() {
        Ok(database) => database,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_unavailable",
                &error,
            )
        }
    };
    let redactor = match state.archive.redactor() {
        Ok(redactor) => redactor,
        Err(error) => {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_unavailable",
                &error,
            )
        }
    };
    identity.name = identity.name.map(|value| redactor.redact_text(&value));
    identity.email = identity.email.map(|value| redactor.redact_text(&value));
    identity.organization = identity
        .organization
        .map(|value| redactor.redact_text(&value));

    let (mut parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_ARCHIVE_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return archive_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "请求体无效或超过 200 MiB",
            )
        }
    };
    let raw_payload: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(_) => {
            return archive_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "团队网关请求体必须是 JSON",
            )
        }
    };
    let normalized = match normalize_request(&path, &raw_payload, &redactor) {
        Ok(normalized) => normalized,
        Err(error) => return archive_error(StatusCode::BAD_REQUEST, "invalid_request", &error),
    };
    let capture =
        match database.capture_request(&identity, &conversation_id, "team_gateway", &normalized) {
            Ok(capture) => capture,
            Err(error) => {
                return archive_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "archive_write_failed",
                    &error,
                )
            }
        };

    strip_team_credentials(&mut parts.headers);
    strip_sensitive_query(&mut parts.uri);
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = next.run(request).await;
    let is_stream = normalized.stream
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"));
    if is_stream {
        if let Err(error) = database.begin_stream_response(&capture, response.status().as_u16()) {
            return archive_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "archive_write_failed",
                &error,
            );
        }
        wrap_streaming_response(response, database, capture, redactor)
    } else {
        persist_non_stream_response(response, database, capture, redactor).await
    }
}

fn is_capture_path(path: &str, method: &axum::http::Method) -> bool {
    if method != axum::http::Method::POST {
        return false;
    }
    path.contains("messages")
        || path.contains("chat/completions")
        || path.contains("responses")
        || path.contains("generateContent")
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "缺少 Authorization: Bearer <JWT>".to_string())?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| "Authorization 必须使用 Bearer JWT".to_string())?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err("Authorization 必须使用 Bearer JWT".to_string());
    }
    Ok(token.trim().to_string())
}

fn conversation_id(headers: &HeaderMap) -> Result<String, String> {
    let value = headers
        .get(CONVERSATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("缺少 {CONVERSATION_HEADER} 请求头"))?;
    if value.chars().count() > 256 || value.chars().any(char::is_control) {
        return Err(format!("{CONVERSATION_HEADER} 格式无效"));
    }
    Ok(value.to_string())
}

fn strip_team_credentials(headers: &mut HeaderMap) {
    let sensitive_names = headers
        .keys()
        .filter(|name| is_sensitive_header(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for name in sensitive_names {
        headers.remove(name);
    }
    headers.remove(CONVERSATION_HEADER);
}

fn is_sensitive_header(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "apikey"
            | "xapikey"
            | "xgoogapikey"
            | "xaccesstoken"
            | "xauthtoken"
            | "xsecuritytoken"
            | "xamzsecuritytoken"
    ) || normalized.ends_with("authorization")
        || normalized.ends_with("apikey")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("authtoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("idtoken")
        || normalized.ends_with("privatekey")
        || normalized.ends_with("clientsecret")
        || normalized.ends_with("secretaccesskey")
        || normalized.ends_with("credential")
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
}

fn strip_sensitive_query(uri: &mut axum::http::Uri) {
    let Some(query) = uri.query() else {
        return;
    };
    let retained = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| {
            let normalized = key
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            !matches!(
                normalized.as_str(),
                "key"
                    | "apikey"
                    | "token"
                    | "accesstoken"
                    | "authtoken"
                    | "refreshtoken"
                    | "idtoken"
                    | "bearertoken"
                    | "authorization"
                    | "auth"
                    | "password"
                    | "secret"
                    | "clientsecret"
                    | "credential"
                    | "credentials"
                    | "sig"
                    | "signature"
            ) && !normalized.ends_with("apikey")
                && !normalized.ends_with("accesstoken")
                && !normalized.ends_with("authtoken")
                && !normalized.ends_with("refreshtoken")
                && !normalized.ends_with("idtoken")
                && !normalized.ends_with("securitytoken")
                && !normalized.ends_with("credential")
                && !normalized.ends_with("signature")
        })
        .collect::<Vec<_>>();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(retained);
    let query = serializer.finish();
    let path_and_query = if query.is_empty() {
        uri.path().to_string()
    } else {
        format!("{}?{query}", uri.path())
    };
    let Ok(path_and_query) = path_and_query.parse() else {
        return;
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    if let Ok(sanitized) = axum::http::Uri::from_parts(parts) {
        *uri = sanitized;
    }
}

async fn persist_non_stream_response(
    response: Response,
    database: Arc<ArchiveDatabase>,
    capture: CaptureHandle,
    redactor: Redactor,
) -> Response {
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_ARCHIVE_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = database.finalize_stream(&capture, Some("upstream_body_error"));
            return archive_error(
                StatusCode::BAD_GATEWAY,
                "upstream_body_error",
                "读取上游响应失败",
            );
        }
    };
    let raw_payload = serde_json::from_slice::<Value>(&body_bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body_bytes).to_string()));
    let (redacted_payload, messages) =
        normalize_response(&capture.provider, &raw_payload, &redactor);
    if let Err(error) = database.capture_non_stream_response(
        &capture,
        parts.status.as_u16(),
        &redacted_payload,
        &messages,
    ) {
        return archive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "archive_write_failed",
            &error,
        );
    }
    super::ArchiveService::new().notify_local_backup_changed();
    Response::from_parts(parts, Body::from(body_bytes))
}

fn wrap_streaming_response(
    response: Response,
    database: Arc<ArchiveDatabase>,
    capture: CaptureHandle,
    redactor: Redactor,
) -> Response {
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    let mut upstream = body.into_data_stream();
    let stream = async_stream::stream! {
        let mut pending = Vec::<u8>::new();
        let mut guard = StreamFinalizeGuard::new(database.clone(), capture.clone());
        while let Some(chunk) = upstream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    let _ = guard.finish(Some("upstream_stream_error"));
                    yield Err::<Bytes, std::io::Error>(std::io::Error::other("upstream stream error"));
                    return;
                }
            };
            pending.extend_from_slice(&chunk);
            while let Some(end) = next_sse_frame_end(&pending) {
                let frame = pending.drain(..end).collect::<Vec<_>>();
                if let Err(error) = persist_sse_frame(&database, &capture, &redactor, &frame) {
                    let _ = guard.finish(Some("capture_error"));
                    yield Err::<Bytes, std::io::Error>(std::io::Error::other(error));
                    return;
                }
                yield Ok::<Bytes, std::io::Error>(Bytes::from(frame));
            }
        }
        if !pending.is_empty() {
            if let Err(error) = persist_sse_frame(&database, &capture, &redactor, &pending) {
                let _ = guard.finish(Some("capture_error"));
                yield Err::<Bytes, std::io::Error>(std::io::Error::other(error));
                return;
            }
            yield Ok::<Bytes, std::io::Error>(Bytes::from(std::mem::take(&mut pending)));
        }
        if let Err(error) = guard.finish(None) {
            yield Err::<Bytes, std::io::Error>(std::io::Error::other(error));
        }
    };
    Response::from_parts(parts, Body::from_stream(stream))
}

fn next_sse_frame_end(bytes: &[u8]) -> Option<usize> {
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4);
    let lf = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2);
    match (crlf, lf) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn persist_sse_frame(
    database: &ArchiveDatabase,
    capture: &CaptureHandle,
    redactor: &Redactor,
    frame: &[u8],
) -> Result<(), String> {
    let text = String::from_utf8_lossy(frame);
    let mut event_type = None;
    let mut data_lines = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_type = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start().to_string());
        }
    }
    let data = data_lines.join("\n");
    if data.is_empty() && event_type.is_none() {
        return database.record_stream_event(capture, Some("comment"), "", "");
    }
    let (redacted_payload, delta) = match serde_json::from_str::<Value>(&data) {
        Ok(mut payload) => {
            redactor.redact_json(&mut payload);
            let delta = extract_stream_event_text(&capture.provider, &payload);
            (
                serde_json::to_string(&payload).map_err(|_| "序列化脱敏流事件失败".to_string())?,
                delta,
            )
        }
        Err(_) => (redactor.redact_text(&data), String::new()),
    };
    database.record_stream_event(capture, event_type.as_deref(), &redacted_payload, &delta)
}

struct StreamFinalizeGuard {
    database: Arc<ArchiveDatabase>,
    capture: CaptureHandle,
    finished: bool,
}

impl StreamFinalizeGuard {
    fn new(database: Arc<ArchiveDatabase>, capture: CaptureHandle) -> Self {
        Self {
            database,
            capture,
            finished: false,
        }
    }

    fn finish(&mut self, reason: Option<&str>) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        let result = self.database.finalize_stream(&self.capture, reason);
        self.finished = true;
        if result.is_ok() {
            super::ArchiveService::new().notify_local_backup_changed();
        }
        result
    }
}

impl Drop for StreamFinalizeGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(Some("client_disconnect"));
        }
    }
}

fn archive_error(status: StatusCode, error_type: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "error": {
                "type": error_type,
                "message": message,
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_lf_and_crlf_sse_events() {
        assert_eq!(next_sse_frame_end(b"data: {}\n\nrest"), Some(10));
        assert_eq!(next_sse_frame_end(b"data: {}\r\n\r\nrest"), Some(12));
        assert_eq!(next_sse_frame_end(b"data: partial"), None);
        assert_eq!(
            next_sse_frame_end(b"data: first\n\ndata: second\r\n\r\n"),
            Some(13)
        );
    }

    #[test]
    fn requires_bearer_and_bounded_conversation_id() {
        let mut headers = HeaderMap::new();
        assert!(extract_bearer(&headers).is_err());
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(extract_bearer(&headers).is_err());
        headers.insert(
            header::AUTHORIZATION,
            "Bearer header.payload.signature".parse().unwrap(),
        );
        assert_eq!(
            extract_bearer(&headers).unwrap(),
            "header.payload.signature"
        );
        headers.insert(CONVERSATION_HEADER, "conversation-42".parse().unwrap());
        assert_eq!(conversation_id(&headers).unwrap(), "conversation-42");
        headers.insert(CONVERSATION_HEADER, "x".repeat(257).parse().unwrap());
        assert!(conversation_id(&headers).is_err());
    }

    #[test]
    fn strips_team_credentials_from_headers_and_query() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer jwt".parse().unwrap());
        headers.insert("x-custom-api-key", "secret".parse().unwrap());
        headers.insert("x-custom-secret", "secret".parse().unwrap());
        headers.insert("x-refresh-token", "token".parse().unwrap());
        headers.insert("anthropic-version", "2023-06-01".parse().unwrap());
        strip_team_credentials(&mut headers);
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert!(!headers.contains_key("x-custom-api-key"));
        assert!(!headers.contains_key("x-custom-secret"));
        assert!(!headers.contains_key("x-refresh-token"));
        assert!(headers.contains_key("anthropic-version"));

        let mut uri: axum::http::Uri = "/v1beta/models/gemini:generateContent?key=secret&X-Amz-Credential=id&X-Amz-Signature=sig&pageToken=next&alt=sse"
            .parse()
            .unwrap();
        strip_sensitive_query(&mut uri);
        assert_eq!(
            uri.path_and_query().unwrap().as_str(),
            "/v1beta/models/gemini:generateContent?pageToken=next&alt=sse"
        );
    }
}
