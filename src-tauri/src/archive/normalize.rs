use super::redaction::Redactor;
use super::types::{NormalizedAttachment, NormalizedMessage, NormalizedRequest};
use serde_json::{json, Value};

pub fn normalize_request(
    path: &str,
    raw_payload: &Value,
    redactor: &Redactor,
) -> Result<NormalizedRequest, String> {
    let provider = provider_from_path(path);
    let mut redacted_payload = raw_payload.clone();
    let attachments = redactor.redact_json(&mut redacted_payload);
    let model = redacted_payload
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| model_from_gemini_path(path))
        .map(|value| redactor.redact_text(&value));
    let stream = redacted_payload
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| path.contains("streamGenerateContent"));

    let mut messages = match provider.as_str() {
        "claude" => normalize_claude_request(&redacted_payload),
        "openai_chat" => normalize_openai_chat_request(&redacted_payload),
        "openai_responses" => normalize_openai_responses_request(&redacted_payload),
        "gemini" => normalize_gemini_request(&redacted_payload),
        _ => Vec::new(),
    };
    associate_attachments(&mut messages, attachments);
    if messages.is_empty() {
        messages.push(NormalizedMessage {
            role: "user".to_string(),
            content: compact_json(&redacted_payload),
            created_at: None,
            metadata: json!({"normalization": "fallback"}),
            attachments: Vec::new(),
        });
    }

    Ok(NormalizedRequest {
        provider,
        model,
        stream,
        redacted_payload,
        messages,
    })
}

pub fn normalize_response(
    provider: &str,
    raw_payload: &Value,
    redactor: &Redactor,
) -> (Value, Vec<NormalizedMessage>) {
    let mut redacted_payload = raw_payload.clone();
    let attachments = redactor.redact_json(&mut redacted_payload);
    let mut messages = match provider {
        "claude" => normalize_claude_response(&redacted_payload),
        "openai_chat" => normalize_openai_chat_response(&redacted_payload),
        "openai_responses" => normalize_openai_responses_response(&redacted_payload),
        "gemini" => normalize_gemini_response(&redacted_payload),
        _ => Vec::new(),
    };
    associate_attachments(&mut messages, attachments);
    (redacted_payload, messages)
}

pub fn provider_from_path(path: &str) -> String {
    if path.contains("chat/completions") {
        "openai_chat".to_string()
    } else if path.contains("responses") {
        "openai_responses".to_string()
    } else if path.contains("generateContent") || path.contains("v1beta/models") {
        "gemini".to_string()
    } else if path.contains("messages") {
        "claude".to_string()
    } else {
        "unknown".to_string()
    }
}

fn model_from_gemini_path(path: &str) -> Option<String> {
    let marker = "/models/";
    let start = path.find(marker)? + marker.len();
    let value = path[start..]
        .split([':', '?', '/'])
        .next()
        .unwrap_or_default();
    (!value.is_empty()).then(|| value.to_string())
}

fn normalize_claude_request(payload: &Value) -> Vec<NormalizedMessage> {
    let mut messages = Vec::new();
    if let Some(system) = payload.get("system") {
        push_message(&mut messages, "system", system, json!({}));
    }
    if let Some(items) = payload.get("messages").and_then(Value::as_array) {
        for item in items {
            let role = item
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let content = item.get("content").unwrap_or(&Value::Null);
            push_message(&mut messages, role, content, message_metadata(item));
        }
    }
    messages
}

fn normalize_claude_response(payload: &Value) -> Vec<NormalizedMessage> {
    let role = payload
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("assistant");
    payload
        .get("content")
        .map(|content| {
            vec![message(
                role,
                extract_content(content),
                json!({"stopReason": payload.get("stop_reason"), "usage": payload.get("usage")}),
            )]
        })
        .unwrap_or_default()
}

fn normalize_openai_chat_request(payload: &Value) -> Vec<NormalizedMessage> {
    payload
        .get("messages")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let role = item.get("role").and_then(Value::as_str)?;
                    let mut content = extract_content(item.get("content").unwrap_or(&Value::Null));
                    if let Some(calls) = item.get("tool_calls") {
                        append_section(&mut content, &extract_content(calls));
                    }
                    Some(message(role, content, message_metadata(item)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_openai_chat_response(payload: &Value) -> Vec<NormalizedMessage> {
    payload
        .get("choices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|choice| choice.get("message"))
        .map(|item| {
            let role = item
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("assistant");
            let mut content = extract_content(item.get("content").unwrap_or(&Value::Null));
            if let Some(calls) = item.get("tool_calls") {
                append_section(&mut content, &extract_content(calls));
            }
            let mut metadata = message_metadata(item);
            if let Some(usage) = payload.get("usage") {
                metadata["usage"] = usage.clone();
            }
            message(role, content, metadata)
        })
        .collect()
}

fn normalize_openai_responses_request(payload: &Value) -> Vec<NormalizedMessage> {
    let mut messages = Vec::new();
    if let Some(instructions) = payload.get("instructions") {
        push_message(&mut messages, "system", instructions, json!({}));
    }
    let Some(input) = payload.get("input") else {
        return messages;
    };
    match input {
        Value::String(_) | Value::Object(_) => {
            if input.is_object() {
                push_responses_item(&mut messages, input);
            } else {
                push_message(&mut messages, "user", input, json!({}));
            }
        }
        Value::Array(items) => {
            for item in items {
                push_responses_item(&mut messages, item);
            }
        }
        _ => {}
    }
    messages
}

fn normalize_openai_responses_response(payload: &Value) -> Vec<NormalizedMessage> {
    let mut messages = Vec::new();
    if let Some(output) = payload.get("output").and_then(Value::as_array) {
        for item in output {
            push_responses_item(&mut messages, item);
        }
    } else if let Some(text) = payload.get("output_text") {
        push_message(&mut messages, "assistant", text, json!({}));
    }
    for item in &mut messages {
        if item.role == "unknown" {
            item.role = "assistant".to_string();
        }
        if let Some(usage) = payload.get("usage") {
            item.metadata["usage"] = usage.clone();
        }
    }
    messages
}

fn push_responses_item(messages: &mut Vec<NormalizedMessage>, item: &Value) {
    let item_type = item
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("message");
    let role = match item_type {
        "function_call_output" | "computer_call_output" => "tool",
        "function_call" | "computer_call" | "reasoning" => "assistant",
        _ => item
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    };
    let content_value = item
        .get("content")
        .or_else(|| item.get("output"))
        .unwrap_or(item);
    push_message(messages, role, content_value, message_metadata(item));
}

fn normalize_gemini_request(payload: &Value) -> Vec<NormalizedMessage> {
    let mut messages = Vec::new();
    if let Some(system) = payload
        .get("systemInstruction")
        .or_else(|| payload.get("system_instruction"))
    {
        push_message(&mut messages, "system", system, json!({}));
    }
    if let Some(contents) = payload.get("contents").and_then(Value::as_array) {
        for item in contents {
            let role = gemini_role(item.get("role").and_then(Value::as_str).unwrap_or("user"));
            push_message(
                &mut messages,
                role,
                item.get("parts").unwrap_or(item),
                message_metadata(item),
            );
        }
    }
    messages
}

fn normalize_gemini_response(payload: &Value) -> Vec<NormalizedMessage> {
    payload
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|candidate| candidate.get("content"))
        .map(|content| {
            let mut metadata = message_metadata(content);
            if let Some(usage) = payload.get("usageMetadata") {
                metadata["usage"] = usage.clone();
            }
            message(
                "assistant",
                extract_content(content.get("parts").unwrap_or(content)),
                metadata,
            )
        })
        .collect()
}

fn gemini_role(role: &str) -> &str {
    match role {
        "model" => "assistant",
        "function" => "tool",
        other => other,
    }
}

fn push_message(messages: &mut Vec<NormalizedMessage>, role: &str, value: &Value, metadata: Value) {
    let content = extract_content(value);
    if !content.trim().is_empty() {
        messages.push(message(role, content, metadata));
    }
}

fn message(role: &str, content: String, metadata: Value) -> NormalizedMessage {
    NormalizedMessage {
        role: normalize_role(role).to_string(),
        content,
        created_at: None,
        metadata,
        attachments: Vec::new(),
    }
}

fn normalize_role(role: &str) -> &str {
    match role.to_ascii_lowercase().as_str() {
        "developer" | "system" => "system",
        "user" | "human" => "user",
        "assistant" | "model" => "assistant",
        "tool" | "function" => "tool",
        _ => "unknown",
    }
}

fn message_metadata(item: &Value) -> Value {
    let mut metadata = serde_json::Map::new();
    for key in [
        "id",
        "type",
        "name",
        "tool_call_id",
        "call_id",
        "status",
        "finish_reason",
        "finishReason",
    ] {
        if let Some(value) = item.get(key) {
            metadata.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(metadata)
}

pub fn extract_content(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        Value::Array(items) => items
            .iter()
            .map(extract_content)
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(object) => {
            let item_type = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match item_type {
                "tool_use" | "function_call" => {
                    let name = object
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let arguments = object
                        .get("input")
                        .or_else(|| object.get("arguments"))
                        .map(compact_json)
                        .unwrap_or_default();
                    format!("[Tool call: {name}]\n{arguments}")
                }
                "tool_result" | "function_call_output" | "functionResponse" => {
                    let result = object
                        .get("content")
                        .or_else(|| object.get("output"))
                        .or_else(|| object.get("response"))
                        .map(extract_content)
                        .unwrap_or_default();
                    format!("[Tool result]\n{result}")
                }
                "image" | "image_url" | "input_image" | "file" | "input_file" | "document"
                | "inline_data" => attachment_marker(value),
                _ => {
                    for key in [
                        "text",
                        "input_text",
                        "output_text",
                        "content",
                        "parts",
                        "delta",
                        "summary",
                    ] {
                        if let Some(child) = object.get(key) {
                            let text = extract_content(child);
                            if !text.trim().is_empty() {
                                return text;
                            }
                        }
                    }
                    if object.contains_key("functionCall") {
                        return extract_content(&object["functionCall"]);
                    }
                    if object.contains_key("functionResponse") {
                        return extract_content(&object["functionResponse"]);
                    }
                    compact_json(value)
                }
            }
        }
    }
}

fn attachment_marker(value: &Value) -> String {
    let serialized = compact_json(value);
    if let Some(start) = serialized.find("[ATTACHMENT") {
        let end = serialized[start..]
            .find(']')
            .map(|offset| start + offset + 1)
            .unwrap_or(serialized.len());
        return serialized[start..end].to_string();
    }
    "[Attachment]".to_string()
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn append_section(target: &mut String, section: &str) {
    if section.trim().is_empty() {
        return;
    }
    if !target.is_empty() {
        target.push('\n');
    }
    target.push_str(section);
}

fn associate_attachments(
    messages: &mut [NormalizedMessage],
    attachments: Vec<NormalizedAttachment>,
) {
    for attachment in attachments {
        let index = messages
            .iter()
            .position(|message| message.content.contains(&attachment.sha256))
            .or_else(|| messages.iter().rposition(|message| message.role == "user"))
            .unwrap_or(0);
        if let Some(message) = messages.get_mut(index) {
            message.attachments.push(attachment);
        }
    }
}

/// Extract a redacted semantic delta from one SSE data payload.
pub fn extract_stream_event_text(provider: &str, payload: &Value) -> String {
    match provider {
        "claude" => {
            if payload
                .pointer("/content_block/type")
                .and_then(Value::as_str)
                == Some("tool_use")
            {
                let name = payload
                    .pointer("/content_block/name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                return format!("\n[Tool call: {name}]\n");
            }
            payload
                .pointer("/delta/text")
                .or_else(|| payload.pointer("/delta/thinking"))
                .or_else(|| payload.pointer("/delta/partial_json"))
                .or_else(|| payload.pointer("/content_block/text"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        }
        "openai_chat" => payload
            .pointer("/choices/0/delta/content")
            .or_else(|| payload.pointer("/choices/0/text"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                payload
                    .pointer("/choices/0/delta/tool_calls")
                    .map(|calls| format!("\n[Tool call delta]\n{}", compact_json(calls)))
            })
            .unwrap_or_default(),
        "openai_responses" => {
            let event_type = payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let delta = payload
                .get("delta")
                .and_then(Value::as_str)
                .or_else(|| {
                    payload
                        .pointer("/response/output_text")
                        .and_then(Value::as_str)
                })
                .unwrap_or_default();
            if event_type.contains("function_call") && !delta.is_empty() {
                format!("\n[Tool call delta]\n{delta}")
            } else {
                delta.to_string()
            }
        }
        "gemini" => payload
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                payload
                    .pointer("/candidates/0/content/parts/0/functionCall")
                    .map(|call| format!("\n[Tool call]\n{}", compact_json(call)))
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_all_supported_request_shapes() {
        let redactor = Redactor::default();
        let cases = [
            (
                "/v1/messages",
                json!({"messages":[{"role":"user","content":"hello"}]}),
            ),
            (
                "/v1/chat/completions",
                json!({"messages":[{"role":"user","content":"hello"}]}),
            ),
            (
                "/v1/responses",
                json!({"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}),
            ),
            (
                "/v1beta/models/gemini:generateContent",
                json!({"contents":[{"role":"user","parts":[{"text":"hello"}]}]}),
            ),
        ];
        for (path, payload) in cases {
            let normalized = normalize_request(path, &payload, &redactor).unwrap();
            assert_eq!(normalized.messages[0].role, "user");
            assert!(normalized.messages[0].content.contains("hello"));
        }
    }
}
