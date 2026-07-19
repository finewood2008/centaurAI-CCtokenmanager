# TokenManager 本机会话适配器

TokenManager 内置 Claude、Codex、Gemini、OpenCode、OpenClaw 和 Hermes 会话解析器。其他 Agent 可以通过本地进程适配器接入，无需重新编译 TokenManager。

## 安装

将一个 JSON 清单放到应用配置目录的 `session-adapters/` 下。适配器会以当前桌面用户权限执行，因此只安装可信程序。

```json
{
  "schemaVersion": 1,
  "id": "my-agent",
  "displayName": "My Agent",
  "command": "/absolute/path/to/my-agent-adapter",
  "args": [],
  "enabled": true,
  "capabilities": ["scan", "load"],
  "watchPaths": ["~/.my-agent/sessions"],
  "timeoutSeconds": 30
}
```

`command` 必须是存在的绝对文件路径。可选能力为 `delete` 和 `resume`。未声明 `delete` 的适配器永远不会被 TokenManager 用来删除来源数据。

## JSON 协议

TokenManager 每次调用启动一次进程，并向标准输入写入一个 JSON 对象：

```json
{
  "protocolVersion": 1,
  "requestId": "uuid",
  "method": "scan",
  "params": {}
}
```

适配器必须在标准输出返回且只返回一个响应对象：

```json
{
  "protocolVersion": 1,
  "requestId": "原样返回请求 ID",
  "ok": true,
  "result": {
    "sessions": [
      {
        "providerId": "ignored",
        "sessionId": "stable-session-id",
        "title": "Conversation title",
        "summary": "Optional summary",
        "projectDir": "/project",
        "createdAt": 1770000000000,
        "lastActiveAt": 1770000005000,
        "sourcePath": "opaque-source-reference",
        "resumeCommand": "my-agent resume stable-session-id"
      }
    ]
  }
}
```

- `scan` 返回 `result.sessions`。
- `load` 接收 `params.sourceRef`，返回 `result.messages`；消息格式为 `{"role":"user","content":"...","ts":1770000000000}`。
- `delete` 接收 `params.sessionId` 和 `params.sourceRef`，返回 `result.deleted`。
- 失败响应使用 `{"ok":false,"error":"安全的错误说明"}`。

单次输出上限为 50 MB，默认超时 30 秒。标准错误只用于诊断，TokenManager 会限制写入日志的长度。

## 私人记忆 API

在“设置 → 对话归档 → 本地 Agent 对话接入”启用本机 API 后，服务固定监听 `http://127.0.0.1:15722`。除 `/v1/health` 外必须提供 `Authorization: Bearer <token>`；会话与记忆端点保持只读，身份写入能力由独立开关控制。

API 只返回 `local_history` 和 `local_proxy`，不会返回团队网关会话、原始来源路径、归档密钥或附件正文。
