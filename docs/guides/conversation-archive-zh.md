# TokenManager 多用户对话归档部署指南

对话归档默认关闭。启用后，TokenManager 会把经过代理的 Claude Messages、OpenAI Chat Completions、OpenAI Responses 和 Gemini Contents 请求统一归档到独立 SQLCipher 数据库，并提供管理员本机全文检索、查看、导出和永久删除能力。

## 安全边界

- 团队客户端只使用 `/team` 命名空间；所有 `/team` 请求都必须携带有效 OIDC JWT。
- `/team` 下的生成请求还必须携带稳定的 `X-TokenManager-Conversation-Id`。
- `/health` 是唯一允许公开匿名访问的端点，只返回存活状态与时间。
- 管理员页面和归档 Tauri 命令仅在本机桌面应用中提供，不对团队 HTTP 客户端开放。
- 公网部署必须由 HTTPS 反向代理终止 TLS，并且只转发 `/team` 和 `/health`。不要公开本地兼容路由或 `/status`。
- 开启归档后，请求只有在脱敏内容成功提交到 SQLCipher 后才会访问上游。归档不可用时返回 `503`。
- 归档数据库和自动恢复快照默认只保存在本机；普通 S3/WebDAV 自动同步不会包含归档数据。

## 1. 推荐：一键初始化

先配置 OIDC/JWKS，然后在“设置 → 对话归档”点击“一键初始化并启用”。S3 或 WebDAV 不是归档启用条件。初始化会按顺序完成：

1. 以关闭状态保存当前归档草稿，避免未完成配置时开始接收团队流量；
2. 选择或生成 SQLCipher 密钥，并创建、校验归档数据库和 FTS5 索引；
3. 编译自定义脱敏规则并实时访问 JWKS；
4. 所有检查成功后才开启归档。

该操作可以安全重复执行，不会返回或显示密钥正文。某个必需步骤失败时，已经安全完成的本地初始化会保留，但归档仍保持关闭；修正页面提示的 OIDC 或脱敏配置后再次点击即可。默认同时尝试创建首个本地恢复快照；快照失败只显示警告，不会阻止归档启用，也不会上传任何数据。

OIDC issuer、audience 和 JWKS 地址属于部署环境，不能提供通用安全默认值。一键初始化会复用管理员已经填写的值，而不会猜测或内置这些凭据。

## 2. SQLCipher 密钥来源

首次一键初始化时，如果既没有环境变量，也没有现有归档数据库，TokenManager 会生成 Base64 编码的 32 字节随机密钥，原子写入应用配置目录中的 `secrets/conversation-archive.key`。Unix 系统上密钥目录权限为 `0700`、文件权限为 `0600`；不安全的权限、符号链接或格式错误都会使初始化失败。

生产部署也可以通过进程环境提供密钥：

生成 Base64 编码的 32 字节随机密钥：

```bash
openssl rand -base64 32
```

在启动 TokenManager 的进程环境中设置：

```bash
export TOKEN_MANAGER_ARCHIVE_KEY='生成的 Base64 值'
```

密钥选择遵循以下严格规则：

- `TOKEN_MANAGER_ARCHIVE_KEY` 一旦存在就具有最高优先级；格式错误时直接失败，绝不会悄悄回退到托管密钥文件；
- 没有环境变量时才读取托管密钥文件；
- 已存在 `conversation-archive.db`、但两个来源都没有可用密钥时，初始化会拒绝生成新密钥，以免把旧归档误判为可恢复；
- 环境变量与托管文件切换前，必须确认它们是同一把密钥。

密钥不会写入常规设置、日志、导出文件、远端归档快照或远端清单。一键初始化生成的托管文件是本机密钥副本。默认的本地恢复快照会包含一份恢复密钥，以便在本机完成数据库与密钥的一致恢复；因此取得快照目录即可能读取归档内容，必须按敏感数据保护整个目录。

健康状态会显示正在使用的密钥来源，但不会显示密钥路径或密钥值。若使用托管密钥，可直接备份该文件并保留其受限权限；不要把内容粘贴到工单、聊天或普通文档。

归档文件位于 TokenManager 配置目录下的 `conversation-archive.db`，Unix 系统权限设为 `0600`。现有 TokenManager 配置数据库仍是普通 SQLite。

## 3. 本地恢复快照

归档自动快照默认启用，并使用以下安全默认值：

- 目录：应用配置目录下的 `archive-backups`；管理员可以改为其他本机绝对路径；
- 节流：归档发生变化后合并创建，默认两个自动快照之间至少间隔 15 分钟（可配置为 1–1440 分钟）；
- 保留：默认最多 30 份（可配置为 1–365 份），超出后删除最旧快照；
- 恢复密钥：默认随本地快照保存，使数据库与密钥可以作为一个恢复单元；
- Unix 权限：快照根目录及子目录为 `0700`，数据库、清单和密钥文件为 `0600`。

“应用只写本机”不等于所选目录不会被操作系统或第三方软件同步。不要把快照目录放在 OneDrive、iCloud、NAS 挂载点或其他自动同步目录中。

设置页可以列出、立即创建、恢复和删除本地快照。恢复前会验证快照校验和、恢复密钥、SQLCipher 密文完整性和 FTS 索引，再原子替换当前归档。恢复时如仍有代理请求持有归档数据库，操作会被拒绝；先停止代理后重试。

自动快照写入失败只会在归档健康状态中显示警告，并在后续归档变更时重试，不会中断正在进行的代理请求。该规则只适用于恢复快照：主归档数据库仍然 fail-closed，请求内容无法成功持久化时会返回 `503`，且不会调用上游。

### 可选的手动远端副本

普通 S3/WebDAV 自动同步只同步 TokenManager 的通用配置数据库，**永远不会自动包含对话归档**。管理员如确有跨设备恢复需求，可以在单次手动上传或恢复操作中勾选“包含/恢复对话归档”；该选项默认不勾选，并且每次操作都必须再次明确确认。

手动上传到 S3/WebDAV 的归档快照保持 SQLCipher 加密，但不包含解密密钥。远端恢复前必须先通过安全渠道在目标设备配置同一把密钥；远端存储不能替代密钥托管。完全不配置 S3/WebDAV 不影响归档初始化、采集、检索或本地恢复。

## 4. 配置 OIDC / JWKS

在“设置 → 对话归档”填写：

| 配置 | 说明 |
|---|---|
| Issuer | JWT `iss` 的精确值 |
| Audience | TokenManager 团队网关对应的 `aud` |
| JWKS URL | OIDC 提供方的签名公钥地址 |
| 签名算法 | 默认 `RS256`；可选 RS256/384/512、ES256/384、EdDSA |
| 姓名/邮箱/组织 Claim | 支持 `profile.name` 这样的点分路径 |

Issuer 和 JWKS URL 必须使用 HTTPS；仅回环地址允许 HTTP。校验范围包括签名、`kid`、算法、issuer、audience、`exp`、`nbf` 和非空 `sub`。JWKS 按 URL 与 `kid` 缓存，遇到未知 `kid` 时立即刷新。

## 5. 配置脱敏

内置规则会在任何归档写入前处理 Authorization、Cookie、JWT、API Key、密码、访问令牌、私钥 PEM 和 URL 凭据。可以添加组织自定义规则，每行格式为：

```text
EMPLOYEE_ID::EMP-[0-9]{6}
INTERNAL_HOST::[a-z0-9-]+\.corp\.example
```

图片、音频、文档和文件引用不保存正文、Base64、二进制、远端 URL 或 provider 文件 ID，只保存引用类型、MIME、文件名、大小和 SHA-256。设置页提供脱敏测试器；确认结果后再启用归档。

## 6. 启用并检查健康状态

“启用归档”会同时进行前端和后端预检。以下项目全部通过后配置才会生效：

- 环境密钥或托管密钥可用，且格式和文件权限正确；
- SQLCipher 数据库和逻辑完整性正常；
- FTS5 使用 trigram tokenizer；
- OIDC 配置有效且 JWKS 可访问；
- 自定义脱敏正则可编译。

推荐始终通过“一键初始化”完成首次开启。普通“启用归档”开关同样执行后端预检，不能绕过密钥、JWKS 或脱敏检查。本地自动快照状态会单独显示；它是恢复能力的健康提示，不是启用前置条件。

本地代理路由保持不变且不要求 JWT，但在归档启用后也会以 `local:<machine-id>` 身份采集，并遵循相同的 fail-closed 规则。关闭归档后，本地代理完全按原行为透传。

## 7. 团队客户端请求

以 OpenAI Chat Completions 为例：

```bash
curl https://token-manager.example.com/team/v1/chat/completions \
  -H "Authorization: Bearer $OIDC_ACCESS_TOKEN" \
  -H "X-TokenManager-Conversation-Id: client-conversation-42" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5","messages":[{"role":"user","content":"hello"}]}'
```

同一用户下的会话归属键为 `issuer + sub + conversation_id`。客户端应在一个逻辑对话的全部请求中复用 conversation ID，不要使用显示名称或邮箱作为 ID。

支持的团队路径与原本地 API 路径一致，只需增加 `/team` 前缀，例如：

- `/team/v1/messages`
- `/team/v1/chat/completions`
- `/team/v1/responses`
- `/team/v1beta/models/{model}:generateContent`

JWT、Cookie、API Key 和会话归档头会在进入上游处理前移除；上游供应商凭据仍由 TokenManager 的 provider 配置提供。

## 8. HTTPS 反向代理示例

下面只展示路由边界；证书、域名和上游端口按部署环境调整：

```nginx
server {
    listen 443 ssl http2;
    server_name token-manager.example.com;

    client_max_body_size 200m;

    location = /health {
        proxy_pass http://127.0.0.1:15721/health;
    }

    location /team/ {
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_pass http://127.0.0.1:15721;
    }

    location / {
        return 404;
    }
}
```

不要配置会记录 Authorization、Cookie、请求体或响应体的反向代理访问日志格式。

## 9. 管理员归档页

“对话归档”页面支持服务端分页、正文全文检索，以及用户、来源、Provider、模型、状态和日期组合筛选。详情页展示消息 revision、工具消息、附件元数据、exchange、Token、错误与部分流状态。

本机历史扫描支持 Claude、Codex、Gemini、OpenCode、OpenClaw 和 Hermes。导入只读来源文件，以 provider、规范化源路径哈希、源会话 ID 和内容哈希去重；导入会话标记为“未归属本机历史”。

JSON 和 Markdown 导出是脱敏后的明文，请将导出目标视为敏感数据。归档页永久删除只清理集中归档及全文索引并写入不含正文的审计记录，不会修改 Session Manager 管理的原始历史文件。

## 10. 本机对话、Agent 记忆与统一身份 API

设置页中的“本地 Agent 对话与记忆接入”可以分别控制会话归档、Agent 记忆抓取、loopback API 和身份写入。API 固定监听 `127.0.0.1:15722`，所有数据端点共用设置页生成的 Bearer Token；身份写入默认关闭，必须显式开启“允许身份写入”：

- `GET /v1/conversations/changes` 与 `GET /v1/conversations/{id}`：现有对话增量流和详情；
- `GET /v1/memories/changes` 与 `GET /v1/memories/{id}`：独立记忆游标、`upsert/delete` 事件和脱敏正文；
- `GET /v1/identity/status`：最近一次统一身份 revision 和逐 Agent 写入结果；
- `PUT /v1/identity`：接收 `SOUL.md`、`AGENTS.md`、`IDENTITY.md`、`USER.md` 的完整快照；
- `GET /v1/health`：返回 `capabilities`，消费者应确认 `memories`；只有开启身份写入时才会包含 `identity-write`。

记忆扫描覆盖 Claude、Codex、Gemini、OpenCode、OpenClaw、Hermes 的全局/项目白名单和声明 `memory-scan`、`memory-load` 的进程适配器。TokenManager 不读取认证配置正文、不下载远程 instruction URL，也不会无界扫描整个用户主目录。某个扫描根发生权限、解析或大小限制错误时，该根不会产生删除事件。

记忆源文件被删除后，API 会发出 `delete` tombstone 并清空归档正文；对话仍维持原有长期归档规则。已有 schema v1 数据库和备份在打开或恢复后会事务式升级到 schema v2。

身份写入只修改 CentaurAI 标记的托管区块，区块外原规则保持不变，并在变化前创建本地备份。OpenClaw 使用 `workspace/` 下的四个原生文件；Hermes 使用 `SOUL.md`、`AGENTS.md` 和 `memories/USER.md`；Claude、Codex、Gemini、OpenCode 分别写入其全局规则入口。托管区块在 Agent 记忆扫描时会被移除，避免统一身份再次回流到个人记忆库。
