<div align="center">

<img src="src-tauri/icons/128x128.png" alt="CentaurAI Token Manager" width="96" />

# CentaurAI Token Manager

CentaurAI-branded desktop key and provider manager for AI coding tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built with Tauri](https://img.shields.io/badge/Built%20with-Tauri%202-orange.svg)](https://tauri.app/)

</div>

## Overview

CentaurAI Token Manager is the CentaurAI distribution of CC Switch. It provides one desktop interface for managing credentials and endpoint configuration used by Claude Code, Claude Desktop, Codex, Gemini CLI, OpenCode, OpenClaw, and Hermes Agent.

This distribution removes upstream advertising, sponsor badges, referral links, recommended-provider placements, and upstream automatic-update entry points. The preset-provider directory is disabled: users configure their own providers and keys directly.

## Features

- Manage API keys and endpoints locally
- Switch configurations across supported AI coding tools
- Custom provider configuration without a promoted-provider directory
- Usage, proxy, MCP, skills, prompt, and session-management tools inherited from CC Switch
- Windows, macOS, and Linux desktop support through Tauri 2
- Compatibility with existing CC Switch application data and `ccswitch://` deep links

## Development

Requirements:

- Node.js with Corepack
- pnpm 10
- Rust toolchain
- Tauri 2 platform dependencies

```bash
corepack pnpm@10 install --frozen-lockfile
corepack pnpm@10 tauri dev
```

Useful checks:

```bash
corepack pnpm@10 typecheck
corepack pnpm@10 test:unit
corepack pnpm@10 build:renderer
cargo check --manifest-path src-tauri/Cargo.toml
```

## Attribution

This project is based on [CC Switch](https://github.com/farion1231/cc-switch) by Jason Young and its contributors. The original copyright notice is retained in [LICENSE](LICENSE), as required by the MIT License.

CentaurAI branding and distribution-specific changes are maintained separately from the upstream project.

## License

MIT. See [LICENSE](LICENSE).
