# openclaw-prompt-defender

Built with: Kimi K2.5 (via Ollama Cloud) • OpenClaw v2026.2.4

**Prompt injection detection and jailbreak prevention** for OpenClaw — combining the best of `prompt-guard` and `detect-injection` using the **Plugin Gateway Pattern**.

**Current Status:** ✅ Input filtering ready (via `message:received` hook) — Output filtering pending upstream OpenClaw contribution.

See [docs/DESIGN.md](docs/DESIGN.md) for full architecture, design decisions, and implementation strategy.

---

## Overview

This project implements a security filter for OpenClaw that scans **user input** for prompt injection and jailbreak attempts before they reach the LLM model.

**Short-term:** Input protection only (works immediately)  
**Long-term:** Full bidirectional filtering via upstream OpenClaw contribution (see [docs/DESIGN.md](docs/DESIGN.md))

| Source | Strength | Ported |
|--------|----------|--------|
| **prompt-guard** | Fast pattern matching, 70% token reduction, SHIELD categories, owner bypass | ✅ |
| **detect-injection** | Dual-layer scanning, HF-based vector detection, safety categories | ✅ |

---

## Architecture

Two-layer security filtering via **Plugin Gateway Pattern**:

- **Plugin** (TypeScript, sandboxed) — hooks into OpenClaw, delegates to service via HTTP
- **Service** (Python/FastAPI, host) — runs prompt-guard, detect-injection, 1Password CLI

**Current:** User input flows through `message:received` hook → `/scan` endpoint → Security Service → Block/Allow  
**Future:** Tool output filtering via `before_tool_result` hook (upstream contribution in progress)

See [docs/DESIGN.md](docs/DESIGN.md) for:
- Full architecture diagram
- The hook timing gap that requires upstream contribution
- Our plan to contribute `before_tool_result` hook to OpenClaw

---

## Project Structure

```
openclaw-prompt-defender/
├── docs/
│   └── DESIGN.md           # Architecture, design decisions, upstream plan
├── plugin/                 # TypeScript plugin (runs in OpenClaw sandbox)
│   ├── src/
│   ├── openclaw.plugin.json
│   └── package.json
├── service/                # Python/FastAPI service (runs on host)
│   ├── app.py
│   └── requirements.txt
├── config/
│   └── example.openclaw.json
└── README.md
```

---

## Quick Start

```bash
# 1. Install service dependencies
cd ~/Projects/openclaw-prompt-defender/service
pip install -r requirements.txt

# 2. Start the service (Terminal 1)
python app.py
# → Service running on http://127.0.0.1:8080

# 3. Build and install plugin (Terminal 2)
cd ~/Projects/openclaw-prompt-defender/plugin
npm install && npm run build

# 4. Configure OpenClaw (see example below)
# Add plugin config to ~/.openclaw/openclaw.json

# 5. Restart OpenClaw
openclaw gateway restart
```

---

## OpenClaw Configuration

```json
{
  "plugins": {
    "load": {
      "prompt-defender": {
        "package": "~/Projects/openclaw-prompt-defender/plugin",
        "config": {
          "service_url": "http://127.0.0.1:8080",
          "timeout_ms": 5000,
          "fail_open": true,
          "owner_ids": ["1461460866850357345"],
          "scan_input": true,
          "scan_output": false
        }
      }
    }
  }
}
```

**Note:** `scan_output` is currently disabled (`false`) because the `tool_result_persist` hook fires **after** the LLM has already seen the content. Output filtering will be enabled after we contribute the `before_tool_result` hook upstream.

---

## Plugin Manifest (`openclaw.plugin.json`)

```json
{
  "name": "openclaw-prompt-defender",
  "version": "0.1.0",
  "description": "Prompt injection detection and jailbreak prevention for OpenClaw",
  "entry": "dist/index.js",
  "hooks": {
    "message:received": {
      "description": "Scan user messages for prompt injection and jailbreak attempts"
    }
  },
  "configSchema": {
    "type": "object",
    "properties": {
      "service_url": {
        "type": "string",
        "default": "http://127.0.0.1:8080"
      },
      "timeout_ms": {
        "type": "number",
        "default": 5000
      },
      "fail_open": {
        "type": "boolean",
        "default": true,
        "description": "Allow on service failure"
      },
      "owner_ids": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Trusted user IDs (bypass scanning)"
      },
      "scan_input": {
        "type": "boolean",
        "default": true,
        "description": "Enable message_received scanning (injection/jailbreak detection)"
      },
      "scan_output": {
        "type": "boolean",
        "default": false,
        "description": "Enable output scanning (pending upstream hook contribution)"
      }
    },
    "required": ["service_url"]
  }
}
```

---

## Filter Profiles

| Profile | Type | Checks | Action | Status |
|---------|------|--------|--------|--------|
| **Input (strict)** | `input` | Injection, jailbreak, obfuscation, SHIELD categories | Block or allow | ✅ **Ready** |
| **Output (moderate)** | `output` | PII scrub, content safety, size limit | Sanitize or allow | ⏳ **Pending upstream** |

---

## Error Handling — Fail Open

By default, the plugin uses **fail-open** strategy: if the security service is unreachable, times out, or errors, the plugin allows and logs a warning. This prevents the security filter outage from blocking all agent functionality.

---

## Logging

The service logs all security events to `~/.openclaw/logs/` following OpenClaw's standard logging pattern:

### Log Files

```
~/.openclaw/logs/
├── config-audit.jsonl                     # OpenClaw system logs
├── prompt-defender-threats.jsonl          # Blocked attacks only
├── prompt-defender-scans.jsonl            # All scan events (allowed + blocked)
└── prompt-defender-summary.json           # Daily statistics
```

### Log Format (JSONL)

**Threats** (`prompt-defender-threats.jsonl`):
```json
{"timestamp":"2026-02-14T13:45:32.123456","severity":"high","tool":"message","patterns":["ignore all previous","disregard your guidelines"],"categories":["instruction_override","jailbreak"],"content_hash":"a1b2c3d4e5f6g7h8"}
```

**Scans** (`prompt-defender-scans.jsonl`):
```json
{"timestamp":"2026-02-14T13:45:32.789012","action":"block","tool_name":"message","severity":"high","pattern_count":2,"duration_ms":12,"categories":["instruction_override","jailbreak"]}
{"timestamp":"2026-02-14T13:46:10.456789","action":"allow","tool_name":"message","severity":"safe","pattern_count":0,"duration_ms":3}
```

### Statistics Endpoint

```bash
# Get threat stats for last 24 hours
curl http://127.0.0.1:8080/stats

# Custom time window (last 7 days)
curl http://127.0.0.1:8080/stats?hours=168
```

**Response:**
```json
{
  "period_hours": 24,
  "total_scans": 142,
  "total_threats": 3,
  "by_severity": {
    "high": 2,
    "medium": 1
  },
  "by_category": {
    "instruction_override": 2,
    "jailbreak": 1,
    "secret_exfiltration": 1
  },
  "by_tool": {
    "message": 3
  }
}
```

### Privacy

- Content is **hashed** (SHA-256, first 16 chars) for deduplication
- Full message content is **never logged** by default
- Content preview logging can be enabled (commented out in `logger.py`)

---

## Source Projects

| Project | Location | License | Notes |
|---------|----------|---------|-------|
| prompt-guard (fork) | `~/Projects/openclaw-skills/prompt-guard` | MIT | Owner bypass added |
| detect-injection (fork) | `~/Projects/openclaw-skills/detect-injection` | Apache 2.0 | Owner bypass added |
| original prompt-guard | `seojoonkim/prompt-guard` | MIT | Upstream |
| original detect-injection | `protectai/detect-injection` | Apache 2.0 | Upstream |

---

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/DESIGN.md](docs/DESIGN.md) | Full architecture, hook timing analysis, upstream contribution plan |
| This README | Quick start, configuration reference, current status |

---

## Roadmap

### Phase 1: Input Filtering (v0.1.0) — Ready to Implement
- ✅ Prompt injection detection via `message:received` hook
- ✅ Jailbreak prevention
- ✅ Owner bypass for trusted users
- ✅ Multi-language support (10 languages)

### Phase 2: Upstream Contribution — In Progress
- 🔄 Contribute `before_tool_result` hook to OpenClaw
- 🔄 Implement at SDK level (all tools)
- 🔄 Tests and documentation

### Phase 3: Output Filtering (v0.2.0) — After Upstream Merge
- ⏳ Tool output scanning via new hook
- ⏳ PII detection and redaction
- ⏳ Content safety filtering

### Phase 4: Polish (v1.0.0)
- Hash cache for performance
- 1Password CLI integration
- Admin dashboard
- Comprehensive test suite

See [docs/DESIGN.md](docs/DESIGN.md) for detailed implementation phases and the hook timing gap that necessitates this approach.

---

## Why Input First?

The `message:received` hook fires **before** the LLM processes user messages, allowing us to block injection attempts immediately. This is fully functional and provides immediate value.

Output filtering via `tool_result_persist` has a **timing gap** — it fires after the LLM has already seen the tool output. We're solving this by contributing a new `before_tool_result` hook to OpenClaw.

See [docs/DESIGN.md](docs/DESIGN.md) for the technical analysis.

---

## Related Projects

| Project | Focus | Complementary? |
|---------|-------|----------------|
| [Knostic Shield](https://github.com/knostic/openclaw-shield) | Secrets, PII, destructive commands | ✅ Yes — use both |
| Our Prompt Defender | Prompt injection, jailbreak | ✅ Different threats |

**Recommendation:** Use Knostic Shield for data protection + Our Prompt Defender for input validation.

---

## License

Dual-licensed under MIT and Apache 2.0 (to match source projects).

---

*Project created: 2026-02-11*  
*Repository: https://github.com/crayon-doing-petri/openclaw-prompt-defender*  
*Status: Phase 1 — Input filtering implementation*  
*Upstream: Contributing `before_tool_result` hook to OpenClaw*
