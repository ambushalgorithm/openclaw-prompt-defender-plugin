# 🛡️ openclaw-prompt-defender

<p align="center">
  <img src="https://img.shields.io/badge/Plugin-TypeScript-blue?style=for-the-badge&logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Service-Python-cyan?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/OpenClaw-v2026.2.4-green?style=for-the-badge" alt="OpenClaw">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

> Prompt injection detection and jailbreak prevention for OpenClaw — scans tool outputs before they reach the LLM.

## ✨ What is this?

**openclaw-prompt-defender** is a security plugin that protects your AI assistant from malicious inputs hidden in tool outputs. It intercepts results from tools like `web_fetch`, `exec`, and `read` before they reach the LLM, scanning for:

- 🎯 **Prompt injection attacks** — Attempts to override your AI's instructions
- 🔓 **Jailbreak attempts** — Tricks to bypass safety guidelines  
- 🔑 **Secret leaks** — Accidental exposure of API keys, tokens, passwords
- 👤 **PII exposure** — Personal information that shouldn't be shared
- 💉 **Malicious content** — XSS, SQL injection, RCE attempts

## 🚀 Quick Start

### Prerequisites

- OpenClaw v2026.2.4+
- Python 3.12+
- Docker (for testing)

### Installation

```bash
# Clone the plugin
git clone https://github.com/ambushalgorithm/openclaw-prompt-defender.git
cd openclaw-prompt-defender

# Install Python dependencies
cd service && pip install -r requirements.txt

# Build the plugin
cd ../plugin && npm install
```

### Run the Service

```bash
cd service
python -m app
# Service runs on http://localhost:8080
```

### Configuration

Add to your OpenClaw config:

```json
{
  "plugins": {
    "enabled": ["prompt-defender"],
    "prompt-defender": {
      "url": "http://localhost:8080"
    }
  }
}
```

## 🏗️ Architecture

```
User Input → OpenClaw → Tool Execution → [Plugin] → [Scanner Service] → LLM
                                              ↓
                                      Block if malicious
```

**Two-part design:**

1. **Plugin** (TypeScript) — Runs in OpenClaw's sandbox, handles hooks
2. **Service** (Python/FastAPI) — Runs on host, does pattern matching & ML detection

## 🔍 Detection Methods

| Method | Patterns | Use Case |
|--------|----------|----------|
| **prompt_guard** | 500+ regex | Core injection detection |
| **ml_detection** | HuggingFace DeBERTa | Advanced ML-based detection |
| **secret_scanner** | 50+ patterns | API keys, tokens, passwords |
| **content_moderation** | OpenAI API | Policy violations |

Each is independently toggleable via feature flags.

## 📖 Usage Examples

### Basic Scanning

```bash
# Scan text for threats
curl -X POST "http://localhost:8080/scan" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello world"}'
```

### Response

```json
{
  "threat_detected": false,
  "verdict": "ALLOW",
  "matches": []
}
```

### Blocked Content

```json
{
  "threat_detected": true,
  "verdict": "BLOCK",
  "matches": [
    {
      "pattern": "[INST]",
      "type": "prompt_injection",
      "severity": "critical"
    }
  ]
}
```

## 🧪 Testing

We use [prompt-injection-testing](https://github.com/ambushalgorithm/prompt-injection-testing) for generating test samples:

```bash
# Clone test samples service
git clone https://github.com/ambushalgorithm/prompt-injection-testing.git
cd prompt-injection-testing
pip install -r requirements.txt
python main.py  # Runs on port 8081
```

### Run Tests

```bash
# Start scanner service
cd service && python -m app &

# Run tests
pytest -v
```

See [Testing](#testing) section for more details.

## 📁 Project Structure

```
openclaw-prompt-defender/
├── plugin/                 # TypeScript plugin (OpenClaw sandbox)
│   ├── src/
│   │   └── index.ts       # before_tool_result hook
│   └── openclaw.plugin.json
│
├── service/                # Python scanner service
│   ├── app.py             # FastAPI /scan endpoint
│   ├── scanner.py         # Tiered scanning engine
│   ├── patterns.py        # Detection patterns
│   └── Dockerfile
│
├── docs/
│   └── DESIGN.md          # Architecture details
│
└── README.md
```

## 🔧 Configuration

```json
{
  "features": {
    "prompt_guard": {
      "enabled": true,
      "tier": 2
    },
    "ml_detection": {
      "enabled": false
    }
  },
  "logging": {
    "enabled": true,
    "path": "./logs"
  }
}
```

## 🐳 Docker

```bash
# Build and run
cd service
docker build -t prompt-defender .
docker run -d -p 8080:8080 prompt-defender
```

Or use docker-compose:

```bash
docker-compose up -d
```

## 🤝 Contributing

Contributions welcome! Check [TODO.md](TODO.md) for current tasks.

## 📜 License

MIT License

## 🔗 Related Projects

- [prompt-injection-testing](https://github.com/ambushalgorithm/prompt-injection-testing) — Test sample generation
- [prompt-guard](https://github.com/seojoonkim/prompt-guard) — Regex patterns
- [detect-injection](https://github.com/protectai/detect-injection) — ML detection
- [openclaw-shield](https://github.com/knostic/openclaw-shield) — Secrets/PII

---

<p align="center">
  <sub>Built with 🔒 for secure AI assistants</sub>
</p>
