# Hello World Plugin + Service

Simplest possible plugin example — appends a string from a local HTTP service to every message.

## Quick Start

### 1. Start the Service

```bash
cd ~/Projects/openclaw-skills/hello-world-service
python app.py
# Or: uvicorn app:app --reload --port 9000
```

Service runs on `http://localhost:9000`:
- `GET /hello` → returns `{"testString": "..."}`
- `GET /health` → returns `{"status": "ok"}`

### 2. Build the Plugin

```bash
cd ~/Projects/openclaw-skills/hello-world-plugin
npm install
npm run build
```

### 3. Configure OpenClaw

Add to `openclaw.json`:

```json
{
  "plugins": {
    "load": [
      {
        "package": "/home/clawdbot/Projects/openclaw-skills/hello-world-plugin",
        "config": {
          "service_url": "http://localhost:9000"
        }
      }
    ]
  }
}
```

### 4. Test

Send any message → It will have `[ appended by hello-world plugin ]` appended.

## How It Works

```
Message "Hello"
    ↓
Plugin calls GET http://localhost:9000/hello
    ↓
Service returns {"testString": " [ appended by hello-world plugin ]"}
    ↓
Plugin returns { content: "Hello" + " [ appended by hello-world plugin ]" }
    ↓
Agent sees modified message
```

## Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Plugin logic (TypeScript) |
| `openclaw.plugin.json` | Plugin manifest |
| `package.json` | NPM dependencies |
| `tsconfig.json` | TypeScript config |
| `app.py` | Test service (Python/FastAPI) |

## Next Steps

Replace the service logic with real security scanning (prompt-guard, detect-injection) to build the `plugin-security-filter`.