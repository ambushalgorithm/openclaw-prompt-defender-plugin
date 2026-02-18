# Prompt Defender Test Samples Service

Standalone service for generating dynamic malicious test content to test prompt injection detection.

## Purpose

This service generates realistic tool outputs (HTML, Markdown, JSON, etc.) with embedded malicious content. Used for end-to-end testing of the prompt-defender plugin → scanner → block flow.

## Installation

```bash
cd service-test
pip install -r requirements.txt
```

## Running

```bash
# Development (with auto-reload)
python main.py

# Or using uvicorn directly
uvicorn app:app --host 0.0.0.0 --port 8081 --reload

# Production
uvicorn app:app --host 0.0.0.0 --port 8081
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Index page with links to all samples |
| `/test` | GET | Same as `/` |
| `/test/{name}` | GET | Dynamic sample (query params control content) |
| `/health` | GET | Health check |

## Query Parameters

| Param | Type | Options | Default | Description |
|-------|------|---------|---------|-------------|
| `filtype` | string | html, md, txt, json, xml | html | Output format |
| `severity` | string | critical, high, medium, low | high | Attack intensity |
| `type` | string | injection, jailbreak, secret, pii | injection | Attack category |
| `obfuscated` | bool | true, false | false | Is attack hidden/encoded? |
| `lang` | string | en, es, fr, de, ru, ko, ja, zh | en | Attack language |
| `clean` | bool | true, false | false | Return clean sample |

## Examples

```bash
# Critical severity HTML with injection
curl "http://localhost:8081/test/test?filtype=html&severity=critical"

# Medium severity Markdown with obfuscated attack
curl "http://localhost:8081/test/test?filtype=md&severity=medium&obfuscated=true"

# JSON with secret leak
curl "http://localhost:8081/test/test?filtype=json&type=secret"

# Clean HTML (should pass scanning)
curl "http://localhost:8081/test/test?clean=true&filtype=html"

# Spanish language injection
curl "http://localhost:8081/test/test?filtype=txt&lang=es"
```

## Testing Workflow

1. Start main scanner service (port 8080):
   ```bash
   cd ../service && python -m app
   ```

2. Start test samples service (port 8081):
   ```bash
   cd service-test && python main.py
   ```

3. Update plugin config to point to main service (port 8080)

4. Have OpenClaw fetch a malicious sample:
   ```
   web_fetch http://localhost:8081/test/test?filtype=html&severity=critical
   ```

5. Plugin intercepts → calls main service → scans → blocks

6. Verify block in logs

## Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run tests
pytest -v
```

## Port

Default: `8081` (configurable in `main.py`)

## Project Structure

```
service-test/
├── app.py              # FastAPI entry point
├── generator.py        # SampleGenerator class
├── templates.py        # Attack templates
├── main.py             # uvicorn runner
├── requirements.txt    # Dependencies
└── README.md          # This file
```
