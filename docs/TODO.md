# TODO - openclaw-prompt-defender-plugin

## Testing Strategy

**IMPORTANT: All e2e testing must be done in Docker.** Only unit tests may be run outside of Docker.

- **Unit tests** → Can run locally (outside Docker)
- **E2E/integration tests** → MUST use `openclaw-e2e` skill (Docker container)

### Prerequisite: Build OpenClaw from feature branch

The `before_tool_result` hook is required for this plugin. It exists in the `feat/before-tool-result` branch.

**To build the e2e container with the feature branch:**
```bash
cd ~/Projects/openclaw
git checkout feat/before-tool-result
docker build -t openclaw-dev:local .
# Restart e2e container with new image
openclaw-e2e stop && openclaw-e2e start
```

---

## Option 1: Integrate prompt-guard as local API

### Overview
Run prompt-guard as a local API server and have the plugin call it via HTTP.

### Steps

1. **Ensure prompt-guard is installed with API server**
   - Verify `prompt-guard[full]` or `prompt-guard[api]` is installed
   - Or install: `pip install .[full]` in ~/Projects/prompt-guard

2. **Add prompt-guard API startup to OpenClaw**
   - Create a systemd service or background script to run `prompt-guard serve --port 8080`
   - Or add to OpenClaw's startup process

3. **Configure plugin**
   - Update `plugin/openclaw.plugin.json` or config to set `service_url: "http://localhost:8080"`

4. **Test the integration (using e2e skill - Docker required)**
   - Start e2e container: `openclaw-e2e start`
   - Copy prompt-guard into container:
     ```bash
     docker cp ~/Projects/prompt-guard openclaw-dev-test:/home/node/prompt-guard
     ```
   - Install prompt-guard in container:
     ```bash
     openclaw-e2e exec "cd /home/node/prompt-guard && pip install .[full]"
     ```
   - Start prompt-guard API server in container:
     ```bash
     openclaw-e2e exec "cd /home/node/prompt-guard && prompt-guard serve --port 8080 &"
     ```
   - Copy plugin into container:
     ```bash
     docker cp ~/Projects/openclaw-plugins-development/openclaw-prompt-defender-plugin/plugin openclaw-dev-test:/home/node/.openclaw/workspace/plugins/
     ```
   - Restart gateway or test directly:
     ```bash
     openclaw-e2e exec "curl -X POST http://localhost:8080/scan -H 'Content-Type: application/json' -d '{\"content\": \"test\"}'"
     ```
   - Verify plugin can reach prompt-guard API
   - Test a scan request/response

5. **Handle edge cases**
   - What if prompt-guard isn't running? (fail-open is already configured)
   - Add health check endpoint?
   - Add startup dependency (plugin waits for API)?

### Dependencies
- prompt-guard Python package with API server
- Network access from plugin to localhost:8080
- openclaw-e2e skill

### Notes
- Current plugin code already expects HTTP service (no code changes needed)
- Just need to run the prompt-guard API server alongside OpenClaw
- Use openclaw-e2e for isolated testing without affecting production
- ALL e2e testing must be done in Docker — only unit tests allowed outside
