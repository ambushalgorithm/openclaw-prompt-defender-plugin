# Design Document — openclaw-prompt-defender

**Project:** openclaw-prompt-defender  
**Date:** 2026-02-11 (Updated with revised strategy)  
**Status:** Architecture revised — Input filtering ready, output filtering pending upstream contribution  
**Repository:** https://github.com/crayon-doing-petri/openclaw-prompt-defender (private)

---

## Executive Summary

A security plugin for OpenClaw focused on **prompt injection detection and jailbreak prevention**. Due to a critical timing gap in OpenClaw's hook system, we are implementing a **phased approach**:

1. **Phase 1:** Input filtering via `message:received` (works immediately)
2. **Phase 2:** Contribute `before_tool_result` hook upstream (for proper output filtering)
3. **Phase 3:** Output filtering via new hook (once upstream PR merges)

**Short-term:** Input protection only  
**Long-term:** Full bidirectional filtering via upstream contribution

---

## Critical Discovery: Hook Timing Gap

### The Problem

Analysis of OpenClaw source code confirms that **`tool_result_persist` fires AFTER the LLM has already processed the tool result** for the current turn.

```typescript
// From src/agents/session-tool-result-guard.ts (line ~148):
// "Apply hard size cap before persistence to prevent oversized tool results
// from consuming the entire context window on **subsequent** LLM calls"
```

The keyword "**subsequent**" confirms that this hook only affects future turns that read from the session transcript. The LLM sees raw content immediately.

### Timing Diagram (Current)

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CURRENT TURN                                   │
│                                                                         │
│  Tool executes ──▶ Returns raw result with secrets                     │
│       │                                                                 │
│       ▼                                                                 │
│  LLM receives raw result IMMEDIATELY                                    │
│       │                  ← NO hook fired yet                            │
│       │                                                                 │
│       ▼                                                                 │
│  LLM processes and potentially outputs secrets                         │
│       │                                                                 │
│       ▼                                                                 │
│  sessionManager.appendMessage() called                                 │
│       │                                                                 │
│       ▼                                                                 │
│  tool_result_persist hook fires (too late)                             │
│       │                                                                 │
│       ▼                                                                 │
│  Sanitized message saved to transcript                                 │
│       │                                                                 │
│       ▼                                                                 │
│  Future turns see redacted version                                     │
└────────────────────────────────────────────────────────────────────────┘
```

### Impact

Our original plan to use `tool_result_persist` for real-time tool output filtering **will not work as intended**. The LLM will still see raw secrets/PII in the current turn.

---

## Revised Strategy

### The Solution: Two-Phase Implementation

#### Phase 1: Input Filtering (Immediate)

✅ **Focus: `message:received` hook** — Scan user messages for prompt injection and jailbreak attempts.

**This works perfectly** because the hook fires before any processing:

```
User sends message ──▶ message:received hook ──▶ Plugin scans ──▶ Allow/Block
                              │
                              ▼
                    Can CANCEL before LLM sees it
```

#### Phase 2: Upstream Contribution (In Progress)

🔄 **Contribute `before_tool_result` hook to OpenClaw** — A new hook that fires immediately after tool execution but **before** the result reaches the LLM.

**Design:**
- Hook wraps at the SDK level (Option B)
- All tools (built-in + custom) pass through it
- Allows modification, sanitization, or blocking of tool results

**Implementation:**
```typescript
api.on("before_tool_result", async (event) => {
  const result = await scan({ 
    type: "output", 
    content: event.content 
  });
  
  if (result.action === "sanitize") {
    return { content: result.sanitized };
  }
  
  if (result.action === "block") {
    return { 
      block: true, 
      blockReason: result.reason 
    };
  }
});
```

#### Phase 3: Output Filtering (After Upstream Merge)

✅ **Full bidirectional filtering** — Once the `before_tool_result` PR merges:
- Input: `message:received` (injection, jailbreak)
- Output: `before_tool_result` (PII, content safety)

#### Phase 4: L5 Gate Tool (Fallback)

🛡️ **Interim protection** — If upstream contribution takes longer than expected, implement an L5-style security gate tool (like Knostic Shield) as a fallback:

```typescript
api.registerTool({
  name: "security_scan",
  execute: async (toolCallId, params) => {
    // Pre-scan file content before agent reads it
    const result = await scanFile(params.file_path);
    return {
      content: result.sanitized,
      status: result.status  // ALLOWED or DENIED
    };
  }
});
```

---

## Revised Architecture

### Phase 1: Input-Only (Current)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Phase 1: Input Filtering Only                      │
│                                                                          │
│  User Input                                                              │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────────┐                                                     │
│  │ message:received│──▶ Security Service ──▶ /scan (input/strict)       │
│  │     hook        │                                                     │
│  └─────────────────┘                                                     │
│       │                                                                  │
│       ▼                                                                  │
│  ┌─────────────────┐                                                     │
│  │  Decision       │                                                     │
│  │  ALLOW / BLOCK  │                                                     │
│  └─────────────────┘                                                     │
│       │                                                                  │
│       ▼                                                                  │
│  LLM Model (sees only safe content)                                      │
│                                                                          │
│  Tool Output ──▶ LLM (raw, unfiltered) ──▶ User                          │
│       ⚠️ LIMITATION: No filtering yet                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 3: Full Bidirectional (After Upstream)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Phase 3: Full Bidirectional Filtering                 │
│                                                                          │
│  User Input                                                              │
│       │                                                                  │
│       ▼                                                                  │
│  message:received ──▶ /scan (input) ──▶ ALLOW/BLOCK ──▶ LLM            │
│                                                                          │
│  Tool Output                                                             │
│       │                                                                  │
│       ▼                                                                  │
│  before_tool_result ──▶ /scan (output) ──▶ SANITIZE ──▶ LLM            │
│       │                                                                  │
│       ▼                                                                  │
│  LLM Model (sees safe content from both directions)                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Upstream Contribution Plan

### What We're Contributing

A new **`before_tool_result` hook** for OpenClaw that fires between tool execution and LLM processing.

### Implementation Details

**Location:** SDK-level tool wrapper (Option B)  
**Approach:** Wrap `tool.execute()` to intercept all tool results

```typescript
// Pseudo-code for implementation
const originalExecute = tool.execute;
tool.execute = async (toolCallId, params, signal, onUpdate) => {
  // Run the tool
  const result = await originalExecute(toolCallId, params, signal, onUpdate);
  
  // Run hook BEFORE returning to agent/LLM
  const hookRunner = getGlobalHookRunner();
  if (hookRunner?.hasHooks("before_tool_result")) {
    const hookResult = await hookRunner.runBeforeToolResult({
      toolName: tool.name,
      toolCallId,
      params,
      content: result,
      isError: result.error != null,
    }, ctx);
    
    if (hookResult?.block) {
      return { error: hookResult.blockReason };
    }
    
    return hookResult?.content ?? result;
  }
  
  return result;
};
```

### Benefits to OpenClaw Community

1. **Security plugins** can finally do real-time output filtering
2. **PII protection** for healthcare, finance, legal use cases
3. **Data loss prevention** without performance overhead of gate tools
4. **Cleaner than L5 pattern** — transparent to agents, no extra tool calls

### Timeline Estimate

| Phase | Duration | Status |
|-------|----------|--------|
| Fork & implement | 1-2 weeks | 🔄 Ready to start |
| Test with prompt-defender | 1 week | Pending implementation |
| Write tests & docs | 1 week | Pending |
| Submit PR | — | Pending |
| Review & merge | 1-4 weeks | Dependent on maintainers |
| **Total** | **4-8 weeks** | Variable |

---

## Revised Implementation Phases

### Phase 1: Input Filtering Foundation (Weeks 1-2)

**Goal:** Working input protection via `message:received`

- [ ] Set up `plugin/` and `service/` directories
- [ ] Create OpenClaw plugin manifest
- [ ] Implement `/scan` endpoint with `type=input`
- [ ] Port `prompt-guard` pattern matcher
- [ ] Implement `message:received` handler
- [ ] Owner bypass system
- [ ] End-to-end testing

**Deliverable:** v0.1.0-alpha with input filtering

### Phase 2: Upstream Contribution (Weeks 3-6)

**Goal:** Implement and contribute `before_tool_result` hook

- [ ] Fork OpenClaw repository
- [ ] Add `before_tool_result` hook type definition
- [ ] Implement hook runner
- [ ] Add invocation site (SDK tool wrapper)
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Submit PR with documentation
- [ ] Engage with maintainers for feedback

**Deliverable:** OpenClaw PR with new hook

### Phase 3: Output Filtering (Weeks 7-8)

**Goal:** Full bidirectional filtering (after upstream PR merges)

- [ ] Add `before_tool_result` handler to plugin
- [ ] Implement `/scan` endpoint with `type=output`
- [ ] Port PII detection patterns
- [ ] Content safety scanning
- [ ] End-to-end testing with both hooks

**Deliverable:** v0.2.0 with bidirectional filtering

### Phase 4: Polish & Features (Weeks 9-10)

**Goal:** Production-ready release

- [ ] Hash cache for performance
- [ ] 1Password CLI integration
- [ ] Multi-language support (10 languages)
- [ ] Comprehensive test suite
- [ ] Documentation
- [ ] L5 gate tool (optional fallback)

**Deliverable:** v1.0.0 stable release

### Phase 5: L5 Gate Tool (Fallback, if needed)

**Goal:** Interim output protection while waiting for upstream

- [ ] Implement `security_scan` tool
- [ ] Pre-scan file reads and exec commands
- [ ] Return sanitized content to agent
- [ ] Prompt injection to ensure agent uses it

**Deliverable:** L5-style gate (optional, if upstream delayed)

---

## Hook Verification Status

### ✅ Available and Working

| Hook | Timing | Can Modify? | Use For |
|------|--------|-------------|---------|
| `message:received` | Before LLM processes | ✅ Yes (content, cancel) | **Input filtering** |

### ⚠️ Available But Timing Issue

| Hook | Timing | Can Modify? | Use For |
|------|--------|-------------|---------|
| `tool_result_persist` | After persistence (LLM already saw it) | ✅ Yes | History sanitization only |

### 🔄 Planned (Upstream Contribution)

| Hook | Timing | Can Modify? | Use For |
|------|--------|-------------|---------|
| `before_tool_result` | After execution, before LLM | ✅ Yes | **Output filtering** (once implemented) |

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Plugin** | TypeScript / Node.js | OpenClaw integration, hooks |
| **Service** | Python / FastAPI | Security scanning, pattern matching |
| **Pattern Engine** | Ported from prompt-guard | Fast regex injection detection |
| **Vector Engine** | Ported from detect-injection | HF-based semantic detection (optional) |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Upstream PR rejected | No output filtering | Implement L5 gate tool as fallback |
| Upstream PR delayed | Output filtering delayed | L5 gate tool for interim protection |
| Service latency | Slow responses | Async scanning, caching, fail-open |
| Pattern false positives | User frustration | Owner bypass, adjustable thresholds |

---

## Success Criteria

### Phase 1 (Input Filtering)
- [ ] Prompt injection detection works
- [ ] Jailbreak prevention works
- [ ] Owner bypass functional
- [ ] Sub-100ms scan latency

### Phase 3 (Full Bidirectional)
- [ ] Input filtering (injection, jailbreak)
- [ ] Output filtering (PII, content safety)
- [ ] Both via appropriate hooks
- [ ] 90% token reduction via hash cache

---

## Comparison: Our Approach vs. Knostic Shield

| Aspect | Knostic Shield | Our Prompt Defender |
|--------|----------------|---------------------|
| **Injection Detection** | ❌ No | ✅ Primary focus |
| **Owner Bypass** | ❌ No | ✅ Yes |
| **Secrets/PII** | ✅ Yes | ✅ Planned (Phase 3) |
| **Architecture** | Pure plugin | Plugin + Service |
| **Output Filtering** | L2 (history only) | Pending upstream hook |
| **Multi-language** | ❌ English only | ✅ 10 languages planned |

**Positioning:** Complementary tools. Use Knostic for data protection, ours for injection prevention.

---

## Current Status

| Milestone | Status |
|-----------|--------|
| Architecture revised | ✅ Complete |
| Critical timing gap identified | ✅ Documented |
| Upstream contribution planned | ✅ Ready to start |
| Phase 1 (input filtering) | 🔄 Ready to implement |
| GitHub repo | ✅ Private |

---

## Next Immediate Action

**Start Phase 1:** Begin implementing input filtering via `message:received` hook while preparing upstream contribution for `before_tool_result`.

---

*Document updated: 2026-02-11*  
*OpenClaw Version: 2026.2.9*  
*OpenClaw Branch: feat/message-received (PR #12637 merged)*  
*Upstream Contribution: before_tool_result hook (planned)*
