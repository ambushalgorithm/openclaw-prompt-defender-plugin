"""Prompt Defender Security Service."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any
import time

from logger import get_logger

app = FastAPI(title="Prompt Defender Security Service")
logger = get_logger()

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory pattern store (will port from prompt-guard)
# For now: simple placeholder patterns
DANGEROUS_PATTERNS = [
    "ignore all previous instructions",
    "disregard your guidelines",
    "system prompt",
    "you are now",
    "pretend to be",
    "roleplay as",
    "new instructions:",
    "override security",
    "bypass restrictions",
    "developer mode",
]

class ScanRequest(BaseModel):
    type: str
    tool_name: str
    content: Any
    is_error: bool = False
    duration_ms: int = 0

class ScanResponse(BaseModel):
    action: str  # "allow", "block", "sanitize"
    reason: str | None = None
    sanitized_content: Any | None = None
    matches: list[dict] | None = None

def scan_content(content: Any) -> tuple[bool, list[dict]]:
    """Scan content for prompt injection patterns.
    
    Returns (is_dangerous, matches)
    """
    if content is None:
        return False, []
    
    # Convert to string if needed
    content_str = str(content).lower()
    matches = []
    
    for pattern in DANGEROUS_PATTERNS:
        if pattern.lower() in content_str:
            matches.append({
                "pattern": pattern,
                "type": "injection_attempt",
                "severity": "high"
            })
    
    return len(matches) > 0, matches

@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """Scan tool result for prompt injection attempts."""
    start_time = time.time()
    
    # Convert content to string for scanning
    content_str = str(request.content)
    
    is_dangerous, matches = scan_content(request.content)
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    if is_dangerous:
        severity = "high" if len(matches) >= 3 else "medium"
        
        # Log the match
        print(f"[PROMPT DEFENDER] Blocked {request.tool_name}: {len(matches)} match(es)")
        for m in matches:
            print(f"  - {m['pattern']}: {m['type']}")
        
        # Log threat to persistent storage
        logger.log_threat(
            severity=severity,
            tool_name=request.tool_name,
            matches=matches,
            content=request.content,
        )
        
        # Log scan event
        logger.log_scan(
            action="block",
            tool_name=request.tool_name,
            severity=severity,
            matches=matches,
            duration_ms=duration_ms,
        )
        
        return ScanResponse(
            action="block",
            reason=f"Potential prompt injection detected ({len(matches)} pattern(s) matched)",
            matches=matches
        )
    
    # Log allowed scan
    logger.log_scan(
        action="allow",
        tool_name=request.tool_name,
        severity="safe",
        matches=[],
        duration_ms=duration_ms,
    )
    
    # Allow through
    return ScanResponse(action="allow")

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "prompt-defender",
        "version": "0.1.0"
    }

@app.get("/patterns")
async def list_patterns():
    """List active detection patterns."""
    return {
        "patterns": DANGEROUS_PATTERNS,
        "count": len(DANGEROUS_PATTERNS)
    }

@app.get("/stats")
async def get_stats(hours: int = 24):
    """Get threat statistics for the last N hours."""
    return logger.get_stats(hours=hours)

if __name__ == "__main__":
    import uvicorn
    print("Starting Prompt Defender service on http://0.0.0.0:8080")
    print("Endpoints:")
    print("  POST /scan   - Scan tool result for prompt injection")
    print("  GET  /health - Health check")
    print("  GET  /patterns - List active patterns")
    uvicorn.run(app, host="0.0.0.0", port=8080)
