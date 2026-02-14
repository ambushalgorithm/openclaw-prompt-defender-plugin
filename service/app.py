"""Prompt Defender Security Service."""
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Optional
import time
import json

from logger import get_logger
from scanner import get_scanner
from decoder import decode_and_scan, has_encoding
from config import load_config, check_owner_bypass, ServiceConfig

app = FastAPI(title="Prompt Defender Security Service")
logger = get_logger()
scanner = get_scanner()

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    type: str
    tool_name: str
    content: Any
    is_error: bool = False
    duration_ms: int = 0
    source: Optional[str] = None  # User ID for owner bypass


class ScanResponse(BaseModel):
    action: str  # "allow", "block", "sanitize"
    reason: Optional[str] = None
    sanitized_content: Optional[Any] = None
    matches: Optional[list[dict]] = None
    owner_bypass: bool = False


@app.post("/scan", response_model=ScanResponse)
async def scan(
    request: ScanRequest,
    x_config: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None)
):
    """Scan tool result for prompt injection attempts."""
    start_time = time.time()
    
    # Load configuration
    try:
        config_dict = json.loads(x_config) if x_config else {}
        config = load_config(config_dict)
    except (json.JSONDecodeError, ValueError):
        config = ServiceConfig()
    
    # Use user_id from request body or header
    user_id = request.source or x_user_id
    
    # Owner bypass check
    if check_owner_bypass(user_id, config.owner_ids):
        logger.log_scan(
            action="allow",
            tool_name=request.tool_name,
            severity="safe",
            matches=[],
            duration_ms=0,
            source=user_id
        )
        
        print(f"[PROMPT DEFENDER] Owner bypass: user {user_id}")
        
        return ScanResponse(
            action="allow",
            reason="Owner bypass active",
            owner_bypass=True
        )
    
    # Convert content to string for scanning
    content_str = str(request.content)
    
    # Check if prompt_guard feature is enabled
    if not config.features.prompt_guard:
        return ScanResponse(action="allow", reason="prompt_guard disabled")
    
    # Decode any encoded content if enabled
    decoded_findings = []
    if config.prompt_guard.decode_base64 and has_encoding(content_str):
        decoded_findings = decode_and_scan(content_str)
        
        # Scan decoded content too
        for finding in decoded_findings:
            content_str += "\n" + finding["decoded"]
    
    # Scan content with tiered scanner
    is_dangerous, matches, scan_duration_ms = scanner.scan(
        content=content_str,
        tier=config.prompt_guard.scan_tier,
        use_cache=config.prompt_guard.hash_cache
    )
    
    total_duration_ms = int((time.time() - start_time) * 1000)
    
    if is_dangerous:
        severity = "critical" if any(m["severity"] == "critical" for m in matches) else "high"
        
        # Log the match
        print(f"[PROMPT DEFENDER] Blocked {request.tool_name}: {len(matches)} match(es)")
        for m in matches:
            print(f"  - {m['type']}: {m['pattern'][:30]}...")
        
        if decoded_findings:
            print(f"  - Decoded {len(decoded_findings)} encoded string(s)")
        
        # Log threat to persistent storage
        logger.log_threat(
            severity=severity,
            tool_name=request.tool_name,
            matches=matches,
            content=request.content,
            source=user_id
        )
        
        # Log scan event
        logger.log_scan(
            action="block",
            tool_name=request.tool_name,
            severity=severity,
            matches=matches,
            duration_ms=total_duration_ms,
            source=user_id
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
        duration_ms=total_duration_ms,
        source=user_id
    )
    
    # Allow through
    return ScanResponse(action="allow")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "prompt-defender",
        "version": "0.2.0",
        "scanner": scanner.get_stats()
    }


@app.get("/stats")
async def get_stats(hours: int = 24):
    """Get threat statistics for the last N hours."""
    stats = logger.get_stats(hours=hours)
    stats["scanner"] = scanner.get_stats()
    return stats


@app.get("/patterns")
async def list_patterns():
    """List active detection patterns."""
    scanner_stats = scanner.get_stats()
    return {
        "patterns_loaded": scanner_stats["patterns_loaded"],
        "cache_stats": {
            "size": scanner_stats["cache_size"],
            "hits": scanner_stats["cache_hits"],
            "misses": scanner_stats["cache_misses"],
            "hit_rate": scanner_stats["hit_rate_percent"]
        }
    }


@app.post("/cache/clear")
async def clear_cache():
    """Clear the pattern cache."""
    scanner.clear_cache()
    return {"status": "cleared", "message": "Pattern cache cleared"}


if __name__ == "__main__":
    import uvicorn
    print("Starting Prompt Defender service on http://0.0.0.0:8080")
    print("Endpoints:")
    print("  POST /scan        - Scan tool result for prompt injection")
    print("  GET  /health      - Health check + scanner stats")
    print("  GET  /stats       - Threat statistics")
    print("  GET  /patterns    - List active patterns")
    print("  POST /cache/clear - Clear pattern cache")
    uvicorn.run(app, host="0.0.0.0", port=8080)
