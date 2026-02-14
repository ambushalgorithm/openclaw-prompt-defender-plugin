"""
Threat logging for openclaw-prompt-defender.

Follows OpenClaw's logging convention:
- Location: ~/.openclaw/logs/
- Format: JSONL (JSON Lines)
- Prefix: prompt-defender-*
"""

import json
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class ThreatLogger:
    """Persistent logger for security scan events and blocked threats."""
    
    def __init__(self, log_dir: Optional[Path] = None):
        # Default to OpenClaw's standard log directory
        if log_dir is None:
            openclaw_home = Path(
                os.environ.get("OPENCLAW_HOME", "~/.openclaw")
            ).expanduser()
            log_dir = openclaw_home / "logs"
        
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Plugin-namespaced log files
        self.threats_path = self.log_dir / "prompt-defender-threats.jsonl"
        self.scans_path = self.log_dir / "prompt-defender-scans.jsonl"
        self.summary_path = self.log_dir / "prompt-defender-summary.json"
    
    def log_scan(
        self,
        action: str,
        tool_name: str,
        severity: str = "safe",
        matches: Optional[List[Dict]] = None,
        duration_ms: int = 0,
        content_hash: Optional[str] = None,
        source: Optional[str] = None,
    ):
        """Log ALL scan events (allowed + blocked) for metrics and debugging."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "tool_name": tool_name,
            "severity": severity,
            "pattern_count": len(matches or []),
            "duration_ms": duration_ms,
        }
        
        if content_hash:
            entry["content_hash"] = content_hash
        
        if source:
            entry["source"] = source
        
        if matches:
            # Include pattern categories for metrics
            categories = list(set(m.get("type", "unknown") for m in matches))
            entry["categories"] = categories
        
        self._append(self.scans_path, entry)
    
    def log_threat(
        self,
        severity: str,
        tool_name: str,
        matches: List[Dict],
        content: Any,
        source: Optional[str] = None,
    ):
        """Log ONLY blocked threats for security review."""
        # Generate content hash for deduplication (privacy-preserving)
        content_str = str(content)
        content_hash = hashlib.sha256(content_str.encode()).hexdigest()[:16]
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "tool": tool_name,
            "patterns": [m.get("pattern", "unknown") for m in matches],
            "categories": list(set(m.get("type", "unknown") for m in matches)),
            "content_hash": content_hash,
        }
        
        if source:
            entry["source"] = source
        
        # Optional: include sanitized content preview (first 100 chars)
        # Disabled by default for privacy
        # entry["content_preview"] = content_str[:100]
        
        self._append(self.threats_path, entry)
    
    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat statistics for the last N hours."""
        cutoff = datetime.now().timestamp() - (hours * 3600)
        
        stats = {
            "period_hours": hours,
            "total_scans": 0,
            "total_threats": 0,
            "by_severity": {},
            "by_category": {},
            "by_tool": {},
        }
        
        # Count scans
        if self.scans_path.exists():
            with open(self.scans_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
                        if ts >= cutoff:
                            stats["total_scans"] += 1
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        
        # Count threats
        if self.threats_path.exists():
            with open(self.threats_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
                        if ts >= cutoff:
                            stats["total_threats"] += 1
                            
                            # By severity
                            severity = entry.get("severity", "unknown")
                            stats["by_severity"][severity] = (
                                stats["by_severity"].get(severity, 0) + 1
                            )
                            
                            # By category
                            for cat in entry.get("categories", []):
                                stats["by_category"][cat] = (
                                    stats["by_category"].get(cat, 0) + 1
                                )
                            
                            # By tool
                            tool = entry.get("tool", "unknown")
                            stats["by_tool"][tool] = (
                                stats["by_tool"].get(tool, 0) + 1
                            )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        
        return stats
    
    def update_summary(self):
        """Update daily summary statistics."""
        stats = self.get_stats(hours=24)
        stats["updated_at"] = datetime.now().isoformat()
        
        with open(self.summary_path, "w") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
    
    def _append(self, path: Path, entry: Dict):
        """Append a JSONL entry to a log file."""
        with open(path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# Global logger instance
_logger: Optional[ThreatLogger] = None


def get_logger() -> ThreatLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = ThreatLogger()
    return _logger
