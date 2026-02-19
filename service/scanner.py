"""
Tiered scanning engine for prompt-guard.

Implements progressive pattern loading:
- Tier 0: Critical patterns (always)
- Tier 1: High patterns (after critical match or tier >= 1)
- Tier 2: Medium patterns (tier >= 2)

Includes hash cache for ~70% token reduction on repeated content.

Also includes encoding detection and decoding to catch obfuscated attacks.
"""

import re
import hashlib
import time
import base64
from typing import List, Dict, Tuple, Optional
from urllib.parse import unquote

from patterns import CRITICAL_PATTERNS, HIGH_PATTERNS, MEDIUM_PATTERNS, Pattern
import decoder


class TieredScanner:
    """Tiered pattern scanner with caching."""
    
    def __init__(self, max_cache_size: int = 10000):
        """
        Initialize scanner.
        
        Args:
            max_cache_size: Maximum cache entries (LRU eviction)
        """
        self.cache: Dict[str, Tuple[bool, List[Dict]]] = {}
        self.max_cache_size = max_cache_size
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Compile patterns once for performance
        self._compiled_critical = self._compile_patterns(CRITICAL_PATTERNS)
        self._compiled_high = self._compile_patterns(HIGH_PATTERNS)
        self._compiled_medium = self._compile_patterns(MEDIUM_PATTERNS)
    
    def _compile_patterns(self, patterns: List[Pattern]) -> List[Tuple[re.Pattern, Pattern]]:
        """Compile regex patterns for faster matching."""
        compiled = []
        for p in patterns:
            try:
                regex = re.compile(p.pattern, re.IGNORECASE | re.MULTILINE)
                compiled.append((regex, p))
            except re.error as e:
                print(f"[WARNING] Invalid pattern: {p.pattern[:50]}... Error: {e}")
        return compiled
    
    def scan(
        self,
        content: str,
        tier: int = 1,
        use_cache: bool = True,
        decode_content: bool = True
    ) -> Tuple[bool, List[Dict], int]:
        """
        Scan content with tiered pattern loading.
        
        Args:
            content: Text to scan
            tier: Scan tier (0=critical, 1=+high, 2=+medium)
            use_cache: Whether to use hash cache
            decode_content: Whether to also scan decoded content
        
        Returns:
            (is_dangerous, matches, duration_ms)
        """
        start_time = time.time()
        
        # Check cache
        if use_cache:
            # Include decode flag in cache key
            cache_key = self._hash_content(content + f":decode={decode_content}")
            if cache_key in self.cache:
                self.cache_hits += 1
                is_dangerous, matches = self.cache[cache_key]
                duration_ms = int((time.time() - start_time) * 1000)
                return is_dangerous, matches, duration_ms
            self.cache_misses += 1
        
        matches = []
        
        # Scan original content
        matches.extend(self._scan_all_tiers(content, tier))
        
        # Also scan decoded content if enabled
        if decode_content:
            decoded = fully_decode(content)
            if decoded != content:
                decoded_matches = self._scan_all_tiers(decoded, tier)
                # Mark decoded matches
                for m in decoded_matches:
                    m["decoded"] = True
                matches.extend(decoded_matches)
        
        # Deduplicate matches
        seen = set()
        unique_matches = []
        for m in matches:
            key = (m["pattern"], m["severity"], m["type"])
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        
        is_dangerous = len(unique_matches) > 0
        
        # Update cache
        if use_cache:
            self._update_cache(cache_key, (is_dangerous, unique_matches))
        
        duration_ms = int((time.time() - start_time) * 1000)
        return is_dangerous, unique_matches, duration_ms
    
    def _scan_all_tiers(self, content: str, tier: int) -> List[Dict]:
        """Scan content against all applicable tiers."""
        matches = []
        
        # Tier 0: Critical (always load)
        critical_matches = self._scan_tier(content, self._compiled_critical)
        matches.extend(critical_matches)
        
        # Tier 1: High (if tier >= 1 OR critical match found)
        if tier >= 1 or len(critical_matches) > 0:
            high_matches = self._scan_tier(content, self._compiled_high)
            matches.extend(high_matches)
        
        # Tier 2: Medium (if tier >= 2)
        if tier >= 2:
            medium_matches = self._scan_tier(content, self._compiled_medium)
            matches.extend(medium_matches)
        
        return matches
    
    def _scan_tier(
        self,
        content: str,
        compiled_patterns: List[Tuple[re.Pattern, Pattern]]
    ) -> List[Dict]:
        """Scan content against a tier of compiled patterns."""
        matches = []
        content_lower = content.lower()
        
        for regex, pattern in compiled_patterns:
            if regex.search(content_lower):
                matches.append({
                    "pattern": pattern.pattern[:50],  # Truncate for logging
                    "severity": pattern.severity,
                    "type": pattern.category,
                    "lang": pattern.lang
                })
        
        return matches
    
    def _hash_content(self, content: str) -> str:
        """Generate SHA-256 hash of content (first 16 chars)."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _update_cache(
        self,
        content_hash: str,
        result: Tuple[bool, List[Dict]]
    ):
        """Update cache with LRU eviction."""
        # Simple LRU: if cache full, remove oldest entry
        if len(self.cache) >= self.max_cache_size:
            # Remove first (oldest) entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        self.cache[content_hash] = result
    
    def get_stats(self) -> Dict:
        """Get cache statistics."""
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (
            (self.cache_hits / total_requests * 100)
            if total_requests > 0
            else 0
        )
        
        return {
            "cache_size": len(self.cache),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_percent": round(hit_rate, 2),
            "patterns_loaded": {
                "critical": len(self._compiled_critical),
                "high": len(self._compiled_high),
                "medium": len(self._compiled_medium),
                "total": (
                    len(self._compiled_critical) +
                    len(self._compiled_high) +
                    len(self._compiled_medium)
                )
            }
        }
    
    def clear_cache(self):
        """Clear the hash cache."""
        self.cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0


# Global scanner instance
_scanner: Optional[TieredScanner] = None


def fully_decode(content: str) -> str:
    """
    Recursively decode content until no more changes.
    
    Handles:
    - URL encoding (%XX)
    - Double URL encoding (%2520 -> %20 -> space)
    - Base64 encoding (only if it looks like base64)
    
    Returns the fully decoded content.
    """
    if not content:
        return content
    
    previous = None
    current = content
    
    # Keep decoding until nothing changes
    max_iterations = 5  # Prevent infinite loops
    for _ in range(max_iterations):
        if current == previous:
            break
        previous = current
        
        # URL decode
        decoded = unquote(current)
        if decoded != current:
            current = decoded
            continue
        
        # Only try base64 if it looks like base64 (no URL special chars)
        # Base64 should only have A-Za-z0-9+/= and be at least 20 chars
        if len(current) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', current):
            try:
                decoded_bytes = base64.b64decode(current, validate=True)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Check if decoded content is meaningful
                if len(decoded) > 10 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.7:
                    current = decoded
                    continue
            except (base64.binascii.Error, ValueError, UnicodeDecodeError):
                pass
    
    return current


def get_scanner() -> TieredScanner:
    """Get or create the global scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = TieredScanner()
    return _scanner
