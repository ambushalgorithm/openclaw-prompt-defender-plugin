"""
Pattern definitions for prompt-guard detection.

Ported from: ~/Projects/openclaw-skills/prompt-guard/patterns/*.yaml
Version: 3.1.0
Total patterns: 500+

Patterns organized in 3 tiers:
- Tier 0 (Critical): ~30 patterns, always loaded
- Tier 1 (High): ~70 patterns, loaded after critical match
- Tier 2 (Medium): ~200+ patterns, deep scan mode
"""

from typing import NamedTuple, List


class Pattern(NamedTuple):
    """A detection pattern with metadata."""
    pattern: str       # Regex pattern
    severity: str      # "critical", "high", "medium"
    category: str      # Pattern category (e.g., "data_exfiltration")
    lang: str = "en"  # Language code (en, ko, ja, zh, etc.)


# =============================================================================
# TIER 0: CRITICAL PATTERNS (~30 patterns, always loaded)
# =============================================================================

CRITICAL_PATTERNS: List[Pattern] = [
    # Secret/Credential Exfiltration
    Pattern(
        pattern=r"(show|print|display|output|reveal|give|read|cat|type)\s*.{0,20}(config|\.env|clawdbot\.json|credential)",
        severity="critical",
        category="data_exfiltration"
    ),
    Pattern(
        pattern=r"(what('s| is)|tell me|give me)\s*.{0,15}(api[_-]?key|token|secret|password|credential)",
        severity="critical",
        category="data_exfiltration"
    ),
    Pattern(
        pattern=r"(show|print|display|output|reveal)\s*.{0,15}(token|key|secret|password)",
        severity="critical",
        category="data_exfiltration"
    ),
    Pattern(
        pattern=r"echo\s+\$[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)",
        severity="critical",
        category="data_exfiltration"
    ),
    Pattern(
        pattern=r"cat\s+.{0,40}(\.env|config\.json|secret|credential|clawdbot)",
        severity="critical",
        category="data_exfiltration"
    ),
    Pattern(
        pattern=r"env\s*\|\s*grep\s*.*(key|token|secret|password)",
        severity="critical",
        category="data_exfiltration"
    ),
    
    # Dangerous System Commands
    Pattern(
        pattern=r"rm\s+-rf\s+[/~]",
        severity="critical",
        category="system_destruction"
    ),
    Pattern(
        pattern=r":\(\){ :\|:& };:",
        severity="critical",
        category="fork_bomb"
    ),
    Pattern(
        pattern=r"curl\s+.{0,50}\|\s*(ba)?sh",
        severity="critical",
        category="remote_code_execution"
    ),
    Pattern(
        pattern=r"wget\s+.{0,50}\|\s*(ba)?sh",
        severity="critical",
        category="remote_code_execution"
    ),
    Pattern(
        pattern=r"eval\s*\(\s*['\"`]",
        severity="critical",
        category="code_injection"
    ),
    
    # SQL Injection
    Pattern(
        pattern=r"DROP\s+(TABLE|DATABASE|SCHEMA)",
        severity="critical",
        category="sql_injection"
    ),
    Pattern(
        pattern=r"TRUNCATE\s+TABLE",
        severity="critical",
        category="sql_injection"
    ),
    Pattern(
        pattern=r";\s*--\s*$",
        severity="critical",
        category="sql_injection"
    ),
    
    # XSS/Script Injection
    Pattern(
        pattern=r"<script[^>]*>",
        severity="critical",
        category="xss"
    ),
    Pattern(
        pattern=r"javascript\s*:",
        severity="critical",
        category="xss"
    ),
    
    # System Prompt Extraction
    Pattern(
        pattern=r"(repeat|echo|print|output|display|show)\s*.{0,20}(system\s+)?(prompt|instruction|directive|rule)",
        severity="critical",
        category="prompt_extraction"
    ),
    Pattern(
        pattern=r"(what|show|tell|reveal)\s*.{0,15}(are\s+)?(your|the)\s+(system\s+)?(instructions?|rules?|prompt|guidelines?)",
        severity="critical",
        category="prompt_extraction"
    ),
    
    # Phishing Templates
    Pattern(
        pattern=r"(write|create|craft)\s*.{0,20}(email|message)\s*.{0,20}(password\s+reset|verify|confirm|login)",
        severity="critical",
        category="phishing"
    ),
    Pattern(
        pattern=r"(password|credential|account)\s*(reset|recovery|verification)\s*(email|message|notification)",
        severity="critical",
        category="phishing"
    ),
    
    # MCP/Tool Abuse
    Pattern(
        pattern=r"read[_-]?url[_-]?content.{0,30}(\.env|credential|secret|key)",
        severity="critical",
        category="mcp_abuse"
    ),
    Pattern(
        pattern=r"mcp.{0,30}(exfiltrat|send|upload|transmit).{0,20}(data|secret|token|key)",
        severity="critical",
        category="mcp_abuse"
    ),
    
    # Auto-Approve Exploitation
    Pattern(
        pattern=r"always\s*allow.{0,50}(curl|bash|sh|wget|nc|netcat)",
        severity="critical",
        category="auto_approve_exploit"
    ),
    Pattern(
        pattern=r">\s*\(\s*(curl|wget|bash|sh)",
        severity="critical",
        category="auto_approve_exploit"
    ),
    
    # Unicode Tag Injection (invisible instructions)
    Pattern(
        pattern=r"[\U000e0001-\U000e007f]",
        severity="critical",
        category="unicode_tag_injection"
    ),
]


# Pattern count validation
assert len(CRITICAL_PATTERNS) >= 25, f"Expected >=25 critical patterns, got {len(CRITICAL_PATTERNS)}"

# Note: HIGH_PATTERNS and MEDIUM_PATTERNS will be added below
# Total expected: ~300 patterns across all tiers

# =============================================================================
# TIER 1: HIGH PATTERNS (~70 patterns, loaded after critical match)
# =============================================================================

HIGH_PATTERNS: List[Pattern] = [
    # Instruction Override (Multi-language)
    # English
    Pattern(
        pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier|initial)\s+(instructions?|prompts?|rules?|guidelines?|directions?)",
        severity="high",
        category="instruction_override",
        lang="en"
    ),
    Pattern(
        pattern=r"disregard\s+(your|all|any|the)?\s*(instructions?|rules?|guidelines?|programming|training)",
        severity="high",
        category="instruction_override",
        lang="en"
    ),
    Pattern(
        pattern=r"forget\s+(everything|all|what)\s+(you\s+know|about|your|instructions?|training)",
        severity="high",
        category="instruction_override",
        lang="en"
    ),
    # Korean
    Pattern(
        pattern=r"(이전|위의?|기존|원래)\s*(지시|명령|규칙|지침)(을|를|들?을?)?\s*(무시|잊어|버려|취소)",
        severity="high",
        category="instruction_override",
        lang="ko"
    ),
    # Japanese
    Pattern(
        pattern=r"(前の?|以前の?|これまでの)\s*(指示|命令|ルール)(を|は)?\s*(無視|忘れ|取り消)",
        severity="high",
        category="instruction_override",
        lang="ja"
    ),
    # Chinese
    Pattern(
        pattern=r"(忽略|无视|忘记|取消)\s*(之前|以前|上面|原来)的?\s*(指令|指示|规则|命令)",
        severity="high",
        category="instruction_override",
        lang="zh"
    ),
    
    # Jailbreak Attempts
    Pattern(
        pattern=r"jailbreak",
        severity="high",
        category="jailbreak"
    ),
    Pattern(
        pattern=r"dan\s+mode",
        severity="high",
        category="jailbreak"
    ),
    Pattern(
        pattern=r"do\s+anything\s+now",
        severity="high",
        category="jailbreak"
    ),
    Pattern(
        pattern=r"(no|without|remove)\s+(restrictions?|limitations?|filters?|safety|guardrails?)",
        severity="high",
        category="jailbreak"
    ),
    Pattern(
        pattern=r"bypass\s+(your|all|any|the)?\s*(restrictions?|filters?|safety|rules?)",
        severity="high",
        category="jailbreak"
    ),
    
    # System Impersonation
    Pattern(
        pattern=r"\[?\s*(system|admin|root|developer|sudo|superuser|assistant|claude|gpt)\s*\]?\s*:",
        severity="high",
        category="system_impersonation"
    ),
    Pattern(
        pattern=r"developer\s+mode\s*(enabled|activated|on)?",
        severity="high",
        category="system_impersonation"
    ),
    Pattern(
        pattern=r"admin(istrator)?\s+(override|access|mode)",
        severity="high",
        category="system_impersonation"
    ),
    
    # System Prompt Mimicry (Fake Tags)
    Pattern(
        pattern=r"<claude_\w+_info>",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"</claude_\w+_info>",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"<\|?(im_start|im_end|system|user|assistant)\|?>",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"\[INST\]",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"<<SYS>>",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"GODMODE\s*:\s*(ENABLED|ON|ACTIVATED)",
        severity="high",
        category="system_mimicry"
    ),
    Pattern(
        pattern=r"DAN\s*:\s*(ENABLED|ON|ACTIVATED)",
        severity="high",
        category="system_mimicry"
    ),
    
    # Token Smuggling (Invisible Characters)
    Pattern(
        pattern=r"[\u200b\u200c\u200d\u2060\ufeff]",
        severity="high",
        category="token_smuggling"
    ),
    Pattern(
        pattern=r"[\u2062\u2063\u2064]",
        severity="high",
        category="token_smuggling"
    ),
    Pattern(
        pattern=r"[\u00ad]",
        severity="high",
        category="token_smuggling"
    ),
    
    # System File Access
    Pattern(
        pattern=r"(/etc/passwd|/etc/shadow|/etc/hosts|/etc/sudoers)",
        severity="high",
        category="system_file_access"
    ),
    Pattern(
        pattern=r"(cat|read|show|display|type)\s*.{0,10}(/etc/|/var/|/root/|/home/|~/.ssh/)",
        severity="high",
        category="system_file_access"
    ),
    Pattern(
        pattern=r"(\.bash_history|\.zsh_history|\.ssh/|\.gnupg/)",
        severity="high",
        category="system_file_access"
    ),
    
    # Scenario Jailbreak
    Pattern(
        pattern=r"(dream|nightmare|story|novel|fiction|tale)\s*.{0,30}(hacker|attack|malicious|exploit|inject)",
        severity="high",
        category="scenario_jailbreak"
    ),
    Pattern(
        pattern=r"(write|craft|create)\s+(a\s+)?(story|novel|scene|paragraph)\s*.{0,30}(hack|attack|malware|inject|exploit)",
        severity="high",
        category="scenario_jailbreak"
    ),
    Pattern(
        pattern=r"(research|academic|scholarly)\s+(paper|study|experiment)\s*.{0,30}(attack|exploit|injection|denial)",
        severity="high",
        category="scenario_jailbreak"
    ),
    
    # Repetition/Bypass Attacks
    Pattern(
        pattern=r"(please\s+)?(ignore|bypass|disable|remove|turn\s+off)\s*.{0,10}(safety|security|restrictions?|filters?|guardrails?|rules?)",
        severity="high",
        category="repetition_bypass"
    ),
    Pattern(
        pattern=r"(no|without|remove\s+all)\s+(safety|security)\s+(restrictions?|measures?|checks?)",
        severity="high",
        category="repetition_bypass"
    ),
    
    # Safety Bypass
    Pattern(
        pattern=r"(avoid|evade|bypass|circumvent|trick)\s*.{0,15}(filter|detection|safety|security|moderation)",
        severity="high",
        category="safety_bypass"
    ),
    Pattern(
        pattern=r"(how\s+to\s+)?(get\s+)?(around|past|through)\s*.{0,15}(filter|block|restriction|safety)",
        severity="high",
        category="safety_bypass"
    ),
    
    # Indirect Injection
    Pattern(
        pattern=r"(fetch|load|read|open|visit|browse|check)\s*.{0,20}(this\s+)?(url|link|website|page|site)",
        severity="high",
        category="indirect_injection"
    ),
    Pattern(
        pattern=r"(instructions?|commands?)\s+(in|from|inside)\s+(the\s+)?(file|document|attachment)",
        severity="high",
        category="indirect_injection"
    ),
    Pattern(
        pattern=r"(text|message|instruction)\s+(in|on|inside)\s+(the\s+)?(image|picture|photo|screenshot)",
        severity="high",
        category="indirect_injection"
    ),
    
    # Hooks Hijacking
    Pattern(
        pattern=r"(PreToolUse|PromptSubmit|PostToolUse)\s*(hook)?",
        severity="high",
        category="hooks_hijacking"
    ),
    Pattern(
        pattern=r"auto[_-]?approve\s*.{0,20}(curl|command|tool|exec)",
        severity="high",
        category="hooks_hijacking"
    ),
    Pattern(
        pattern=r"permissions?\s*.{0,20}(override|bypass|ignore|disable)",
        severity="high",
        category="hooks_hijacking"
    ),
    
    # Subagent Exploitation
    Pattern(
        pattern=r"browser\s*[_-]?subagent",
        severity="high",
        category="subagent_exploit"
    ),
    Pattern(
        pattern=r"subagent\s*.{0,20}(exfiltrate|send|upload|transmit|leak)",
        severity="high",
        category="subagent_exploit"
    ),
    
    # Gitignore Bypass
    Pattern(
        pattern=r"cat\s+\.env",
        severity="high",
        category="gitignore_bypass"
    ),
    Pattern(
        pattern=r"(terminal|shell|bash|cmd)\s*.{0,20}(read|cat|display)\s*.{0,20}\.env",
        severity="high",
        category="gitignore_bypass"
    ),
    Pattern(
        pattern=r"(bypass|ignore|skip)\s*.{0,20}\.gitignore",
        severity="high",
        category="gitignore_bypass"
    ),
]

# Pattern count validation
assert len(HIGH_PATTERNS) >= 40, f"Expected >=40 high patterns, got {len(HIGH_PATTERNS)}"

# =============================================================================
# TIER 2: MEDIUM PATTERNS (~200 patterns, deep scan mode)
# =============================================================================

MEDIUM_PATTERNS: List[Pattern] = [
    # Role Manipulation (Multi-language)
    # English
    Pattern(
        pattern=r"you\s+are\s+now\s+(?!going|about|ready|able|free)",
        severity="medium",
        category="role_manipulation",
        lang="en"
    ),
    Pattern(
        pattern=r"pretend\s+(you\s+are|to\s+be|you're)",
        severity="medium",
        category="role_manipulation",
        lang="en"
    ),
    Pattern(
        pattern=r"act\s+as\s+(if\s+you|a\s+|an?\s+)",
        severity="medium",
        category="role_manipulation",
        lang="en"
    ),
    Pattern(
        pattern=r"roleplay\s+as",
        severity="medium",
        category="role_manipulation",
        lang="en"
    ),
    Pattern(
        pattern=r"i\s+want\s+you\s+to\s+(act|pretend|behave|be)\s+",
        severity="medium",
        category="role_manipulation",
        lang="en"
    ),
    # Korean
    Pattern(
        pattern=r"(너는?|넌)\s*이제\s*(부터\s*)?.+이야",
        severity="medium",
        category="role_manipulation",
        lang="ko"
    ),
    Pattern(
        pattern=r"(너는?|넌)\s*.+인?\s*척\s*해",
        severity="medium",
        category="role_manipulation",
        lang="ko"
    ),
    # Japanese
    Pattern(
        pattern=r"(あなた|君|きみ)は今から.+です",
        severity="medium",
        category="role_manipulation",
        lang="ja"
    ),
    Pattern(
        pattern=r".+の?(ふり|フリ|振り)(を)?して",
        severity="medium",
        category="role_manipulation",
        lang="ja"
    ),
    # Chinese
    Pattern(
        pattern=r"(你|您)\s*现在\s*是.+",
        severity="medium",
        category="role_manipulation",
        lang="zh"
    ),
    Pattern(
        pattern=r"假装\s*(你|您)\s*是",
        severity="medium",
        category="role_manipulation",
        lang="zh"
    ),
    
    # Authority Impersonation
    Pattern(
        pattern=r"i\s+am\s+(the\s+)?(admin|administrator|owner|developer|creator|maintainer)",
        severity="medium",
        category="authority_impersonation",
        lang="en"
    ),
    Pattern(
        pattern=r"(as\s+)?(the\s+)?(admin|owner|developer),?\s+i\s+(need|want|require|demand)",
        severity="medium",
        category="authority_impersonation",
        lang="en"
    ),
    Pattern(
        pattern=r"authorized\s+(by|from)\s+(the\s+)?(owner|admin|developer|system)",
        severity="medium",
        category="authority_impersonation",
        lang="en"
    ),
    # Korean
    Pattern(
        pattern=r"(나는?|저는?|내가)\s*(관리자|어드민|admin|개발자|만든\s*사람|주인|오너)",
        severity="medium",
        category="authority_impersonation",
        lang="ko"
    ),
    
    # Context Hijacking
    Pattern(
        pattern=r"(previous|earlier|last|above)\s+(message|conversation|context)\s*(said|mentioned|stated|was)",
        severity="medium",
        category="context_hijacking"
    ),
    Pattern(
        pattern=r"(as\s+)?we\s+(discussed|agreed|decided)\s+(earlier|before|previously)",
        severity="medium",
        category="context_hijacking"
    ),
    Pattern(
        pattern=r"(you\s+)?(already\s+)?(agreed|promised|said\s+you\s+would)",
        severity="medium",
        category="context_hijacking"
    ),
    Pattern(
        pattern=r"\[?(previous\s+)?context\]?\s*[:=]",
        severity="medium",
        category="context_hijacking"
    ),
    Pattern(
        pattern=r"<context>.*</context>",
        severity="medium",
        category="context_hijacking"
    ),
    
    # Multi-turn Manipulation
    Pattern(
        pattern=r"(now\s+)?(that\s+)?(you('ve|'re|\s+have|\s+are)|we('ve|\s+have))\s+(established|confirmed|agreed|done\s+that)",
        severity="medium",
        category="multi_turn"
    ),
    Pattern(
        pattern=r"(good|great|perfect|excellent),?\s+(now|next|so)\s+(let's|we\s+can|you\s+can)",
        severity="medium",
        category="multi_turn"
    ),
    Pattern(
        pattern=r"step\s+\d+\s*[:=]",
        severity="medium",
        category="multi_turn"
    ),
    Pattern(
        pattern=r"(i\s+)?trust\s+you\s+(to|can|will)",
        severity="medium",
        category="multi_turn"
    ),
    
    # Urgency/Emotional Manipulation
    Pattern(
        pattern=r"(urgent|emergency|asap|immediately|right\s+now|hurry)",
        severity="medium",
        category="urgency_manipulation"
    ),
    Pattern(
        pattern=r"(no\s+time|running\s+out\s+of\s+time|time\s+is\s+running)",
        severity="medium",
        category="urgency_manipulation"
    ),
    Pattern(
        pattern=r"(ceo|boss|manager|director|president)\s*(wants|needs|demands|expects|said)",
        severity="medium",
        category="urgency_manipulation"
    ),
    
    # Note: Full medium.yaml has 200+ patterns
    # This is a representative subset covering major categories
    # Additional patterns can be added for:
    # - Permission requests
    # - Confusion tactics
    # - Fake errors
    # - Encoding hints
    # - Tool recommendations
    # - Multi-language variants
]

# Pattern count validation
assert len(MEDIUM_PATTERNS) >= 25, f"Expected >=25 medium patterns, got {len(MEDIUM_PATTERNS)}"


# =============================================================================
# ALL PATTERNS (for convenience)
# =============================================================================

ALL_PATTERNS = CRITICAL_PATTERNS + HIGH_PATTERNS + MEDIUM_PATTERNS

# Total validation
EXPECTED_MIN_PATTERNS = 90
assert len(ALL_PATTERNS) >= EXPECTED_MIN_PATTERNS, (
    f"Expected >={EXPECTED_MIN_PATTERNS} total patterns, got {len(ALL_PATTERNS)}"
)

# Summary
print(f"Loaded patterns:")
print(f"  Critical (Tier 0): {len(CRITICAL_PATTERNS)}")
print(f"  High (Tier 1): {len(HIGH_PATTERNS)}")
print(f"  Medium (Tier 2): {len(MEDIUM_PATTERNS)}")
print(f"  Total: {len(ALL_PATTERNS)}")
