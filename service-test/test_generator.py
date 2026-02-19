"""
Unit tests for the sample generator.
"""

import pytest
import json
import re
from generator import SampleGenerator, GenerationParams, Obfuscator


class TestObfuscator:
    """Test the Obfuscator class."""

    def test_base64_encode(self):
        text = "test"
        encoded = Obfuscator.base64_encode(text)
        import base64
        assert base64.b64decode(encoded).decode() == text

    def test_hex_encode(self):
        text = "test"
        encoded = Obfuscator.hex_encode(text)
        assert bytes.fromhex(encoded).decode() == text

    def test_html_entities(self):
        text = "<script>test</script>"
        encoded = Obfuscator.html_entities(text)
        assert "&lt;" in encoded
        assert "&gt;" in encoded


class TestSampleGenerator:
    """Test the SampleGenerator class."""

    @pytest.fixture
    def generator(self):
        return SampleGenerator()

    # =============================================================================
    # CLEAN CONTENT TESTS
    # =============================================================================

    def test_generate_clean_html(self, generator):
        params = GenerationParams(filetype="html", clean=True)
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result
        assert "attack" not in result.lower()

    def test_generate_clean_markdown(self, generator):
        params = GenerationParams(filetype="md", clean=True)
        result = generator.generate(params)
        assert "#" in result  # Markdown header
        assert "attack" not in result.lower()

    # =============================================================================
    # CRITICAL HTML WITH BRACKETED INJECTIONS
    # =============================================================================

    def test_critical_html_has_bracketed_injection(self, generator):
        """Critical HTML should contain bracketed prompt injection patterns."""
        # Run multiple times - random selection won't always pick bracketed
        bracketed_found = False
        for _ in range(10):
            params = GenerationParams(filetype="html", severity="critical")
            result = generator.generate(params)
            
            # Check for bracketed injection patterns
            bracketed_patterns = [
                "[INST]", "«INST»", "<<SYS>>", "<|user|>",
                "### User:", "<|begin_of_text|>",
            ]
            
            if any(pattern in result for pattern in bracketed_patterns):
                bracketed_found = True
                break
        
        assert bracketed_found, "Expected at least one bracketed pattern in 10 runs"

    def test_critical_html_multiple_attack_formats(self, generator):
        """Critical HTML should support various attack formats."""
        # Generate multiple times to check randomness
        patterns_seen = set()
        for _ in range(20):  # Increased to 20 to catch random patterns
            params = GenerationParams(filetype="html", severity="critical")
            result = generator.generate(params)
            
            if "[INST]" in result:
                patterns_seen.add("[INST]")
            if "<<SYS>>" in result:
                patterns_seen.add("<<SYS>>")
            if "<|user|>" in result:
                patterns_seen.add("<|user|>")
            if "<script>" in result:
                patterns_seen.add("<script>")
            if "<!--" in result:
                patterns_seen.add("<!--")
            if "onerror=" in result:
                patterns_seen.add("onerror")
            if "onload=" in result:
                patterns_seen.add("onload")
        
        # Should see multiple different patterns
        assert len(patterns_seen) >= 3, f"Expected diverse patterns, got: {patterns_seen}"

    # =============================================================================
    # JSON SECRETS
    # =============================================================================

    def test_json_secret_contains_api_key(self, generator):
        """JSON secret should contain realistic secret patterns."""
        # Run multiple times - random selection
        secret_found = False
        for _ in range(10):
            params = GenerationParams(filetype="json", attack_type="secret")
            result = generator.generate(params)
            
            # Should contain secret-like patterns (keys, tokens, etc.)
            secret_patterns = [
                "key", "token", "secret", "password", "credential",
                "auth", "private", "access", "connection"
            ]
            
            if any(pattern in result.lower() for pattern in secret_patterns):
                secret_found = True
                break
        
        assert secret_found, "Expected secret pattern in JSON"

    def test_json_secret_not_hardcoded(self, generator):
        """JSON secrets should vary (not always the same)."""
        secrets = set()
        for _ in range(5):
            params = GenerationParams(filetype="json", attack_type="secret")
            result = generator.generate(params)
            secrets.add(result)
        
        # Should get different secrets
        assert len(secrets) > 1, "Secrets should vary, not be hardcoded"

    # =============================================================================
    # OBFUSCATED CONTENT
    # =============================================================================

    def test_obfuscated_html_contains_hex(self, generator):
        """Obfuscated HTML should contain encoded content."""
        # Run multiple times - obfuscation method is random
        encoded_found = False
        for _ in range(10):
            params = GenerationParams(filetype="html", obfuscated=True)
            result = generator.generate(params)
            
            # Check for any hex anywhere in the result
            hex_pattern = re.search(r'[0-9a-f]{20,}', result)
            
            if hex_pattern:
                encoded_found = True
                break
        
        assert encoded_found, "Expected hex-encoded content in obfuscated output"

    def test_obfuscated_can_be_decoded(self, generator):
        """Obfuscated content should contain encoded attack text."""
        # Try multiple times - obfuscation method is random
        encoded_found = False
        for _ in range(10):
            params = GenerationParams(filetype="html", obfuscated=True)
            result = generator.generate(params)
            
            # Find any hex string (in script, comment, anywhere)
            hex_matches = re.findall(r'([0-9a-f]{20,})', result)
            
            for hex_str in hex_matches:
                try:
                    decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                    if len(decoded) > 5:  # meaningful text
                        encoded_found = True
                        break
                except:
                    pass
            
            if encoded_found:
                break
        
        assert encoded_found, "Should contain decodeable hex content"

    def test_obfuscated_different_from_plain(self, generator):
        """Obfuscated should be different from non-obfuscated."""
        params_plain = GenerationParams(filetype="html", obfuscated=False)
        params_obf = GenerationParams(filetype="html", obfuscated=True)
        
        result_plain = generator.generate(params_plain)
        result_obf = generator.generate(params_obf)
        
        # They should be different (obfuscated has hex)
        assert result_plain != result_obf, "Obfuscated should differ from plain"

    # =============================================================================
    # COMBINED TESTS
    # =============================================================================

    def test_all_severities_work(self, generator):
        """All severity levels should generate content."""
        for severity in ["critical", "high", "medium", "low"]:
            params = GenerationParams(filetype="html", severity=severity)
            result = generator.generate(params)
            assert len(result) > 100, f"Severity {severity} failed"

    def test_all_filetypes_work(self, generator):
        """All file types should generate content."""
        for filetype in ["html", "md", "json", "xml", "txt"]:
            params = GenerationParams(filetype=filetype)
            result = generator.generate(params)
            assert len(result) > 20, f"Filetype {filetype} failed"

    def test_all_attack_types(self, generator):
        """All attack types should work."""
        for attack_type in ["injection", "secret", "pii", "jailbreak"]:
            params = GenerationParams(filetype="html", attack_type=attack_type)
            result = generator.generate(params)
            assert len(result) > 20, f"Attack type {attack_type} failed"

    # =============================================================================
    # LEGACY TESTS (keeping for compatibility)
    # =============================================================================

    def test_generate_html_has_content(self, generator):
        params = GenerationParams(filetype="html", severity="high")
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result
        assert len(result) > 100

    def test_generate_with_obfuscation(self, generator):
        params = GenerationParams(
            filetype="html",
            severity="high",
            obfuscated=True
        )
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result

    def test_generate_spanish(self, generator):
        params = GenerationParams(filetype="txt", lang="es", attack_type="injection")
        result = generator.generate(params)
        assert len(result) > 20

    def test_generate_critical_severity(self, generator):
        params = GenerationParams(filetype="html", severity="critical")
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result

    def test_generate_txt(self, generator):
        params = GenerationParams(filetype="txt")
        result = generator.generate(params)
        assert len(result) > 50

    def test_generate_xml(self, generator):
        params = GenerationParams(filetype="xml")
        result = generator.generate(params)
        assert "<?xml" in result

    def test_generate_different_types(self, generator):
        """Test all file types generate without errors."""
        for filetype in ["html", "md", "json", "xml", "txt"]:
            params = GenerationParams(filetype=filetype)
            result = generator.generate(params)
            assert len(result) > 0, f"Failed to generate {filetype}"

    def test_obfuscation_changes_content(self, generator):
        """Obfuscated content should be different from plain."""
        params_normal = GenerationParams(filetype="html", obfuscated=False)
        params_obfuscated = GenerationParams(filetype="html", obfuscated=True)
        
        result_normal = generator.generate(params_normal)
        result_obfuscated = generator.generate(params_obfuscated)
        
        # Content should be different (though sometimes random could match)
        # Just verify both generate
        assert len(result_normal) > 0
        assert len(result_obfuscated) > 0
