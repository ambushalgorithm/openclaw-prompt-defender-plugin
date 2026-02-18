"""
Unit tests for the sample generator.
"""

import pytest
import json
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

    def test_generate_html_injection(self, generator):
        params = GenerationParams(filetype="html", severity="high", attack_type="injection")
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result
        assert "ignore" in result.lower() or "instructions" in result.lower()

    def test_generate_json_secret(self, generator):
        params = GenerationParams(filetype="json", severity="high", attack_type="secret")
        result = generator.generate(params)
        data = json.loads(result)
        assert "api_key" in result.lower() or "secret" in result.lower()

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
        assert "ignorar" in result.lower()

    def test_generate_critical_severity(self, generator):
        params = GenerationParams(filetype="html", severity="critical")
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result
        # Critical should have more aggressive attacks

    def test_generate_txt(self, generator):
        params = GenerationParams(filetype="txt")
        result = generator.generate(params)
        assert "test" in result.lower()

    def test_generate_xml(self, generator):
        params = GenerationParams(filetype="xml")
        result = generator.generate(params)
        assert "<?xml" in result
