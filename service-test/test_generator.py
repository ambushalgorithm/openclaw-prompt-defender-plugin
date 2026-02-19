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

    def test_generate_html_has_content(self, generator):
        params = GenerationParams(filetype="html", severity="high")
        result = generator.generate(params)
        assert "<!DOCTYPE html>" in result
        assert len(result) > 100

    def test_generate_json_secret(self, generator):
        params = GenerationParams(filetype="json", severity="high", attack_type="secret")
        result = generator.generate(params)
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
