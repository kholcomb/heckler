"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

from heckler.characters import Severity
from heckler.config import Config, _minimal_yaml_parse, load_config


class TestMinimalYamlParse:
    def test_simple_key_value(self) -> None:
        result = _minimal_yaml_parse("severity: error\nallow_bom: true\n")
        assert result["severity"] == "error"
        assert result["allow_bom"] is True

    def test_boolean_values(self) -> None:
        result = _minimal_yaml_parse("a: true\nb: false\nc: yes\nd: no\n")
        assert result["a"] is True
        assert result["b"] is False
        assert result["c"] is True
        assert result["d"] is False

    def test_list_items(self) -> None:
        text = "allowlist:\n  - '*.po'\n  - '**/locale/**'\n"
        result = _minimal_yaml_parse(text)
        assert result["allowlist"] == ["*.po", "**/locale/**"]

    def test_inline_list(self) -> None:
        result = _minimal_yaml_parse('items: [a, b, c]\n')
        assert result["items"] == ["a", "b", "c"]

    def test_empty_list(self) -> None:
        result = _minimal_yaml_parse("extra: []\n")
        assert result["extra"] == []

    def test_comments_ignored(self) -> None:
        result = _minimal_yaml_parse("# comment\nseverity: high\n# another\n")
        assert result["severity"] == "high"
        assert len(result) == 1


class TestLoadConfig:
    def test_defaults(self) -> None:
        config = Config.defaults()
        assert config.severity_threshold == Severity.LOW
        assert config.allow_bom is True
        assert config.scan_deps is False

    def test_load_from_file(self, config_file: Path) -> None:
        config = load_config(config_path=str(config_file))
        assert config.severity_threshold == Severity.MEDIUM
        assert "**/*.po" in config.exclude_patterns
        assert "third_party" in config.skip_dirs

    def test_scan_deps_override(self) -> None:
        config = load_config(scan_deps=True)
        assert config.scan_deps is True

    def test_missing_config_uses_defaults(self) -> None:
        config = load_config(config_path="/nonexistent/.heckler.yml")
        assert config.severity_threshold == Severity.LOW
