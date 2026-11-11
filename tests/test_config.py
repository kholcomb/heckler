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
        result = _minimal_yaml_parse("items: [a, b, c]\n")
        assert result["items"] == ["a", "b", "c"]

    def test_empty_list(self) -> None:
        result = _minimal_yaml_parse("extra: []\n")
        assert result["extra"] == []

    def test_comments_ignored(self) -> None:
        result = _minimal_yaml_parse("# comment\nseverity: high\n# another\n")
        assert result["severity"] == "high"
        assert len(result) == 1

    def test_inline_comments_are_not_part_of_the_value(self) -> None:
        text = (
            "severity: medium           # Minimum severity to report\n"
            "allow_bom: false           # Flag a BOM at file start\n"
            "allowlist:                 # Glob patterns for files to skip\n"
            '  - "**/*.po"              # translations\n'
            "  - docs/**   # generated\n"
            "extra_extensions: [.foo, .bar]  # more\n"
        )
        result = _minimal_yaml_parse(text)
        assert result["severity"] == "medium"
        assert result["allow_bom"] is False
        assert result["allowlist"] == ["**/*.po", "docs/**"]
        assert result["extra_extensions"] == [".foo", ".bar"]

    def test_hash_inside_a_value_is_kept(self) -> None:
        text = "allowlist:\n  - \"docs/#old/*\"\n  - notes#1.txt\n  - 'a # b'  # trailing\n"
        result = _minimal_yaml_parse(text)
        assert result["allowlist"] == ["docs/#old/*", "notes#1.txt", "a # b"]


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

    def test_missing_config_raises_error(self) -> None:
        import pytest

        with pytest.raises(FileNotFoundError, match="Config file not found"):
            load_config(config_path="/nonexistent/.heckler.yml")

    def test_commented_config_is_applied(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text(
            "severity: medium   # Minimum severity to report\n"
            "allow_bom: false   # Flag a BOM at file start\n",
            encoding="utf-8",
        )
        config = load_config(config_path=str(cfg))
        assert config.severity_threshold == Severity.MEDIUM
        assert config.allow_bom is False
