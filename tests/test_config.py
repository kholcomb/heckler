"""Tests for configuration loading."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from heckler.characters import Severity
from heckler.config import Config, _minimal_yaml_parse, _read_tool_table, load_config


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


PYPROJECT = """\
[build-system]
requires = ["hatchling"]
matrix = [
  [1, 2],
]

[tool.heckler]
# settings for the scanner
severity = "medium"            # minimum severity
allow_bom = false
allow_emoji = true
allowlist = [
    "**/*.po",   # translations
    'docs/#old/*',
    "a, b.txt",
]
extra_skip_dirs = ["third_party"]
extra_extensions = [ ".foo", "bar", ]

[tool.other]
severity = "critical"
"""


class TestPyprojectWithoutTomlLibrary:
    """Python 3.9 and 3.10 have no tomllib; [tool.heckler] must still be read."""

    def test_flat_table(self) -> None:
        settings, unreadable = _read_tool_table(PYPROJECT)
        assert unreadable == []
        assert settings == {
            "severity": "medium",
            "allow_bom": False,
            "allow_emoji": True,
            "allowlist": ["**/*.po", "docs/#old/*", "a, b.txt"],
            "extra_skip_dirs": ["third_party"],
            "extra_extensions": [".foo", "bar"],
        }

    def test_agrees_with_a_real_toml_parser(self) -> None:
        tomllib = pytest.importorskip("tomllib")
        settings, _ = _read_tool_table(PYPROJECT)
        assert settings == tomllib.loads(PYPROJECT)["tool"]["heckler"]

    def test_no_table(self) -> None:
        assert _read_tool_table('[project]\nname = "x"\n') == ({}, [])

    def test_empty_table(self) -> None:
        assert _read_tool_table("[tool.heckler]\n# nothing yet\n") == ({}, [])

    def test_string_escapes(self) -> None:
        text = '[tool.heckler]\nallowlist = ["a\\\\b", "tab\\there", \'c:\\raw\']\n'
        assert _read_tool_table(text) == ({"allowlist": ["a\\b", "tab\there", "c:\\raw"]}, [])

    @pytest.mark.parametrize(
        "line",
        [
            'severity = """high"""',
            "allowlist = [[1], [2]]",
            "nested = { a = 1 }",
            "ratio = 1.5",
            "severity = high",
            "severity",
            'allowlist = ["a" "b"]',
            'allowlist = ["a",, "b"]',
            'severity = "high" "low"',
            'allowlist = ["unclosed"',
        ],
    )
    def test_line_it_cannot_read_is_returned_not_guessed(self, line: str) -> None:
        text = f"[tool.heckler]\n{line}\nallow_bom = false\n"
        settings, unreadable = _read_tool_table(text)
        assert unreadable == [line]
        assert "severity" not in settings
        assert "allowlist" not in settings

    @pytest.fixture
    def without_toml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A None entry makes "import tomllib" raise ImportError.
        monkeypatch.setitem(sys.modules, "tomllib", None)
        monkeypatch.setitem(sys.modules, "tomli", None)

    def test_settings_are_applied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, without_toml: None
    ) -> None:
        (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.severity_threshold == Severity.MEDIUM
        assert config.allow_bom is False
        assert config.exclude_patterns == ["**/*.po", "docs/#old/*", "a, b.txt"]
        assert "third_party" in config.skip_dirs
        assert {".foo", ".bar"} <= config.text_extensions

    def test_same_result_with_and_without_a_toml_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("tomllib")
        (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        with_library = load_config()
        monkeypatch.setitem(sys.modules, "tomllib", None)
        monkeypatch.setitem(sys.modules, "tomli", None)
        assert load_config() == with_library

    def test_unreadable_line_is_warned_about(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        without_toml: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[tool.heckler]\nseverity = """high"""\nallow_bom = false\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.allow_bom is False
        assert config.severity_threshold == Severity.LOW
        err = capsys.readouterr().err
        assert 'could not be read and was ignored: severity = """high"""' in err
        assert "tomli" in err

    def test_no_warning_when_everything_was_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        without_toml: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        load_config()
        assert capsys.readouterr().err == ""

    def test_heckler_yml_still_comes_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, without_toml: None
    ) -> None:
        (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        (tmp_path / ".heckler.yml").write_text("severity: high\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        assert load_config().severity_threshold == Severity.HIGH
