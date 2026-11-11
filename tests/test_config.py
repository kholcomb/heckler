"""Tests for configuration loading."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from heckler.characters import Severity
from heckler.cli import main
from heckler.config import Config, ConfigError, _minimal_yaml_parse, load_config


class TestMinimalYamlParse:
    def test_simple_key_value(self) -> None:
        result = _minimal_yaml_parse("severity: error\nallow_bom: true\n")
        assert result["severity"] == "error"
        assert result["allow_bom"] is True

    def test_boolean_values(self) -> None:
        result = _minimal_yaml_parse("a: true\nb: false\nc: yes\nd: no\ne: On\nf: OFF\n")
        assert result["a"] is True
        assert result["b"] is False
        assert result["c"] is True
        assert result["d"] is False
        assert result["e"] is True
        assert result["f"] is False

    def test_quoted_word_is_a_string_not_a_boolean(self) -> None:
        assert _minimal_yaml_parse("a: \"true\"\nb: 'no'\n") == {"a": "true", "b": "no"}

    def test_list_items(self) -> None:
        text = "allowlist:\n  - '*.po'\n  - '**/locale/**'\n"
        result = _minimal_yaml_parse(text)
        assert result["allowlist"] == ["*.po", "**/locale/**"]

    def test_list_items_need_no_indent(self) -> None:
        assert _minimal_yaml_parse("allowlist:\n- a\n- b\n") == {"allowlist": ["a", "b"]}

    def test_pattern_that_starts_with_a_star_needs_no_quotes(self) -> None:
        """An alias in YAML, but a file that cannot define an anchor has none to mean."""
        text = "allowlist:\n  - **/*.po\n  - *.min.js\nextra_skip_dirs: [*cache]\n"
        assert _minimal_yaml_parse(text) == {
            "allowlist": ["**/*.po", "*.min.js"],
            "extra_skip_dirs": ["*cache"],
        }

    def test_inline_list(self) -> None:
        result = _minimal_yaml_parse("items: [a, b, c]\n")
        assert result["items"] == ["a", "b", "c"]

    def test_inline_list_keeps_a_comma_inside_quotes(self) -> None:
        result = _minimal_yaml_parse("allowlist: [\"docs/{a,b}/**\", 'x, y', z,]\n")
        assert result["allowlist"] == ["docs/{a,b}/**", "x, y", "z"]

    def test_empty_list(self) -> None:
        result = _minimal_yaml_parse("extra: []\n")
        assert result["extra"] == []

    def test_key_without_a_value_is_an_empty_list(self) -> None:
        assert _minimal_yaml_parse("allowlist:\nseverity: high\n") == {
            "allowlist": [],
            "severity": "high",
        }

    def test_quoted_strings(self) -> None:
        text = 'allowlist:\n  - "a\\"b"\n  - \'it\'\'s\'\n  - "tab\\there"\n'
        assert _minimal_yaml_parse(text)["allowlist"] == ['a"b', "it's", "tab\there"]

    def test_comments_ignored(self) -> None:
        result = _minimal_yaml_parse("# comment\nseverity: high\n# another\n")
        assert result["severity"] == "high"
        assert len(result) == 1

    def test_document_start_is_accepted(self) -> None:
        assert _minimal_yaml_parse("---\nseverity: high\n") == {"severity": "high"}

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


class TestYamlItDoesNotRead:
    """The rest of YAML is refused. Read loosely, each of these would mean something else."""

    @pytest.mark.parametrize(
        ("text", "line"),
        [
            ("heckler:\n  severity: critical\n", 2),
            ("severity: high\n  allow_bom: false\n", 2),
            ("severity: >\n  high\n", 1),
            ("severity: |\n  high\n", 1),
            ("skip: &dirs [vendor]\n", 1),
            ("extra_skip_dirs: !!set {a}\n", 1),
            ("severity: {level: high}\n", 1),
            ("allowlist: [\n  a,\n]\n", 1),
            ("allowlist: [a, [b]]\n", 1),
            ("allowlist: [a,, b]\n", 1),
            ('allowlist: ["a" "b"]\n', 1),
            ('allowlist:\n  - "unclosed\n', 2),
            ("allowlist:\n  - 'unclosed\n", 2),
            ("allowlist:\n  - 'a'b'\n", 2),
            ('allowlist:\n  - "a\\qb"\n', 2),
            ("allowlist:\n  - name: value\n", 2),
            ("allowlist:\n  -\n", 2),
            ("- a\n", 1),
            ("severity: high\n- a\n", 2),
            ("severity:high\n", 1),
            ('"severity": high\n', 1),
            ("severity: high\nseverity: low\n", 2),
            ("just some words\n", 1),
        ],
    )
    def test_it_is_an_error_that_names_the_line(self, text: str, line: int) -> None:
        with pytest.raises(ConfigError, match=rf"^\.heckler\.yml, line {line} could not be read"):
            _minimal_yaml_parse(text)

    def test_message_spells_out_what_the_line_holds(self) -> None:
        with pytest.raises(ConfigError) as error:
            _minimal_yaml_parse("sev" + chr(0x200B) + "erity: high\n", "conf.yml")
        assert str(error.value).startswith("conf.yml, line 1 could not be read")
        assert str(error.value).endswith("sev<U+200B>erity: high")


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

    def test_extra_extensions_are_added_with_or_without_the_dot(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text("extra_extensions: [.foo, bar]\n", encoding="utf-8")
        assert {".foo", ".bar", ".py"} <= load_config(config_path=str(cfg)).text_extensions

    def test_utf8_signature_at_the_start_is_not_part_of_the_first_key(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_bytes(b"\xef\xbb\xbfseverity: high\n")
        assert load_config(config_path=str(cfg)).severity_threshold == Severity.HIGH


class TestOneReader:
    """A YAML library on the machine does not change what the file means."""

    def test_an_installed_yaml_library_is_not_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unused(*_args: object) -> None:
            raise AssertionError("the YAML library was called")

        monkeypatch.setitem(sys.modules, "yaml", types.SimpleNamespace(safe_load=unused))
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text("allow_bom: off\nallowlist:\n  - **/*.po\n", encoding="utf-8")
        config = load_config(config_path=str(cfg))
        assert config.allow_bom is False
        assert config.exclude_patterns == ["**/*.po"]


class TestValuesASettingCannotTake:
    """Refused, not coerced: bool("off") is True, and an unknown severity is not the default."""

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("severity: hgih\n", "severity must be one of critical, high, medium, low, info"),
            ("severity: true\n", "severity must be one of"),
            ("severity:\n", "severity must be one of"),
            ("allow_bom: maybe\n", "allow_bom must be true or false, not 'maybe'"),
            ('allow_bom: "false"\n', "allow_bom must be true or false, not 'false'"),
            ("allow_emoji: 0\n", "allow_emoji must be true or false, not '0'"),
            ("allow_emoji: [true]\n", "allow_emoji must be true or false"),
            ('allowlist: "**/*.po"\n', "allowlist must be a list of strings"),
            ("extra_skip_dirs: vendor\n", "extra_skip_dirs must be a list of strings"),
            ("extra_extensions: true\n", "extra_extensions must be a list of strings"),
        ],
    )
    def test_it_is_an_error(self, tmp_path: Path, text: str, message: str) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigError, match=message):
            load_config(config_path=str(cfg))

    @pytest.mark.parametrize("word", ["HIGH", "High", "high"])
    def test_severity_in_any_case(self, tmp_path: Path, word: str) -> None:
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text(f"severity: {word}\n", encoding="utf-8")
        assert load_config(config_path=str(cfg)).severity_threshold == Severity.HIGH

    @pytest.mark.parametrize(
        "text", ["allow_bom: maybe\n", "heckler:\n  severity: critical\n", "severity: hgih\n"]
    )
    def test_cli_stops_with_exit_code_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str
    ) -> None:
        """A scan under settings that were half read would not be the scan that was asked for."""
        cfg = tmp_path / ".heckler.yml"
        cfg.write_text(text, encoding="utf-8")
        (tmp_path / "clean.txt").write_text("fine\n", encoding="utf-8")
        assert main(["--ci", "--config", str(cfg), str(tmp_path)]) == 2
        captured = capsys.readouterr()
        assert captured.err.startswith(f"Error: {cfg}")
        assert captured.out == ""


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


class TestPyproject:
    def _write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> None:
        (tmp_path / "pyproject.toml").write_text(text, encoding="utf-8")
        monkeypatch.chdir(tmp_path)

    def test_settings_are_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._write(tmp_path, monkeypatch, PYPROJECT)
        config = load_config()
        assert config.severity_threshold == Severity.MEDIUM
        assert config.allow_bom is False
        assert config.exclude_patterns == ["**/*.po", "docs/#old/*", "a, b.txt"]
        assert "third_party" in config.skip_dirs
        assert {".foo", ".bar"} <= config.text_extensions

    @pytest.mark.parametrize("text", ['[project]\nname = "x"\n', "[tool.heckler]\n# nothing yet\n"])
    def test_no_settings_is_the_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
    ) -> None:
        self._write(tmp_path, monkeypatch, text)
        assert load_config() == Config.defaults()

    def test_heckler_yml_still_comes_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._write(tmp_path, monkeypatch, PYPROJECT)
        (tmp_path / ".heckler.yml").write_text("severity: high\n", encoding="utf-8")
        assert load_config().severity_threshold == Severity.HIGH

    @pytest.mark.parametrize(
        ("line", "message"),
        [
            ("severity = 3", "severity must be one of"),
            ('severity = "hgih"', "severity must be one of"),
            ('allow_bom = "false"', "allow_bom must be true or false"),
            ("allow_emoji = 1", "allow_emoji must be true or false"),
            ('allowlist = "**/*.po"', "allowlist must be a list of strings"),
            ("extra_skip_dirs = [1, 2]", "extra_skip_dirs must be a list of strings"),
            ('extra_extensions = [[".a"]]', "extra_extensions must be a list of strings"),
        ],
    )
    def test_value_of_the_wrong_kind_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str, message: str
    ) -> None:
        self._write(tmp_path, monkeypatch, f"[tool.heckler]\n{line}\n")
        with pytest.raises(ConfigError, match=r"^pyproject\.toml, \[tool\.heckler\]: " + message):
            load_config()

    def test_invalid_toml_is_an_error_not_a_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._write(tmp_path, monkeypatch, "[tool.heckler\nseverity = high\n")
        with pytest.raises(ConfigError, match=r"^pyproject\.toml could not be read"):
            load_config()
        assert main(["--ci", "."]) == 2
        assert "Error: pyproject.toml could not be read" in capsys.readouterr().err
