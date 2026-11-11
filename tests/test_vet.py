"""Tests for package vetting."""

from __future__ import annotations

import io
import json
import tarfile
import unittest.mock
import urllib.error
import zipfile
from pathlib import Path

import pytest

from heckler.vet import (
    _download_npm,
    _download_pypi,
    _parse_spec,
    _safe_tar_extract,
    _safe_zip_extract,
    _UnsafeArchiveError,
    _validate_archive_member,
    detect_registry,
    extract_package,
)


class TestDetectRegistry:
    def test_npm_at_version(self) -> None:
        assert detect_registry("express@4.18.0") == "npm"

    def test_npm_scoped(self) -> None:
        assert detect_registry("@babel/core@7.24.0") == "npm"

    def test_pypi_double_equals(self) -> None:
        assert detect_registry("requests==2.31.0") == "pypi"

    def test_pypi_gte(self) -> None:
        assert detect_registry("django>=4.2") == "pypi"

    def test_pypi_compatible(self) -> None:
        assert detect_registry("flask~=3.0") == "pypi"

    def test_unknown_bare_name(self) -> None:
        assert detect_registry("lodash") == "unknown"


class TestParseSpec:
    def test_npm_unscoped_with_version(self) -> None:
        assert _parse_spec("express@4.18.0", "npm") == ("express", "4.18.0")

    def test_npm_unscoped_no_version(self) -> None:
        assert _parse_spec("express", "npm") == ("express", None)

    def test_npm_scoped_with_version(self) -> None:
        assert _parse_spec("@babel/core@7.24.0", "npm") == ("@babel/core", "7.24.0")

    def test_npm_scoped_no_version(self) -> None:
        assert _parse_spec("@babel/core", "npm") == ("@babel/core", None)

    def test_pypi_exact(self) -> None:
        assert _parse_spec("requests==2.31.0", "pypi") == ("requests", "2.31.0")

    def test_pypi_bare_name(self) -> None:
        assert _parse_spec("requests", "pypi") == ("requests", None)

    def test_pypi_rejects_gte(self) -> None:
        with pytest.raises(SystemExit):
            _parse_spec("django>=4.2", "pypi")

    def test_pypi_rejects_compatible(self) -> None:
        with pytest.raises(SystemExit):
            _parse_spec("flask~=3.0", "pypi")


class TestValidateArchiveMember:
    def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        with pytest.raises(_UnsafeArchiveError, match="Path traversal"):
            _validate_archive_member("../../etc/passwd", resolved, tmp_path)

    def test_rejects_absolute_path_escape(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        with pytest.raises(_UnsafeArchiveError, match="Path escapes"):
            _validate_archive_member("/etc/passwd", resolved, tmp_path)

    def test_allows_normal_path(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        _validate_archive_member("package/index.js", resolved, tmp_path)

    def test_allows_nested_path(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        _validate_archive_member("package/src/lib/util.js", resolved, tmp_path)


class TestSafeZipExtract:
    def _make_zip(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        return zip_path

    def test_normal_zip_extracts(self, tmp_path: Path) -> None:
        zip_path = self._make_zip(tmp_path, {"hello.txt": b"world"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())
        assert (extract_dir / "hello.txt").read_bytes() == b"world"

    def test_rejects_path_traversal_zip(self, tmp_path: Path) -> None:
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../evil.txt", b"gotcha")
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="Path traversal"):
            _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())


class TestSafeTarExtract:
    def _make_tar(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        tar_path = tmp_path / "test.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            for name, content in entries.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return tar_path

    def test_normal_tar_extracts(self, tmp_path: Path) -> None:
        tar_path = self._make_tar(tmp_path, {"hello.txt": b"world"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
        assert (extract_dir / "hello.txt").read_bytes() == b"world"

    def test_rejects_path_traversal_tar(self, tmp_path: Path) -> None:
        tar_path = self._make_tar(tmp_path, {"../../evil.txt": b"gotcha"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="(?i)unsafe|traversal|outside"):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())

    def test_rejects_symlink_tar(self, tmp_path: Path) -> None:
        tar_path = tmp_path / "symlink.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="(?i)unsafe|link|absolute"):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())


class TestDownloadNpm:
    """Verify npm registry API download logic with mocked urllib."""

    def test_downloads_tarball_from_registry(self, tmp_path: Path) -> None:
        registry_meta = {
            "name": "express",
            "version": "4.18.0",
            "dist": {
                "tarball": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
            },
        }
        tarball_bytes = b"fake-tarball-content"

        def fake_urlopen(req, **kwargs):  # type: ignore[no-untyped-def]
            url = req.full_url if hasattr(req, "full_url") else req
            resp = unittest.mock.MagicMock()
            if "express/4.18.0" in url:
                resp.read.return_value = json.dumps(registry_meta).encode()
            else:
                # Streamed in chunks: hand back the payload, then end-of-stream.
                resp.read.side_effect = [tarball_bytes, b""]
            resp.__enter__ = lambda s: s
            resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return resp

        with unittest.mock.patch("heckler.vet.urllib.request.urlopen", side_effect=fake_urlopen):
            result = _download_npm("express", "4.18.0", str(tmp_path))

        assert result.name == "express-4.18.0.tgz"
        assert result.read_bytes() == tarball_bytes

    def test_404_exits(self, tmp_path: Path) -> None:
        def fake_urlopen(req, **kwargs):  # type: ignore[no-untyped-def]
            raise urllib.error.HTTPError(
                url="",
                code=404,
                msg="Not Found",
                hdrs=None,
                fp=None,  # type: ignore[arg-type]
            )

        with (
            unittest.mock.patch("heckler.vet.urllib.request.urlopen", side_effect=fake_urlopen),
            pytest.raises(SystemExit),
        ):
            _download_npm("nonexistent-pkg", "1.0.0", str(tmp_path))


class TestDownloadPyPI:
    """Verify PyPI registry API download logic with mocked urllib."""

    def test_prefers_wheel_over_sdist(self, tmp_path: Path) -> None:
        registry_meta = {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/pkg-1.0.tar.gz",
                    "filename": "pkg-1.0.tar.gz",
                },
                {
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/pkg-1.0-py3-none-any.whl",
                    "filename": "pkg-1.0-py3-none-any.whl",
                },
            ],
        }
        wheel_bytes = b"fake-wheel-content"
        downloaded_url = None

        def fake_urlopen(req, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal downloaded_url
            url = req.full_url if hasattr(req, "full_url") else req
            resp = unittest.mock.MagicMock()
            if "pypi.org" in url:
                resp.read.return_value = json.dumps(registry_meta).encode()
            else:
                downloaded_url = url
                # Streamed in chunks: hand back the payload, then end-of-stream.
                resp.read.side_effect = [wheel_bytes, b""]
            resp.__enter__ = lambda s: s
            resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return resp

        with unittest.mock.patch("heckler.vet.urllib.request.urlopen", side_effect=fake_urlopen):
            result = _download_pypi("pkg", "1.0", str(tmp_path))

        assert result.name == "pkg-1.0-py3-none-any.whl"
        assert result.read_bytes() == wheel_bytes
        assert downloaded_url is not None
        assert "whl" in downloaded_url

    def test_falls_back_to_sdist(self, tmp_path: Path) -> None:
        registry_meta = {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/pkg-1.0.tar.gz",
                    "filename": "pkg-1.0.tar.gz",
                },
            ],
        }
        sdist_bytes = b"fake-sdist-content"

        def fake_urlopen(req, **kwargs):  # type: ignore[no-untyped-def]
            url = req.full_url if hasattr(req, "full_url") else req
            resp = unittest.mock.MagicMock()
            if "pypi.org" in url:
                resp.read.return_value = json.dumps(registry_meta).encode()
            else:
                # Streamed in chunks: hand back the payload, then end-of-stream.
                resp.read.side_effect = [sdist_bytes, b""]
            resp.__enter__ = lambda s: s
            resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return resp

        with unittest.mock.patch("heckler.vet.urllib.request.urlopen", side_effect=fake_urlopen):
            result = _download_pypi("pkg", "1.0", str(tmp_path))

        assert result.name == "pkg-1.0.tar.gz"
        assert result.read_bytes() == sdist_bytes


class TestVetEndToEnd:
    """End-to-end vet tests using locally-built archives (no network)."""

    def _make_npm_tgz(self, tmp_path: Path, files: dict[str, bytes]) -> Path:
        """Build a .tgz mimicking npm pack output (files under package/ prefix)."""
        tgz_path = tmp_path / "evil-pkg-1.0.0.tgz"
        with tarfile.open(tgz_path, "w:gz") as tf:
            for name, content in files.items():
                info = tarfile.TarInfo(name=f"package/{name}")
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return tgz_path

    def test_extract_and_scan_finds_glassworm(self, tmp_path: Path) -> None:
        """Build a fake npm package with Glassworm variation selectors,
        extract it, and verify the scanner finds them."""
        from heckler.scanner import Scanner

        # JS file with planted Glassworm variation selectors
        evil_js = "const payload = `\ufe00\ufe01\ufe0f`;\n".encode()
        clean_js = b"module.exports = {};\n"

        tgz = self._make_npm_tgz(
            tmp_path,
            {
                "index.js": evil_js,
                "util.js": clean_js,
                "package.json": b'{"name": "evil-pkg", "version": "1.0.0"}',
            },
        )

        # Extract
        extract_dir = extract_package(tgz, str(tmp_path))

        # Scan the extracted package
        scanner = Scanner(
            skip_dirs=frozenset(),
            scan_deps=True,
        )
        findings = scanner.scan_path(extract_dir)

        assert len(findings) == 3
        assert all(f.category.value == "variation_selector" for f in findings)
        assert all(f.severity.value == "critical" for f in findings)

    def test_extract_and_scan_clean_package(self, tmp_path: Path) -> None:
        """A clean package should produce zero findings."""
        from heckler.scanner import Scanner

        tgz = self._make_npm_tgz(
            tmp_path,
            {
                "index.js": b"module.exports = { add: (a, b) => a + b };\n",
                "package.json": b'{"name": "clean-pkg", "version": "1.0.0"}',
            },
        )

        extract_dir = extract_package(tgz, str(tmp_path))
        scanner = Scanner(skip_dirs=frozenset(), scan_deps=True)
        findings = scanner.scan_path(extract_dir)
        assert findings == []

    def test_extract_and_scan_wheel(self, tmp_path: Path) -> None:
        """Build a fake .whl (zip) with a planted bidi attack, extract, scan."""
        from heckler.scanner import Scanner

        evil_py = 'access = "\u202eadmin"\n'.encode()
        whl_path = tmp_path / "evil_pkg-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("evil_pkg/__init__.py", evil_py)
            zf.writestr("evil_pkg/utils.py", b"x = 1\n")

        extract_dir = extract_package(whl_path, str(tmp_path))
        scanner = Scanner(skip_dirs=frozenset(), scan_deps=True)
        findings = scanner.scan_path(extract_dir)

        assert len(findings) == 1
        assert findings[0].codepoint_hex == "U+202E"
        assert findings[0].severity.value == "critical"
