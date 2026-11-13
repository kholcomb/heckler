"""Tests for package vetting."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import unittest.mock
import urllib.error
import urllib.parse
import warnings
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest

from heckler import vet
from heckler.config import Config
from heckler.vet import (
    _check_tar_sizes,
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


class TestTarSizeLimits:
    """The limits on what an archive unpacks to hold on every Python.

    They were checked only in the fallback for a Python whose tarfile has no
    'data' filter. Where it has one, which is every current release, a 61 KB
    archive unpacked to a 60 MB file: the filter looks at where a member
    goes and what kind it is, not at how large it is.

    No archive here is large or unpacks to anything large. The limits are
    lowered to about a kilobyte for the test, and the members are zeros.
    """

    @pytest.fixture(params=["data filter", "no filter"])
    def extract(
        self, request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Callable[[Path], Path]:
        """Unpack an archive into a new directory, with and without the filter."""
        if request.param == "no filter":
            real = tarfile.TarFile.extractall

            def extractall(
                self: tarfile.TarFile, path: Any = ".", members: Any = None, **options: Any
            ) -> None:
                if "filter" in options:  # the answer of Python 3.11.0 to 3.11.3
                    raise TypeError("extractall() got an unexpected keyword argument 'filter'")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    real(self, path, members)

            monkeypatch.setattr(tarfile.TarFile, "extractall", extractall)

        def run(tar_path: Path) -> Path:
            extract_dir = tmp_path / "out"
            extract_dir.mkdir()
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
            return extract_dir

        return run

    def _make_tar(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        tar_path = tmp_path / "test.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            for name, content in entries.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return tar_path

    def test_member_over_the_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extract: Callable[[Path], Path]
    ) -> None:
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        tar_path = self._make_tar(tmp_path, {"small.txt": b"ok", "big.bin": b"\x00" * 1001})
        with pytest.raises(_UnsafeArchiveError, match=r"File too large \(1001 bytes\): big\.bin"):
            extract(tar_path)
        assert list((tmp_path / "out").iterdir()) == [], "checked before anything is written"

    def test_member_at_the_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extract: Callable[[Path], Path]
    ) -> None:
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        tar_path = self._make_tar(tmp_path, {"small.txt": b"ok", "big.bin": b"\x00" * 1000})
        assert sorted(p.name for p in extract(tar_path).iterdir()) == ["big.bin", "small.txt"]

    def test_total_over_the_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extract: Callable[[Path], Path]
    ) -> None:
        monkeypatch.setattr(vet, "_MAX_TOTAL_SIZE", 1500)
        entries = {f"part{number}.bin": b"\x00" * 600 for number in range(3)}
        tar_path = self._make_tar(tmp_path, entries)
        with pytest.raises(_UnsafeArchiveError, match="Total extraction size exceeds 1500 bytes"):
            extract(tar_path)
        assert list((tmp_path / "out").iterdir()) == []

    def test_reading_stops_at_the_first_member_over_the_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Headers are read one at a time, so a huge archive is not walked to its end."""
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        entries = {"big.bin": b"\x00" * 1001}
        entries.update({f"file{number}.txt": b"x" for number in range(200)})
        tar_path = self._make_tar(tmp_path, entries)

        headers_read = []
        real = tarfile.TarFile.next

        def counting_next(self: tarfile.TarFile) -> tarfile.TarInfo | None:
            headers_read.append(1)
            return real(self)

        monkeypatch.setattr(tarfile.TarFile, "next", counting_next)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="File too large"):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
        assert len(headers_read) < 5

    def test_member_that_declares_a_negative_size(self) -> None:
        """A size below zero would otherwise be taken off the total."""
        member = tarfile.TarInfo("negative.bin")
        member.size = -256
        with pytest.raises(
            _UnsafeArchiveError, match=r"Invalid size \(-256 bytes\): negative\.bin"
        ):
            _check_tar_sizes([member])  # type: ignore[arg-type]

    def test_archive_whose_header_declares_a_negative_size(self, tmp_path: Path) -> None:
        """Refused on every Python, by tarfile where it checks this itself.

        Newer releases of tarfile reject such a header when the archive is
        opened; on the ones before, heckler's own check does. The archive is
        one header with nothing behind it.
        """
        header = bytearray(tarfile.TarInfo("negative.bin").tobuf(tarfile.GNU_FORMAT))
        header[124:136] = b"\xff" * 11 + b"\x00"  # the size field, in base 256: -256
        header[148:156] = b" " * 8
        header[148:156] = b"%06o\x00 " % sum(header)
        tar_path = tmp_path / "negative.tar"
        tar_path.write_bytes(bytes(header) + b"\x00" * 1024)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises((_UnsafeArchiveError, tarfile.ReadError)):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
        assert list(extract_dir.iterdir()) == []


def _raw_header(name: str, kind: bytes, size: int) -> bytearray:
    """One tar header of the type *kind* that declares *size* bytes behind it."""
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size
    return bytearray(info.tobuf(tarfile.GNU_FORMAT))


def _resealed(header: bytearray) -> bytes:
    """*header* with the checksum of what it holds now."""
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\x00 " % sum(header)
    return bytes(header)


class TestWhatTheSizeOfAMemberDoesNotCover:
    """The size of a member is not all that tarfile writes or reads for an archive.

    A sparse member reports the size its file is said to have, and unpacking
    copies what the archive stores for it, which can be any amount more,
    before it cuts the file down. A header that carries a long name or pax
    records is not a member at all, and tarfile reads the whole of it into
    memory: one that declared 32 MB of zeros made a 144-byte archive take
    100 MB. Both went past the limits, so both are refused.

    Nothing here is large. A header that declares 32 MB has nothing behind it.
    """

    def _unpack(self, tar_path: Path, out: Path) -> None:
        out.mkdir()
        _safe_tar_extract(tar_path, out, out.resolve())

    @pytest.fixture
    def low_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        monkeypatch.setattr(vet, "_MAX_TOTAL_SIZE", 1500)

    def test_sparse_member_is_refused(self, tmp_path: Path, low_limits: None) -> None:
        """Its header stores 2,048 bytes and says the file is one byte long."""
        header = _raw_header("sparse.bin", tarfile.GNUTYPE_SPARSE, 2048)
        header[386:410] = b"%011o\x00%011o\x00" % (0, 2048)  # one piece: all of it
        header[483:495] = b"%011o\x00" % 1  # the size the file is said to have
        tar_path = tmp_path / "sparse.tar"
        tar_path.write_bytes(_resealed(header) + b"\x00" * (2048 + 1024))
        with pytest.raises(_UnsafeArchiveError, match="sparse file: sparse.bin"):
            self._unpack(tar_path, tmp_path / "out")
        assert list((tmp_path / "out").iterdir()) == []

    def test_sparse_member_declared_in_a_pax_header_is_refused(
        self, tmp_path: Path, low_limits: None
    ) -> None:
        """The same, in the format that keeps the map in front of the data."""
        data = b"1\n0\n1536\n".ljust(512, b"\x00") + b"\x00" * 1536
        info = tarfile.TarInfo("GNUSparseFile.0/sparse.bin")
        info.size = len(data)
        info.pax_headers = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "sparse.bin",
            "GNU.sparse.realsize": "1",
        }
        tar_path = tmp_path / "sparse.tar"
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(info, io.BytesIO(data))
        with pytest.raises(_UnsafeArchiveError, match="sparse file: sparse.bin"):
            self._unpack(tar_path, tmp_path / "out")
        assert list((tmp_path / "out").iterdir()) == []

    @pytest.mark.parametrize(
        "kind",
        [
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.SOLARIS_XHDTYPE,
        ],
        ids=["long name", "long link", "pax", "pax global", "solaris pax"],
    )
    def test_extended_header_over_the_limit_is_refused_for_what_it_declares(
        self, tmp_path: Path, kind: bytes
    ) -> None:
        tar_path = tmp_path / "header.tar"
        header = _raw_header("././@LongLink", kind, 32 * 1024 * 1024)
        tar_path.write_bytes(bytes(header) + b"\x00" * 1024)
        with pytest.raises(_UnsafeArchiveError, match=r"Header too large \(33554432 bytes\)"):
            self._unpack(tar_path, tmp_path / "out")

    @pytest.mark.parametrize(
        "tar_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT], ids=["gnu", "pax"]
    )
    def test_long_name_is_unpacked(self, tmp_path: Path, tar_format: int) -> None:
        """A name over 100 bytes is what these headers are for."""
        name = "package/" + "d" * 80 + "/" + "f" * 80 + ".txt"
        info = tarfile.TarInfo(name)
        info.size = 2
        tar_path = tmp_path / "long.tar"
        with tarfile.open(tar_path, "w", format=tar_format) as tf:
            tf.addfile(info, io.BytesIO(b"ok"))
        self._unpack(tar_path, tmp_path / "out")
        assert (tmp_path / "out" / name).read_bytes() == b"ok"

    def test_extended_header_at_the_limit_is_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        name = "package/" + "d" * 80 + "/" + "f" * 80 + ".txt"
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADER_SIZE", len(name) + 1)  # and its NUL
        info = tarfile.TarInfo(name)
        tar_path = tmp_path / "long.tar"
        with tarfile.open(tar_path, "w", format=tarfile.GNU_FORMAT) as tf:
            tf.addfile(info)
        self._unpack(tar_path, tmp_path / "out")
        assert (tmp_path / "out" / name).exists()
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADER_SIZE", len(name))
        with pytest.raises(_UnsafeArchiveError, match="Header too large"):
            self._unpack(tar_path, tmp_path / "again")

    def _member(self, name: str, data: bytes) -> bytes:
        """A regular member: its header and its data, filled up to the block."""
        info = tarfile.TarInfo(name)
        info.size = len(data)
        return info.tobuf(tarfile.GNU_FORMAT) + data.ljust(-(-len(data) // 512) * 512, b"\x00")

    def test_headers_in_a_row_are_held_to_the_limit_together(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each one is within the limit, and tarfile holds them all until the member."""
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADER_SIZE", 1024)
        long_name = bytes(_raw_header("././@LongLink", tarfile.GNUTYPE_LONGNAME, 1024))
        name = b"package/a.txt".ljust(1024, b"\x00")
        tar_path = tmp_path / "run.tar"
        tar_path.write_bytes((long_name + name) * 2 + self._member("a.txt", b"ok") + b"\x00" * 1024)
        with pytest.raises(_UnsafeArchiveError, match=r"Header too large \(2048 bytes\)"):
            self._unpack(tar_path, tmp_path / "out")
        assert list((tmp_path / "out").iterdir()) == []

    def test_long_run_of_headers_is_refused(self, tmp_path: Path) -> None:
        """They declare nothing, so no size stops them, and tarfile calls itself for each."""
        empty = bytes(_raw_header("././@LongLink", tarfile.GNUTYPE_LONGNAME, 0))
        tar_path = tmp_path / "run.tar"
        tar_path.write_bytes(empty * 1000 + self._member("a.txt", b"ok") + b"\x00" * 1024)
        with pytest.raises(_UnsafeArchiveError, match=r"Too many headers in a row \(17\)"):
            self._unpack(tar_path, tmp_path / "out")

    def test_run_of_headers_ends_at_a_member(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One header in front of each of two members is one in a row, twice."""
        names = ["package/" + letter * 120 + ".txt" for letter in "ab"]
        tar_path = tmp_path / "long.tar"
        with tarfile.open(tar_path, "w", format=tarfile.GNU_FORMAT) as tf:
            for name in names:
                tf.addfile(tarfile.TarInfo(name))
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADERS", 1)
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADER_SIZE", 150)  # one name, and not two
        out = tmp_path / "out"
        self._unpack(tar_path, out)
        assert sorted(p.relative_to(out).as_posix() for p in out.glob("*/*")) == names
        monkeypatch.setattr(vet, "_MAX_EXTENDED_HEADERS", 0)
        with pytest.raises(_UnsafeArchiveError, match=r"Too many headers in a row \(1\)"):
            self._unpack(tar_path, tmp_path / "again")

    def test_header_that_declares_a_negative_size_is_refused(self, tmp_path: Path) -> None:
        """It would come off what the run declares, and an older tarfile reads on to the end."""
        header = bytes(_raw_header("././@LongLink", tarfile.GNUTYPE_LONGNAME, -1024))
        tar_path = tmp_path / "negative.tar"
        tar_path.write_bytes(header + self._member("a.txt", b"ok") + b"\x00" * 1024)
        with pytest.raises(_UnsafeArchiveError, match=r"Invalid size \(-1024 bytes\)"):
            self._unpack(tar_path, tmp_path / "out")

    def test_map_of_a_sparse_member_is_not_read(self, tmp_path: Path) -> None:
        """Its map says it has a thousand million entries, and it is refused without them.

        The entries are not there. A tarfile that went on to read them would
        fail on that, and not with the refusal.
        """
        data = b"1000000000\n0\n".ljust(512, b"\x00")
        info = tarfile.TarInfo("GNUSparseFile.0/sparse.bin")
        info.size = len(data)
        info.pax_headers = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "sparse.bin",
            "GNU.sparse.realsize": "1",
        }
        tar_path = tmp_path / "sparse.tar"
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tf:
            tf.addfile(info, io.BytesIO(data))
        with pytest.raises(_UnsafeArchiveError, match="sparse file: sparse.bin"):
            self._unpack(tar_path, tmp_path / "out")


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


def _fake_pypi(
    files: dict[str, tuple[str, bytes]], requested: list[str]
) -> AbstractContextManager[Any]:
    """A stand-in for urlopen that serves one PyPI release.

    *files* maps a filename to its ``(packagetype, content)``. Every file URL
    that is fetched is appended to *requested*.
    """
    meta = {
        "urls": [
            {
                "packagetype": packagetype,
                "url": f"https://files.pythonhosted.org/{filename}",
                "filename": filename,
                "digests": {"sha256": hashlib.sha256(content).hexdigest()},
            }
            for filename, (packagetype, content) in files.items()
        ],
    }

    def fake_urlopen(req, **kwargs):  # type: ignore[no-untyped-def]
        url = req.full_url if hasattr(req, "full_url") else req
        resp = unittest.mock.MagicMock()
        if urllib.parse.urlsplit(url).hostname == "pypi.org":
            resp.read.return_value = json.dumps(meta).encode()
        else:
            requested.append(url)
            # Streamed in chunks: hand back the payload, then end-of-stream.
            resp.read.side_effect = [files[url.rsplit("/", 1)[-1]][1], b""]
        resp.__enter__ = lambda s: s
        resp.__exit__ = unittest.mock.MagicMock(return_value=False)
        return resp

    return unittest.mock.patch("heckler.vet.urllib.request.urlopen", side_effect=fake_urlopen)


class TestDownloadPyPI:
    """Verify PyPI registry API download logic with mocked urllib."""

    def test_downloads_the_sdist_and_every_wheel(self, tmp_path: Path) -> None:
        files = {
            "pkg-1.0-cp312-cp312-win_amd64.whl": ("bdist_wheel", b"fake-windows-wheel"),
            "pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl": ("bdist_wheel", b"fake-linux-wheel"),
            "pkg-1.0.tar.gz": ("sdist", b"fake-sdist-content"),
        }
        requested: list[str] = []
        with _fake_pypi(files, requested):
            result = _download_pypi("pkg", "1.0", str(tmp_path))

        # The sdist first, then the wheels by name.
        assert [path.name for path in result] == [
            "pkg-1.0.tar.gz",
            "pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
            "pkg-1.0-cp312-cp312-win_amd64.whl",
        ]
        assert [path.read_bytes() for path in result] == [
            b"fake-sdist-content",
            b"fake-linux-wheel",
            b"fake-windows-wheel",
        ]
        assert len(requested) == 3

    def test_sdist_only(self, tmp_path: Path) -> None:
        with _fake_pypi({"pkg-1.0.tar.gz": ("sdist", b"fake-sdist-content")}, []):
            result = _download_pypi("pkg", "1.0", str(tmp_path))
        assert [path.name for path in result] == ["pkg-1.0.tar.gz"]
        assert result[0].read_bytes() == b"fake-sdist-content"

    def test_wheel_only(self, tmp_path: Path) -> None:
        with _fake_pypi({"pkg-1.0-py3-none-any.whl": ("bdist_wheel", b"fake-wheel")}, []):
            result = _download_pypi("pkg", "1.0", str(tmp_path))
        assert [path.name for path in result] == ["pkg-1.0-py3-none-any.whl"]

    def test_file_heckler_cannot_unpack_is_named_not_downloaded(self, tmp_path: Path) -> None:
        files = {
            "pkg-1.0.win32.exe": ("bdist_wininst", b"MZ"),
            "pkg-1.0-py2.7.egg": ("bdist_egg", b"fake-egg"),
            "pkg-1.0.tar.gz": ("sdist", b"fake-sdist-content"),
        }
        requested: list[str] = []
        not_scanned: list[tuple[str, str]] = []
        with _fake_pypi(files, requested):
            result = _download_pypi("pkg", "1.0", str(tmp_path), not_scanned)

        assert [path.name for path in result] == ["pkg-1.0.tar.gz", "pkg-1.0-py2.7.egg"]
        assert not_scanned == [("pkg-1.0.win32.exe", "heckler cannot unpack this type of file")]
        assert not any(url.endswith(".exe") for url in requested)

    def test_checksum_is_verified_for_every_file(self, tmp_path: Path) -> None:
        files = {
            "pkg-1.0.tar.gz": ("sdist", b"fake-sdist-content"),
            "pkg-1.0-py3-none-any.whl": ("bdist_wheel", b"fake-wheel"),
        }
        with _fake_pypi(files, []):
            # What the registry serves for the wheel is not what it promised.
            files["pkg-1.0-py3-none-any.whl"] = ("bdist_wheel", b"something else")
            with pytest.raises(SystemExit):
                _download_pypi("pkg", "1.0", str(tmp_path))

    @pytest.mark.parametrize("filename", ["../pkg-1.0.tar.gz", "a/b.whl", "..", "a\\b.whl", ""])
    def test_filename_that_is_a_path_is_refused(self, tmp_path: Path, filename: str) -> None:
        with _fake_pypi({filename: ("sdist", b"x")}, []), pytest.raises(SystemExit):
            _download_pypi("pkg", "1.0", str(tmp_path))
        assert not (tmp_path.parent / "pkg-1.0.tar.gz").exists()


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


PLANTED_SELECTORS = "".join(chr(cp) for cp in (0xFE01, 0xFE02, 0xFE03))


def _tar_gz(path: Path, files: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return path


def _zip(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return path


Serve = Callable[..., None]


class TestVetPackage:
    """vet_package() from spec to exit code, with the download replaced by local archives."""

    @pytest.fixture
    def serve(self, monkeypatch: pytest.MonkeyPatch) -> Serve:
        """Make download_package() return the given archives instead of fetching any."""

        def install(archives: list[Path], cannot_unpack: tuple[str, ...] = ()) -> None:
            def fake_download(
                spec: str, registry: str, tmpdir: str, not_scanned: list[tuple[str, str]]
            ) -> list[Path]:
                not_scanned.extend(
                    (name, "heckler cannot unpack this type of file") for name in cannot_unpack
                )
                return archives

            monkeypatch.setattr(vet, "download_package", fake_download)

        return install

    def _vet(self, spec: str = "pkg==1.0", **kwargs: object) -> int:
        return vet.vet_package(spec, None, Config.defaults(), color=False, **kwargs)  # type: ignore[arg-type]

    def test_clean_release_names_every_file_it_scanned(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        serve(
            [
                _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/pkg/__init__.py": b"x = 1\n"}),
                _zip(tmp_path / "pkg-1.0-py3-none-any.whl", {"pkg/__init__.py": b"x = 1\n"}),
            ]
        )
        assert self._vet() == 0
        out = capsys.readouterr().out
        assert "[VET] pkg==1.0 (pypi) — 2 file(s) scanned, 0 findings. CLEAN." in out
        assert "  scanned: pkg-1.0.tar.gz" in out
        assert "  scanned: pkg-1.0-py3-none-any.whl" in out

    def test_a_file_name_the_stream_cannot_encode(
        self, tmp_path: Path, serve: Serve, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        name = chr(0x444) + chr(0x430) + "-1.0.tar.gz"
        serve([_tar_gz(tmp_path / name, {"pkg-1.0/pkg/__init__.py": b"x = 1\n"})])
        raw = io.BytesIO()
        monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252", newline=""))
        assert self._vet() == 0
        sys.stdout.flush()
        header = f"[VET] pkg==1.0 (pypi) {chr(0x2014)} 1 file(s) scanned, 0 findings. CLEAN."
        assert header.encode("cp1252") in raw.getvalue()
        assert b"  scanned: " + name.encode("ascii", "backslashreplace") in raw.getvalue()

    def test_sdist_is_scanned_when_the_wheel_is_clean(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """pip builds from the sdist wherever no wheel fits; a clean wheel says nothing of it."""
        planted = f"token = `{PLANTED_SELECTORS}`\n".encode()
        serve(
            [
                _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/setup.py": planted}),
                _zip(tmp_path / "pkg-1.0-py3-none-any.whl", {"pkg/__init__.py": b"x = 1\n"}),
            ]
        )
        assert self._vet() == 1
        out = capsys.readouterr().out
        assert "3 finding(s) (3 CRITICAL). DO NOT INSTALL." in out
        assert "pkg-1.0.tar.gz/pkg-1.0/setup.py" in out

    def test_one_wheel_among_several(self, tmp_path: Path, serve: Serve) -> None:
        planted = f"token = '{PLANTED_SELECTORS}'\n".encode()
        serve(
            [
                _zip(tmp_path / "pkg-1.0-cp312-linux_x86_64.whl", {"pkg/__init__.py": b"x = 1\n"}),
                _zip(tmp_path / "pkg-1.0-cp312-win_amd64.whl", {"pkg/__init__.py": planted}),
            ]
        )
        assert self._vet() == 1

    def test_findings_name_the_archive_they_are_in(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        planted = f"token = '{PLANTED_SELECTORS}'\n".encode()
        serve([_zip(tmp_path / "pkg-1.0-py3-none-any.whl", {"pkg/__init__.py": planted})])
        assert self._vet(output_format="json") == 1
        findings = json.loads(capsys.readouterr().out)
        assert {f["file"] for f in findings} == {"pkg-1.0-py3-none-any.whl/pkg/__init__.py"}
        assert {f["package"] for f in findings} == {"pkg==1.0"}

    @pytest.mark.parametrize(
        "name",
        [
            "package/bin/cli",  # an executable script without an extension
            "package/hooks.pth",  # runs at interpreter start-up
            "package/install.cmd",
            "package/templates/page.tmpl",
            "package/README",
        ],
    )
    def test_every_text_file_is_scanned(self, tmp_path: Path, serve: Serve, name: str) -> None:
        planted = f"# {PLANTED_SELECTORS}\n".encode()
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", {name: planted, "package/index.js": b"1;\n"})])
        assert self._vet("pkg@1.0.0") == 1

    def test_binary_files_are_left_out(self, tmp_path: Path, serve: Serve) -> None:
        blob = b"\x89PNG\x00\x00" + chr(0xA0).encode() * 10
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", {"package/logo.png": blob})])
        assert self._vet("pkg@1.0.0") == 0

    def test_binary_files_are_named(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        blob = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4 + chr(0xA0).encode() * 10
        files = {"package/logo.png": blob, "package/index.js": b"1;\n"}
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", files)])
        assert self._vet("pkg@1.0.0") == 0
        assert (
            "  binary, not scanned as text: pkg-1.0.0.tgz/package/logo.png"
            in capsys.readouterr().out
        )

    def test_padding_does_not_take_a_text_file_out_of_the_scan(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """300 NUL bytes in its first comment made the file binary, and the verdict CLEAN."""
        text = b"// plain\n" * 200 + f"// {PLANTED_SELECTORS}\n".encode()
        blob = b"// " + b"\x00" * 300 + b"\n" + text
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", {"package/lib/loader": blob})])
        assert self._vet("pkg@1.0.0") == 1
        out = capsys.readouterr().out
        assert "3 finding(s) (3 CRITICAL). DO NOT INSTALL." in out
        assert "Variation Selector 2 (in a file that looks binary)" in out
        assert "  binary, not scanned as text: pkg-1.0.0.tgz/package/lib/loader" in out

    def test_archive_with_a_member_over_the_size_limit_is_not_unpacked(
        self,
        tmp_path: Path,
        serve: Serve,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(vet, "_MAX_EXTRACT_SIZE", 1000)
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", {"package/big.js": b"/" * 1001})])
        assert self._vet("pkg@1.0.0") == 2
        captured = capsys.readouterr()
        assert "0 file(s) scanned, 0 findings, 1 file(s) not scanned. INCOMPLETE." in captured.out
        assert (
            "pkg-1.0.0.tgz was not scanned: it could not be unpacked"
            " (File too large (1001 bytes): package/big.js)" in captured.err
        )

    @pytest.mark.parametrize(
        "first_line",
        [b"// cli \x00\n", b"#!/usr/bin/env node\n// \x00\n"],
        ids=["plain", "shebang"],
    )
    def test_a_nul_does_not_opt_a_script_out(
        self, tmp_path: Path, serve: Serve, first_line: bytes
    ) -> None:
        planted = first_line + f"// {PLANTED_SELECTORS}\n".encode() + b"run();\n" * 20
        serve([_tar_gz(tmp_path / "pkg-1.0.0.tgz", {"package/bin/cli": planted})])
        assert self._vet("pkg@1.0.0") == 1

    def test_suppression_comments_in_the_package_are_not_honoured(
        self, tmp_path: Path, serve: Serve
    ) -> None:
        planted = f"x = 'a{chr(0x200B)}b'  # heckler-ignore\n".encode()
        serve([_zip(tmp_path / "pkg-1.0-py3-none-any.whl", {"pkg/__init__.py": planted})])
        assert self._vet() == 1

    def test_damaged_archive_is_reported_as_incomplete(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        damaged = tmp_path / "pkg-1.0.0.tgz"
        damaged.write_bytes(b"this is not a gzip file")
        serve([damaged])

        assert self._vet("pkg@1.0.0") == 2
        captured = capsys.readouterr()
        assert "0 file(s) scanned, 0 findings, 1 file(s) not scanned. INCOMPLETE." in captured.out
        assert "  not scanned: pkg-1.0.0.tgz" in captured.out
        assert "CLEAN" not in captured.out
        assert "Warning: pkg-1.0.0.tgz was not scanned: it could not be unpacked" in captured.err

    def test_other_files_are_scanned_when_one_archive_is_damaged(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        planted = f"token = '{PLANTED_SELECTORS}'\n".encode()
        sdist = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/pkg/__init__.py": planted})
        damaged = tmp_path / "pkg-1.0-py3-none-any.whl"
        damaged.write_bytes(b"PK this is not a zip file")
        serve([sdist, damaged])

        assert self._vet() == 1
        out = capsys.readouterr().out
        assert "1 file(s) scanned" in out
        assert "  scanned: pkg-1.0.tar.gz" in out
        assert "  not scanned: pkg-1.0-py3-none-any.whl" in out

    def test_file_that_could_not_be_unpacked_fails_the_vet(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sdist = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/pkg/__init__.py": b"x = 1\n"})
        serve([sdist], cannot_unpack=("pkg-1.0.win32.exe",))

        assert self._vet() == 2
        captured = capsys.readouterr()
        assert "1 file(s) scanned, 0 findings, 1 file(s) not scanned. INCOMPLETE." in captured.out
        assert "  not scanned: pkg-1.0.win32.exe" in captured.out
        assert "CLEAN" not in captured.out
        assert "No dangerous" not in captured.out
        assert "Warning: pkg-1.0.win32.exe was not scanned" in captured.err
        assert "--allow-unscanned" in captured.err

    def test_allow_unscanned(self, tmp_path: Path, serve: Serve) -> None:
        sdist = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/pkg/__init__.py": b"x = 1\n"})
        serve([sdist], cannot_unpack=("pkg-1.0.win32.exe",))
        assert self._vet(allow_unscanned=True) == 0

    def test_findings_outrank_what_was_not_scanned(self, tmp_path: Path, serve: Serve) -> None:
        planted = f"token = '{PLANTED_SELECTORS}'\n".encode()
        sdist = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/setup.py": planted})
        serve([sdist], cannot_unpack=("pkg-1.0.win32.exe",))
        assert self._vet() == 1

    def test_command_line(
        self, tmp_path: Path, serve: Serve, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from heckler.cli import main

        sdist = _tar_gz(tmp_path / "pkg-1.0.tar.gz", {"pkg-1.0/pkg/__init__.py": b"x = 1\n"})
        serve([sdist], cannot_unpack=("pkg-1.0.win32.exe",))
        assert main(["--vet", "pkg==1.0"]) == 2
        assert main(["--vet", "pkg==1.0", "--allow-unscanned"]) == 0
        assert "  scanned: pkg-1.0.tar.gz" in capsys.readouterr().out
