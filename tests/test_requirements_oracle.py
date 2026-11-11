"""Version and requirement parsing, held to the packaging library.

lockfile.py reads requirement lines and compares versions with its own code,
because heckler has no runtime dependencies. packaging is the reference
implementation of the same rules (PEP 440 and PEP 508). It is installed for
the tests only, and these tests fail where the two disagree.
"""

from __future__ import annotations

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from heckler.lockfile import _normalize_dist_name, _parse_requirement, _same_python_version

# Spellings PEP 440 accepts, several for the same version.
VERSIONS = [
    "1",
    "1.0",
    "1.0.0",
    "1.0.0.0",
    "01.0",
    "v1.0",
    " 1.0 ",
    "1.1",
    "1.01",
    "1.10",
    "0!1.0",
    "1!1.0",
    "1.0+local",
    "1.0+abc.1",
    "1.0a1",
    "1.0A1",
    "1.0alpha1",
    "1.0.a.1",
    "1.0-alpha-1",
    "1.0_alpha_1",
    "1.0a",
    "1.0a0",
    "1.0a2",
    "1.0b2",
    "1.0beta2",
    "1.0rc1",
    "1.0RC1",
    "1.0c1",
    "1.0pre1",
    "1.0preview1",
    "1.0.post1",
    "1.0post1",
    "1.0-post1",
    "1.0_post1",
    "1.0-1",
    "1.0.rev1",
    "1.0r1",
    "1.0.post",
    "1.0.post0",
    "1.0.post2",
    "1.0.dev1",
    "1.0dev1",
    "1.0-dev1",
    "1.0.dev",
    "1.0.dev0",
    "1.0a1.post2",
    "1.0a1.post2.dev3",
    "1.0alpha1-2.dev3",
    "1.0.post1.dev2",
    "2024.01.05",
    "2024.1.5",
    "2.31.0",
    "2.31",
]

NAMES = [
    "PyYAML",
    "pyyaml",
    "zope.interface",
    "zope-interface",
    "Zope_Interface",
    "a__b",
    "a-.-b",
    "Typing_Extensions",
    "ruamel.yaml.clib",
]

# Requirement lines that PEP 508 accepts.
REQUIREMENTS = [
    "requests",
    "requests==2.31.0",
    "requests == 2.31.0",
    "requests===2.31.0",
    "requests>=2,<3",
    "requests~=2.31",
    "requests!=2.0",
    "requests==2.*",
    "requests==2.31.0,!=2.0",
    "requests[socks]==2.31.0",
    "requests [socks] == 2.31.0",
    "requests[a,b] >= 1 ; os_name=='nt'",
    "requests==2.31.0 ; python_version < '3.13'",
    "requests ==2.31.0;extra=='x'",
    "requests (==2.31.0)",
    "requests(>=2)",
    "requests @ https://example.test/requests-2.31.0-py3-none-any.whl",
    "Requests==2.31.0",
    "zope.interface==6.0",
    "name-with-dash==1",
    "a.b_c==1",
    "a==1.0+local",
    "a==1!2.0",
    "a==1.0a1",
    "a==1.0.post1",
]


def _without_local(version: str) -> Version:
    """heckler does not compare the local part, so neither does the reference."""
    return Version(Version(version).public)


class TestVersions:
    def test_every_pair_compares_as_packaging_says(self) -> None:
        wrong = [
            (left, right)
            for left in VERSIONS
            for right in VERSIONS
            if _same_python_version(left, right) != (_without_local(left) == _without_local(right))
        ]
        assert wrong == []

    def test_the_list_holds_more_than_one_spelling_of_a_version(self) -> None:
        """Or the test above would pass for a comparison of the text alone."""
        same = sum(_without_local(a) == _without_local(b) for a in VERSIONS for b in VERSIONS)
        assert same > 4 * len(VERSIONS)

    @pytest.mark.parametrize(
        ("left", "right", "same"),
        [
            ("2004d", "2004d", True),
            ("2004d", "2004D", True),
            ("2004d", "2004e", False),
            ("1.0", "1.0-final", False),
            ("1.0", "", False),
        ],
    )
    def test_text_that_is_not_a_version_is_only_equal_to_itself(
        self, left: str, right: str, same: bool
    ) -> None:
        assert _same_python_version(left, right) is same


class TestNames:
    @pytest.mark.parametrize("name", NAMES)
    def test_normalized_as_packaging_does(self, name: str) -> None:
        assert _normalize_dist_name(name) == canonicalize_name(name)


class TestRequirements:
    @pytest.mark.parametrize("line", REQUIREMENTS)
    def test_name_and_pin_are_what_packaging_reads(self, line: str) -> None:
        requirement = Requirement(line)
        specifiers = list(requirement.specifier)
        # The one case with a version to hold the installed copy to: a
        # single exact pin without a wildcard.
        pin = ""
        if len(specifiers) == 1 and specifiers[0].operator in ("==", "==="):
            pin = "" if "*" in specifiers[0].version else specifiers[0].version

        parsed = _parse_requirement(line)
        assert parsed is not None
        assert (_normalize_dist_name(parsed[0]), parsed[1]) == (
            canonicalize_name(requirement.name),
            pin,
        )
