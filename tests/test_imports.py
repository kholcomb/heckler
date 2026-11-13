"""Nothing in the package imports from outside the standard library.

The statements are read, not run: the package imports inside functions, and
importing a module does not run those.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import heckler

PACKAGE = Path(heckler.__file__).parent
ALLOWED = sys.stdlib_module_names | {"heckler"}
SAMPLE = """
import os.path, packaging.version
from . import scanner
from .config import Config
def f():
    from regex import compile
if TYPE_CHECKING:
    import yaml
importlib.import_module("tomli.sub")
__import__("colorama")
import_module(name)
"""


def _imports(source: str) -> list[tuple[int, str]]:
    """Return the line and first dotted name of every import in the source."""
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, node.col_offset, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.append((node.lineno, node.col_offset, node.module.split(".")[0]))
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if isinstance(func, ast.Attribute):
                name = func.attr
            if name not in ("__import__", "import_module"):
                continue
            argument = node.args[0] if node.args else None
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                target = argument.value.split(".")[0]
            else:
                target = "<computed>"
            found.append((node.lineno, node.col_offset, target))
    found.sort(key=lambda entry: entry[:2])
    return [(line, target) for line, _, target in found]


def test_the_reader_sees_every_way_of_importing() -> None:
    assert _imports(SAMPLE) == [
        (2, "os"),
        (2, "packaging"),
        (6, "regex"),
        (8, "yaml"),
        (9, "tomli"),
        (10, "colorama"),
        (11, "<computed>"),
    ]


def test_the_package_imports_the_standard_library_and_itself() -> None:
    files = sorted(PACKAGE.rglob("*.py"))
    assert files, f"no modules under {PACKAGE}"
    offenders = [
        f"{path.relative_to(PACKAGE)}:{line} imports {name}"
        for path in files
        for line, name in _imports(path.read_text(encoding="utf-8"))
        if name not in ALLOWED
    ]
    assert offenders == []
