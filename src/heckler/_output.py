"""Write to standard output without failing on characters the stream cannot encode."""

from __future__ import annotations

import json
import sys


def write_out(text: str, *, json_document: bool = False) -> None:
    """Print ``text`` and a newline to ``sys.stdout``.

    The stream is probed with its own error handler, so ``text`` is changed
    exactly when ``print()`` would raise. Where the stream can encode it, with
    its handler, it is printed as it is. Where it cannot, the characters it
    cannot take are escaped: every character outside ASCII as a JSON string
    escape when ``text`` is a JSON document written with ``ensure_ascii=False``,
    the ones the stream cannot take as backslash escapes otherwise. A stream
    that reports no encoding or no handler, or one Python has no codec or
    handler for, is written to as it is.
    """
    encoding: str | None = getattr(sys.stdout, "encoding", None)
    errors: str | None = getattr(sys.stdout, "errors", None)
    if encoding is None or errors is None:
        print(text)
        return
    try:
        text.encode(encoding, errors)
    except LookupError:
        print(text)
        return
    except UnicodeEncodeError:
        if json_document:
            text = "".join(c if ord(c) < 0x80 else json.dumps(c)[1:-1] for c in text)
        else:
            text = text.encode(encoding, "backslashreplace").decode(encoding)
    print(text)
