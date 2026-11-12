"""Write to standard output without failing on characters the stream cannot encode."""

from __future__ import annotations

import json
import sys


def write_out(text: str, *, json_document: bool = False) -> None:
    """Print ``text`` and a newline to ``sys.stdout``.

    Where the stream can encode ``text``, it is printed as it is. Where it
    cannot, the characters it cannot take are escaped: as JSON string escapes
    when ``text`` is a JSON document written with ``ensure_ascii=False``, as
    backslash escapes otherwise.
    """
    encoding: str | None = getattr(sys.stdout, "encoding", None)
    errors: str | None = getattr(sys.stdout, "errors", None)
    if encoding is None or errors != "strict":
        print(text)
        return
    try:
        text.encode(encoding)
    except LookupError:
        print(text)
        return
    except UnicodeEncodeError:
        if json_document:
            text = "".join(c if ord(c) < 0x80 else json.dumps(c)[1:-1] for c in text)
        else:
            text = text.encode(encoding, "backslashreplace").decode(encoding)
    print(text)
