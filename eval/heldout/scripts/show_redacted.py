"""Print an archive's Python files with every string literal and comment replaced,
for hand triage without copying URLs, tokens or payload text out of the container.

Runs inside a --network none container. Usage:
  python -I show_redacted.py ROOT SAMPLE [MAX_LINES_PER_FILE] [LINE_REGEX]
With LINE_REGEX, only matching lines (redacted) are printed, with their line numbers.
"""

import io
import re
import sys
import tarfile
import tokenize
import zipfile
from pathlib import Path


def members(path):
    data = path.read_bytes()
    if data[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(data))
        return [(i.filename, zf.read(i)) for i in zf.infolist()
                if not i.is_dir() and i.file_size < 2_000_000]
    tf = tarfile.open(fileobj=io.BytesIO(data))
    return [(m.name, tf.extractfile(m).read()) for m in tf.getmembers()
            if m.isfile() and m.size < 2_000_000]


def redact(src):
    out = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return None
    for tok in toks:
        if tok.type == tokenize.STRING:
            out.append(tok._replace(string=f"'<str{len(tok.string)}>'"))
        elif tok.type == tokenize.COMMENT:
            out.append(tok._replace(string="#"))
        elif tok.type in (tokenize.FSTRING_START, tokenize.FSTRING_MIDDLE, tokenize.FSTRING_END) \
                if hasattr(tokenize, "FSTRING_START") else False:
            out.append(tok._replace(string="" if tok.type != tokenize.FSTRING_START else "'<fstr>'"))
        else:
            out.append(tok)
    try:
        return tokenize.untokenize(out)
    except ValueError:
        return " ".join(t.string for t in out)


root, sample = Path(sys.argv[1]), sys.argv[2]
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 80
pattern = re.compile(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None
for name, data in members(root / sample):
    print(f"=== {name} ({len(data)} bytes)")
    if not name.endswith(".py"):
        continue
    text = redact(data.decode("utf-8", "replace"))
    if text is None:
        print("<does not tokenize>")
        continue
    lines = [l[:160] for l in text.splitlines() if l.strip()]
    if pattern:
        lines = [f"{i}: {l[:160]}" for i, l in enumerate(text.splitlines(), 1) if pattern.search(l)]
    print("\n".join(lines[:limit]))
    if len(lines) > limit:
        print(f"... {len(lines) - limit} more lines")
