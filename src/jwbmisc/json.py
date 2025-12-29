import re
from typing import Any
import json
from pathlib import Path
import gzip


def jsonc_loads(data: str):
    data = re.sub(r"//.*$", "", data, flags=re.MULTILINE)
    data = re.sub(r"/\*.*?\*/", "", data, flags=re.DOTALL)
    return json.loads(data)


def jsonc_read(f: str | Path):
    f = Path(f)
    open_fn = gzip.open if f.suffix.lower() == ".gz" else open
    with open_fn(f, "rt", encoding="utf-8") as fd:
        return jsonc_loads(fd.read())


def ndjson_read(f: str | Path):
    f = Path(f)
    open_fn = gzip.open if f.suffix.lower() == ".gz" else open
    with open_fn(f, "rt", encoding="utf-8") as fd:
        for line in fd:
            line = line.strip()
            if line and not line.startswith("#"):
                yield json.loads(line)


def ndjson_write(data: list[Any], f: str | Path):
    f = Path(f)
    open_fn = gzip.open if f.suffix.lower() == ".gz" else open
    with open_fn(f, "wb") as fd:
        for record in data:
            blob = (json.dumps(record) + "\n").encode("utf-8")
            fd.write(blob)


def resilient_loads(data):
    if not data:
        return None
    try:
        return json.loads(data)
    except Exception:
        return None
