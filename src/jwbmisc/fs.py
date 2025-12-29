import subprocess as sp
from collections.abc import Iterable
from pathlib import Path


def fzf(entries: Iterable[str]):
    process = sp.Popen(
        ["fzf", "+m"],
        stdout=sp.PIPE,
        stdin=sp.PIPE,
        encoding="utf-8",
    )

    stdout, _ = process.communicate(input="\n".join(entries) + "\n")
    return stdout.strip()


def find_root(start, req):
    p = Path(start).absolute()
    if p.is_file():
        p = p.parent

    while p.parent != p:
        files = {f.name for f in p.iterdir()}
        if req <= files:
            return p
        p = p.parent
    return None
