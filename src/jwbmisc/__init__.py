import subprocess as sp
import keyring
import random
import string
import re
from collections.abc import Iterable
from typing import Any
import os
import json
from pathlib import Path
import gzip


def run_cmd(
    cmd,
    env=None,
    capture=False,
    stdin=None,
    contains_sensitive_data=False,
    timeout=20,
    decode=True,
    dry_run=False,
):
    if env is None:
        env = {}
    env = {**os.environ, **env}
    env.pop("__PYVENV_LAUNCHER__", None)

    if stdin is not None:
        stdin = stdin.encode("utf-8")

    cmd = [str(v) for v in cmd]

    if dry_run:
        print(cmd)
        if capture:
            return ("", "")
        return

    try:
        res = sp.run(
            cmd,
            capture_output=capture,
            env=env,
            check=True,
            timeout=timeout,
            input=stdin,
        )
    except sp.CalledProcessError as ex:
        redacted_bytes = "<redacted>".encode("utf-8")
        out = redacted_bytes if contains_sensitive_data else ex.output
        err = redacted_bytes if contains_sensitive_data else ex.stderr
        raise sp.CalledProcessError(ex.returncode, ex.cmd, out, err) from None

    if not capture:
        return None
    if decode:
        return (res.stdout.decode("utf-8"), res.stderr.decode("utf-8"))
    return (res.stdout, res.stderr)


def split_host(host: str) -> tuple[str | None, int | None]:
    if not host:
        return (None, None)
    res = host.split(":", 1)
    if len(res) == 1:
        return (res[0], None)
    return (res[0], int(res[1]))


def resilient_loads(data):
    if not data:
        return None
    try:
        return json.loads(data)
    except Exception:
        return None


def goo(
    d: dict[str, Any],
    *keys: str | int,
    default: Any | None = None,
    raise_on_default: bool = False,
):
    path = ".".join(str(k) for k in keys)
    parts = path.split(".")

    res = d
    for p in parts:
        if res is None:
            if raise_on_default:
                raise ValueError("'{path}' does not exist")
            return default
        if isinstance(res, (list, set, tuple)):
            res = res[int(p)]
        else:
            res = res.get(p)
    if res is None:
        if raise_on_default:
            raise ValueError("'{path}' does not exist")
        return default
    return res


def fzf(entries: Iterable[str]):
    process = sp.Popen(
        ["fzf", "+m"],
        stdout=sp.PIPE,
        stdin=sp.PIPE,
        encoding="utf-8",
    )

    stdout, _ = process.communicate(input="\n".join(entries) + "\n")
    return stdout.strip()


def get_pass(*pass_keys: str):
    if not pass_keys:
        raise ValueError("no pass keys supplied")

    for pass_key in pass_keys:
        if pass_key.startswith("pass://"):
            k = pass_key.removeprefix("pass://")
            lnum = 1
            if "?" in k:
                k, lnum = k.rsplit("?", 1)
            return _call_unix_pass(k, int(lnum))

        if pass_key.startswith("env://"):
            env_var = pass_key.removeprefix("env://").replace("/", "__")
            if env_var not in os.environ:
                raise KeyError(f"{env_var} (derived from {pass_key}) is not in the env")
            return os.environ[env_var]

        if pass_key.startswith("file://"):
            f = Path(pass_key.removeprefix("file://"))
            if not f.exists() or f.is_dir():
                raise KeyError(f"{f} (derived from {pass_key}) does not exist or is a dir")
            return f.read_text().strip()

        if pass_key.startswith("keyring://"):
            args = pass_key.removeprefix("keyring://").split("/")
            pw = keyring.get_password(*args)
            if pw is None:
                raise KeyError(f"could not find a password for {pass_key}")
            return pw

    raise KeyError(f"Could not acquire password from one of {pass_keys}")


def _call_unix_pass(key, lnum=1):
    proc = sp.Popen(["pass", "show", key], stdout=sp.PIPE, encoding="utf-8")
    value, _ = proc.communicate()

    if lnum is None or lnum == 0:
        return value.strip()
    lines = value.splitlines()

    try:
        if isinstance(lnum, list):
            pw = [lines[ln - 1].strip() for ln in lnum]
        pw = lines[lnum - 1].strip()
    except IndexError:
        raise KeyError(f"could not not retrieve lines {lnum} for {key}")

    return pw


def jinja_replace(s, config, relaxed=False, delim=("{{", "}}")):
    """Jinja for poor people. A very simple
    function to replace variables in text using `{{variable}}` syntax.

    :param s: the template string/text
    :param config: a dict of variable -> replacement mapping
    :param relaxed: Don't raise a KeyError if a variable is not in the config dict.
    :param delim: Change the delimiters to something else.
    """

    def handle_match(m):
        k = m.group(1)
        if k in config:
            return config[k]
        if relaxed:
            return m.group(0)
        raise KeyError(f"{k} is not in the supplied replacement variables")

    return re.sub(re.escape(delim[0]) + r"\s*(\w+)\s*" + re.escape(delim[1]), handle_match, s)


def randomsuffix(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


def confirm(question, default="n"):
    prompt = f"{question} (y/n)"
    if default is not None:
        prompt += f" [{default}]"
    answer = input(prompt).strip().lower()
    return answer.startswith("y")


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
