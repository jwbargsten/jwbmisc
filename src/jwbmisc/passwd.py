import subprocess as sp
import os
from urllib.parse import urlparse, parse_qs
from pathlib import Path

PASS_BIN = os.environ.get("JWBMISC_PASS_BIN", "pass")


def get_pass(*pass_keys: str):
    if not pass_keys:
        raise ValueError("no pass keys supplied")

    for pass_key in pass_keys:
        if pass_key.startswith("pass://"):
            url = urlparse(pass_key, scheme="pass")
            query = parse_qs(url.query)
            lines = query.get("lines", ["1"])[0]
            format = query.get("format", ["raw"])[0]
            if lines == "all":
                lines = None
            else:
                lines = [int(n) - 1 for n in lines.split(",")]
            netloc = url.netloc.rstrip("/")
            path = url.path.lstrip("/")
            key = f"{netloc}/{path}".lstrip("/")
            return _call_unix_pass(key, lines, format)

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
            import keyring

            args = pass_key.removeprefix("keyring://").split("/")
            pw = keyring.get_password(*args)
            if pw is None:
                raise KeyError(f"could not find a password for {pass_key}")
            return pw

        if pass_key.startswith("keeper://"):
            path = pass_key.removeprefix("keeper://")

            parts = path.split("/")
            return _keeper_password(*parts)

    raise KeyError(f"Could not acquire password from one of {pass_keys}")


def _call_unix_pass(key: str, idcs: list[int] | None = None, format: str = "list") -> str | list[str] | None:
    proc = sp.Popen([PASS_BIN, "show", key], stdout=sp.PIPE, stderr=sp.PIPE, encoding="utf-8")
    value, stderr = proc.communicate()

    if proc.returncode != 0:
        raise KeyError(f"pass failed for '{key}': {stderr.strip()}")

    if idcs is None or idcs == [-1]:
        return value.rstrip()

    lines = value.splitlines()
    try:
        lines = [lines[idx] for idx in idcs]
    except IndexError:
        raise KeyError(f"could not retrieve line idcs {idcs} for {key}")

    if format == "list":
        return lines
    return "\n".join(lines)


def _keeper_password(record_uid: str, field_path: str | None = None) -> str:
    from .keeper import get_password as keeper_get_password

    return keeper_get_password(record_uid, field_path)
