import subprocess as sp
import os
from pathlib import Path

PASS_BIN = os.environ.get("JWBMISC_PASS_BIN", "pass")


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
            import keyring

            args = pass_key.removeprefix("keyring://").split("/")
            pw = keyring.get_password(*args)
            if pw is None:
                raise KeyError(f"could not find a password for {pass_key}")
            return pw

        if pass_key.startswith("keeper://"):
            path = pass_key.removeprefix("keeper://")
            if "/" not in path:
                raise KeyError("Invalid keeper:// format. Expected: keeper://RECORD_UID/field/fieldname")

            record_uid, field_path = path.split("/", 1)
            return _keeper_password(record_uid, field_path)

    raise KeyError(f"Could not acquire password from one of {pass_keys}")


def _call_unix_pass(key, lnum=1):
    proc = sp.Popen([PASS_BIN, "show", key], stdout=sp.PIPE, stderr=sp.PIPE, encoding="utf-8")
    value, stderr = proc.communicate()

    if proc.returncode != 0:
        raise KeyError(f"pass failed for '{key}': {stderr.strip()}")

    if lnum is None or lnum == 0:
        return value.strip()
    lines = value.splitlines()

    try:
        if isinstance(lnum, list):
            pw = [lines[ln - 1].strip() for ln in lnum]
        else:
            pw = lines[lnum - 1].strip()
    except IndexError:
        raise KeyError(f"could not retrieve lines {lnum} for {key}")

    return pw


def _keeper_password(record_uid: str, field_path: str) -> str:
    from .keeper import get_password as keeper_get_password

    return keeper_get_password(record_uid, field_path)
