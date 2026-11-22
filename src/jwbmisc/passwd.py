import importlib.util
import os
import shutil
import subprocess as sp
from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

logger = getLogger(__name__)

PASS_BIN = os.environ.get("JWBMISC_PASS_BIN", "pass")


class BackendUnavailable(Exception):
    """The password manager for a URL is not installed/usable on this machine."""


@dataclass(frozen=True)
class Backend:
    scheme: str
    available: Callable[[], bool]
    get: Callable[[str, bool], str | list[str]]


def get_pass(*pass_keys: str, interactive: bool = True) -> str | list[str]:
    """Get a secret, trying each URL in order until one succeeds.

    Each URL addresses the secret in one password manager, e.g.
    ``get_pass("keeper://UID/password", "pass://work/token", "env://TOKEN")``.
    URLs whose manager is not available are skipped, failures fall through to the
    next URL. If all fail, a ``KeyError`` listing every reason is raised.

    With ``interactive=False``, backends never prompt (e.g. Keeper is skipped when
    there is no stored session instead of starting a login).
    """
    if not pass_keys:
        raise ValueError("no pass keys supplied")

    # validate all URLs up front: an unknown scheme is a programming error,
    # it should not be masked by an earlier URL happening to succeed
    backends = [(key, _backend_for(key)) for key in pass_keys]

    errors: list[str] = []
    for pass_key, backend in backends:
        if not backend.available():
            errors.append(f"{pass_key}: {backend.scheme} is not available")
            continue
        try:
            return backend.get(pass_key, interactive)
        except (KeyError, BackendUnavailable) as e:
            msg = e.args[0] if e.args else str(e)
            logger.debug("could not get %s: %s", pass_key, msg)
            errors.append(f"{pass_key}: {msg}")

    raise KeyError("Could not acquire password:\n  " + "\n  ".join(errors))


def _backend_for(pass_key: str) -> Backend:
    scheme, sep, _ = pass_key.partition("://")
    if not sep or scheme not in BACKENDS:
        raise ValueError(f"unsupported pass key '{pass_key}', supported schemes: {', '.join(BACKENDS)}")
    return BACKENDS[scheme]


def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


# --- pass ---------------------------------------------------------------------


def _pass_available() -> bool:
    return shutil.which(PASS_BIN) is not None


def _pass_get(pass_key: str, _interactive: bool) -> str | list[str]:
    url = urlparse(pass_key, scheme="pass")
    query = parse_qs(url.query)
    lines_q = query.get("lines", ["1"])[0]
    format = query.get("format", ["raw"])[0]
    lines = None if lines_q == "all" else [int(n) - 1 for n in lines_q.split(",")]
    netloc = url.netloc.rstrip("/")
    path = url.path.lstrip("/")
    key = f"{netloc}/{path}".lstrip("/")
    return _call_unix_pass(key, lines, format)


def _call_unix_pass(key: str, idcs: list[int] | None = None, format: str = "list") -> str | list[str]:
    proc = sp.Popen([PASS_BIN, "show", key], stdout=sp.PIPE, stderr=sp.PIPE, encoding="utf-8")
    value, stderr = proc.communicate()

    if proc.returncode != 0:
        raise KeyError(f"pass failed for '{key}': {stderr.strip()}")

    if idcs is None or idcs == [-1]:
        if format == "raw":
            return value.rstrip()
        else:
            return value.rstrip().splitlines()

    lines = value.splitlines()
    try:
        lines = [lines[idx] for idx in idcs]
    except IndexError:
        raise KeyError(f"could not retrieve line idcs {idcs} for {key}")

    if format == "list":
        return lines
    return "\n".join(lines)


# --- env / file ---------------------------------------------------------------


def _env_get(pass_key: str, _interactive: bool) -> str:
    env_var = pass_key.removeprefix("env://").replace("/", "__")
    if env_var not in os.environ:
        raise KeyError(f"{env_var} (derived from {pass_key}) is not in the env")
    return os.environ[env_var]


def _file_get(pass_key: str, _interactive: bool) -> str:
    f = Path(pass_key.removeprefix("file://"))
    if not f.exists() or f.is_dir():
        raise KeyError(f"{f} (derived from {pass_key}) does not exist or is a dir")
    return f.read_text().strip()


# --- keyring ------------------------------------------------------------------


def _keyring_available() -> bool:
    if not _has_module("keyring"):
        return False
    import keyring
    from keyring.backends import fail

    # keyring is importable, but there is no usable OS backend (e.g. headless linux)
    return not isinstance(keyring.get_keyring(), fail.Keyring)


def _keyring_get(pass_key: str, _interactive: bool) -> str:
    import keyring
    from keyring.errors import KeyringError

    args = pass_key.removeprefix("keyring://").split("/")
    try:
        pw = keyring.get_password(*args)
    except KeyringError as e:
        raise KeyError(f"keyring error: {e}") from e
    if pw is None:
        raise KeyError(f"could not find a password for {pass_key}")
    return pw


# --- keeper -------------------------------------------------------------------


def _keeper_available() -> bool:
    return _has_module("keepercommander")


def _keeper_get(pass_key: str, interactive: bool) -> str:
    record_uid, _, field_path = pass_key.removeprefix("keeper://").partition("/")
    return _keeper_password(record_uid, field_path or None, interactive)


def _keeper_password(record_uid: str, field_path: str | None = None, interactive: bool = True) -> str:
    from .keeper import get_password as keeper_get_password

    return keeper_get_password(record_uid, field_path, interactive=interactive)


BACKENDS: dict[str, Backend] = {
    b.scheme: b
    for b in [
        Backend("pass", _pass_available, _pass_get),
        Backend("env", lambda: True, _env_get),
        Backend("file", lambda: True, _file_get),
        Backend("keyring", _keyring_available, _keyring_get),
        Backend("keeper", _keeper_available, _keeper_get),
    ]
}
