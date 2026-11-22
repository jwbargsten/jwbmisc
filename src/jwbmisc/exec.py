import os
import subprocess as sp
from pathlib import Path


def run_cmd(
    cmd: list[str],
    env: dict[str, str] | None = None,
    capture: bool = False,
    stdin: bytes | str | None = None,
    contains_sensitive_data: bool = False,
    timeout: float | None = 300,
    cwd: str | Path | None = None,
    decode: bool = True,
    dry_run: bool = False,
) -> tuple[str, str] | tuple[bytes, bytes] | None:
    if isinstance(cmd, str):
        raise TypeError("cmd must be a list of arguments, not a string")
    if env is None:
        env = {}
    env = {**os.environ, **env}
    _ = env.pop("__PYVENV_LAUNCHER__", None)

    if stdin is not None and not isinstance(stdin, bytes):
        stdin = stdin.encode("utf-8")

    cmd = [str(v) for v in cmd]

    if cwd is not None:
        cwd = str(cwd)

    if dry_run:
        print(cmd)
        if capture:
            return ("", "") if decode else (b"", b"")
        return

    redacted = "<redacted>" if decode else b"<redacted>"

    try:
        res = sp.run(
            cmd,
            capture_output=capture,
            env=env,
            check=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin,
        )
    except (sp.CalledProcessError, sp.TimeoutExpired) as ex:
        # TimeoutExpired carries the partial output collected before the kill. Its stubs
        # type stdout/stderr as bytes, but with decode=True we deliberately store str.
        if contains_sensitive_data:
            ex.stdout = redacted  # type: ignore
            ex.stderr = redacted  # type: ignore
        elif decode:
            # errors="replace": a decode error must not hide the original failure
            if isinstance(ex.stdout, bytes):
                ex.stdout = ex.stdout.decode("utf-8", errors="replace")  # type: ignore
            if isinstance(ex.stderr, bytes):
                ex.stderr = ex.stderr.decode("utf-8", errors="replace")  # type: ignore
        raise

    if not capture:
        return None
    if decode:
        return (res.stdout.decode("utf-8"), res.stderr.decode("utf-8"))
    return (res.stdout, res.stderr)
