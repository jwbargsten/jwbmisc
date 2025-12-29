import subprocess as sp
import os


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
