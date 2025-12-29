import subprocess as sp
import keyring
import random
import string
import re
from collections.abc import Iterable
from typing import Any, Optional
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

        if pass_key.startswith("keeper://"):
            # Parse keeper://RECORD_UID/field/fieldname
            path = pass_key.removeprefix("keeper://")
            if "/" not in path:
                raise KeyError(f"Invalid keeper:// format. Expected: keeper://RECORD_UID/field/fieldname")

            record_uid, field_path = path.split("/", 1)
            return _get_keeper_password(record_uid, field_path)

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


class _MinimalKeeperUI:
    """Minimal UI for SSO + TOTP using questionary."""

    def on_sso_redirect(self, step):
        import webbrowser
        import questionary

        print(f"\nOpening SSO login URL in browser...")
        webbrowser.open_new_tab(step.sso_login_url)

        token = questionary.text(
            "Paste the SSO token from your browser:",
            instruction="(Token appears in URL or on page after login)"
        ).ask()

        if not token:
            raise KeyError("No SSO token provided")
        step.set_sso_token(token.strip())

    def on_two_factor(self, step):
        import questionary
        from keepercommander.auth import login_steps

        channels = step.get_channels()
        totp_channel = next(
            (c for c in channels if c.channel_type == login_steps.TwoFactorChannel.Authenticator),
            None
        )

        if not totp_channel:
            raise KeyError("TOTP authenticator not available")

        totp_code = questionary.text(
            "Enter 2FA code from your authenticator app:",
            validate=lambda text: len(text) == 6 and text.isdigit()
        ).ask()

        if not totp_code:
            raise KeyError("No TOTP code provided")

        step.duration = login_steps.TwoFactorDuration.Every12Hours
        step.send_code(totp_channel.channel_uid, totp_code.strip())

    def on_password(self, step):
        raise KeyError("Password login not supported. Use SSO.")

    def on_device_approval(self, step):
        print("⏳ Waiting for device approval...")

    def on_sso_data_key(self, step):
        from keepercommander.auth import login_steps
        step.request_data_key(login_steps.DataKeyShareChannel.KeeperPush)


def _extract_keeper_field(record, field_path: str) -> Optional[str]:
    """Extract field value from Keeper record."""
    from keepercommander import vault as keeper_vault

    # Parse field path: "field/password" or "custom_field/api_key"
    parts = field_path.split("/", 1)
    if len(parts) != 2:
        return None

    field_type, field_name = parts

    # Handle V2 PasswordRecord
    if isinstance(record, keeper_vault.PasswordRecord):
        if field_type == "field":
            if field_name == "password":
                return record.password
            elif field_name == "login":
                return record.login
            elif field_name == "notes":
                return record.notes

    # Handle V3 TypedRecord
    elif isinstance(record, keeper_vault.TypedRecord):
        if field_type == "field":
            field = record.get_typed_field(field_name)
        elif field_type == "custom_field":
            field = next((f for f in record.custom if f.label == field_name), None)
        else:
            return None

        if field and field.value:
            # Return first value if list
            return field.value[0] if isinstance(field.value, list) else str(field.value)

    return None


def _perform_keeper_login(params):
    """Perform interactive Keeper SSO login with TOTP support."""
    from keepercommander import api
    from keepercommander.config_storage import loader
    import questionary

    # Get username if not set
    if not params.user:
        print("\n" + "="*70)
        print("KEEPER COMMANDER - SSO LOGIN")
        print("="*70)

        params.user = questionary.text(
            "Enter your Keeper username (email):",
            validate=lambda text: "@" in text
        ).ask()

        if not params.user:
            raise KeyError("No username provided")

    # Set hostname
    params.server = os.environ.get("KEEPER_HOSTNAME", "keepersecurity.com")

    # Custom UI for SSO + TOTP
    ui = _MinimalKeeperUI()

    # Perform login
    try:
        api.login(params, login_ui=ui)
        loader.store_config_properties(params)
        print("✓ Keeper login successful!")
    except KeyboardInterrupt:
        raise KeyError("\nKeeper login cancelled by user.") from None
    except Exception as e:
        raise KeyError(f"Keeper login failed: {e}") from e


def _get_keeper_password(record_uid: str, field_path: str) -> str:
    """
    Retrieve password from Keeper vault using Commander.

    Args:
        record_uid: Keeper record UID
        field_path: Field path like 'field/password' or 'custom_field/api_key'

    Returns:
        The password/secret value

    Raises:
        KeyError: If authentication fails or record/field not found
    """
    # Lazy import Commander
    try:
        from keepercommander.params import KeeperParams
        from keepercommander import api
        from keepercommander.config_storage import loader
        from keepercommander import vault as keeper_vault
    except ImportError as e:
        raise KeyError(
            "Keeper Commander not installed. Install with: pip install keepercommander"
        ) from e

    # Setup config path
    config_file = Path.home() / ".keeper" / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)

    # Initialize params
    params = KeeperParams(config_filename=str(config_file))
    params.user = os.environ.get("KEEPER_USERNAME", "")

    # Load existing session or login
    if config_file.exists():
        try:
            loader.load_config_properties(params)
            if not params.session_token:
                raise ValueError("No session token")
        except Exception:
            # Session invalid, re-login
            _perform_keeper_login(params)
    else:
        # First time login
        _perform_keeper_login(params)

    # Sync vault
    try:
        api.sync_down(params)
    except Exception as e:
        raise KeyError(f"Failed to sync Keeper vault: {e}") from e

    # Get record
    try:
        record = keeper_vault.KeeperRecord.load(params, record_uid)
    except Exception as e:
        raise KeyError(f"Record {record_uid} not found: {e}") from e

    # Extract field value
    value = _extract_keeper_field(record, field_path)
    if value is None:
        raise KeyError(f"Field '{field_path}' not found in record {record_uid}")

    return value


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


def qw(s: str) -> list[str]:
    return s.split()
