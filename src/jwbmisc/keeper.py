import json
from keepercommander import vault as keeper_vault
from keepercommander import api
from time import sleep
from keepercommander.params import KeeperParams
from keepercommander.config_storage import loader
import os
from .interactive import ask
from pathlib import Path
import webbrowser
from keepercommander.auth import login_steps
from logging import getLogger

logger = getLogger(__name__)


class _MinimalKeeperUI:
    def __init__(self):
        self.waiting_for_sso_data_key = False

    def on_sso_redirect(self, step):
        self.waiting_for_sso_data_key = False
        webbrowser.open_new_tab(step.sso_login_url)

        token = ask("SSO token: ")

        if not token:
            raise ValueError("No SSO token provided")
        step.set_sso_token(token.strip())

    def on_two_factor(self, step):
        channels = step.get_channels()
        totp_channel = next(
            (c for c in channels if c.channel_type == login_steps.TwoFactorChannel.Authenticator), None
        )

        if not totp_channel:
            raise ValueError("TOTP authenticator not available")

        totp_code = ask("2FA code:")

        if not totp_code:
            raise ValueError("No TOTP code provided")

        step.duration = login_steps.TwoFactorDuration.Every12Hours
        try:
            step.send_code(totp_channel.channel_uid, totp_code.strip())
            logger.info("keeper 2fa success")
        except api.KeeperApiError:
            logger.info("keeper api error")

    def on_password(self, _step):
        raise KeyError("Password login not supported. Use SSO.")

    def on_device_approval(self, _step):
        logger.info("Waiting for device approval...")

    def on_sso_data_key(self, step):
        if not self.waiting_for_sso_data_key:
            logger.info("sent push")
            step.request_data_key(login_steps.DataKeyShareChannel.KeeperPush)
            self.waiting_for_sso_data_key = True
        logger.info("waiting for push")
        sleep(1)
        step.resume()


def _extract_keeper_field(record, field: str) -> str | None:
    if isinstance(record, keeper_vault.TypedRecord):
        value = record.get_typed_field(field)
        if value is None:
            value = next((f for f in record.custom if f.label == field), None)

        if value and value.value:
            return value.value[0] if isinstance(value.value, list) else str(value.value)

    return None


def _perform_keeper_login(params):
    if not params.user:
        user = os.environ.get("KEEPER_USERNAME", None)
        if user is None:
            user = ask("User (email): ")
        user = user.strip()
        if not user:
            raise ValueError("No username provided")
        params.user = user

        server = os.environ.get("KEEPER_SERVER", None)
        if server is None:
            server = ask("Server:")

        if not server:
            raise ValueError("No server provided")
        params.server = server

    try:
        api.login(params, login_ui=_MinimalKeeperUI())
    except KeyboardInterrupt:
        raise KeyError("\nKeeper login cancelled by user.") from None
    except Exception as e:
        raise KeyError(f"Keeper login failed: {e}") from e


def get_keeper_password(record_uid: str, field_path: str) -> str:
    config_file = Path.home() / ".config" / "keeper" / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)

    params = KeeperParams(config_filename=str(config_file))

    if config_file.exists():
        try:
            params.config = json.loads(config_file.read_text())
            loader.load_config_properties(params)
            if not params.session_token:
                raise ValueError("No session token")
        except Exception:
            _perform_keeper_login(params)
    else:
        _perform_keeper_login(params)

    try:
        api.sync_down(params)
    except Exception as e:
        raise KeyError(f"Failed to sync Keeper vault: {e}") from e

    try:
        record = keeper_vault.KeeperRecord.load(params, record_uid)
    except Exception as e:
        raise KeyError(f"Record {record_uid} not found: {e}") from e

    value = _extract_keeper_field(record, field_path)
    if value is None:
        raise KeyError(f"Field '{field_path}' not found in record {record_uid}")

    return value
