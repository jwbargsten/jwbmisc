import pytest

from jwbmisc.keeper import (
    _MinimalKeeperUI,
    _extract_keeper_field,
    _perform_keeper_login,
    get_keeper_password,
)


class MockTypedField:
    def __init__(self, value):
        self.value = value
        self.label = None


class MockTypedRecord:
    def __init__(self, fields=None, custom=None):
        self._fields = fields or {}
        self.custom = custom or []

    def get_typed_field(self, name):
        return self._fields.get(name)


class TestExtractKeeperField:
    def test_typed_record_with_list_value(self, mocker):
        mocker.patch("jwbmisc.keeper.keeper_vault.TypedRecord", MockTypedRecord)
        field = MockTypedField(["password123"])
        record = MockTypedRecord(fields={"password": field})

        result = _extract_keeper_field(record, "password")
        assert result == "password123"

    def test_typed_record_with_string_value(self, mocker):
        mocker.patch("jwbmisc.keeper.keeper_vault.TypedRecord", MockTypedRecord)
        field = MockTypedField("single_value")
        record = MockTypedRecord(fields={"password": field})

        result = _extract_keeper_field(record, "password")
        assert result == "single_value"

    def test_typed_record_field_not_found(self, mocker):
        mocker.patch("jwbmisc.keeper.keeper_vault.TypedRecord", MockTypedRecord)
        record = MockTypedRecord(fields={})

        result = _extract_keeper_field(record, "missing")
        assert result is None

    def test_typed_record_custom_field(self, mocker):
        mocker.patch("jwbmisc.keeper.keeper_vault.TypedRecord", MockTypedRecord)
        custom_field = MockTypedField(["custom_value"])
        custom_field.label = "custom_field"
        record = MockTypedRecord(fields={}, custom=[custom_field])

        result = _extract_keeper_field(record, "custom_field")
        assert result == "custom_value"

    def test_non_typed_record_returns_none(self):
        result = _extract_keeper_field(object(), "any_field")
        assert result is None


class TestMinimalKeeperUI:
    def test_on_password_raises(self):
        ui = _MinimalKeeperUI()
        with pytest.raises(KeyError, match="Password login not supported"):
            ui.on_password(None)

    def test_on_sso_redirect(self, mocker):
        mock_webbrowser = mocker.patch("jwbmisc.keeper.webbrowser")
        mocker.patch("jwbmisc.keeper.ask", return_value="sso_token_123")

        step = mocker.MagicMock()
        step.sso_login_url = "https://sso.example.com"

        ui = _MinimalKeeperUI()
        ui.on_sso_redirect(step)

        mock_webbrowser.open_new_tab.assert_called_once_with("https://sso.example.com")
        step.set_sso_token.assert_called_once_with("sso_token_123")

    def test_on_sso_redirect_empty_token_raises(self, mocker):
        mocker.patch("jwbmisc.keeper.webbrowser")
        mocker.patch("jwbmisc.keeper.ask", return_value="")

        step = mocker.MagicMock()
        step.sso_login_url = "https://sso.example.com"

        ui = _MinimalKeeperUI()
        with pytest.raises(ValueError, match="No SSO token"):
            ui.on_sso_redirect(step)

    def test_on_two_factor(self, mocker):
        mocker.patch("jwbmisc.keeper.ask", return_value="123456")
        mock_channel = mocker.MagicMock()
        mock_channel.channel_type = mocker.patch("jwbmisc.keeper.login_steps.TwoFactorChannel").Authenticator
        mock_channel.channel_uid = "channel_123"

        step = mocker.MagicMock()
        step.get_channels.return_value = [mock_channel]

        ui = _MinimalKeeperUI()
        ui.on_two_factor(step)

        step.send_code.assert_called_once_with("channel_123", "123456")

    def test_on_two_factor_no_totp_raises(self, mocker):
        mocker.patch("jwbmisc.keeper.login_steps.TwoFactorChannel")
        mock_channel = mocker.MagicMock()
        mock_channel.channel_type = "other_type"

        step = mocker.MagicMock()
        step.get_channels.return_value = [mock_channel]

        ui = _MinimalKeeperUI()
        with pytest.raises(ValueError, match="TOTP authenticator not available"):
            ui.on_two_factor(step)

    def test_on_device_approval_does_not_raise(self, mocker):
        ui = _MinimalKeeperUI()
        ui.on_device_approval(None)  # Should not raise

    def test_on_sso_data_key_first_call(self, mocker):
        mock_sleep = mocker.patch("jwbmisc.keeper.sleep")
        mocker.patch("jwbmisc.keeper.login_steps")

        step = mocker.MagicMock()

        ui = _MinimalKeeperUI()
        assert ui.waiting_for_sso_data_key is False

        ui.on_sso_data_key(step)

        assert ui.waiting_for_sso_data_key is True
        step.request_data_key.assert_called_once()
        step.resume.assert_called_once()
        mock_sleep.assert_called_once_with(1)

    def test_on_sso_data_key_subsequent_call(self, mocker):
        mock_sleep = mocker.patch("jwbmisc.keeper.sleep")
        step = mocker.MagicMock()

        ui = _MinimalKeeperUI()
        ui.waiting_for_sso_data_key = True

        ui.on_sso_data_key(step)

        step.request_data_key.assert_not_called()
        step.resume.assert_called_once()
        mock_sleep.assert_called_once_with(1)


class TestPerformKeeperLogin:
    def test_login_with_env_vars(self, mocker, env_var):
        env_var(KEEPER_USERNAME="user@example.com", KEEPER_SERVER="keepersecurity.com")
        mock_api = mocker.patch("jwbmisc.keeper.api")

        params = mocker.MagicMock()
        params.user = None

        _perform_keeper_login(params)

        assert params.user == "user@example.com"
        assert params.server == "keepersecurity.com"
        mock_api.login.assert_called_once()

    def test_login_with_user_input(self, mocker):
        mock_api = mocker.patch("jwbmisc.keeper.api")
        mock_ask = mocker.patch("jwbmisc.keeper.ask")
        mock_ask.side_effect = ["user@example.com", "keepersecurity.com"]

        params = mocker.MagicMock()
        params.user = None

        _perform_keeper_login(params)

        assert params.user == "user@example.com"
        assert params.server == "keepersecurity.com"
        mock_api.login.assert_called_once()

    def test_login_keyboard_interrupt(self, mocker, env_var):
        env_var(KEEPER_USERNAME="user@example.com", KEEPER_SERVER="keepersecurity.com")
        mock_api = mocker.patch("jwbmisc.keeper.api")
        mock_api.login.side_effect = KeyboardInterrupt()

        params = mocker.MagicMock()
        params.user = None

        with pytest.raises(KeyError, match="cancelled by user"):
            _perform_keeper_login(params)


class TestGetKeeperPassword:
    def test_successful_password_retrieval(self, mocker, tmp_path):
        mocker.patch("jwbmisc.keeper.Path.home", return_value=tmp_path)

        mock_params = mocker.MagicMock()
        mock_params.session_token = None
        mocker.patch("jwbmisc.keeper.KeeperParams", return_value=mock_params)

        mock_api = mocker.patch("jwbmisc.keeper.api")
        mock_vault = mocker.patch("jwbmisc.keeper.keeper_vault")

        mock_record = mocker.MagicMock()
        mock_vault.KeeperRecord.load.return_value = mock_record

        mocker.patch("jwbmisc.keeper._extract_keeper_field", return_value="the_password")
        mocker.patch("jwbmisc.keeper._perform_keeper_login")

        result = get_keeper_password("RECORD123", "password")

        assert result == "the_password"
        mock_api.sync_down.assert_called_once()

    def test_field_not_found_raises(self, mocker, tmp_path):
        mocker.patch("jwbmisc.keeper.Path.home", return_value=tmp_path)

        mock_params = mocker.MagicMock()
        mock_params.session_token = None
        mocker.patch("jwbmisc.keeper.KeeperParams", return_value=mock_params)

        mocker.patch("jwbmisc.keeper.api")
        mock_vault = mocker.patch("jwbmisc.keeper.keeper_vault")
        mock_vault.KeeperRecord.load.return_value = mocker.MagicMock()

        mocker.patch("jwbmisc.keeper._extract_keeper_field", return_value=None)
        mocker.patch("jwbmisc.keeper._perform_keeper_login")

        with pytest.raises(KeyError, match="Field.*not found"):
            get_keeper_password("RECORD123", "missing_field")

    def test_sync_failure_raises(self, mocker, tmp_path):
        mocker.patch("jwbmisc.keeper.Path.home", return_value=tmp_path)

        mock_params = mocker.MagicMock()
        mock_params.session_token = None
        mocker.patch("jwbmisc.keeper.KeeperParams", return_value=mock_params)

        mock_api = mocker.patch("jwbmisc.keeper.api")
        mock_api.sync_down.side_effect = Exception("Sync failed")

        mocker.patch("jwbmisc.keeper._perform_keeper_login")

        with pytest.raises(KeyError, match="Failed to sync"):
            get_keeper_password("RECORD123", "password")
