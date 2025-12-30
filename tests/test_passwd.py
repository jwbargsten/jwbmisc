import pytest

from jwbmisc.passwd import _call_unix_pass, _keeper_password, get_pass


class TestGetPass:
    def test_no_keys_raises(self):
        with pytest.raises(ValueError, match="no pass keys"):
            get_pass()

    def test_pass_url_single_line(self, fake_pass):
        result = get_pass("pass://test/secret")
        assert result == "password123"

    def test_pass_url_with_line_number(self, fake_pass):
        result = get_pass("pass://test/multiline?2")
        assert result == "line2"

    def test_pass_url_missing_raises(self, fake_pass):
        with pytest.raises(KeyError, match="pass failed"):
            get_pass("pass://test/missing")

    def test_env_url(self, env_var):
        env_var(MY_PASSWORD="secret123")
        result = get_pass("env://MY_PASSWORD")
        assert result == "secret123"

    def test_env_url_with_slashes(self, env_var):
        env_var(MY__NESTED__VAR="nested_value")
        result = get_pass("env://MY/NESTED/VAR")
        assert result == "nested_value"

    def test_env_url_missing_raises(self):
        with pytest.raises(KeyError, match="is not in the env"):
            get_pass("env://NONEXISTENT_VAR_12345")

    def test_file_url(self, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file_password\n")
        result = get_pass(f"file://{secret_file}")
        assert result == "file_password"

    def test_file_url_strips_whitespace(self, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("  password  \n\n")
        result = get_pass(f"file://{secret_file}")
        assert result == "password"

    def test_file_url_missing_raises(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with pytest.raises(KeyError, match="does not exist"):
            get_pass(f"file://{missing}")

    def test_file_url_directory_raises(self, tmp_path):
        with pytest.raises(KeyError, match="does not exist or is a dir"):
            get_pass(f"file://{tmp_path}")

    def test_keyring_url(self, mocker):
        mocker.patch.dict("sys.modules", {"keyring": mocker.MagicMock()})
        import sys

        sys.modules["keyring"].get_password.return_value = "keyring_password"

        result = get_pass("keyring://service/username")
        assert result == "keyring_password"
        sys.modules["keyring"].get_password.assert_called_once_with("service", "username")

    def test_keyring_url_not_found_raises(self, mocker):
        mocker.patch.dict("sys.modules", {"keyring": mocker.MagicMock()})
        import sys

        sys.modules["keyring"].get_password.return_value = None

        with pytest.raises(KeyError, match="could not find a password"):
            get_pass("keyring://service/username")

    def test_keeper_url(self, mocker):
        mock_keeper = mocker.patch("jwbmisc.passwd._keeper_password")
        mock_keeper.return_value = "keeper_password"

        result = get_pass("keeper://RECORD123/field/password")
        assert result == "keeper_password"
        mock_keeper.assert_called_once_with("RECORD123", "field/password")

    def test_keeper_url_invalid_format_raises(self):
        with pytest.raises(KeyError, match="Invalid keeper:// format"):
            get_pass("keeper://RECORD123")


class TestCallUnixPass:
    def test_single_line(self, fake_pass):
        result = _call_unix_pass("test/secret")
        assert result == "password123"

    def test_get_specific_line(self, fake_pass):
        result = _call_unix_pass("test/multiline", lnum=2)
        assert result == "line2"

    def test_get_all_lines(self, fake_pass):
        result = _call_unix_pass("test/multiline", lnum=0)
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result

    def test_error_raises_keyerror(self, fake_pass):
        with pytest.raises(KeyError, match="pass failed"):
            _call_unix_pass("test/missing")

    def test_line_number_out_of_range(self, fake_pass):
        with pytest.raises(KeyError, match="could not retrieve lines"):
            _call_unix_pass("test/secret", lnum=99)


class TestKeeperPassword:
    def test_delegates_to_get_keeper_password(self, mocker):
        mock_get = mocker.patch("jwbmisc.keeper.get_keeper_password")
        mock_get.return_value = "keeper_secret"

        result = _keeper_password("RECORD_UID", "field/path")
        assert result == "keeper_secret"
        mock_get.assert_called_once_with("RECORD_UID", "field/path")
