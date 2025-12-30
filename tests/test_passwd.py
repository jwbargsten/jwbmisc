# pyright: basic
import pytest

import jwbmisc.passwd as pw
from pathlib import Path

pw.PASS_BIN = str((Path(__file__).parent / "pass").absolute())


class TestUnixPass:
    def test_pass_url_single_line(self):
        result = pw.get_pass("pass://test/secret")
        assert result == "password123"

    def test_pass_url_with_line_number(self):
        result = pw.get_pass("pass://test/multiline?2")
        assert result == "line2"

    def test_pass_url_with_all_lines(self):
        result = pw.get_pass("pass://test/multiline?0")
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result

    def test_pass_url_with_invalid_line_number(self):
        with pytest.raises(KeyError):
            pw.get_pass("pass://test/multiline?99")


class TestGetPass:
    def test_no_keys_raises(self):
        with pytest.raises(ValueError):
            pw.get_pass()

    def test_pass_url_missing_raises(self):
        with pytest.raises(KeyError, match="pass failed"):
            pw.get_pass("pass://test/missing")

    def test_env_url(self, env_var):
        env_var(MY_PASSWORD="secret123")
        result = pw.get_pass("env://MY_PASSWORD")
        assert result == "secret123"

    def test_env_url_with_slashes(self, env_var):
        env_var(MY__NESTED__VAR="nested_value")
        result = pw.get_pass("env://MY/NESTED/VAR")
        assert result == "nested_value"

    def test_env_url_missing_raises(self):
        with pytest.raises(KeyError, match="is not in the env"):
            pw.get_pass("env://NONEXISTENT_VAR_12345")

    def test_file_url(self, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file_password\n")
        result = pw.get_pass(f"file://{secret_file}")
        assert result == "file_password"

    def test_file_url_strips_whitespace(self, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("  password  \n\n")
        result = pw.get_pass(f"file://{secret_file}")
        assert result == "password"

    def test_file_url_missing_raises(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with pytest.raises(KeyError, match="does not exist"):
            pw.get_pass(f"file://{missing}")

    def test_file_url_directory_raises(self, tmp_path):
        with pytest.raises(KeyError, match="does not exist or is a dir"):
            pw.get_pass(f"file://{tmp_path}")

    def test_keyring_url(self, mocker):
        mocker.patch("keyring.get_password", return_value="keyring_password")

        result = pw.get_pass("keyring://service/username")
        assert result == "keyring_password"

    def test_keyring_url_not_found_raises(self, mocker):
        mocker.patch("keyring.get_password", return_value=None)

        with pytest.raises(KeyError):
            pw.get_pass("keyring://service/username")
