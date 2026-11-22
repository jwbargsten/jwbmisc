# pyright: basic
from pathlib import Path

import pytest

import jwbmisc.passwd as pw

pw.PASS_BIN = str((Path(__file__).parent / "pass").absolute())
pw.OP_BIN = str((Path(__file__).parent / "op").absolute())

needs_keyring = pytest.mark.skipif(not pw._can_import("keyring"), reason="keyring not installed")
needs_keeper = pytest.mark.skipif(not pw._can_import("jwbmisc.keeper"), reason="keepercommander not installed")


class TestUnixPass:
    def test_pass_url_single_line(self):
        result = pw.get_pass("pass://test/secret")
        assert result == "password123"

    def test_pass_url_with_line_number(self):
        result = pw.get_pass("pass://test/multiline?lines=2")
        assert result == "line2"

    def test_pass_url_with_all_lines(self):
        result = pw.get_pass("pass://test/multiline?lines=all&format=list")
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result

    def test_interactive_leaves_gpg_opts_alone(self, monkeypatch):
        monkeypatch.delenv("PASSWORD_STORE_GPG_OPTS", raising=False)
        assert pw.get_pass("pass://test/gpg-opts") == "<unset>"

    def test_non_interactive_disables_pinentry(self, monkeypatch):
        monkeypatch.delenv("PASSWORD_STORE_GPG_OPTS", raising=False)
        assert pw.get_pass("pass://test/gpg-opts", interactive=False) == "--pinentry-mode error"

    def test_non_interactive_keeps_existing_gpg_opts(self, monkeypatch):
        monkeypatch.setenv("PASSWORD_STORE_GPG_OPTS", "--armor")
        result = pw.get_pass("pass://test/gpg-opts", interactive=False)
        assert result == "--armor --pinentry-mode error"

    def test_pass_url_with_invalid_line_number(self):
        with pytest.raises(KeyError):
            pw.get_pass("pass://test/multiline?lines=99")


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

    @needs_keyring
    def test_keyring_url(self, mocker):
        mocker.patch("keyring.get_keyring")
        mocker.patch("keyring.get_password", return_value="keyring_password")

        result = pw.get_pass("keyring://service/username")
        assert result == "keyring_password"

    @needs_keyring
    def test_keyring_url_not_found_raises(self, mocker):
        mocker.patch("keyring.get_keyring")
        mocker.patch("keyring.get_password", return_value=None)

        with pytest.raises(KeyError):
            pw.get_pass("keyring://service/username")


class TestFallback:
    def test_unknown_scheme_raises_value_error(self):
        with pytest.raises(ValueError, match="unsupported pass key"):
            pw.get_pass("nope://foo")

    def test_unknown_scheme_raises_even_if_earlier_key_succeeds(self, env_var):
        env_var(MY_PASSWORD="secret123")
        with pytest.raises(ValueError):
            pw.get_pass("env://MY_PASSWORD", "nope://foo")

    def test_falls_through_to_next_key(self, env_var):
        env_var(MY_PASSWORD="secret123")
        assert pw.get_pass("pass://test/missing", "env://MY_PASSWORD") == "secret123"

    def test_first_success_wins(self, env_var):
        env_var(MY_PASSWORD="secret123")
        assert pw.get_pass("pass://test/secret", "env://MY_PASSWORD") == "password123"

    def test_skips_unavailable_backend(self, monkeypatch, env_var):
        env_var(MY_PASSWORD="secret123")
        monkeypatch.setattr(pw, "PASS_BIN", "/nonexistent/pass")
        assert pw.get_pass("pass://test/secret", "env://MY_PASSWORD") == "secret123"

    def test_all_fail_lists_every_reason(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pw, "PASS_BIN", "/nonexistent/pass")
        with pytest.raises(KeyError) as exc:
            pw.get_pass("pass://test/secret", "env://NONEXISTENT_VAR_12345", f"file://{tmp_path}/x")
        msg = exc.value.args[0]
        assert "pass is not available" in msg
        assert "is not in the env" in msg
        assert "does not exist" in msg


@needs_keeper
class TestKeeperUrl:
    def test_keeper_url_with_field(self, mocker):
        mock_keeper = mocker.patch("jwbmisc.keeper.get_password", return_value="keeper_password")
        assert pw.get_pass("keeper://RECORD123/field/password") == "keeper_password"
        mock_keeper.assert_called_once_with("RECORD123", "field/password", interactive=True)

    def test_keeper_url_without_field(self, mocker):
        mock_keeper = mocker.patch("jwbmisc.keeper.get_password", return_value="keeper_password")
        pw.get_pass("keeper://RECORD123", interactive=False)
        mock_keeper.assert_called_once_with("RECORD123", None, interactive=False)

    def test_non_interactive_keeper_without_session_falls_through(self, mocker, env_var):
        from jwbmisc import keeper

        env_var(MY_PASSWORD="secret123")
        mocker.patch.object(keeper, "CONFIG_FILE", mocker.MagicMock(exists=lambda: False))
        login = mocker.patch("jwbmisc.keeper.perform_login")

        result = pw.get_pass("keeper://RECORD123/password", "env://MY_PASSWORD", interactive=False)

        assert result == "secret123"
        login.assert_not_called()

    @needs_keeper
    def test_ctrl_c_aborts_instead_of_falling_through(self, mocker, env_var):
        env_var(MY_PASSWORD="secret123")
        mocker.patch("jwbmisc.keeper.get_password", side_effect=KeyboardInterrupt())

        with pytest.raises(KeyboardInterrupt):
            pw.get_pass("keeper://RECORD123/password", "env://MY_PASSWORD")


class TestOnePassword:
    def test_op_url(self):
        assert pw.get_pass("op://test/item/password") == "op_secret"

    def test_op_url_with_query_passed_through(self):
        assert pw.get_pass("op://test/item/one-time password?attribute=otp") == "123456"

    def test_op_missing_falls_through(self, env_var):
        env_var(MY_PASSWORD="secret123")
        assert pw.get_pass("op://test/item/missing", "env://MY_PASSWORD") == "secret123"

    def test_op_error_in_message_when_non_interactive(self):
        with pytest.raises(KeyError, match="item not found"):
            pw.get_pass("op://test/item/missing", interactive=False)

    def test_op_unavailable_is_skipped(self, monkeypatch, env_var):
        env_var(MY_PASSWORD="secret123")
        monkeypatch.setattr(pw, "OP_BIN", "/nonexistent/op")
        assert pw.get_pass("op://test/item/password", "env://MY_PASSWORD") == "secret123"

    def test_interactive_keeps_app_integration(self, monkeypatch):
        monkeypatch.delenv("OP_BIOMETRIC_UNLOCK_ENABLED", raising=False)
        assert pw.get_pass("op://test/env/biometric") == "<unset>"

    def test_non_interactive_disables_app_integration(self, monkeypatch):
        monkeypatch.delenv("OP_BIOMETRIC_UNLOCK_ENABLED", raising=False)
        assert pw.get_pass("op://test/env/biometric", interactive=False) == "false"

    def test_non_interactive_has_no_stdin(self):
        assert pw.get_pass("op://test/stdin/tty", interactive=False) == "no-tty"


class TestOptionalDependencies:
    """get_pass must work, and skip the backend, when an optional dependency is missing or broken."""

    @staticmethod
    def _hide_module(monkeypatch, name):
        import sys

        for mod in [m for m in sys.modules if m == name or m.startswith(f"{name}.")]:
            monkeypatch.delitem(sys.modules, mod)
        monkeypatch.setitem(sys.modules, name, None)  # makes "import name" raise ImportError

    def test_missing_keepercommander_skips_keeper(self, monkeypatch, env_var):
        env_var(MY_PASSWORD="secret123")
        self._hide_module(monkeypatch, "keepercommander")
        # forget jwbmisc.keeper, so it is imported again and runs into the missing keepercommander
        monkeypatch.delitem(__import__("sys").modules, "jwbmisc.keeper", raising=False)

        with pytest.raises(KeyError, match="keeper is not available"):
            pw.get_pass("keeper://RECORD123/password", "env://NONEXISTENT_VAR_12345")
        assert pw.get_pass("keeper://RECORD123/password", "env://MY_PASSWORD") == "secret123"

    def test_missing_keyring_skips_keyring(self, monkeypatch, env_var):
        env_var(MY_PASSWORD="secret123")
        self._hide_module(monkeypatch, "keyring")

        with pytest.raises(KeyError, match="keyring is not available"):
            pw.get_pass("keyring://svc/user", "env://NONEXISTENT_VAR_12345")
        assert pw.get_pass("keyring://svc/user", "env://MY_PASSWORD") == "secret123"

    def test_broken_import_skips_backend(self, monkeypatch, env_var):
        env_var(MY_PASSWORD="secret123")
        real_import = __import__("importlib").import_module

        def broken(name, *args):
            if name == "jwbmisc.keeper":
                raise AttributeError("module 'keepercommander' has no attribute 'xyz'")
            return real_import(name, *args)

        monkeypatch.setattr(pw.importlib, "import_module", broken)
        assert pw.get_pass("keeper://RECORD123/password", "env://MY_PASSWORD") == "secret123"
