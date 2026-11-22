# pyright: basic
import subprocess

import pytest
from pathlib import Path

from jwbmisc.exec import run_cmd

PASS_BIN = str((Path(__file__).parent / "pass").absolute())


class TestRunCmd:
    def test_capture_stdout(self):
        stdout, stderr = run_cmd([PASS_BIN, "show", "test/secret"], capture=True)
        assert stdout.strip() == "password123"
        assert stderr == ""

    def test_capture_disabled_returns_none(self):
        result = run_cmd([PASS_BIN, "show", "test/secret"], capture=False)
        assert result is None

    def test_decode_true_returns_strings(self):
        stdout, stderr = run_cmd([PASS_BIN, "show", "test/secret"], capture=True, decode=True)
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

    def test_decode_false_returns_bytes(self):
        stdout, stderr = run_cmd([PASS_BIN, "show", "test/secret"], capture=True, decode=False)
        assert isinstance(stdout, bytes)
        assert isinstance(stderr, bytes)

    def test_env_merging(self, env_var):
        env_var(MY_TEST_VAR="test_value")
        stdout, _ = run_cmd(["bash", "-c", "echo $MY_TEST_VAR"], capture=True)
        assert stdout.strip() == "test_value"

    def test_custom_env_overrides(self, env_var):
        env_var(MY_VAR="original")
        stdout, _ = run_cmd(
            ["bash", "-c", "echo $MY_VAR"],
            capture=True,
            env={"MY_VAR": "override"},
        )
        assert stdout.strip() == "override"

    def test_pyvenv_launcher_removed(self, env_var):
        env_var(__PYVENV_LAUNCHER__="/some/path")
        stdout, _ = run_cmd(
            ["bash", "-c", 'echo "${__PYVENV_LAUNCHER__:-unset}"'],
            capture=True,
        )
        assert stdout.strip() == "unset"

    def test_stdin_encoding(self):
        stdout, _ = run_cmd(["cat"], capture=True, stdin="hello world")
        assert stdout == "hello world"

    def test_dry_run_prints_command(self, capsys):
        result = run_cmd(["echo", "test"], dry_run=True, capture=False)
        assert result is None
        captured = capsys.readouterr()
        assert "echo" in captured.out

    def test_dry_run_with_capture_returns_empty(self, capsys):
        result = run_cmd(["echo", "test"], dry_run=True, capture=True)
        assert result == ("", "")

    def test_called_process_error(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd([PASS_BIN, "show", "test/missing"], capture=True)
        assert exc_info.value.returncode == 1

    def test_called_process_error_output_decoded(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd([PASS_BIN, "show", "test/missing"], capture=True)
        assert exc_info.value.stdout == ""
        assert exc_info.value.stderr == "Error: not found\n"

    def test_called_process_error_output_bytes_without_decode(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd([PASS_BIN, "show", "test/missing"], capture=True, decode=False)
        assert exc_info.value.stderr == b"Error: not found\n"

    def test_called_process_error_invalid_utf8_does_not_mask_error(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd(["bash", "-c", "printf 'bad \\xff' >&2; exit 3"], capture=True)
        assert exc_info.value.returncode == 3
        assert exc_info.value.stderr == "bad �"

    def test_called_process_error_without_capture(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd(["bash", "-c", "exit 2"])
        assert exc_info.value.stdout is None
        assert exc_info.value.stderr is None

    # output is assembled at runtime so "secret" only appears in the output, not in the
    # command line (which is part of the exception message); exec, so the kill on
    # timeout hits sleep itself and the pipes close right away
    TIMEOUT_CMD = ["bash", "-c", "printf '%s%s\\n' sec ret; printf '%s%s\\n' sec ret-err >&2; exec sleep 5"]

    def test_timeout_output_decoded(self):
        with pytest.raises(subprocess.TimeoutExpired) as exc_info:
            run_cmd(self.TIMEOUT_CMD, capture=True, timeout=0.5)
        assert exc_info.value.stdout == "secret\n"
        assert exc_info.value.stderr == "secret-err\n"

    def test_timeout_sensitive_data_redacted(self):
        with pytest.raises(subprocess.TimeoutExpired) as exc_info:
            run_cmd(self.TIMEOUT_CMD, capture=True, timeout=0.5, contains_sensitive_data=True)
        assert exc_info.value.stdout == "<redacted>"
        assert exc_info.value.stderr == "<redacted>"
        assert "secret" not in str(exc_info.value)

    def test_sensitive_data_redacted(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd([PASS_BIN, "show", "test/missing"], capture=True, contains_sensitive_data=True)
        assert exc_info.value.stdout == "<redacted>"
        assert exc_info.value.stderr == "<redacted>"

    def test_sensitive_data_redacted_as_bytes_without_decode(self):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            run_cmd(
                [PASS_BIN, "show", "test/missing"],
                capture=True,
                contains_sensitive_data=True,
                decode=False,
            )
        assert exc_info.value.stdout == b"<redacted>"
        assert exc_info.value.stderr == b"<redacted>"

    def test_cmd_args_converted_to_strings(self):
        stdout, _ = run_cmd(["echo", 123, 456], capture=True)
        assert stdout.strip() == "123 456"
