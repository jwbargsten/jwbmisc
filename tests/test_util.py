import pytest

from jwbmisc.util import ask, confirm, goo, qw, randomsuffix, split_host


class TestAsk:
    def test_returns_user_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "user_answer")
        assert ask("Question?") == "user_answer"

    def test_returns_default_on_empty_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert ask("Question?", default="default_value") == "default_value"

    def test_returns_none_when_no_default_and_empty(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert ask("Question?") is None

    def test_strips_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "  answer  ")
        assert ask("Question?") == "answer"


class TestConfirm:
    def test_returns_true_for_y(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "y")
        assert confirm("Continue?") is True

    def test_returns_true_for_yes(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "yes")
        assert confirm("Continue?") is True

    def test_returns_true_for_Y(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "Y")
        assert confirm("Continue?") is True

    def test_returns_false_for_n(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "n")
        assert confirm("Continue?") is False

    def test_returns_false_for_no(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "no")
        assert confirm("Continue?") is False

    def test_empty_uses_default_n(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert confirm("Continue?", default="n") is False

    def test_empty_uses_default_y(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert confirm("Continue?", default="y") is True


class TestRandomsuffix:
    def test_correct_length(self):
        result = randomsuffix(10)
        assert len(result) == 10

    def test_only_lowercase(self):
        result = randomsuffix(100)
        assert result.islower()
        assert result.isalpha()

    def test_zero_length(self):
        assert randomsuffix(0) == ""


class TestQw:
    def test_splits_on_whitespace(self):
        assert qw("a b c") == ["a", "b", "c"]

    def test_splits_on_multiple_spaces(self):
        assert qw("a   b   c") == ["a", "b", "c"]

    def test_splits_on_tabs(self):
        assert qw("a\tb\tc") == ["a", "b", "c"]

    def test_splits_on_newlines(self):
        assert qw("a\nb\nc") == ["a", "b", "c"]

    def test_empty_string(self):
        assert qw("") == []

    def test_single_word(self):
        assert qw("word") == ["word"]


class TestSplitHost:
    def test_host_and_port(self):
        assert split_host("localhost:8080") == ("localhost", 8080)

    def test_host_only(self):
        assert split_host("localhost") == ("localhost", None)

    def test_empty_string(self):
        assert split_host("") == (None, None)

    def test_ipv4_with_port(self):
        assert split_host("192.168.1.1:443") == ("192.168.1.1", 443)


class TestGoo:
    def test_simple_key(self):
        d = {"a": 1}
        assert goo(d, "a") == 1

    def test_nested_keys(self):
        d = {"a": {"b": {"c": 3}}}
        assert goo(d, "a", "b", "c") == 3

    def test_dot_notation(self):
        d = {"a": {"b": 2}}
        assert goo(d, "a.b") == 2

    def test_list_index(self):
        d = {"items": ["a", "b", "c"]}
        assert goo(d, "items", 1) == "b"

    def test_missing_key_returns_default(self):
        d = {"a": 1}
        assert goo(d, "b", default="missing") == "missing"

    def test_missing_key_returns_none_by_default(self):
        d = {"a": 1}
        assert goo(d, "b") is None

    def test_raise_on_default(self):
        d = {"a": 1}
        with pytest.raises(ValueError, match="does not exist"):
            goo(d, "b", raise_on_default=True)

    def test_none_in_path_returns_default(self):
        d = {"a": None}
        assert goo(d, "a", "b", default="missing") == "missing"

    def test_mixed_keys_and_indices(self):
        d = {"users": [{"name": "Alice"}, {"name": "Bob"}]}
        assert goo(d, "users", 0, "name") == "Alice"
