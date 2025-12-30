import pytest

from jwbmisc.string import jinja_replace, qw, split_host, randomsuffix


class TestJinjaReplace:
    def test_basic_replacement(self):
        result = jinja_replace("Hello {{name}}!", {"name": "World"})
        assert result == "Hello World!"

    def test_multiple_variables(self):
        result = jinja_replace("{{a}} + {{b}} = {{c}}", {"a": "1", "b": "2", "c": "3"})
        assert result == "1 + 2 = 3"

    def test_whitespace_in_delimiters(self):
        result = jinja_replace("Hello {{ name }}!", {"name": "World"})
        assert result == "Hello World!"

    def test_no_variables(self):
        result = jinja_replace("Hello World!", {})
        assert result == "Hello World!"

    def test_missing_variable_raises(self):
        with pytest.raises(KeyError, match="missing"):
            jinja_replace("Hello {{missing}}!", {})

    def test_missing_variable_relaxed(self):
        result = jinja_replace("Hello {{missing}}!", {}, relaxed=True)
        assert result == "Hello {{missing}}!"

    def test_custom_delimiters(self):
        result = jinja_replace("Hello <%name%>!", {"name": "World"}, delim=("<%", "%>"))
        assert result == "Hello World!"

    def test_custom_delimiters_with_regex_chars(self):
        result = jinja_replace("Hello ${{name}}$!", {"name": "World"}, delim=("${{", "}}$"))
        assert result == "Hello World!"

    def test_empty_config(self):
        result = jinja_replace("no vars here", {})
        assert result == "no vars here"

    def test_repeated_variable(self):
        result = jinja_replace("{{x}} and {{x}}", {"x": "same"})
        assert result == "same and same"


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
