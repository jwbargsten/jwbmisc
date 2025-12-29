import pytest

from jwbmisc.string import jinja_replace


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
