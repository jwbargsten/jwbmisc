import pytest
from jwbmisc.collection import goo


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
