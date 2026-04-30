import pytest
from jwbmisc.collection import goo


class TestDig:
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

    def test_missing_key_returns_none_when_default_is_none(self):
        d = {"a": 1}
        assert goo(d, "b", default=None) is None

    def test_missing_key_raises_when_no_default(self):
        d = {"a": 1}
        with pytest.raises(ValueError, match="not found"):
            goo(d, "b")

    def test_error_message_names_failing_component(self):
        d = {"a": {"b": {"c": 1}}}
        with pytest.raises(ValueError, match="'x'.*'a.x'"):
            goo(d, "a.x.y")

    def test_none_in_path_returns_default(self):
        d = {"a": None}
        assert goo(d, "a", "b", default="missing") == "missing"

    def test_mixed_keys_and_indices(self):
        d = {"users": [{"name": "Alice"}, {"name": "Bob"}]}
        assert goo(d, "users", 0, "name") == "Alice"

    def test_does_not_index_into_string(self):
        d = {"name": "alice"}
        assert goo(d, "name", 0, default="x") == "x"

    def test_attribute_fallback_on_dataclass(self):
        from dataclasses import dataclass

        @dataclass
        class Inner:
            val: int

        @dataclass
        class Outer:
            inner: Inner

        obj = Outer(inner=Inner(val=42))
        assert goo(obj, "inner.val") == 42

    def test_attribute_fallback_missing_returns_default(self):
        from dataclasses import dataclass

        @dataclass
        class Foo:
            x: int = 1

        assert goo(Foo(), "y", default="missing") == "missing"

    def test_mixed_mapping_and_object(self):
        from dataclasses import dataclass

        @dataclass
        class Item:
            name: str

        d = {"items": [Item(name="alice"), Item(name="bob")]}
        assert goo(d, "items", 1, "name") == "bob"
