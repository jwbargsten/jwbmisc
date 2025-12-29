import gzip

from jwbmisc.json import (
    jsonc_loads,
    jsonc_read,
    ndjson_read,
    ndjson_write,
    resilient_loads,
)


class TestJsoncLoads:
    def test_valid_json(self):
        result = jsonc_loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_single_line_comments(self):
        data = """{
            "key": "value" // this is a comment
        }"""
        result = jsonc_loads(data)
        assert result == {"key": "value"}

    def test_block_comments(self):
        data = """{
            /* comment */
            "key": "value"
        }"""
        result = jsonc_loads(data)
        assert result == {"key": "value"}

    def test_mixed_comments(self):
        data = """{
            // line comment
            "a": 1, /* block */
            "b": 2 // another
        }"""
        result = jsonc_loads(data)
        assert result == {"a": 1, "b": 2}


class TestJsoncRead:
    def test_read_json_file(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text('{"key": "value"}')
        result = jsonc_read(f)
        assert result == {"key": "value"}

    def test_read_json_with_comments(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text('{"key": "value"} // comment')
        result = jsonc_read(f)
        assert result == {"key": "value"}

    def test_read_gzipped_json(self, tmp_path):
        f = tmp_path / "test.json.gz"
        with gzip.open(f, "wt", encoding="utf-8") as fd:
            fd.write('{"key": "value"}')
        result = jsonc_read(f)
        assert result == {"key": "value"}


class TestNdjsonRead:
    def test_read_ndjson(self, tmp_path):
        f = tmp_path / "test.ndjson"
        f.write_text('{"a": 1}\n{"b": 2}\n{"c": 3}\n')
        result = list(ndjson_read(f))
        assert result == [{"a": 1}, {"b": 2}, {"c": 3}]

    def test_skips_empty_lines(self, tmp_path):
        f = tmp_path / "test.ndjson"
        f.write_text('{"a": 1}\n\n{"b": 2}\n')
        result = list(ndjson_read(f))
        assert result == [{"a": 1}, {"b": 2}]

    def test_skips_comment_lines(self, tmp_path):
        f = tmp_path / "test.ndjson"
        f.write_text('# comment\n{"a": 1}\n# another\n{"b": 2}\n')
        result = list(ndjson_read(f))
        assert result == [{"a": 1}, {"b": 2}]

    def test_read_gzipped_ndjson(self, tmp_path):
        f = tmp_path / "test.ndjson.gz"
        with gzip.open(f, "wt", encoding="utf-8") as fd:
            fd.write('{"a": 1}\n{"b": 2}\n')
        result = list(ndjson_read(f))
        assert result == [{"a": 1}, {"b": 2}]


class TestNdjsonWrite:
    def test_write_ndjson(self, tmp_path):
        f = tmp_path / "test.ndjson"
        data = [{"a": 1}, {"b": 2}]
        ndjson_write(data, f)
        content = f.read_text()
        assert content == '{"a": 1}\n{"b": 2}\n'

    def test_write_gzipped_ndjson(self, tmp_path):
        f = tmp_path / "test.ndjson.gz"
        data = [{"a": 1}, {"b": 2}]
        ndjson_write(data, f)
        with gzip.open(f, "rt", encoding="utf-8") as fd:
            content = fd.read()
        assert content == '{"a": 1}\n{"b": 2}\n'


class TestResilientLoads:
    def test_valid_json(self):
        assert resilient_loads('{"key": "value"}') == {"key": "value"}

    def test_invalid_json_returns_none(self):
        assert resilient_loads("not json") is None

    def test_empty_string_returns_none(self):
        assert resilient_loads("") is None

    def test_none_input_returns_none(self):
        assert resilient_loads(None) is None
