from jwbmisc.fs import find_root, fzf


class TestFzf:
    def test_returns_selected_entry(self, fake_fzf):
        result = fzf(["first", "second", "third"])
        assert result == "first"

    def test_empty_entries(self, fake_fzf):
        result = fzf([])
        assert result == ""


class TestFindRoot:
    def test_finds_root_at_current_level(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        result = find_root(tmp_path, {"pyproject.toml"})
        assert result == tmp_path

    def test_finds_root_one_level_up(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        result = find_root(subdir, {"pyproject.toml"})
        assert result == tmp_path

    def test_finds_root_multiple_levels_up(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        result = find_root(deep, {"pyproject.toml"})
        assert result == tmp_path

    def test_returns_none_when_not_found(self, tmp_path):
        result = find_root(tmp_path, {"nonexistent.file"})
        assert result is None

    def test_requires_multiple_files(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        result = find_root(tmp_path, {"pyproject.toml", "setup.py"})
        assert result is None

        (tmp_path / "setup.py").touch()
        result = find_root(tmp_path, {"pyproject.toml", "setup.py"})
        assert result == tmp_path

    def test_start_from_file(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        file_in_subdir = subdir / "some_file.py"
        file_in_subdir.touch()
        result = find_root(file_in_subdir, {"pyproject.toml"})
        assert result == tmp_path
