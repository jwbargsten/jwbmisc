from jwbmisc.interactive import ask, confirm


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
