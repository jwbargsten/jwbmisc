import os
from pathlib import Path

import pytest


@pytest.fixture
def env_var():
    original = os.environ.copy()

    def _set(**kwargs):
        for k, v in kwargs.items():
            os.environ[k] = v

    yield _set
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def fake_fzf(monkeypatch):
    tests_dir = Path(__file__).parent
    monkeypatch.setenv("PATH", f"{tests_dir}:{os.environ['PATH']}")
