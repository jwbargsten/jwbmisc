import random
import string
from typing import Any


def ask(question, default=None):
    if default is not None:
        question += f" [{default}]"
    answer = input(question.strip() + " ").strip()
    return answer if answer else default


def confirm(question, default="n"):
    prompt = f"{question} (y/n)"
    if default is not None:
        prompt += f" [{default}]"
    answer = input(prompt).strip().lower()
    if not answer:
        answer = default.lower() if default else "n"
    return answer.startswith("y")


def randomsuffix(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


def qw(s: str) -> list[str]:
    return s.split()


def split_host(host: str) -> tuple[str | None, int | None]:
    if not host:
        return (None, None)
    res = host.split(":", 1)
    if len(res) == 1:
        return (res[0], None)
    return (res[0], int(res[1]))


def goo(
    d: dict[str, Any],
    *keys: str | int,
    default: Any | None = None,
    raise_on_default: bool = False,
):
    path = ".".join(str(k) for k in keys)
    parts = path.split(".")

    res = d
    for p in parts:
        if res is None:
            if raise_on_default:
                raise ValueError(f"'{path}' does not exist")
            return default
        if isinstance(res, (list, set, tuple)):
            res = res[int(p)]
        else:
            res = res.get(p)
    if res is None:
        if raise_on_default:
            raise ValueError(f"'{path}' does not exist")
        return default
    return res
