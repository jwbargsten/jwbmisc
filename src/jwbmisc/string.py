import re
import random
import string


def jinja_replace(s, config, relaxed: bool = False, delim: tuple[str, str] = ("{{", "}}")):
    """Jinja for poor people. A very simple
    function to replace variables in text using `{{variable}}` syntax.

    :param s: the template string/text
    :param config: a dict of variable -> replacement mapping
    :param relaxed: Don't raise a KeyError if a variable is not in the config dict.
    :param delim: Change the delimiters to something else.
    """

    def handle_match(m):
        k = m.group(1)
        if k in config:
            return config[k]
        if relaxed:
            return m.group(0)
        raise KeyError(f"{k} is not in the supplied replacement variables")

    return re.sub(re.escape(delim[0]) + r"\s*(\w+)\s*" + re.escape(delim[1]), handle_match, s)


def randomsuffix(length: int):
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
