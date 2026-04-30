from collections.abc import Mapping, Sequence
from typing import Any

_MISSING = object()


def goo(
    d: Any,
    *keys: str | int,
    default: Any = _MISSING,
    sep: str = ".",
) -> Any:
    """Get a value from a nested structure of mappings, sequences, and objects.

    Traverses ``d`` following the given ``keys``. At each step the access
    method depends on the current node:

    * ``Mapping`` (dict, etc.): looked up by key.
    * ``Sequence`` (list, tuple, etc., but **not** ``str``/``bytes``): indexed
      by integer. Numeric strings (e.g. ``"0"``) are converted automatically.
    * Anything else with a string key: attribute access via ``getattr``.
      This covers pydantic models, dataclasses, attrs classes, namedtuples
      accessed by field name, etc.

    String keys are split on ``sep`` by default, so ``"a.b.c"`` is equivalent
    to passing ``"a", "b", "c"`` as separate arguments.

    Args:
        d: The nested structure to traverse.
        *keys: One or more keys describing the path. String keys are split on
            ``sep`` (unless ``sep`` is empty).
        default: Value to return if the path does not exist. If omitted, a
            ``ValueError`` is raised instead. Passing ``None`` (or any other
            value) explicitly is distinguished from omitting it entirely.
        sep: Separator used to split string keys into path components.
            Defaults to ``"."``. Pass an empty string to disable splitting
            and treat each key literally (useful when keys contain dots).

    Returns:
        The value found at the given path, or ``default`` if provided and
        the path does not exist.

    Raises:
        ValueError: If the path does not exist and no ``default`` was given.
            The message names the failing component and the path traversed
            up to that point.

    Examples:
        >>> d = {"a": {"b": {"c": 1}}, "items": [{"name": "x"}, {"name": "y"}]}
        >>> goo(d, "a.b.c")
        1
        >>> goo(d, "a", "b", "c")
        1
        >>> goo(d, "items.0.name")
        'x'
        >>> goo(d, "items", 0, "name")
        'x'
        >>> goo(d, "a.x.y", default=42)
        42
        >>> goo({"a": None}, "a") is None
        True
        >>> goo(d, "a/b/c", sep="/")
        1
        >>> goo({"a.b": 1}, "a.b", sep="")
        1
    """
    if sep:
        keys = tuple(part for k in keys for part in (k.split(sep) if isinstance(k, str) else [k]))

    res = d
    for i, k in enumerate(keys):
        nxt: Any = _MISSING

        if isinstance(res, (str, bytes)):
            pass
        elif isinstance(res, Mapping):
            try:
                nxt = res[k]
            except (KeyError, TypeError):
                pass
        elif isinstance(res, Sequence):
            try:
                idx = k if isinstance(k, int) else int(k)
            except (TypeError, ValueError):
                idx = None
            if idx is not None:
                try:
                    nxt = res[idx]
                except IndexError:
                    pass
        elif isinstance(k, str):
            nxt = getattr(res, k, _MISSING)

        if nxt is _MISSING:
            if default is _MISSING:
                traversed = keys[: i + 1]
                path = sep.join(str(x) for x in traversed) if sep else ", ".join(str(x) for x in traversed)
                raise ValueError(f"component {k!r} not found at path {path!r}")
            return default
        res = nxt
    return res
