from typing import Any

_MISSING = object()


def goo(
    d: Any,
    *keys: str | int,
    default: Any = _MISSING,
    sep: str = ".",
) -> Any:
    """Get a value from a nested structure of dicts, lists, and tuples.

    Traverses ``d`` following the given ``keys``, descending into dicts by key
    and into lists/tuples by integer index. String keys are split on ``sep``
    by default, so a single dotted path like ``"a.b.c"`` is equivalent to
    passing ``"a", "b", "c"`` as separate arguments.

    Args:
        d: The nested structure to traverse. Typically a dict, but the root
            can be any indexable container.
        *keys: One or more keys describing the path. String keys are split on
            ``sep`` (unless ``sep`` is empty). Integer keys are used as-is and
            are required for indexing into lists or tuples when not using a
            string path. Numeric strings (e.g. ``"0"``) are also accepted for
            list/tuple indices.
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

    Examples:
        >>> d = {"a": {"b": {"c": 1}}, "items": [{"name": "x"}, {"name": "y"}]}

        Dotted path (default behaviour):

        >>> dget(d, "a.b.c")
        1

        Equivalent with separate keys:

        >>> dget(d, "a", "b", "c")
        1

        Indexing into lists works with numeric string components or ints:

        >>> dget(d, "items.0.name")
        'x'
        >>> dget(d, "items", 0, "name")
        'x'

        Returning a default when the path is missing:

        >>> dget(d, "a.x.y", default=42)
        42

        ``None`` is a valid stored value, distinct from "missing":

        >>> dget({"a": None}, "a") is None
        True

        Custom separator, or disabling splitting for keys that contain dots:

        >>> dget(d, "a/b/c", sep="/")
        1
        >>> dget({"a.b": 1}, "a.b", sep="")
        1
    """
    if sep:
        keys = tuple(
            part
            for k in keys
            for part in (k.split(sep) if isinstance(k, str) else [k])
        )

    res = d
    for k in keys:
        try:
            if isinstance(res, (list, tuple)):
                res = res[int(k)]
            elif isinstance(res, dict):
                res = res[k]
            else:
                raise KeyError(k)
        except (KeyError, IndexError, ValueError, TypeError):
            if default is _MISSING:
                path = sep.join(str(x) for x in keys) if sep else ", ".join(str(x) for x in keys)
                raise ValueError(f"'{path}' does not exist") from None
            return default
    return res
