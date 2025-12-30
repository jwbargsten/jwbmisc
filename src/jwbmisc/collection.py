from typing import Any


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
