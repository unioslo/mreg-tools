from pathlib import Path
from typing import TypeVar

from pydantic import TypeAdapter


T = TypeVar("T")


def dump_json(obj: T, typ: type[T], filename: Path) -> None:
    """Dump an object to a JSON file using Pydantic's TypeAdapter for validation."""
    adapter = TypeAdapter(typ)
    _ = filename.write_bytes(adapter.dump_json(obj))
