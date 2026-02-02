from __future__ import annotations

from io import StringIO
import logging
from pathlib import Path
from typing import TypeVar

from pydantic import TypeAdapter

T = TypeVar("T")

logger = logging.getLogger(__name__)


def dump_json(obj: T, typ: type[T], filename: Path, indent: int = 2) -> None:
    """Dump an object to a JSON file using Pydantic's TypeAdapter for validation."""
    adapter = TypeAdapter(typ)
    _ = filename.write_bytes(adapter.dump_json(obj, indent=indent))


def load_json(typ: type[T], filename: Path) -> T | None:
    """Load an object from a JSON file using Pydantic's TypeAdapter for validation."""
    adapter = TypeAdapter(typ)
    try:
        data = filename.read_bytes()
        return adapter.validate_json(data)
    except FileNotFoundError:
        logger.debug("File %s does not exist", str(filename))
    except Exception as e:
        logger.error("Failed to load file %s: %e", str(filename), e)
    return None


def compare_file_size(oldfile, newfile, newlines):
    """Compare filesizes with the new and old file, and if difference
    above values in COMPARE_LIMITS_LINES, raise an exception.
    """
    encoding = cfg["default"].get("fileencoding", "utf-8")
    with open(oldfile, encoding=encoding) as old:
        oldlines = old.readlines()

    if newlines == oldlines:
        return

    old_count = len(oldlines)
    diff_limit = cfg["default"].getfloat("max_line_change_percent")
    if diff_limit is None:
        for linecount, limit in COMPARE_LIMITS_LINES.items():
            if old_count < linecount:
                diff_limit = limit
                break

    diff_percent = (len(newlines) - old_count) / old_count * 100
    if abs(diff_percent) > diff_limit:
        raise TooManyLineChanges(
            newfile,
            f"New file {newfile} changed too much: {diff_percent:.2f}%, limit {diff_limit}%",
        )


def write_file(filename: Path, f: StringIO, ignore_size_change=False):
    dstfile = os.path.join(cfg["default"]["destdir"], filename)
    encoding = cfg["default"].get("fileencoding", "utf-8")

    tempf, oldmask = UmaskNamedTemporaryFile(
        delete=False,
        mode="w",
        encoding=encoding,
        dir=cfg["default"]["workdir"],
        prefix=f"{filename}.",
    )
    f.seek(0)
    newlines = f.readlines()
    if len(newlines) < ABSOLUTE_MIN_SIZE:
        raise TooSmallNewFile(tempf.name, f"new file less than {ABSOLUTE_MIN_SIZE} lines")
    # Write first to make sure the workdir can hold the new file
    f.seek(0)
    shutil.copyfileobj(f, tempf)
    tempf.close()

    if os.path.isfile(dstfile):
        if not ignore_size_change:
            compare_file_size(dstfile, tempf.name, newlines)
        if cfg["default"].getboolean("keepoldfile", True):
            oldfile = f"{dstfile}_old"
            if os.path.isfile(oldfile):
                os.chmod(oldfile, stat.S_IRUSR | stat.S_IWUSR)
            shutil.copy2(dstfile, oldfile)
            os.chmod(oldfile, stat.S_IRUSR)
    shutil.move(tempf.name, dstfile)
    if oldmask is not None:
        # restore umask
        os.umask(oldmask)
    else:
        os.chmod(dstfile, stat.S_IRUSR)
