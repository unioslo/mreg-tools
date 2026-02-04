from __future__ import annotations

from functools import wraps
import logging
import os
import shutil
import sys
import tempfile
from io import StringIO
from pathlib import Path
from time import time
from typing import NoReturn
from typing import TypeVar

from pydantic import TypeAdapter

T = TypeVar("T")

logger = logging.getLogger(__name__)


def timing(f):
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        logging.info(f"func:{f.__name__} args:[{args}, {kw}] took: {te - ts:.4} sec")
        return result

    return wrap


# Maximum size change in percent for each line count threshold
COMPARE_LIMITS_LINES = {50: 50, 100: 20, 1000: 15, 10000: 10, sys.maxsize: 10}
# Absolute minimum file size, in lines
ABSOLUTE_MIN_SIZE = 10


class TooManyLineChanges(Exception):
    """Raised when the file size change exceeds the allowed limit."""

    newfile: str | Path
    message: str

    def __init__(self, newfile: str | Path, message: str) -> None:
        super().__init__(message)
        self.newfile = newfile
        self.message = message


class TooSmallNewFile(Exception):
    """Raised when the new file has fewer lines than the minimum required."""

    newfile: str | Path
    message: str

    def __init__(self, newfile: str | Path, message: str) -> None:
        super().__init__(message)
        self.newfile = newfile
        self.message = message


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


def compare_file_size(
    oldfile: Path,
    newlines: list[str],
    max_line_change_percent: float | None = None,
    encoding: str = "utf-8",
) -> None:
    """Compare file sizes and raise an exception if the difference exceeds the limit.

    Args:
        oldfile: Path to the existing file to compare against.
        newlines: Lines of the new file content.
        max_line_change_percent: Maximum allowed change in percent. If None, uses
            dynamic limits based on file size.
        encoding: File encoding to use when reading the old file.

    Raises:
        TooManyLineChanges: If the size difference exceeds the allowed limit.
    """
    with oldfile.open(encoding=encoding) as old:
        oldlines = old.readlines()

    if oldlines == newlines:
        return

    old_count = len(oldlines)
    diff_limit = max_line_change_percent
    if diff_limit is None:
        for linecount, limit in COMPARE_LIMITS_LINES.items():
            if old_count < linecount:
                diff_limit = limit
                break

    if diff_limit is None:
        diff_limit = COMPARE_LIMITS_LINES[sys.maxsize]

    diff_percent = (len(newlines) - old_count) / old_count * 100
    if abs(diff_percent) > diff_limit:
        raise TooManyLineChanges(
            oldfile,
            f"File {oldfile} changed too much: {diff_percent:.2f}%, limit {diff_limit}%",
        )


def write_file(
    destfile: Path,
    content: StringIO,
    *,
    workdir: Path,
    encoding: str = "utf-8",
    ignore_size_change: bool = False,
    keepoldfile: bool = True,
    max_line_change_percent: float | None = None,
) -> None:
    """Write content to a file with safety checks.

    Writes the content to a temporary file first, then performs size validation
    against the existing file (if any), and finally moves the temporary file
    to the destination.

    Args:
        destfile: Full path to the destination file.
        content: StringIO containing the content to write.
        workdir: Directory for temporary files.
        encoding: File encoding.
        ignore_size_change: If True, skip file size validation.
        keepoldfile: If True, keep a backup of the old file as `<destfile>_old`.
        max_line_change_percent: Maximum allowed change in percent. If None, uses
            dynamic limits based on file size.

    Raises:
        TooSmallNewFile: If the new file has fewer lines than ABSOLUTE_MIN_SIZE.
        TooManyLineChanges: If the size difference exceeds the allowed limit.
    """
    # Create temp file in workdir
    tempf = tempfile.NamedTemporaryFile(
        delete=False,
        mode="w",
        encoding=encoding,
        dir=workdir,
        prefix=f"{destfile.name}.",
    )

    try:
        # Read content to validate size
        content_str = content.getvalue()
        newlines = content_str.splitlines(keepends=True)
        if len(newlines) < ABSOLUTE_MIN_SIZE:
            raise TooSmallNewFile(
                tempf.name, f"new file less than {ABSOLUTE_MIN_SIZE} lines"
            )

        # Write content to temp file
        with open(tempf.name, "w", encoding=encoding) as f:
            f.write(content_str)

        # Validate against existing file
        if destfile.is_file() and not ignore_size_change:
            compare_file_size(
                destfile,
                newlines,
                max_line_change_percent=max_line_change_percent,
                encoding=encoding,
            )

        # Keep backup of old file
        if destfile.is_file() and keepoldfile:
            oldfile = destfile.with_name(f"{destfile.name}_old")
            _ = shutil.copy2(destfile, oldfile)

        # Move temp file to destination
        _ = shutil.move(tempf.name, destfile)

    except Exception:
        # Clean up temp file on error
        Path(tempf.name).unlink(missing_ok=True)
        raise


def error(msg: str, code: int = os.EX_UNAVAILABLE) -> NoReturn:
    logger.error(msg)
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)
