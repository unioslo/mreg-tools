from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from functools import wraps
from io import StringIO
from pathlib import Path
from time import time
from typing import NoReturn
from typing import TypeVar

import structlog.stdlib
from pydantic import TypeAdapter

from mreg_tools.exceptions import TooManyLineChanges
from mreg_tools.exceptions import TooSmallNewFile
from mreg_tools.output import info

T = TypeVar("T")

logger = structlog.stdlib.get_logger()


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
ABSOLUTE_MIN_SIZE = 5


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
        logger.debug("Old file and new content are identical", oldfile=str(oldfile))
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
    mode: int | None = None,
) -> None:
    """Write content to a file with safety checks.

    Writes the content to a temporary file first, then performs size validation
    against the existing file (if any), and finally moves the temporary file
    to the destination if changes are within accepted parameters.

    Args:
        destfile: Full path to the destination file.
        content: StringIO containing the content to write.
        workdir: Directory for temporary files.
        encoding: File encoding.
        ignore_size_change: If True, skip file size validation.
        keepoldfile: If True, keep a backup of the old file as `<destfile>_old`.
        max_line_change_percent: Maximum allowed change in percent. If None, uses
            dynamic limits based on file size.
        mode: File mode to set on the destination file. If None, no change is made.

    Raises:
        TooSmallNewFile: If the new file has fewer lines than ABSOLUTE_MIN_SIZE.
        TooManyLineChanges: If the size difference exceeds the allowed limit.
    """
    # Create a temp file to write the new contents to
    tempf = tempfile.NamedTemporaryFile(
        delete=False,
        mode="w",
        encoding=encoding,
        dir=workdir,
        prefix=f"{destfile.name}.",
    )
    # NOTE: we could call chmod on the temp file here
    # but do we really want that? Ideally, we get rid of mode altogether.

    # Ensure number of lines is above minimum
    content_str = content.getvalue()
    newlines = content_str.splitlines(keepends=True)
    if len(newlines) < ABSOLUTE_MIN_SIZE:
        raise TooSmallNewFile(
            tempf.name, f"new file {tempf.name} less than {ABSOLUTE_MIN_SIZE} lines"
        )

    # Write content to temp file before checking size
    with open(tempf.name, "w", encoding=encoding) as f:
        f.write(content_str)
    logger.info(
        "Wrote temp file", file=tempf.name, encoding=encoding, lines=len(newlines)
    )

    # Validate against existing file
    # NOTE: This may raise an exception, but we have already writtten
    # to the temp file at this point. This allows users to inspect
    # the temp file manually to approve the changes and re-run
    # the command with ignore_size_change=True or manually move
    # the temp file to the destination.
    if destfile.exists() and not ignore_size_change:
        compare_file_size(
            destfile,
            newlines,
            max_line_change_percent=max_line_change_percent,
            encoding=encoding,
        )

    # Keep backup of old file
    if destfile.exists() and keepoldfile:
        oldfile = destfile.with_name(f"{destfile.name}_old")
        _ = shutil.copy2(destfile, oldfile)

    # Move temp file to destination
    _ = shutil.move(tempf.name, destfile)

    if mode is not None:
        destfile.chmod(mode)

    info(f"Wrote file {destfile} ({len(newlines)} lines)")


def error(msg: str, code: int | None = os.EX_UNAVAILABLE) -> NoReturn:
    from mreg_tools.output import err_console  # noqa: PLC0415

    logger.error(msg)
    err_console.print(f"[bold red]ERROR:[/bold red] {msg}")
    sys.exit(code)


def mkdir(path: str | Path) -> None:
    """Make a directory at the given path, aborting if it cannot be created."""
    path = Path(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        error(f"Failed to create directory {path}: {e}", code=e.errno)


def run_postcommand(command: list[str], timeout: int | float | None = None) -> None:
    """Run a post-command using subprocess.run with the given command and timeout."""
    # TODO: output capture? logging? error handling?
    logger.info("Running post-command: %s", " ".join(command))
    subprocess.run(command, timeout=timeout)
