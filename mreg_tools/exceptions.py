from __future__ import annotations

from pathlib import Path

import structlog.stdlib

logger = structlog.stdlib.get_logger()


class MregToolsError(Exception):
    """Base exception for mreg-tools."""


class LockFileError(MregToolsError):
    """Exception raised for errors related to lock files."""


class LockFileInUseError(LockFileError):
    """Exception raised when a lock file is already in use by another process."""


class DiffError(MregToolsError):
    """Exception raised when a diff operation fails."""


class TooManyLineChanges(DiffError):
    """Raised when the file size change exceeds the allowed limit."""

    newfile: str | Path
    message: str

    def __init__(self, newfile: str | Path, message: str) -> None:
        super().__init__(message)
        self.newfile = newfile
        self.message = message


class TooSmallNewFile(DiffError):
    """Raised when the new file has fewer lines than the minimum required."""

    newfile: str | Path
    message: str

    def __init__(self, newfile: str | Path, message: str) -> None:
        super().__init__(message)
        self.newfile = newfile
        self.message = message


def handle_exception(e: Exception) -> None:
    """Handle exceptions raised during command execution, log and exit."""
    from rich.traceback import Traceback

    from mreg_tools.output import err_console
    from mreg_tools.output import exit_err

    if isinstance(e, MregToolsError):
        logger.exception("MregToolsError occurred")
        exit_err(str(e))
    else:
        logger.exception("Unhandled exception occurred")
        # Print traceback for unhandled exceptions
        err_console.print(Traceback.from_exception(type(e), e, e.__traceback__))
        exit_err(f"An unexpected error occurred: {e}")
