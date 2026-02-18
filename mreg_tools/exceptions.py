from __future__ import annotations

from pathlib import Path


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
