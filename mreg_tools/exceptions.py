from __future__ import annotations


class MregToolsError(Exception):
    """Base exception for mreg-tools."""


class LockFileError(MregToolsError):
    """Exception raised for errors related to lock files."""


class LockFileInUseError(LockFileError):
    """Exception raised when a lock file is already in use by another process."""
