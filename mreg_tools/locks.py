from __future__ import annotations

import structlog.stdlib
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import fasteners

from mreg_tools.exceptions import LockFileInUseError

logger = structlog.stdlib.get_logger(__name__)


@contextmanager
def lock_file(
    lockfile: Path, timeout: int | float | None = None
) -> Generator[None, None, None]:
    """Context manager for entering/acquiring a file lock.

    Args:
        lockfile: Path to the file to lock.
        timeout: Timeout in seconds to wait for the lock.
    """
    log = logger.bind(lockfile=str(lockfile), timeout=timeout)
    lock = fasteners.InterProcessLock(lockfile)
    try:
        # Do not wait for the lock if another process is running the same command.
        # NOTE: each command should have its own lock file
        if lock.acquire(blocking=False, timeout=timeout):
            log.info("Acquired lock")
            yield
        else:
            log.error(
                "Another process is running the same command. Could not acquire lock."
            )
            raise LockFileInUseError(f"Could not acquire lock on {lockfile}")

    finally:
        try:
            lock.release()
            lockfile.unlink(missing_ok=True)
            log.info("Released lock")
        # Trying to release a lock that isn't acquired raises a threading.ThreadError
        # which kind of makes no sense.
        except threading.ThreadError:
            pass
        except Exception:
            log.exception("Unknown error releasing lock", lockfile=str(lockfile))
