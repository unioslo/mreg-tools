"""Custom type definitions for the application."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from collections.abc import Sequence
from enum import IntEnum
from typing import Any
from typing import Self

type LDIFEntryValue = str | int | Sequence[str] | Sequence[int]
type LDIFEntry = Mapping[str, str | int | Sequence[str] | Sequence[int]]


class LogLevel(IntEnum):
    """Enum for log levels."""

    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    @classmethod
    def _missing_(cls, value: Any) -> Self:
        """Case-insensitive name lookup when normal lookup fails."""
        try:
            return cls[value.upper()]
        except Exception:
            raise ValueError(f"Invalid log level: {value}") from None
