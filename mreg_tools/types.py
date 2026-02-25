"""Custom type definitions for the application."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from collections.abc import Sequence
from enum import StrEnum
from typing import Any
from typing import Self

type LDIFEntryValue = str | int | Sequence[str] | Sequence[int]
type LDIFEntry = Mapping[str, str | int | Sequence[str] | Sequence[int]]


class LogLevel(StrEnum):
    """Enum for log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    def __int__(self) -> int:
        """Return the log level as its numeric value."""
        return logging.getLevelNamesMapping()[self]

    @classmethod
    def _missing_(cls, value: Any) -> Self:
        """Case-insensitive name lookup when normal lookup fails."""
        from mreg_tools.exceptions import MregToolsError  # noqa: PLC0415

        try:
            return cls[value.upper()]
        except (AttributeError, KeyError):
            try:
                return cls[logging.getLevelName(value)]  # pyright: ignore[reportDeprecated, reportAny]
            except (AttributeError, KeyError):
                pass
        raise MregToolsError(f"Invalid log level: {value}") from None


class DhcpHostsType(StrEnum):
    """Enum for DHCP hosts types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    IPV6BYIPV4 = "ipv6byipv4"
