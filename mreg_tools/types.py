"""Custom type definitions for the application."""

from __future__ import annotations
from collections.abc import Mapping, Sequence

type LDIFEntryValue = str | int | Sequence[str] | Sequence[int]
type LDIFEntry = Mapping[str, str | int | Sequence[str] | Sequence[int]]
