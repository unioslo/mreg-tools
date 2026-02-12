from __future__ import annotations

import io
import re
import sys
from abc import ABC
from abc import abstractmethod
from ast import literal_eval
from base64 import b64encode
from functools import cached_property
from typing import override

from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import DataT
from mreg_tools.config import LDIFCommandConfig
from mreg_tools.config import ResolvedLdifCommandConfig
from mreg_tools.types import LDIFEntry

needs_base64 = re.compile(r"\A[\s:<]|[\0-\37\177]|\s\Z").search


def handle_value(attr: str, value: str | int) -> str:
    # Ignore empty values
    if isinstance(value, str) and not value:
        return ""
    if isinstance(value, str) and needs_base64(value):
        value = str(b64encode(value.encode("utf-8")), "utf-8")
        return f"{attr}:: {value}\n"
    else:
        return f"{attr}: {value}\n"


def entry_string(entry: LDIFEntry) -> str:
    """Produce an LDIF formatted string from an LDIF entry dictionary."""
    result = ""
    for attr, value in entry.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for val in value:
                result += handle_value(attr, val)
        elif isinstance(value, set):
            for val in sorted(value):
                result += handle_value(attr, val)
        elif isinstance(value, (int, str)):
            result += handle_value(attr, value)
        else:
            print(f"Unhandled value type {type(value)}, {value}")
            sys.exit(1)

    if result != "":
        result += "\n"
    return result


def to_iso646_60(string: str | None) -> str:
    """Convert Norwegian characters to their ISO 646-60 representation."""
    tr = dict(zip("ÆØÅæøå", "[\\]{|}"))
    if string is None:
        return ""
    return "".join([tr.get(i, i) for i in string])


def make_head_entry(cfg):
    # FIXME: DEPRECATED! Remove after migrating LDIF commands to LDIFBase
    head_entry = {}
    for attr, value in cfg.items("ldif"):
        # Convert a string tuple to an actual tuple
        if value.startswith("(") and value.endswith(")"):
            value = literal_eval(value)
        head_entry[attr] = value
    return head_entry


class LDIFBase(CommandBase[DataT], ABC):
    """Base class for LDIF utilities.

    Commands that produce LDIF output should define classes that
    inherit from this class.
    """

    @property
    @abstractmethod
    @override
    def command_config(self) -> LDIFCommandConfig:
        """Raw command config section (e.g. HostsLdifConfig)."""
        ...

    @abstractmethod
    def create_ldif(self) -> io.StringIO:
        """Create the LDIF file. Should be called after data is populated."""
        ...

    def run(self) -> None:
        ldif = self.create_ldif()

        # TODO: if encoding is ascii, _all_ strings
        #       should be processed with to_iso646_60 before being written

        self.write(ldif)

    @cached_property
    @override
    def config(self) -> ResolvedLdifCommandConfig:
        """Resolved config with defaults applied. Primary config access point."""
        return self._app_config.resolve_ldif(self.command_config)

    def get_head_entry(self) -> LDIFEntry:
        """Get the LDIF head entry from the command configuration."""
        return self.config.ldif.as_head_entry()
