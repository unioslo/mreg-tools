from __future__ import annotations

import re
import sys
from abc import ABC
from abc import abstractmethod
from ast import literal_eval
from base64 import b64encode
from pathlib import Path

from mreg_api import MregClient

from mreg_tools.config import Config
from mreg_tools.config import LDIFCommandConfig
from mreg_tools.types import LDIFEntry

needs_base64 = re.compile(r"\A[\s:<]|[\0-\37\177]|\s\Z").search


class LDIFBase(ABC):
    """Base class for LDIF utilities.

    Commands that produce LDIF output should define classes that
    inherit from this class.
    """

    def __init__(self, config: Config) -> None:
        from mreg_tools.app import (  # noqa: PLC0415 # TODO: move to top-level after refactoring is complete
            app,
        )

        self.config: Config = config

        self.workdir: Path = self.command_config.workdir or config.default.workdir
        self.destdir: Path = self.command_config.destdir or config.default.destdir
        self.logdir: Path = self.command_config.logdir or config.default.logdir
        self.filename: Path = self.destdir / self.command_config.filename

        self.client: MregClient  # annotation only
        if self.command_config.mreg:
            self.client = app.get_client(self.config.hosts_ldif.mreg)
        else:
            self.client = app.get_client(self.config.mreg)

        self._create_dirs()

    def _create_dirs(self) -> None:
        """Create necessary directories for LDIF output."""
        for path in [self.workdir, self.destdir, self.logdir]:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                sys.exit(e.errno)

    def get_head_entry(self) -> LDIFEntry:
        """Get the LDIF head entry from the command configuration."""
        return self.command_config.ldif.as_head_entry()

    @property
    @abstractmethod
    def command_config(self) -> LDIFCommandConfig:
        """Return the configuration for the current command."""
        raise NotImplementedError


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
