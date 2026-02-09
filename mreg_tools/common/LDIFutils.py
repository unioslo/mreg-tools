from __future__ import annotations

import re
import sys
from abc import ABC
from abc import abstractmethod
from ast import literal_eval
from base64 import b64encode
from functools import cached_property

from mreg_api import MregClient

from mreg_tools.api import get_client_and_login
from mreg_tools.config import Config
from mreg_tools.config import LDIFCommandConfig
from mreg_tools.config import ResolvedLdifCommandConfig
from mreg_tools.output import exit_err
from mreg_tools.types import LDIFEntry

needs_base64 = re.compile(r"\A[\s:<]|[\0-\37\177]|\s\Z").search


class LDIFBase(ABC):
    """Base class for LDIF utilities.

    Commands that produce LDIF output should define classes that
    inherit from this class.
    """

    def __init__(self, app_config: Config) -> None:
        self._app_config: Config = app_config
        self.client: MregClient = get_client_and_login(self.config.mreg_config)
        self._create_dirs()
        self._check_valid_ldif_config()

    @property
    @abstractmethod
    def command_config(self) -> LDIFCommandConfig:
        """Raw command config section (e.g. HostsLdifConfig)."""
        ...

    # NOTE: should we replace this with some sort of private attr on command configs?
    #       if so, how to implenent? Pydantic PrivateAttr? How do we ensure that is
    #       set on all subclasses?
    @property
    @abstractmethod
    def command(self) -> str:
        """Command name, used for logging, etc."""
        ...

    def _check_valid_ldif_config(self) -> None:
        """Check if the LDIF configuration is valid."""
        for attr in ["cn", "dn", "objectClass", "ou"]:
            if not getattr(self.config.ldif, attr):
                exit_err(
                    f"[{self.command}.ldif] {attr} not set in the configuration.",
                    escape=True,
                )

    @cached_property
    def config(self) -> ResolvedLdifCommandConfig:
        """Resolved config with defaults applied. Primary config access point."""
        return self._app_config.resolve_ldif(self.command_config)

    def _create_dirs(self) -> None:
        """Create necessary directories for LDIF output."""
        for path in [self.config.workdir, self.config.destdir, self.config.logdir]:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                exit_err(f"Failed to create directory {path}: {e}", code=e.errno)

    def get_head_entry(self) -> LDIFEntry:
        """Get the LDIF head entry from the command configuration."""
        return self.config.ldif.as_head_entry()


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
