from __future__ import annotations

import io
import re
import sys
from abc import ABC
from abc import abstractmethod
from ast import literal_eval
from base64 import b64encode
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any
from typing import Generic
from typing import Protocol
from typing import TypeVar

import structlog.stdlib
from mreg_api import MregClient
from mreg_api.types import QueryParams
from structlog.stdlib import BoundLogger

from mreg_tools.api import get_client_and_login
from mreg_tools.common.utils import dump_json
from mreg_tools.common.utils import load_json
from mreg_tools.common.utils import run_postcommand
from mreg_tools.common.utils import write_file
from mreg_tools.config import Config
from mreg_tools.config import LDIFCommandConfig
from mreg_tools.config import ResolvedLdifCommandConfig
from mreg_tools.output import exit_err
from mreg_tools.types import LDIFEntry

needs_base64 = re.compile(r"\A[\s:<]|[\0-\37\177]|\s\Z").search


logger = structlog.stdlib.get_logger()

DataT = TypeVar("DataT", bound="LdifDataStorageBase")


class LDIFBase(ABC, Generic[DataT]):
    """Base class for LDIF utilities.

    Commands that produce LDIF output should define classes that
    inherit from this class.
    """

    def __init__(self, app_config: Config) -> None:
        self._app_config: Config = app_config
        self.client: MregClient = get_client_and_login(self.config.mreg)
        self.logger: BoundLogger = logger.bind(command=self.command)

        # Setup
        self._create_dirs()

        # Abstract, must be set by subclass or command logic before calling .create_ldif()
        self.data: DataT

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

    @abstractmethod
    def create_ldif(self) -> io.StringIO:
        """Create the LDIF file. Should be called after data is populated."""
        ...

    def should_fetch(self) -> bool:
        """Determine if data should be fetched from MREG."""
        # No saved data, _must_ fetch
        if not self.data.has_data():
            self.logger.debug("No saved data")
            return True

        # Force use saved data
        if self.config.use_saved_data:
            self.logger.debug("Using saved MREG data")
            return False

        # Force fetch
        if self.config.force_check:
            self.logger.debug("Force check enabled, fetching new data")
            return True

        # Saved data exists, check if it is up to date
        for ldif_data in self.data:
            logger = self.logger.bind(ldif_data=ldif_data.name)
            logger.debug("Checking")

            # Explicit check to ensure we don't get index errors
            if not ldif_data.data:
                logger.debug("No saved data")
                return True

            first_item = ldif_data.first_func()
            if first_item != ldif_data.data[0]:
                logger.debug("First item has changed")
                return True

            if ldif_data.count_func() != len(ldif_data.data):
                logger.debug("Number of items has changed")
                return True

        return False

    def run(self) -> None:
        self.data.load(self.config.workdir)
        if self.should_fetch():
            # TODO: implement saving/loading of partial data for debugging ONLY.
            # Currently not enabled, as we don't have the necessary heuristics
            # to determine if a hybrid approach is appropriate.
            # We don't currently have a way to signal which parts of the
            # data should be fetched and which should be loaded from disk
            # in `should_fetch()`.
            for ldif_data in self.data:
                ldif_data.fetch()
            self.data.dump(self.config.workdir)

        ldif = self.create_ldif()

        # Write the LDIF to disk
        write_file(
            self.config.destdir / self.config.filename,
            ldif,
            workdir=self.config.workdir,
            encoding=self.config.encoding,
            ignore_size_change=self.config.ignore_size_change,
            keepoldfile=self.config.keepoldfile,
            max_line_change_percent=self.config.max_line_change_percent,
            mode=self.config.mode,
        )

        if self.config.postcommand:
            run_postcommand(
                self.config.postcommand,
                self.config.postcommand_timeout,
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


T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


class GetFunc(Protocol, Generic[T]):
    """Function to fetch all results for a given MREG resource type."""

    def __call__(
        self, params: QueryParams | None = None, limit: int | None = None
    ) -> list[T]: ...


class FirstFunc(Protocol, Generic[T_co]):
    """Function to get the first item for a given MREG resource type."""

    def __call__(self) -> T_co | None: ...


class CountFunc(Protocol):
    """Function to get the count of items for a given MREG resource type."""

    def __call__(self) -> int: ...


@dataclass
class LdifData(Generic[T]):
    """Loading, fetching and dumping of data for a specific MREG resource type."""

    name: str
    type: type[T]
    default: list[T]
    first_func: FirstFunc[T]
    get_func: GetFunc[T]
    count_func: CountFunc
    _data: list[T] | None = None

    @property
    def data(self) -> list[T]:
        return self._data if self._data is not None else self.default

    @data.setter
    def data(self, value: list[T]) -> None:
        self._data = value

    def fetch(self) -> None:
        """Fetch data from MREG using the provided get_func. Populates `data` in-place."""
        logger.debug("Fetching data from MREG", resource=self.name)
        self.data = self.get_func(limit=None, params={"ordering": "name"})

    def dump(self, directory: Path) -> None:
        """Dump data to a JSON file.

        Args:
            directory (Path): Directory to dump the JSON file to.
        """
        dump_json(self.data, list[self.type], self.filename_json(directory))

    def load(self, directory: Path) -> None:
        """Load data from a JSON file.

        Args:
            directory (Path): Directory to load from.
        """
        self.data = (
            load_json(list[self.type], self.filename_json(directory)) or self.default
        )

    def filename_json(self, directory: Path) -> Path:
        """Get the filename for the JSON file."""
        return directory / f"{self.name}.json"


class LdifDataStorageBase:
    """Base class for LDIF data storage containers.

    Subclasses define LdifData instance attributes. All LdifData attributes
    are automatically discovered via introspection.
    """

    def __iter__(self) -> Iterator[LdifData[Any]]:
        return iter(v for v in vars(self).values() if isinstance(v, LdifData))

    def dump(self, directory: Path) -> None:
        for ldif_data in self:
            ldif_data.dump(directory)

    def load(self, directory: Path) -> None:
        for ldif_data in self:
            ldif_data.load(directory)

    def has_data(self) -> bool:
        return all(bool(ldif_data.data) for ldif_data in self)

    def __bool__(self) -> bool:
        return self.has_data()


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
