from __future__ import annotations

import io
import subprocess
from abc import ABC
from abc import abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any
from typing import Generic
from typing import Protocol
from typing import TypeVar
from typing import final

import structlog.stdlib
from mreg_api import MregClient
from mreg_api.types import QueryParams
from structlog.stdlib import BoundLogger

from mreg_tools.api import get_client_and_login
from mreg_tools.common.utils import dump_json
from mreg_tools.common.utils import load_json
from mreg_tools.common.utils import write_file
from mreg_tools.config import CommandConfig
from mreg_tools.config import Config
from mreg_tools.config import ResolvedCommandConfig
from mreg_tools.locks import lock_file
from mreg_tools.output import exit_err

logger = structlog.stdlib.get_logger()

DataT = TypeVar("DataT", bound="MregDataStorage")

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
class MregData(Generic[T]):
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


class MregDataStorage:
    """Base class for data storage containers.

    Subclasses define MregData instance attributes. All MregData attributes
    are automatically discovered via introspection.
    """

    def __iter__(self) -> Iterator[MregData[Any]]:
        return iter(v for v in vars(self).values() if isinstance(v, MregData))

    def dump(self, directory: Path) -> None:
        for mreg_data in self:
            mreg_data.dump(directory)

    def load(self, directory: Path) -> None:
        for mreg_data in self:
            mreg_data.load(directory)

    def has_data(self) -> bool:
        return all(bool(mreg_data.data) for mreg_data in self)

    def __bool__(self) -> bool:
        return self.has_data()


class CommandBase(ABC, Generic[DataT]):
    """Base class for commands that fetch data from MREG.

    Commands that need to fetch, cache, and process MREG data should
    inherit from this class.
    """

    def __init__(self, app_config: Config) -> None:
        self._app_config: Config = app_config
        self.client: MregClient = get_client_and_login(self.config.mreg)
        self.logger: BoundLogger = logger.bind(command=self.command)

        # Setup
        self._create_dirs()

        # Abstract, must be set by subclass or command logic before calling .run()
        self.data: DataT

        self._updated: bool = False

    @property
    @abstractmethod
    def command_config(self) -> CommandConfig:
        """Raw command config section."""
        ...

    @property
    @abstractmethod
    def command(self) -> str:
        """Command name, used for logging, etc."""
        ...

    @cached_property
    def config(self) -> ResolvedCommandConfig:
        """Resolved config with defaults applied. Primary config access point."""
        return self._app_config.resolve(self.command_config)

    @abstractmethod
    def run(self) -> None:
        """Main command logic. Assumes data is populated and ready to use."""
        ...

    @final
    def __call__(self) -> None:
        """Entry point for running the command."""
        lock_path = self.config.workdir / f"{self.command}.lock"
        with lock_file(lock_path):
            self.init_data()
            self.run()
            if self.config.postcommand:
                self.run_postcommand(
                    self.config.postcommand, self.config.postcommand_timeout
                )

    # TODO: ensure this method is called before run() and only once!
    def init_data(self) -> None:
        """Load saved data from disk sand fetch new data if needed.

        Should be called before calling `run()`.
        """
        self.data.load(self.config.workdir)

        if self.should_fetch():
            self.fetch()
            self._updated = True
            self.data.dump(self.config.workdir)

    def fetch(self) -> None:
        """Fetch data from MREG for all MregData instances in the data storage."""
        for mreg_data in self.data:
            try:
                mreg_data.fetch()
            except Exception as e:
                self.logger.error(
                    "Failed to fetch data from MREG",
                    resource=mreg_data.name,
                    error=str(e),
                )
                exit_err(f"Failed to fetch data for {mreg_data.name} from MREG: {e}")

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

        # Check if data is up to date
        for mreg_data in self.data:
            data_logger = self.logger.bind(mreg_data=mreg_data.name)
            data_logger.debug("Checking")

            # Explicit check to ensure we don't get index errors
            if not mreg_data.data:
                data_logger.debug("No saved data")
                return True

            first_item = mreg_data.first_func()
            if first_item != mreg_data.data[0]:
                data_logger.debug("First item has changed")
                return True

            if mreg_data.count_func() != len(mreg_data.data):
                data_logger.debug("Number of items has changed")
                return True

        return False

    def write(self, content: io.StringIO, *, filename: str | None = None) -> None:
        """Write content to the output file using options from the config."""
        filename = filename or self.config.filename
        write_file(
            self.config.destdir / filename,
            content,
            workdir=self.config.workdir,
            encoding=self.config.encoding,
            ignore_size_change=self.config.ignore_size_change,
            keepoldfile=self.config.keepoldfile,
            max_line_change_percent=self.config.max_line_change_percent,
            mode=self.config.mode,
        )

    def _create_dirs(self) -> None:
        """Create necessary directories."""
        for path in [self.config.workdir, self.config.destdir, self.config.logdir]:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                exit_err(f"Failed to create directory {path}: {e}", code=e.errno)

    def run_postcommand(
        self, command: list[str], timeout: int | float | None = None
    ) -> None:
        """Run a post-command using subprocess.run with the given command and timeout."""
        # TODO: output capture? logging? error handling?
        # NOTE: must use `postcommand` key in logger, as `command` is already
        #       bound to the name of the CLI command being executed.
        self.logger.info("Running post-command", postcommand=command)
        subprocess.run(command, timeout=timeout)
