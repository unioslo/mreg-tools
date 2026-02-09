from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

import typer
from rich.console import RenderableType
from rich.status import Status
from rich.style import StyleType

from mreg_tools.config import Config
from mreg_tools.locks import lock_file
from mreg_tools.output import err_console


class StatusCallable(Protocol):
    """Function that returns a Status object.

    Protocol for rich.console.Console.status method.
    """

    def __call__(
        self,
        status: RenderableType,
        *,
        spinner: str = "dots",
        spinner_style: StyleType = "status.spinner",
        speed: float = 1.0,
        refresh_per_second: float = 12.5,
    ) -> Status: ...


class MregToolsApp(typer.Typer):
    _config: Config | None = None  # Set by main callback

    @property
    def status(self) -> StatusCallable:
        """Get a status context manager from the error console."""
        return err_console.status

    def set_config(self, config: Config) -> None:
        """Set the global config object.

        Args:
            config (Config): Config object to set.
        """
        self._config = config

    def get_config(self) -> Config:
        """Get the global config object.

        Raises:
            RuntimeError: Config has not been set yet.

        Returns:
            Config: The global config object.
        """
        if self._config is None:
            raise RuntimeError("Config not set")
        return self._config

    @contextmanager
    def lock(self, workdir: Path, file: str | Path) -> Generator[None, None, None]:
        """Get a lock for the given file."""
        file = Path(file).with_suffix(".lock")
        lock_file_path = workdir / file

        with lock_file(lock_file_path):
            yield


app = MregToolsApp(
    help="mreg-tools",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
