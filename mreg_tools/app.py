from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Protocol

import typer
from rich.console import Console
from rich.console import RenderableType
from rich.status import Status
from rich.style import StyleType

if TYPE_CHECKING:
    from mreg_tools.config import Config


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
    _console: Console | None = None

    @property
    def status(self) -> StatusCallable:
        """Get a status context manager from the error console."""
        from mreg_tools.output import err_console

        return err_console.status

    def configure(self, config: Config) -> None:
        """Configure the app with the given config."""
        self.set_config(config)
        self.get_console()

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

    def get_console(self) -> Console:
        """Get a Rich Console object with the configured theme.

        Once the config is loaded, this returns a persistent console
        with the configured theme. Prior to that, it returns a new
        console with the default theme.
        """
        from mreg_tools.output.output import get_console

        if self._console:
            return self._console

        if self._config:
            theme = self._config.get_theme()
            self._console = get_console(theme=theme)
            # HACK: patch the global console _and_ typer styles
            from mreg_tools import _patches
            from mreg_tools.output import output

            output.console = self._console
            _patches.patch_typer_styles(theme.as_rich_theme())
            return self._console
        else:
            return get_console()  # default theme


app = MregToolsApp(
    help="mreg-tools",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
