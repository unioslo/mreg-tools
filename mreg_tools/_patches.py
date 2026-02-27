from __future__ import annotations

import typer.rich_utils
from rich.console import Console
from rich.theme import Theme

from mreg_tools.output.theme import DEFAULT_THEME


def _get_rich_console(stderr: bool = False) -> Console:  # pyright: ignore[reportUnusedParameter]  # noqa: ARG001
    from mreg_tools.app import app

    return app.get_console()


def patch_typer_styles(theme: Theme) -> None:
    """Patch the Typer styles with the given theme."""

    typer.rich_utils.STYLE_OPTION = theme.styles.get("option") or "bold cyan"
    typer.rich_utils.STYLE_SWITCH = theme.styles.get("switch") or "bold green"
    typer.rich_utils.STYLE_NEGATIVE_OPTION = (
        theme.styles.get("negative_option") or "bold magenta"
    )
    typer.rich_utils.STYLE_NEGATIVE_SWITCH = (
        theme.styles.get("negative_switch") or "bold red"
    )
    typer.rich_utils.STYLE_METAVAR = theme.styles.get("metavar") or "bold yellow"
    typer.rich_utils.STYLE_METAVAR_SEPARATOR = theme.styles.get("metavar_sep") or "dim"
    typer.rich_utils.STYLE_USAGE = theme.styles.get("usage") or "yellow"
    typer.rich_utils.STYLE_USAGE_COMMAND = theme.styles.get("usage_command") or "bold"
    typer.rich_utils.STYLE_DEPRECATED = theme.styles.get("deprecated") or "red"
    typer.rich_utils.STYLE_DEPRECATED_COMMAND = (
        theme.styles.get("deprecated_command") or "dim"
    )
    typer.rich_utils.STYLE_HELPTEXT_FIRST_LINE = ""
    typer.rich_utils.STYLE_HELPTEXT = "dim"
    typer.rich_utils.STYLE_OPTION_HELP = ""
    typer.rich_utils.STYLE_OPTION_DEFAULT = "dim"
    typer.rich_utils.STYLE_OPTION_ENVVAR = "dim yellow"
    typer.rich_utils.STYLE_REQUIRED_SHORT = "red"
    typer.rich_utils.STYLE_REQUIRED_LONG = "dim red"
    typer.rich_utils.STYLE_OPTIONS_PANEL_BORDER = "dim"
    typer.rich_utils.STYLE_COMMANDS_PANEL_BORDER = "dim"
    typer.rich_utils.STYLE_COMMANDS_TABLE_FIRST_COLUMN = (
        theme.styles.get("command") or "bold cyan"
    )
    typer.rich_utils.STYLE_ERRORS_PANEL_BORDER = "red"
    typer.rich_utils.STYLE_ABORTED = "red"


typer.rich_utils._get_rich_console = _get_rich_console  # pyright: ignore[reportPrivateUsage]
patch_typer_styles(DEFAULT_THEME.as_rich_theme())
