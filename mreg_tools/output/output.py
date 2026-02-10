"""Output utilities for mreg-tools."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from typing import NoReturn

import structlog.stdlib
import typer
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.markup import render

from mreg_tools.output.style import DEFAULT_THEME

logger = structlog.stdlib.get_logger()


# stdout console used to print results
console = Console(theme=DEFAULT_THEME)

# stderr console used to print prompts, messages, etc.
err_console = Console(
    stderr=True,
    highlight=False,
    soft_wrap=True,
    theme=DEFAULT_THEME,
)


class Icon(StrEnum):
    """Icons representing different types of messages."""

    DEBUG = "⚙"
    INFO = "!"
    OK = "✓"
    ERROR = "✗"
    PROMPT = "?"
    WARNING = "⚠"


RESERVED_EXTRA_KEYS = (
    "name",
    "level",
    "pathname",
    "lineno",
    "msg",
    "args",
    "exc_info",
    "func",
    "sinfo",
)


def get_extra_dict(**kwargs: Any) -> dict[str, Any]:
    """Format the extra dict for logging.

    Renames some keys to avoid collisions with the default keys.

    See: https://docs.python.org/3.11/library/logging.html#logging.LogRecord
    """
    for k in list(kwargs):  # iterate over copy while mutating
        if k in RESERVED_EXTRA_KEYS:
            kwargs[f"{k}_"] = kwargs.pop(k)
    return kwargs


def debug_kv(key: str, value: Any) -> None:
    """Print and log a key value pair."""
    msg = f"[bold]{key:<20}:[/bold] {value}"

    logger.debug(
        render(msg).plain, extra=get_extra_dict(key=key, value=value), stacklevel=2
    )
    err_console.print(msg)


def debug(message: str, *, icon: str = "", **kwargs: Any) -> None:
    """Log with INFO level and print an informational message."""
    logger.debug(message, extra=get_extra_dict(**kwargs), stacklevel=2)
    err_console.print(message)


def info(message: str, *, icon: str = Icon.INFO, **kwargs: Any) -> None:
    """Log with INFO level and print an informational message."""
    logger.info(message, extra=get_extra_dict(**kwargs), stacklevel=2)
    err_console.print(f"[success]{icon}[/] {message}")


def success(message: str, icon: str = Icon.OK, **kwargs: Any) -> None:
    """Log with INFO level and print a success message."""
    logger.info(message, extra=get_extra_dict(**kwargs), stacklevel=2)
    err_console.print(f"[success]{icon}[/] {message}")


def warning(message: str, icon: str = Icon.WARNING, **kwargs: Any) -> None:
    """Log with WARNING level and optionally print a warning message."""
    logger.warning(message, extra=get_extra_dict(**kwargs), stacklevel=2)
    err_console.print(f"[warning]{icon} {message}[/]")


def error(
    message: str,
    *,
    icon: str = Icon.ERROR,
    exc_info: bool = False,
    log: bool = True,
    **kwargs: Any,
) -> None:
    """Log with ERROR level and print an error message."""
    if log:  # we can disable logging when the logger isn't set up yet
        logger.error(
            message, extra=get_extra_dict(**kwargs), exc_info=exc_info, stacklevel=2
        )
    err_console.print(f"[error]{icon} ERROR: {message}")


def print_help(ctx: typer.Context) -> None:
    """Print the help message for the given context."""
    err_console.print(ctx.get_help())


def exit_ok(message: str | None = None, code: int | None = 0, **kwargs: Any) -> NoReturn:
    """Log a message with INFO level and exit with the given code (default: 0).

    Args:
        message (str): Message to print.
        code (int, optional): Exit code. Defaults to 0.
        **kwargs: Additional keyword arguments to pass to the extra dict.
    """
    if message:
        info(message, **kwargs)
    raise SystemExit(code if code is not None else 0)


def exit_err(
    message: str,
    code: int | None = 1,
    escape: bool = False,
    log: bool = True,
    exc_info: bool = False,
    **kwargs: Any,
) -> NoReturn:
    """Log a message with ERROR level and exit with the given code (default: 1).

    Args:
        message (str): Message to print.
        escape (bool): Whether to escape the message for rich markup. Defaults to False.
        code (int, optional): Exit code. Defaults to 1.
        log (bool): Whether to log the error message. Defaults to True.
        exc_info (bool): Whether to include exception info in the log.
        Enables logging regardless of `log` value. Defaults to False.
        **kwargs: Additional keyword arguments to pass to the extra dict.
    """
    if escape:
        message = escape_markup(message)
    error(message, exc_info=exc_info, log=log or exc_info, **kwargs)
    raise SystemExit(code if code is not None else 1)
