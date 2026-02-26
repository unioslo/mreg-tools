from __future__ import annotations  # noqa: I001

from pathlib import Path
from typing import Annotated

import typer

# Register commands

from mreg_tools.app import app
from mreg_tools.config import Config
from mreg_tools.logs import configure_logging
from mreg_tools.types import LogLevel

# fmt: off
# NOTE: EXTREMELY IMPORTANT TO LEAVE THIS IMPORT HERE!
# This imports the commands from each module and registers them with the
# typer app. If this import is removed, no commands will be registered
# and the CLI will not work.
from mreg_tools import commands  # noqa: F401  # pyright: ignore[reportUnusedImport]
# fmt: on


@app.callback(invoke_without_command=True)
def main_callback(
    config: Annotated[
        Path | None, typer.Option("--config", help="Path to config file.")
    ] = None,
    log_level: Annotated[
        LogLevel | None,
        typer.Option("--log-level", help="Log level", case_sensitive=False),
    ] = None,
) -> None:
    conf = Config.load(config)
    # NOTE: !!IMPORTANT!! Config must be set before anything else!
    app.set_config(conf)

    if log_level is not None:
        conf.logging.level = LogLevel(log_level)

    configure_logging(conf)


def main():
    app()


if __name__ == "__main__":
    main()
