from pathlib import Path
from typing import Annotated

import typer

from mreg_tools.app import app
from mreg_tools.config import Config


@app.callback(invoke_without_command=True)
def main_callback(
    config: Annotated[
        Path | None, typer.Option("--config", help="Path to config file.")
    ] = None,
):
    conf = Config.load(config)
    # NOTE: !!IMPORTANT!! Config must be set before anything else!
    app.set_config(conf)

    # client = app.get_client(conf.mreg)


@app.command("test")
def test() -> None:
    client = app.get_client()
    host = client.host.get_by_any_means_or_raise("auspex")
    print(f"Host: {host.name}, {host.id}")


def main():
    app()


if __name__ == "__main__":
    main()
