from __future__ import annotations

import io
from typing import Annotated
from typing import Final
from typing import final
from typing import override

import structlog.stdlib
import typer
from mreg_api.models import Host

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import GetHostinfoConfig

COMMAND_NAME: Final[str] = "get-hostinfo"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class HostDataStorage(MregDataStorage):
    """Storage for fetched host data."""

    def __init__(self, hosts: MregData[Host]) -> None:
        self.hosts = hosts


@final
class GetHostInfo(CommandBase[HostDataStorage]):
    """get-hostinfo command class."""

    def __init__(self, app_config: Config):
        super().__init__(app_config)
        self.data = HostDataStorage(
            hosts=MregData(
                name="hosts",
                type=Host,
                default=[],
                first_func=self.client.host.get_first,
                get_func=self.client.host.get_list,
                count_func=self.client.host.get_count,
            )
        )

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> GetHostinfoConfig:
        return self._app_config.get_hostinfo

    @override
    def run(self) -> None:
        self.create_hosts_csv(self.data.hosts.data)

    def create_hosts_csv(self, hosts: list[Host]) -> None:
        contents = io.StringIO()  # file-like string object
        for host in hosts:
            contents.write(self.host_to_csv_string(host))
        # TODO: validation that the file is correctly formatted and valid CSV?
        self.write(contents)

    # NOTE: Ported as-is. Separator cannot be configured
    def host_to_csv_string(self, host: Host) -> str:
        """Generate a CSV string for a host.

        Args:
            host (Host): Host object.

        Returns:
            str:
        """
        emails = " ".join(host.contact_emails)
        return "{};{}\n".format(host.name, emails)


@app.command(COMMAND_NAME, help="Export host info from mreg as a CSV file.")
def main(
    force_check: Annotated[
        bool | None,
        typer.Option(
            "--force",
            "--force-check",
            help="Force refresh of data from mreg",
        ),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="Ignore size changes when writing the output file",
        ),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="Force use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
    filename: Annotated[
        str | None,
        typer.Option(
            "--filename",
            help="Filename for the output file",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.get_hostinfo.force_check = force_check
    if ignore_size_change is not None:
        conf.get_hostinfo.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.get_hostinfo.use_saved_data = use_saved_data
    if filename is not None:
        conf.get_hostinfo.filename = filename

    cmd = GetHostInfo(conf)
    cmd()


if __name__ == "__main__":
    main()
