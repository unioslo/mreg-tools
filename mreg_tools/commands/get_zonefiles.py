from __future__ import annotations

import io
from typing import Annotated
from typing import Final
from typing import final
from typing import override

import structlog.stdlib
import typer
from mreg_api.models import ForwardZone
from mreg_api.models import ReverseZone
from mreg_api.models import Zone

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import GetZoneFilesConfig
from mreg_tools.output import exit_err

COMMAND_NAME: Final[str] = "get-zonefiles"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class ZoneDataStorage(MregDataStorage):
    """Storage for fetched host data."""

    def __init__(
        self, zones: MregData[ForwardZone], reverse_zones: MregData[ReverseZone]
    ) -> None:
        self.forward_zones = zones
        self.reverse_zones = reverse_zones


@final
class GetZoneFiles(CommandBase[ZoneDataStorage]):
    """get-zonefiles command class."""

    def __init__(self, app_config: Config):
        super().__init__(app_config)
        self.data = ZoneDataStorage(
            zones=MregData(
                name="forward_zones",
                type=ForwardZone,
                default=[],
                first_func=self.client.forward_zone.get_first,
                get_func=self.client.forward_zone.get_list,
                count_func=self.client.forward_zone.get_count,
            ),
            reverse_zones=MregData(
                name="reverse_zones",
                type=ReverseZone,
                default=[],
                first_func=self.client.reverse_zone.get_first,
                get_func=self.client.reverse_zone.get_list,
                count_func=self.client.reverse_zone.get_count,
            ),
        )

    @override
    def should_run_postcommand(self) -> bool:
        """Run post-command if any zones were updated."""
        return self.is_updated

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> GetZoneFilesConfig:
        return self._app_config.get_zonefiles

    @override
    def run(self) -> None:
        self.create_zone_files(self.data.forward_zones.data, self.data.reverse_zones.data)

    def create_zone_files(
        self, forward_zones: list[ForwardZone], reverse_zones: list[ReverseZone]
    ) -> None:
        """Create the zone files for all configured zones."""
        zone_map = {zone.name: zone for zone in forward_zones + reverse_zones}

        def _get_zone_by_name(name: str) -> Zone:
            if name not in zone_map:
                exit_err(
                    f"Zone {name} not found in mreg", command=self.command, zone=name
                )
            return zone_map[name]

        # Create zone files for all configured zones
        for zone in self.command_config.zones:
            self.create_zone_file(_get_zone_by_name(zone.zone), zone.destname)

        # Create zone files for zones that exclude private address ranges
        for zone in self.command_config.zones_exclude_private:
            self.create_zone_file_private(_get_zone_by_name(zone.zone), zone.destname)

    def create_zone_file(self, zone: Zone, destname: str) -> None:
        """Create the zone file for a given zone."""
        # NOTE: It's unclear what this warning signifies.
        #       It has been ported from the old script.
        if zone.serialno % 100 == 99:
            self.logger.warning(
                "zone reached max serial", zone=zone.name, serialno=zone.serialno
            )
        self._do_create_zone_file(zone, destname, exclude_private=False)

    def create_zone_file_private(self, zone: Zone, destname: str) -> None:
        """Create the zone file for a given zone, excluding private address ranges."""
        self._do_create_zone_file(zone, destname, exclude_private=True)

    def _do_create_zone_file(
        self, zone: Zone, destname: str, exclude_private: bool
    ) -> None:
        """Create the zone file for a given zone, with an option to exclude private address ranges."""
        contents = io.StringIO()

        zonefile = self.client.zonefile.get_by_name_or_raise(
            zone.name, exclude_private=exclude_private
        )
        contents.write(zonefile)

        # NOTE: we look up data based on the destname, _not_ the name of the zone!
        if extra := self.get_extra_zone_data(destname):
            contents.write(extra)

        self.write(contents, filename=destname)

    def get_extra_zone_data(self, name: str) -> str | None:
        """Get the extra data for a zone from the extradir if it exists."""
        if not self.command_config.extradir:
            self.logger.debug("No extra dir configured")
            return None

        extrafile = self.command_config.extradir / f"{name}_extra"
        if not extrafile.exists():
            self.logger.info(f"No extra data file found for {name} at {extrafile}")
            return None

        try:
            return extrafile.read_text()
        except PermissionError as e:
            self.logger.error(
                "Permission error reading extra data file",
                error=e,
                extrafile=extrafile,
            )
            raise e
        except Exception as e:
            self.logger.error(
                "Error reading extra data file",
                error=e,
                extrafile=extrafile,
            )
            raise e


@app.command(COMMAND_NAME, help="Export zone files from mreg.")
def main(
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="force refresh of data from mreg"),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="ignore size changes when writing the zone files",
        ),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="force use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
    filename: Annotated[
        str | None,
        typer.Option(
            "--filename",
            help="output filename for the zone files",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.get_zonefiles.force_check = force_check
    if ignore_size_change is not None:
        conf.get_zonefiles.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.get_zonefiles.use_saved_data = use_saved_data
    if filename is not None:
        conf.get_zonefiles.filename = filename

    cmd = GetZoneFiles(conf)
    cmd()


if __name__ == "__main__":
    main()
