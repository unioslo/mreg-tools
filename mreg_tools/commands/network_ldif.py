from __future__ import annotations

import io
from typing import Annotated
from typing import Final
from typing import NotRequired
from typing import TypedDict
from typing import final
from typing import override

import structlog.stdlib
import typer
from mreg_api.models import Network

from mreg_tools.app import app
from mreg_tools.common.LDIFutils import LDIFBase
from mreg_tools.common.LDIFutils import LdifData
from mreg_tools.common.LDIFutils import LdifDataStorageBase
from mreg_tools.common.LDIFutils import entry_string
from mreg_tools.config import Config
from mreg_tools.config import NetworkLdifConfig

COMMAND_NAME: Final[str] = "network-ldif"

# Logger for the module independent of the LDIFBase logger
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class NetworkLdifEntry(TypedDict):
    """Network LDIF entry structure."""

    dn: str
    cn: str
    objectClass: list[str]
    description: str | None
    ipNetworkNumber: str
    ipNetmaskNumber: str
    uioNetworkCategory: list[str]
    uioNetworkLocation: list[str]
    uioIpAddressRangeStart: NotRequired[int]
    uioIpAddressRangeEnd: NotRequired[int]
    uioIpV6AddressRangeStart: NotRequired[int]
    uioIpV6AddressRangeEnd: NotRequired[int]
    uioVlanID: NotRequired[int]


class NetworkLdifDataStorage(LdifDataStorageBase):
    def __init__(self, networks: LdifData[Network]) -> None:
        self.networks = networks


@final
class NetworkLDIF(LDIFBase[NetworkLdifDataStorage]):
    def __init__(self, app_config: Config) -> None:
        super().__init__(app_config)
        self.data = NetworkLdifDataStorage(
            networks=LdifData(
                name="networks",
                type=Network,
                default=[],
                first_func=self.client.network.get_first,
                get_func=self.client.network.get_list,
                count_func=self.client.network.get_count,
            )
        )

    @property
    @override
    def command(self) -> str:
        return "network-ldif"

    @property
    @override
    def command_config(self) -> NetworkLdifConfig:
        return self._app_config.network_ldif

    @override
    def create_ldif(self) -> io.StringIO:
        """Create the LDIF file from fetched data."""
        # Collect the LDIF entries
        entries: list[NetworkLdifEntry] = []
        for network in self.data.networks.data:
            entry = self.network_to_ldif_entry(network)
            entries.append(entry)

        # Construct the string to write to the LDIF file
        ldifs = io.StringIO()
        if self.config.ldif.make_head_entry:
            ldifs.write(entry_string(self.get_head_entry()))
        for entry in entries:
            ldifs.write(entry_string(entry))
        return ldifs

    def network_to_ldif_entry(self, network: Network) -> NetworkLdifEntry:
        """Generate an LDIF entry for a network.

        Args:
            network (Network): Network object.

        Returns:
            NetworkLdifEntry: LDIF entry dictionary for the network.
        """
        entry: NetworkLdifEntry = {
            "dn": f"cn={network.network},{self.config.ldif.dn}",
            "cn": network.network,
            "objectClass": ["top", "ipNetwork", "uioIpNetwork"],
            "description": network.description,
            "ipNetworkNumber": str(network.network_address),
            "ipNetmaskNumber": str(network.ip_network.netmask),
            "uioNetworkCategory": sorted(network.category.split(" ")),
            "uioNetworkLocation": sorted(network.location.split(" ")),
        }
        if network.ip_network.version == 4:
            entry["uioIpAddressRangeStart"] = int(network.network_address)
            entry["uioIpAddressRangeEnd"] = int(network.broadcast_address)
        else:
            entry["uioIpV6AddressRangeStart"] = int(network.network_address)
            entry["uioIpV6AddressRangeEnd"] = int(network.broadcast_address)
        if network.vlan is not None:
            entry["uioVlanID"] = network.vlan
        return entry


@app.command(COMMAND_NAME, help="Export network from mreg as a ldif.")
def main(
    config: Annotated[
        str | None,
        typer.Option("--config", help="(DEPRECATED) path to config file", hidden=True),
    ] = None,
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="force refresh of data from mreg"),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="ignore size changes when writing the LDIF file",
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
            help="output filename for the ldif file",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.network_ldif.force_check = force_check
    if ignore_size_change is not None:
        conf.network_ldif.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.network_ldif.use_saved_data = use_saved_data
    if filename is not None:
        conf.network_ldif.filename = filename

    ldif = NetworkLDIF(conf)
    with app.lock(ldif.config.workdir, COMMAND_NAME):
        ldif.run()
    ldif.create_ldif()


if __name__ == "__main__":
    main()
