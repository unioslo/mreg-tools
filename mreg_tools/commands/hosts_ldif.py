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
from mreg_api.models import Host
from mreg_api.models import Network
from mreg_api.models import NetworkPolicy
from mreg_api.models import Srv

from mreg_tools.app import app
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.common.ldif import LDIFBase
from mreg_tools.common.ldif import entry_string
from mreg_tools.config import Config
from mreg_tools.config import HostsLdifConfig

COMMAND_NAME: Final[str] = "hosts-ldif"

# Logger for the module independent of the LDIFBase logger
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class HostLDIFEntry(TypedDict):
    """Host LDIF entry structure."""

    dn: str
    host: str
    objectClass: str | list[str]
    memberNisNetgroup: NotRequired[list[str]]
    nisNetgroupTriple: NotRequired[list[str]]
    uioHostComment: NotRequired[str]
    uioHostContact: NotRequired[str]
    uioHostMacAddr: NotRequired[list[str]]
    uioVlanID: NotRequired[list[int]]  # NOTE: only supports 1 VLAN ID per host currently
    uioHostNetworkPolicy: NotRequired[str]


def get_host_network_policies(host: Host, networks: list[Network]) -> list[NetworkPolicy]:
    """Get the list of network policies applied to a host."""
    policies: list[NetworkPolicy] = []
    for ip in host.ipaddresses:
        for network in networks:
            if not network.policy:
                continue
            if ip.ipaddress in network.ip_network:
                policies.append(network.policy)
    return policies


def get_isolated_policy_name(policies: list[NetworkPolicy]) -> str:
    """Get the isolated policy name for the host using the first applicable policy."""
    for policy in policies:
        if policy.community_template_pattern:
            return f"{policy.community_template_pattern}_isolated"
    raise ValueError(
        "Unable to determine isolated policy name for policies: "  # pyright: ignore[reportImplicitStringConcatenation]
        f"{', '.join(p.name for p in policies)}"
    )


def get_host_network_policy_name(host: Host, networks: list[Network]) -> str | None:
    """Get the LDIF network policy name for a host.

    If the host has no policies, return None.
    If the host is part of multiple communities, isolate it.
    If the host is part of a single community, return the community's global name if available.
    If the host is part of policies but no community, isolate it.

    Args:
        host (Host): Host object
        networks (list[Network]): List of Network objects

    Returns:
        str | None: Network policy name or None if not found

    Raises:
        ValueError: If the host is part of policies but no isolated
        policy name can be determined.
    """
    # A network policy is a prerequisite for communities
    policies = get_host_network_policies(host, networks)
    if not policies:
        return None

    # Host is part of a single community
    if len(host.communities) == 1:
        # Return the community's global name if available
        return (
            host.communities[0].community.global_name
            or host.communities[0].community.name
        )
    # Host is part of multiple communities - log it and isolate it
    elif len(host.communities) > 1:
        host_net_policy = get_isolated_policy_name(policies)
        logger.warning(
            "Multiple communities found for host. Isolating host.",
            host=host.name,
            communities=[com.community.name for com in host.communities],
            policy=host_net_policy,
        )
        return host_net_policy
    # Isolate if part of a policy but no community assigned
    return get_isolated_policy_name(policies)


def get_host_vlan_ids(host: Host, networks: list[Network]) -> list[int]:
    """Get vlan IDs for a host.

    Args:
        host (Host): Host object
        networks (list[Network]): List of Network objects

    Returns:
        list[int]: List of VLAN IDs for the host
    """
    ids: set[int] = set()
    for ip in host.ipaddresses + host.ptr_overrides:
        for network in networks:
            # Skip networks with no VLAN
            if network.vlan is None:
                continue

            # Skip networks with different IP version
            if network.ip_network.version != ip.ipaddress.version:
                continue

            # Found matching network
            if ip.ipaddress in network.ip_network:
                ids.add(network.vlan)
                break
    return sorted(ids)


class HostsDataStorage(MregDataStorage):
    def __init__(
        self,
        hosts: MregData[Host],
        networks: MregData[Network],
        srvs: MregData[Srv],
    ) -> None:
        self.hosts = hosts
        self.networks = networks
        self.srvs = srvs


@final
class HostsLDIF(LDIFBase[HostsDataStorage]):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        # Storage of fetched data
        self.data = HostsDataStorage(
            hosts=MregData(
                name="hosts",
                type=Host,
                default=[],
                get_func=self.client.host.get_list,
                first_func=self.client.host.get_first,
                count_func=self.client.host.get_count,
            ),
            networks=MregData(
                name="networks",
                type=Network,
                default=[],
                get_func=self.client.network.get_list,
                first_func=self.client.network.get_first,
                count_func=self.client.network.get_count,
            ),
            srvs=MregData(
                name="srvs",
                type=Srv,
                default=[],
                get_func=self.client.srv.get_list,
                first_func=self.client.srv.get_first,
                count_func=self.client.srv.get_count,
            ),
        )

    @property
    @override
    def command(self) -> str:
        return "hosts-ldif"

    @property
    @override
    def command_config(self) -> HostsLdifConfig:
        return self._app_config.hosts_ldif

    def _name_to_base_entry(self, name: str) -> HostLDIFEntry:
        """Create a base LDIF entry for a host name."""
        return {
            "dn": f"host={name},{self.config.ldif.dn}",
            "host": name,
            "objectClass": "uioHostinfo",
        }

    def host_to_ldif_entry(
        self,
        host: Host,
    ) -> HostLDIFEntry:
        """Convert a host object to an LDIF entry."""
        entry = self._name_to_base_entry(host.name)
        entry["uioHostComment"] = host.comment
        if emails := " ".join(host.contact_emails):
            entry["uioHostContact"] = emails

        mac_addresses = {ip.macaddress for ip in host.ipaddresses if ip.macaddress}
        if mac_addresses:
            entry["uioHostMacAddr"] = sorted(mac_addresses)

        # Add host network policy if applicable
        if net_pol := get_host_network_policy_name(host, self.data.networks.data):
            entry["uioHostNetworkPolicy"] = net_pol

        # Add VLAN ID if applicable
        if vlan_ids := get_host_vlan_ids(host, self.data.networks.data):
            # Only support one VLAN ID for now!
            if len(vlan_ids) > 1:
                self.logger.warning(
                    "Multiple VLAN IDs for host. Using first ID.",
                    host=host.name,
                    vlan_ids=vlan_ids,
                    first_vlan_id=vlan_ids[0],
                )
            entry["uioVlanID"] = vlan_ids[:1]

        return entry

    @override
    def create_ldif(self) -> io.StringIO:
        """Create the LDIF file from fetched data."""
        # Collect the LDIF entries
        entries: list[HostLDIFEntry] = []
        for host in self.data.hosts.data:
            entry = self.host_to_ldif_entry(host)
            entries.append(entry)

            # Add CNAME entries for the host directly after it
            for cname in host.cnames:
                cname_entry = self._name_to_base_entry(cname.name)
                entries.append(cname_entry)

        for srv in self.data.srvs.data:
            entry = self._name_to_base_entry(srv.name)
            entries.append(entry)

        # Construct the string to write to the LDIF file
        ldifs = io.StringIO()
        ldifs.write(entry_string(self.get_head_entry()))
        for entry in entries:
            ldifs.write(entry_string(entry))

        return ldifs


@app.command(COMMAND_NAME, help="Export hosts from mreg as a ldif.")
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
        conf.hosts_ldif.force_check = force_check
    if ignore_size_change is not None:
        conf.hosts_ldif.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.hosts_ldif.use_saved_data = use_saved_data
    if filename is not None:
        conf.hosts_ldif.filename = filename

    cmd = HostsLDIF(conf)
    with app.lock(cmd.config.workdir, COMMAND_NAME):
        cmd()

    # TODO: limit to a specific zone if configured


if __name__ == "__main__":
    main()
