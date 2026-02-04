from __future__ import annotations

import io
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from typing import Generic
from typing import NamedTuple
from typing import NotRequired
from typing import TypedDict
from typing import TypeVar
from typing import final
from typing import override

import fasteners
import typer
from mreg_api.models import Host
from mreg_api.models import Network
from mreg_api.models import NetworkPolicy
from mreg_api.models import Srv

from mreg_tools import common
from mreg_tools.app import app
from mreg_tools.common.LDIFutils import LDIFBase
from mreg_tools.common.LDIFutils import entry_string
from mreg_tools.common.LDIFutils import make_head_entry
from mreg_tools.common.utils import error
from mreg_tools.config import Config
from mreg_tools.config import HostsLdifConfig
from mreg_tools.utils import dump_json
from mreg_tools.utils import load_json

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, stream=sys.stdout)


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


@common.utils.timing
def create_ldif(ldifdata, ignore_size_change):
    def _base_entry(name):
        return {
            "dn": f"host={name},{dn}",
            "host": name,
            "objectClass": "uioHostinfo",
        }

    def _write(entry):
        f.write(entry_string(entry))

    hosts = ldifdata.hosts
    ip2vlan = create_ip_to_vlan_mapping(hosts, ldifdata.networks)
    id2ip = get_id_to_ip_mapping(hosts)
    net2policy = create_network_to_policy_mapping(ldifdata.networks)

    f = io.StringIO()
    dn = cfg["ldif"]["dn"]
    _write(make_head_entry(cfg))
    for i in hosts:
        entry = _base_entry(i["name"])
        entry.update(
            {
                "uioHostComment": i["comment"],
                "uioHostContact": i["contact"],
            }
        )
        mac = {ip["macaddress"] for ip in i["ipaddresses"] if ip["macaddress"]}
        if mac:
            entry["uioHostMacAddr"] = sorted(mac)
        for ipaddr in i["ips"]:
            if ipaddr in ip2vlan:
                entry["uioVlanID"] = ip2vlan[ipaddr]
                if len(i["ips"]) > 1:
                    logger.warning(
                        "Multiple IPs for host %s, using VLAN %s from IP %s",
                        i["name"],
                        ip2vlan[ipaddr],
                        ipaddr,
                    )
                break

        # Add the host's network policy (using the community's global name, else <template_pattern>_isolated)
        policies = get_host_policies(i, net2policy)
        if policies:
            host_net_policy: str

            # Determine the community/policy name to use in the export
            communities = get_host_communities(i, id2ip)

            # Host is part of a single community
            if len(communities) == 1:
                com = communities.pop()
                host_net_policy = com.community_global or com.community
            # Host is part of multiple communities - log it and isolate it
            elif len(communities) > 1:
                host_net_policy = policies.get_isolated_policy_name()
                logger.warning(
                    "Multiple communities found for host %s: %s. Isolating host to policy %s.",
                    i["name"],
                    ", ".join(com.community for com in communities),
                    host_net_policy,
                )
            # Host is not part of a community - isolate it
            else:
                host_net_policy = policies.get_isolated_policy_name()

            host_net_policy = host_net_policy.strip()
            if host_net_policy:
                entry["uioHostNetworkPolicy"] = host_net_policy
            else:
                raise ValueError(
                    f"No applicable network policy found for host {i['name']}"
                )

        _write(entry)
        for cinfo in i["cnames"]:
            _write(_base_entry(cinfo["name"]))
    for i in ldifdata.srvs:
        _write(_base_entry(i["name"]))
    try:
        common.utils.write_file(
            cfg["default"]["filename"], f, ignore_size_change=ignore_size_change
        )
    except common.utils.TooManyLineChanges as e:
        error(e.message)


@common.utils.timing
def hosts_ldif(args):
    for i in (
        "destdir",
        "workdir",
    ):
        common.utils.mkdir(cfg["default"][i])

    lockfile = os.path.join(cfg["default"]["workdir"], __file__ + "lockfile")
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        ldifdata = LdifData(conn=conn, sources=SOURCES)

        if ldifdata.updated or args.force_check or args.use_saved_data:
            ldifdata.get_entries(
                force=args.force_check, use_saved_data=args.use_saved_data
            )
            create_ldif(ldifdata, args.ignore_size_change)
            if "postcommand" in cfg["default"]:
                common.utils.run_postcommand()
        else:
            logger.info("No updates")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


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
            "Multiple communities found for host %s: %s. Isolating host to policy %s.",
            host.name,
            ", ".join(com.community.name for com in host.communities),
            host_net_policy,
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


T = TypeVar("T")


@dataclass
class LdifData(Generic[T]):
    name: str
    type: type[T]
    default: T
    _data: T | None = None

    @property
    def data(self) -> T:
        return self._data if self._data is not None else self.default

    @data.setter
    def data(self, value: T) -> None:
        self._data = value

    def dump(self, directory: Path) -> None:
        """Dump data to a JSON file.

        Args:
            directory (Path): Directory to dump the JSON file to.
        """
        dump_json(self.data, self.type, self.filename_json(directory))

    def load(self, directory: Path) -> None:
        """Load data from a JSON file.

        Args:
            directory (Path): Directory to load from.
        """
        self.data = load_json(self.type, self.filename_json(directory)) or self.default

    def filename_json(self, directory: Path) -> Path:
        """Get the filename for the JSON file."""
        return directory / f"{self.name}.json"


class LdifDataStorage(NamedTuple):
    hosts: LdifData[list[Host]]
    networks: LdifData[list[Network]]
    srvs: LdifData[list[Srv]]

    def dump(self, directory: Path) -> None:
        """Dump fetched data to JSON files."""
        for ldif_data in self:
            ldif_data.dump(directory)

    def load(self, directory: Path) -> None:
        """Load fetched data from JSON files."""
        for ldif_data in self:
            ldif_data.load(directory)

    def has_data(self) -> bool:
        """Return True if _all_ of the data files have data."""
        return all(bool(ldif_data.data) for ldif_data in self)

    def __bool__(self) -> bool:
        """Return True if _ALL_ of the data files have data."""
        return self.has_data()


@final
class HostsLDIF(LDIFBase):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        # Storage of fetched data
        self.data = LdifDataStorage(
            hosts=LdifData(name="hosts", type=list[Host], default=[]),
            networks=LdifData(name="networks", type=list[Network], default=[]),
            srvs=LdifData(name="srvs", type=list[Srv], default=[]),
        )

    @property
    @override
    def command_config(self) -> HostsLdifConfig:
        return self.config.hosts_ldif

    def run(self) -> None:
        self.data.load(self.workdir)
        if self.should_fetch():
            # Fetch data from MREG then dump it to disk before processing
            self.data.networks.data = self.client.network.get_list(limit=None)
            self.data.srvs.data = self.client.srv.get_list(limit=None)
            self.data.hosts.data = self.client.host.get_list(limit=None)
            self.data.dump(self.workdir)
        self.create_ldif()

    def should_fetch(self) -> bool:
        """Determine if data should be fetched from MREG."""
        # No saved data, _must_ fetch
        if not self.data.has_data():
            logger.debug("No saved data, fetching new data.")
            return True

        # Force use saved data
        if self.config.hosts_ldif.use_saved_data and self.data.has_data():
            return False

        # Force fetch
        if self.config.hosts_ldif.force_check:
            return True

        # Saved data exists, check if it is up to date
        # TODO: refactor first and count checks. Can we do it dynamically, so that
        # we don't have to hardcode it for each data type?
        if self.data.hosts.data:
            first_host = self.client.host.get_first()
            if first_host != self.data.hosts.data[0]:
                logger.debug("First host has changed, fetching new data.")
                return True
            elif self.client.host.get_count() != len(self.data.hosts.data):
                logger.debug("Number of hosts has changed, fetching new data.")
                return True
        elif self.data.networks.data:
            first_network = self.client.network.get_first()
            if first_network != self.data.networks.data[0]:
                logger.debug("First network has changed, fetching new data.")
                return True
            elif self.client.network.get_count() != len(self.data.networks.data):
                logger.debug("Number of networks has changed, fetching new data.")
                return True
        elif self.data.srvs.data:
            first_srv = self.client.srv.get_first()
            if first_srv != self.data.srvs.data[0]:
                logger.debug("First srv has changed, fetching new data.")
                return True
            elif self.client.srv.get_count() != len(self.data.srvs.data):
                logger.debug("Number of srvs has changed, fetching new data.")
                return True
        return False

    def _fetch(self) -> None:
        self.data.networks.data = self.client.network.get_list(limit=None)
        self.data.srvs.data = self.client.srv.get_list(limit=None)
        self.data.hosts.data = self.client.host.get_list(limit=None)

    def _name_to_base_entry(self, name: str) -> HostLDIFEntry:
        """Create a base LDIF entry for a host name."""
        return {
            "dn": f"host={name},{self.config.hosts_ldif.ldif.dn}",
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
                logger.warning(
                    "Multiple VLAN IDs for host %s: %s. Using the first one: %s",
                    host.name,
                    vlan_ids,
                    vlan_ids[0],
                )
            entry["uioVlanID"] = vlan_ids[:1]

        return entry

    def create_ldif(self) -> None:
        """Create the LDIF file from fetched data."""
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

        ldifs = io.StringIO()
        ldifs.write(entry_string(self.get_head_entry()))
        for entry in entries:
            ldifs.write(entry_string(entry))
        self.filename.write_text(ldifs.getvalue(), encoding=self.encoding)


@app.command("hosts-ldif", help="Export hosts from mreg as a ldif.")
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

    h = HostsLDIF(conf)
    h.run()

    # TODO: limit to a specific zone if configured


if __name__ == "__main__":
    main()
