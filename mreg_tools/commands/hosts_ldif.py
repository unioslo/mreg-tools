from __future__ import annotations

import io
import ipaddress
import logging
import os
import pickle
import sys
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Generic
from typing import NamedTuple
from typing import NotRequired
from typing import TypedDict
from typing import TypeVar
from typing import final
from typing import override

import fasteners
import requests
import typer
from mreg_api.models import Host
from mreg_api.models import IPAddress
from mreg_api.models import Network
from mreg_api.models import NetworkPolicy as NetworkPolicy2
from mreg_api.models import Srv
from mreg_api.types import IP_AddressT

from mreg_tools import common
from mreg_tools.app import app
from mreg_tools.common.LDIFutils import LDIFBase
from mreg_tools.common.LDIFutils import entry_string
from mreg_tools.common.LDIFutils import make_head_entry
from mreg_tools.common.utils import error
from mreg_tools.common.utils import updated_entries
from mreg_tools.config import Config
from mreg_tools.config import HostsLdifConfig
from mreg_tools.utils import dump_json
from mreg_tools.utils import load_json

SOURCES = {
    "hosts": "/api/v1/hosts/",
    "srvs": "/api/v1/srvs",
    "networks": "/api/v1/networks/",
}


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, stream=sys.stdout)


class LdifData:
    def __init__(self, conn=None, sources={}):
        self.conn = conn
        self.sources = sources
        self._updated = None

    def _url(self, path):
        url = requests.compat.urljoin(cfg["mreg"]["url"], path)
        if cfg.has_option("mreg", "zone"):
            zones = cfg["mreg"]["zone"]
            url += f"?zone__name__in={zones}"
        return url

    @common.utils.timing
    def _get_entries(self, url, name, update=True):
        if "?" in url:
            url += "&"
        else:
            url += "?"
        url += "page_size=1000&ordering=name"

        filename = os.path.join(cfg["default"]["workdir"], f"{name}.pickle")
        if update:
            objects = self.conn.get_list(url)
            with open(filename, "wb") as f:
                pickle.dump(objects, f)
        else:
            if not os.path.isfile(filename):
                error(f"No saved data file {filename} to use")
            with open(filename, "rb") as f:
                objects = pickle.load(f)
        return objects

    @common.utils.timing
    def get_entries(self, force=True, use_saved_data=False):
        for name, endpoint in self.sources.items():
            url = self._url(endpoint)
            _updated = getattr(self, f"_updated_{name}") or force
            objects = self._get_entries(url, name, update=_updated and not use_saved_data)
            setattr(self, f"{name}", objects)

    @property
    def updated(self):
        if self._updated is not None:
            return self._updated

        self._updated = False
        for name, endpoint in self.sources.items():
            url = self._url(endpoint)
            tmp = updated_entries(self.conn, url, f"{name}.json")
            self._updated |= tmp
            setattr(self, f"_updated_{name}", tmp)

        return self._updated


def create_ip_to_vlan_mapping(hosts, networks):
    # Create and return a mapping between ip addresses and its vlan, if any

    all_4ips = []
    all_6ips = []
    ip2vlan = {}
    net4_to_vlan = {}
    net6_to_vlan = {}

    for n in networks:
        if n["vlan"] is None:
            continue
        network = ipaddress.ip_network(n["network"])
        if network.version == 4:
            net4_to_vlan[network] = n["vlan"]
        else:
            net6_to_vlan[network] = n["vlan"]

    for i in hosts:
        host_ips = []
        for ip in i["ipaddresses"] + i["ptr_overrides"]:
            ipaddr = ipaddress.ip_address(ip["ipaddress"])
            if ipaddr.version == 4:
                all_4ips.append(ipaddr)
            else:
                all_6ips.append(ipaddr)

            host_ips.append(ipaddr)
        # Store the ip list on the host object
        i["ips"] = host_ips

    for net_to_vlan, all_ips in ((net4_to_vlan, all_4ips), (net6_to_vlan, all_6ips)):
        if not net_to_vlan:
            continue
        networks = list(net_to_vlan.keys())
        network = networks.pop(0)
        vlan = net_to_vlan[network]
        for ip in sorted(all_ips):
            while network.broadcast_address < ip:
                if not networks:
                    logger.debug(f"IP after last network: {ip}")
                    break
                network = networks.pop(0)
                vlan = net_to_vlan[network]

            if ip in network:
                ip2vlan[ip] = vlan
            else:
                logger.debug(f"Not in network: {ip}, current network {network}")

    return ip2vlan


IdToIpMappingType = dict[str, dict[str, Any]]
"""Mapping of IP address ID to the full IP address object."""


def get_id_to_ip_mapping(hosts: list[dict[str, Any]]) -> IdToIpMappingType:
    """Get a mapping of ip address IDs to the full IP address object."""
    id2ip: IdToIpMappingType = {}
    for i in hosts:
        for ip in i["ipaddresses"]:
            ip_id = str(ip.get("id", ""))
            if ip_id and ip_id not in id2ip:
                id2ip[ip_id] = ip
    return id2ip


class HostCommunity(NamedTuple):
    community: str
    community_global: str | None
    ip: str
    mac: str


def get_host_communities(
    host: dict[str, Any], ip_mapping: IdToIpMappingType
) -> set[HostCommunity]:
    """Get the set of communities a host belongs to.

    Correlates the community object's IP address ID to IP and MAC addresses.
    """
    communities: set[HostCommunity] = set()
    for community_obj in host["communities"]:
        # Correlate the community's IP address ID to the full IP object
        ip_id = community_obj.get("ipaddress")
        ip_obj = ip_mapping.get(str(ip_id))
        if not ip_obj:
            logger.debug(f"No IP address found for ID {ip_id} on host {host['name']}")
            continue
        mac = ip_obj["macaddress"]
        ip = ip_obj["ipaddress"]

        # Construct the HostCommunity object
        community = community_obj.get("community")
        community_name = community.get("name")
        community_global = community.get("global_name")
        if community_name and ip and mac:
            communities.add(
                HostCommunity(
                    community=community_name,
                    community_global=community_global,
                    ip=ip,
                    mac=mac,
                )
            )

    return communities


class NetworkPolicy(NamedTuple):
    """Network policy with its attributes.

    This data structure maps the API resource for a network policy.
    """

    name: str
    description: str | None = (
        None  # NOTE: can we remove union type? TextField(blank=True, ...) in model
    )
    community_template_pattern: str | None = None
    attributes: tuple[str, ...] = tuple()


class HostNetworkPolicy(NamedTuple):
    """Active network policy (on a host) for the given IP address.

    This data structure correlates a network policy to a specific IP and MAC
    address on a host.
    """

    # NOTE: this data structure corrlates
    # Extra fields that we need for host correlation:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    mac: str

    # Fields from the original API resource:
    name: str
    description: str | None = None
    community_template_pattern: str | None = None
    attributes: tuple[str, ...] = tuple()

    def get_isolated_name(self) -> str | None:
        """Get the isolated community name for this policy, if applicable."""
        if self.community_template_pattern:
            return f"{self.community_template_pattern}_isolated"
        logger.warning("No community template pattern for policy %s", self.name)
        return None


class HostPolicies:
    """Set of network policies applied to a host."""

    def __init__(self, policies: set[HostNetworkPolicy]):
        self.policies = policies

    def __bool__(self) -> bool:
        """Return True if there are any policies."""
        return bool(self.policies)

    def __iter__(self) -> Generator[HostNetworkPolicy, None, None]:
        """Iterate over the policies."""
        for policy in self.policies:
            yield policy

    def get_isolated_policy_name(self) -> str:
        """Get the isolated policy name for the host using the first applicable policy.

        Raises ValueError if no isolated policy name can be determined.
        We cannot produce a valid export if the host is part of policies,
        but none support isolation.
        """
        if not self.policies:
            raise ValueError("No policies available to determine isolated policy name.")

        for policy in self.policies:
            name = policy.get_isolated_name()
            if name is not None:
                return name

        raise ValueError(
            "Unable to determine isolated policy name for policies: "  # pyright: ignore[reportImplicitStringConcatenation]
            f"{', '.join(p.name for p in self.policies)}"
        )


NetworkPolicyMappingType = dict[
    ipaddress.IPv4Network | ipaddress.IPv6Network, NetworkPolicy
]
"""Mapping of network to policy name."""


def create_network_to_policy_mapping(
    networks: list[dict[str, Any]],
) -> NetworkPolicyMappingType:
    net_to_policy: NetworkPolicyMappingType = {}
    for n in networks:
        policy = n.get("policy")
        if policy is None:
            continue

        try:
            network = ipaddress.ip_network(n["network"])
        except ValueError:
            logger.warning(f"Invalid network {n['network']}")
            continue

        # Add all attributes with True values to the set of attributes
        attributes: set[str] = set()
        for attr in policy.get(
            "attributes", []
        ):  # list of dicts {"name": str, "value": bool}
            attr_val = attr.get("value")
            attr_name = attr.get("name")
            if attr_val is True and attr_name:
                attributes.add(attr_name)

        net_to_policy[network] = NetworkPolicy(
            name=policy["name"],
            description=policy.get("description"),
            community_template_pattern=policy.get("community_template_pattern")
            or policy.get("community_mapping_prefix"),
            attributes=tuple(attributes),
        )
    return net_to_policy


def get_host_policies(
    host: dict[str, Any], network2policy: NetworkPolicyMappingType
) -> HostPolicies:
    """Get the set of network policies applied to a host."""
    policies: set[HostNetworkPolicy] = set()
    for ipaddr in host["ipaddresses"]:
        try:
            ip = ipaddress.ip_address(ipaddr["ipaddress"])
        except ValueError:
            logger.warning(
                f"Invalid IP address {ipaddr['ipaddress']} on host {host['name']}"
            )
            continue

        mac = ipaddr.get("macaddress")
        if not mac:
            logger.debug(
                f"No MAC address for IP {ip} on host {host['name']}. Not including in policies."
            )
            continue

        # Correlate the IP address to its network policy
        for network, policy in network2policy.items():
            if ip in network:
                policies.add(
                    HostNetworkPolicy(
                        name=policy.name,
                        description=policy.description,
                        community_template_pattern=policy.community_template_pattern,
                        ip=ip,
                        mac=mac,
                        attributes=tuple(policy.attributes),
                    )
                )

    return HostPolicies(policies)


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


IdToIpMappingType2 = dict[int, IPAddress]


NetworkPolicyMappingType2 = dict[
    ipaddress.IPv4Network | ipaddress.IPv6Network, NetworkPolicy2
]


def create_network_to_policy_mapping2(
    networks: list[Network],
) -> NetworkPolicyMappingType2:
    """Create a mapping of networks to network policies.

    Args:
        networks (list[Network]): List of Network objects

    Returns:
        NetworkPolicyMappingType2: _description_
    """
    net_to_policy: NetworkPolicyMappingType2 = {}
    for network in networks:
        policy = network.policy
        if policy is None:
            continue
        try:
            network = ipaddress.ip_network(network.network)
        except ValueError:
            logger.warning(f"Invalid network {network.network}")
            continue

        net_to_policy[network] = policy
    return net_to_policy


def get_host_network_policies(
    host: Host, policy_map: NetworkPolicyMappingType2
) -> list[NetworkPolicy2]:
    """Get the list of network policies applied to a host."""
    policies: list[NetworkPolicy2] = []
    for ip in host.ipaddresses:
        for network, policy in policy_map.items():
            if ip.ipaddress in network:
                policies.append(policy)
    return policies


def get_isolated_policy_name(policies: list[NetworkPolicy2]) -> str:
    """Get the isolated policy name for the host using the first applicable policy."""
    for policy in policies:
        if policy.community_template_pattern:
            return f"{policy.community_template_pattern}_isolated"
    raise ValueError(
        "Unable to determine isolated policy name for policies: "  # pyright: ignore[reportImplicitStringConcatenation]
        f"{', '.join(p.name for p in policies)}"
    )


def get_host_network_policy_name(
    host: Host, policy_map: NetworkPolicyMappingType2
) -> str | None:
    """Get the LDIF network policy name for a host.

    If the host has no policies, return None.
    If the host is part of multiple communities, isolate it.
    If the host is part of a single community, return the community's global name if available.
    If the host is part of policies but no community, isolate it.

    Args:
        host (Host): Host object
        policy_map (NetworkPolicyMappingType2): Mapping of networks to policies

    Returns:
        str | None: Network policy name or None if not found

    Raises:
        ValueError: If the host is part of policies but no isolated
        policy name can be determined.
    """
    # A network policy is a prerequisite for communities
    policies = get_host_network_policies(host, policy_map)
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


IPVlanMapping = dict[IP_AddressT, int]
"""Mapping of IP addresses to VLAN IDs."""


def create_ip_to_vlan_mapping2(
    hosts: list[Host], networks: list[Network]
) -> IPVlanMapping:
    """Create a mapping between IPs and their VLANs.

    Args:
        hosts (list[Host]): _list of Host objects_
        networks (list[Network]): _list of Network objects_

    Returns:
        IPVlanMapping: Mapping of IP addresses to VLAN IDs
    """
    all_4ips: list[ipaddress.IPv4Address] = []
    all_6ips: list[ipaddress.IPv6Address] = []
    net4_to_vlan: dict[ipaddress.IPv4Network, int] = {}
    net6_to_vlan: dict[ipaddress.IPv6Network, int] = {}

    ip2vlan: dict[IP_AddressT, int] = {}

    # Categorize networks by IP version
    for n in networks:
        if n.vlan is None:
            continue

        if isinstance(n.ip_network, ipaddress.IPv4Network):
            net4_to_vlan[n.ip_network] = n.vlan
        else:
            net6_to_vlan[n.ip_network] = n.vlan

    # Collect all IP addresses from hosts
    for host in hosts:
        for ip in host.ipaddresses + host.ptr_overrides:
            if isinstance(ip.ipaddress, ipaddress.IPv4Address):
                all_4ips.append(ip.ipaddress)
            else:
                all_6ips.append(ip.ipaddress)

    # Map IPv4 addresses to VLANs
    for ipv4 in all_4ips:
        for network, vlan in net4_to_vlan.items():
            if ipv4 in network:
                ip2vlan[ipv4] = vlan
                break
        else:
            logger.debug(f"IPv4 address {ipv4} not in any network")

    # Map IPv6 addresses to VLANs
    for ipv6 in all_6ips:
        for network, vlan in net6_to_vlan.items():
            if ipv6 in network:
                ip2vlan[ipv6] = vlan
                break
        else:
            logger.debug(f"IPv6 address {ipv6} not in any network")
    return ip2vlan


def get_host_vlan_ids(host: Host, ip_vlan_map: IPVlanMapping) -> list[int]:
    """Get vlan IDs for a host.

    Args:
        host (Host): Host object
        ip_vlan_map (IPVlanMapping): Mapping of IP addresses to VLAN IDs

    Returns:
        list[int]: List of VLAN IDs for the host
    """
    ids: list[int] = []
    for ip in host.ipaddresses:
        if ip.ipaddress in ip_vlan_map:
            ids.append(ip_vlan_map[ip.ipaddress])
    if len(ids) > 1:
        logger.warning(
            "Multiple VLAN IDs for host %s: %s. Using the first one: %s",
            host.name,
            ids,
            ids[0],
        )
    return ids


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
        policy_map: NetworkPolicyMappingType2,
        ip_vlan_map: IPVlanMapping,
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
        if net_pol := get_host_network_policy_name(host, policy_map):
            entry["uioHostNetworkPolicy"] = net_pol

        # Add VLAN ID if applicable
        if vlan_ids := get_host_vlan_ids(host, ip_vlan_map):
            # Only support one VLAN ID for now!
            entry["uioVlanID"] = vlan_ids[:1]

        return entry

    def create_ldif(self) -> None:
        """Create the LDIF file from fetched data."""
        entries: list[HostLDIFEntry] = []
        policy_map = create_network_to_policy_mapping2(self.data.networks.data)
        ip_to_vlan_map = create_ip_to_vlan_mapping2(
            self.data.hosts.data, self.data.networks.data
        )
        for host in self.data.hosts.data:
            entry = self.host_to_ldif_entry(host, policy_map, ip_to_vlan_map)
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
        print(entries)


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

    # logger = common.utils.getLogger()
    # conn = common.connection.Connection(cfg["mreg"])
    # hosts_ldif(args)

    h = HostsLDIF(conf)
    h.run()


if __name__ == "__main__":
    main()
