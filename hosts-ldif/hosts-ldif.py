import argparse
import configparser
import io
import ipaddress
import pickle
import os
import pathlib
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple, Union

import fasteners

import requests

parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection
import common.utils

from common.utils import error, updated_entries
from common.LDIFutils import entry_string, make_head_entry

SOURCES = {
    "hosts": "/api/v1/hosts/",
    "srvs": "/api/v1/srvs",
    "networks": "/api/v1/networks/",
}

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
        if '?' in url:
            url += '&'
        else:
            url += '?'
        url += 'page_size=1000&ordering=name'

        filename = os.path.join(cfg['default']['workdir'], f"{name}.pickle")
        if update:
            objects = self.conn.get_list(url)
            with open(filename, 'wb') as f:
                pickle.dump(objects, f)
        else:
            if not os.path.isfile(filename):
                error(f"No saved data file {filename} to use")
            with open(filename, 'rb') as f:
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
        if n['vlan'] is None:
            continue
        network = ipaddress.ip_network(n['network'])
        if network.version == 4:
            net4_to_vlan[network] = n['vlan']
        else:
            net6_to_vlan[network] = n['vlan']

    for i in hosts:
        host_ips = []
        for ip in i['ipaddresses'] + i['ptr_overrides']:
            ipaddr = ipaddress.ip_address(ip['ipaddress'])
            if ipaddr.version == 4:
                all_4ips.append(ipaddr)
            else:
                all_6ips.append(ipaddr)

            host_ips.append(ipaddr)
        # Store the ip list on the host object
        i['ips'] = host_ips

    for net_to_vlan, all_ips in ((net4_to_vlan, all_4ips),
                                 (net6_to_vlan, all_6ips)):
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


IdToIpMappingType = Dict[str, Dict[str, Any]]
"""Mapping of IP address ID to the full IP address object."""


def get_id_to_ip_mapping(hosts: List[Dict[str, Any]]) -> IdToIpMappingType:
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
    community_global: Optional[str]
    ip: str
    mac: str


def get_host_communities(
    host: Dict[str, Any], ip_mapping: IdToIpMappingType
) -> Set[HostCommunity]:
    """Get the set of communities a host belongs to.

    Correlates the community object's IP address ID to IP and MAC addresses.
    """
    communities: Set[HostCommunity] = set()
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
    """Network policy with its attributes."""

    name: str
    description: Optional[str] = None # NOTE: can we remove union type? TextField(blank=True, ...) in model
    community_template_pattern: Optional[str] = None
    attributes: Tuple[str, ...] = tuple()

    def get_isolated_name(self) -> Optional[str]:
        """Get the isolated community name for this policy, if applicable."""
        if self.community_template_pattern:
            return f"{self.community_template_pattern}_isolated"
        logger.warning("No community template pattern for policy %s", self.name)
        return None

class HostNetworkPolicy(NamedTuple):
    """Active network policy (on a host) for the given IP address."""

    policy: NetworkPolicy
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    mac: str
    attributes: Tuple[str, ...] = tuple()


class HostPolicies:
    """Set of network policies applied to a host."""
    def __init__(self, policies: Set[HostNetworkPolicy]):
        self.policies = policies

    def get_isolated_policy(self) -> Optional[HostNetworkPolicy]:
        """Get the first isolated policy for the host, if any."""
        for policy in self.policies:
            if "isolated" in policy.attributes:
                return policy
        return None


NetworkPolicyMappingType = Dict[
    Union[ipaddress.IPv4Network, ipaddress.IPv6Network], NetworkPolicy
]
"""Mapping of network to policy name."""


def create_network_to_policy_mapping(
    networks: List[Dict[str, Any]],
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
        attributes: Set[str] = set()
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
            community_template_pattern=policy.get("community_template_pattern") or policy.get("community_mapping_prefix"),
            attributes=tuple(attributes),
        )
    return net_to_policy


def get_host_policies(
    host: Dict[str, Any], network2policy: NetworkPolicyMappingType
) -> HostPolicies:
    """Get the set of network policies applied to a host."""
    policies: Set[HostNetworkPolicy] = set()
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
                        policy=policy,
                        ip=ip,
                        mac=mac,
                        attributes=tuple(policy.attributes),
                    )
                )

    return HostPolicies(policies)


@common.utils.timing
def create_ldif(ldifdata, ignore_size_change):

    def _base_entry(name):
        return {
            'dn': f'host={name},{dn}',
            'host': name,
            'objectClass': 'uioHostinfo',
            }

    def _write(entry):
        f.write(entry_string(entry))

    hosts = ldifdata.hosts
    ip2vlan = create_ip_to_vlan_mapping(hosts, ldifdata.networks)
    id2ip = get_id_to_ip_mapping(hosts)
    net2policy = create_network_to_policy_mapping(ldifdata.networks)

    f = io.StringIO()
    dn = cfg['ldif']['dn']
    _write(make_head_entry(cfg))
    for i in hosts:
        entry = _base_entry(i["name"])
        entry.update({
            'uioHostComment':  i['comment'],
            'uioHostContact':  i['contact'],
            })
        mac = {ip['macaddress'] for ip in i['ipaddresses'] if ip['macaddress']}
        if mac:
            entry['uioHostMacAddr'] = sorted(mac)
        for ipaddr in i['ips']:
            if ipaddr in ip2vlan:
                entry['uioVlanID'] = ip2vlan[ipaddr]
                if len(i["ips"]) > 1:
                    logger.warning("Multiple IPs for host %s, using VLAN %s from IP %s",
                                   i["name"], ip2vlan[ipaddr], ipaddr)
                break

        # Add the host's network policy (using the community's global name, else <template_pattern>_isolated)
        policies = get_host_policies(i, net2policy)
        if policies:
            host_net_policy: Optional[str] = None

            # Determine the community/policy name to use in the export
            communities = get_host_communities(i, id2ip)

            # Host is part of a single community
            if len(communities) == 1:
                com = communities.pop()
                host_net_policy = com.community_global or com.community
            # Host is part of multiple communities - log and isolate if network supports it
            elif len(communities) > 1:
                pol = policies.get_isolated_policy()
                if pol is not None:
                    isolated_name = pol.policy.get_isolated_name()
                    if isolated_name:
                        host_net_policy = isolated_name
                        logger.warning(
                            "Multiple communities found for host %s: %s. Isolating host to policy %s.",
                            i["name"],
                            ", ".join(com.community for com in communities),
                            pol.policy.name,
                        )
                else:
                    logger.warning("Unable to determine isolated policy for host %s with multiple communities", i["name"])
            # Host is not part of a community - isolate if network supports it
            elif policies.get_isolated_policy():
                pol = policies.get_isolated_policy()
                if pol is not None:
                    host_net_policy = pol.policy.get_isolated_name()

            if host_net_policy:
                entry["uioHostNetworkPolicy"] = host_net_policy
            else:
                logger.debug(
                    "No applicable network policy found for host %s", i["name"]
                )

        _write(entry)
        for cinfo in i["cnames"]:
            _write(_base_entry(cinfo["name"]))
    for i in ldifdata.srvs:
        _write(_base_entry(i["name"]))
    try:
        common.utils.write_file(cfg['default']['filename'], f,
                                ignore_size_change=ignore_size_change)
    except common.utils.TooManyLineChanges as e:
        error(e.message)


@common.utils.timing
def hosts_ldif(args):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    lockfile = os.path.join(cfg['default']['workdir'], __file__ + 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        ldifdata = LdifData(conn=conn, sources=SOURCES)

        if ldifdata.updated or args.force_check or args.use_saved_data:
            ldifdata.get_entries(force=args.force_check, use_saved_data=args.use_saved_data)
            create_ldif(ldifdata, args.ignore_size_change)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand()
        else:
            logger.info("No updates")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export hosts from mreg as a ldif.")
    parser.add_argument("--config",
                        default="hosts-ldif.conf",
                        help="path to config file (default: %(default)s)")
    parser.add_argument('--force-check',
                        action='store_true',
                        help='force refresh of data from mreg')
    parser.add_argument('--ignore-size-change',
                        action='store_true',
                        help='ignore size changes')
    parser.add_argument('--use-saved-data',
                        action='store_true',
                        help='force use saved data from previous runs. --force-check')
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read(args.config)

    for i in ('default', 'mreg', 'ldif'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    if 'filename' not in cfg['default']:
        error("Missing 'filename' in default section in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    hosts_ldif(args)


if __name__ == '__main__':
    main()
