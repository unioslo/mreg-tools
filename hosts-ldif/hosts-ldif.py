import argparse
import configparser
import io
import ipaddress
import pickle
import os
import pathlib
import sys

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
            with open(filename, 'rb') as f:
                objects = pickle.load(f)
        return objects

    @common.utils.timing
    def get_entries(self, force=True):
        for name, endpoint in self.sources.items():
            url = self._url(endpoint)
            _updated = getattr(self, f"_updated_{name}") or force
            objects = self._get_entries(url, name, update=_updated)
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
                if 'uioVlanID' not in entry:
                    entry['uioVlanID'] = set()
                entry['uioVlanID'].add(ip2vlan[ipaddr])

        # Add the host's community
        communities = i["communities"]
        if communities:
            # NOTE: use only first community per host (FOR NOW!)
            com = communities[0]["community"]
            com_name = com["global_name"] or com["name"]
        else:
            com_name = "default"
        entry["uioHostNetworkPolicy"] = com_name

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

        if ldifdata.updated or args.force_check:
            ldifdata.get_entries(force=args.force_check)
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
