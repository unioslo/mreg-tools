import argparse
import configparser
import io
import ipaddress
import os
import pathlib
import sys

import fasteners

import requests

parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection
import common.utils

from common.utils import error
from common.LDIFutils import entry_string, make_head_entry


def create_ldif(networks, ignore_size_change):
    f = io.StringIO()
    dn = cfg['ldif']['dn']
    head_entry = make_head_entry(cfg)
    f.write(entry_string(head_entry))
    f.write('\n')
    for network, i in networks.items():
        cn = i['network']
        entry = {
            'dn': f'cn={cn},{dn}',
            'cn': cn,
            'objectClass': ('top', 'ipNetwork', 'uioIpNetwork'),
            'description': i['description'],
            'ipNetworkNumber': str(network.network_address),
            'ipNetmaskNumber': str(network.netmask),
            'uioIpAddressRangeStart': int(network.network_address),
            'uioIpAddressRangeEnd': int(network.broadcast_address),
            }
        if i['vlan'] is not None:
            entry['uioVlanID'] = i['vlan']
        f.write(entry_string(entry))
        f.write('\n')
    try:
        common.utils.write_file(cfg['default']['filename'], f,
                                ignore_size_change=ignore_size_change)
    except common.utils.TooManyLineChanges as e:
        error(e.message)


@common.utils.timing
def get_networks(url, skipipv6):
    ret = conn.get_list(url + '?page_size=1000')
    networks = {}
    for i in ret:
        network = ipaddress.ip_network(i['network'])
        if not skipipv6 and network.version == 6:
            continue
        networks[network] = i
    return networks


@common.utils.timing
def network_ldif(args, url):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    lockfile = os.path.join(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        if common.utils.updated_entries(conn, url, 'networks.json') or args.force_check:
            networks = get_networks(url, cfg['mreg'].getboolean('ipv6networks'))
            create_ldif(networks, args.ignore_size_change)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand()
        else:
            logger.info("No updated networks")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export network from mreg as a ldif.")
    parser.add_argument("--config",
                        default="network-ldif.conf",
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
            error(logger, f"Missing section {i} in config file", os.EX_CONFIG)

    if not cfg['default']['filename']:
        error(logger, f"Missing 'filename' in default section in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/networks/')
    network_ldif(args, url)


if __name__ == '__main__':
    main()
