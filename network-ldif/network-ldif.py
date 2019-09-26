import argparse
import configparser
import datetime
import io
import ipaddress
import logging
import os
import re
import sys

import fasteners

import requests


sys.path.append('..')
import common.connection
import common.utils

from common.utils import error
from common.LDIFutils import entry_string, make_head_entry


def setup_logging():
    if cfg['default']['logdir']:
        logdir = cfg['default']['logdir']
    else:
        logging.error("No logdir defined in config file")
        sys.exit(1)

    common.utils.mkdir(logdir)
    filename = datetime.datetime.now().strftime('%Y-%m-%d.log')
    filepath = os.path.join(logdir, filename)
    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=filepath,
                    level=logging.INFO)
    return logging.getLogger(__name__)


def create_ldif(networks):
    def write_file(filename):
        common.utils.write_file(cfg, filename, f)

    f = io.StringIO()
    dn = cfg['ldif']['dn']
    head_entry = make_head_entry(cfg)
    f.write(entry_string(head_entry))
    f.write('\n')
    for network, i in networks.items():
        cn = i['network']
        entry = {
            'dn': f'{cn},{dn}',
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
    write_file('networks.ldif')


@common.utils.timing
def get_networks(url, ipv6=False):
    ret = conn.get_list(url + '?page_size=1000')
    networks = {}
    for i in ret:
        network = ipaddress.ip_network(i['network'])
        if not ipv6 and network.version == 6:
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
        if common.utils.updated_entries(cfg, conn, url, 'networks.json') or args.force:
            networks = get_networks(url, cfg['mreg']['ipv6networks'])
            create_ldif(networks)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand(cfg)
            lock.release()
        else:
            logger.info("No updated networks")
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export network from mreg as a ldif.")
    parser.add_argument("--config",
                        default="network-ldif.conf",
                        help="path to config file (default: %(default)s)")
    parser.add_argument('--force',
                        action='store_true',
                        help='force update')
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read(args.config)

    for i in ('default', 'mreg', 'ldif'):
        if i not in cfg:
            error(logger, f"Missing section {i} in config file", os.EX_CONFIG)

    logger = setup_logging()
    conn = common.connection.Connection(cfg['mreg'])
    url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/networks/')
    network_ldif(args, url)


if __name__ == '__main__':
    main()
