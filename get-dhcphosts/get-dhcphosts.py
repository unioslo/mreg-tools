import argparse
import configparser
import io
import ipaddress
import os
import pathlib
import sys
from collections import defaultdict
from os.path import join as opj

import fasteners

import requests


parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection
import common.utils

from common.utils import error


def create_files(dhcphosts, onefile):
    def write_file(filename):
        # 5 lines is a group with domain and a single host.
        common.utils.ABSOLUTE_MIN_SIZE = 5
        common.utils.write_file(filename, f)

    f = io.StringIO()
    # Sort domain by tld, domain [,subdomain, [subdomain..]]
    for domain in sorted(list(dhcphosts.keys()), key=lambda i: list(reversed(i.split('.')))):
        hosts = dhcphosts[domain]
        f.write("group { \n")
        f.write(f"    option domain-name \"{domain}\";\n\n")
        for hostname, mac, ip in hosts:
            # Crude and cheap test to check for ipv6
            if ':' in ip:
                fixed = 'fixed-address6'
            else:
                fixed = 'fixed-address'
            info = f"    host {hostname} {{ hardware ethernet {mac}; {fixed} {ip}; }}\n"
            f.write(info)
        f.write("}\n")

        if not onefile:
            write_file(domain)
            f = io.StringIO()
    if onefile:
        write_file(cfg['default'].get('filename', 'hosts.conf'))


def create_url():
    path = '/api/v1/dhcphosts/'
    if 'hosts' in cfg['mreg']:
        hosts = cfg['mreg']['hosts']
        if hosts not in ('ipv4', 'ipv6', 'ipv6byipv4'):
            error("'hosts' must be one of 'ipv4', 'ipv6', 'ipv6byipv4'")
        path += f'{hosts}/'
    else:
        error("Missing 'hosts' in mreg section of config")
    if 'range' in cfg['mreg']:
        try:
            ipaddress.ip_network(cfg['mreg']['range'])
        except ValueError as e:
            error(f'Invalid range in config: {e}')
        path += cfg['mreg']['range']

    return requests.compat.urljoin(cfg["mreg"]["url"], path)


@common.utils.timing
def get_dhcphosts(url):
    ret = conn.get(url).json()
    dhcphosts = defaultdict(list)
    done = set()
    # Make sure we only use hostname as a key once, as ISC dhcpd
    # requires that the identifier in "host identifier { foo; }"
    # is unique. For hosts with multiple IPs append the MAC without
    # colons to make it unique.
    for i in ret:
        hostname = i["host__name"]
        if i['host__zone__name'] is not None:
            domain = i['host__zone__name']
        else:
            if hostname.count('.') > 1:
                domain = hostname.split(".", 1)[1]
            else:
                domain = hostname
        if hostname in done:
            hostname = "{}-{}".format(hostname, i['macaddress'].replace(":", ""))
        else:
            done.add(hostname)
        dhcphosts[domain].append((hostname, i['macaddress'], i['ipaddress']))
    return dhcphosts


def dhcphosts(args):
    for dir in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][dir])

    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        entries_url = requests.compat.urljoin(cfg['mreg']['url'], '/api/v1/ipaddresses/')
        obj_filter = 'macaddress__gt=""&page_size=1&ordering=-updated_at'
        if common.utils.updated_entries(conn, entries_url, 'dhcp.json',
                                        obj_filter=obj_filter) or args.force:
            dhcphosts = get_dhcphosts(create_url())
            create_files(dhcphosts, args.one_file)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand()
        else:
            logger.info("No updated dhcp entries")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Create dhcp config from mreg.")
    parser.add_argument("--config",
                        default="get-dhcphosts.conf",
                        help="path to config file (default: get-dhcphosts.conf)")
    parser.add_argument("--one-file",
                        action="store_true",
                        help="Write all hosts to one file, instead of per domain")
    parser.add_argument('--force',
                        action='store_true',
                        help='force update')
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    for i in ('default', 'mreg'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    dhcphosts(args)


if __name__ == '__main__':
    main()
