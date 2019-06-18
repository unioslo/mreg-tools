import argparse
import configparser
import datetime
import io
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from os.path import join as opj

import fasteners

# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

import requests


sys.path.append('..')
import common.connection
import common.utils


def error(msg, code=os.EX_UNAVAILABLE):
    logging.error(msg)
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except PermissionError as e:
        error(f"{e}", code=e.errno)


def setup_logging():
    if cfg['default']['logdir']:
        logdir = cfg['default']['logdir']
    else:
        error("No logdir defined in config file")

    mkdir(logdir)
    filename = datetime.datetime.now().strftime('%Y-%m-%d.log')
    filepath = opj(logdir, filename)
    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=filepath,
                    level=logging.INFO)
    return logging.getLogger(__name__)


def create_files(dhcphosts, onefile):
    def write_file(filename):
        dstfile = opj(cfg['default']['destdir'], filename)
        # XXX: add difflib or ignore
        if os.path.isfile(dstfile):
            os.rename(dstfile, f"{dstfile}_old")
        with open(dstfile, 'w') as dest:
            f.seek(0)
            shutil.copyfileobj(f, dest)
        os.chmod(dstfile, 0o400)

    f = io.StringIO()
    # Sort domain by tld, domain [,subdomain, [subdomain..]]
    for domain in sorted(list(dhcphosts.keys()), key=lambda i: list(reversed(i.split('.')))):
        hosts = dhcphosts[domain]
        f.write("group { \n")
        f.write(f"    option domain-name \"{domain}\";\n")
        for hostname, mac, ip in hosts:
            info = f"""
    host {hostname} {{ hardware ethernet {mac}; fixed-address {ip}; }}
"""
            f.write(info)
        f.write("}\n")

        if not onefile:
            write_file(domain)
            f = io.StringIO()
    if onefile:
        write_file('hosts.conf')


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
def updated_dhcp_entries() -> bool:
    """Check if the most recently updated ipaddress is the same as
       from the previous run."""

    def get_old_ipaddress():
        filename = opj(cfg['default']['workdir'], "oldip.json")
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, EOFError):
            logging.warning(f"Could read data from {filename}")
            return None

    def write_old_ipaddress(info):
        filename = opj(cfg['default']['workdir'], "oldip.json")
        try:
            with open(filename, 'w') as f:
                return json.dump(info, f)
        except PermissionError:
            error(f"No permission to write to {filename}")

    old_ipaddress = get_old_ipaddress()
    path = '/api/v1/ipaddresses/?macaddress__gt=""&page_size=1&ordering=updated_at'
    url = requests.compat.urljoin(cfg["mreg"]["url"], path)
    new_ipaddress = conn.get(url).json()
    if old_ipaddress is not None:
        old_updated_at = parse_date(old_ipaddress['results'][0]['updated_at'])
        new_updated_at = parse_date(new_ipaddress['results'][0]['updated_at'])
        if old_ipaddress['count'] != new_ipaddress['count'] or \
           old_ipaddress['results'][0]['id'] != new_ipaddress['results'][0]['id'] or \
           old_updated_at < new_updated_at:
            write_old_ipaddress(new_ipaddress)
            return True
        return False
    write_old_ipaddress(new_ipaddress)
    return True


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


def dhcphosts(args, url):
    for dir in ('destdir', 'workdir',):
        mkdir(cfg['default'][dir])

    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        if updated_dhcp_entries():
            dhcphosts = get_dhcphosts(url)
            create_files(dhcphosts, args.one_file)
            if 'postcommand' in cfg['default']:
                run_postcommand()
            lock.release()
        else:
            logger.info("No updated dhcp entries")
    else:
        logger.warning(f"Could not lock on {lockfile}")


@common.utils.timing
def run_postcommand():
    command = json.loads(cfg['default']['postcommand'])
    subprocess.run(command)


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Create dhcp config from mreg.")
    parser.add_argument("--config",
                        default="get-dhcphosts.conf",
                        help="path to config file (default: get-dhcphosts.conf)")
    parser.add_argument("--one-file",
                        action="store_true",
                        help="Write all hosts to one file, instead of per domain")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    for i in ('default', 'mreg'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    logger = setup_logging()
    conn = common.connection.Connection(cfg['mreg'])
    url = create_url()
    dhcphosts(args, url)


if __name__ == '__main__':
    main()
