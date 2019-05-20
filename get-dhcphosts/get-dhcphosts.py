import argparse
import configparser
import datetime
import ipaddress
import logging
import os
import shutil
import sys
import tempfile

import fasteners
import requests

from collections import defaultdict
from os.path import join as opj

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


def create_files(dhcphosts, onefile):
    def write_file():
        if onefile:
            filename = "hosts.conf"
            mode = "a"
        else:
            filename = domain
            mode = "w"
        dstfile = opj(cfg['default']['destdir'], filename)
        # XXX: add difflib or ignore
        # xxx: fix rename hosts.conf to hosts.conf_old before done...
        if os.path.isfile(dstfile):
            os.rename(dstfile, f"{dstfile}_old")
        with open(dstfile, mode) as dest:
            f.seek(0)
            shutil.copyfileobj(f, dest)
        os.chmod(dstfile, 0o400)

    for domain, hosts in dhcphosts.items():
        with tempfile.TemporaryFile(mode='w+', dir=cfg['default']['workdir']) as f:
            f.write("group { \n")
            f.write(f"    option domain-name \"{domain}\";\n")
            for hostname, mac, ip in hosts:
                info = """
    host {} {{ hardware ethernet {}; fixed-address {}; }}
""".format(hostname, mac, ip)
                f.write(info)
            f.write("}\n")
            write_file()


@common.utils.timing
def get_dhcphosts():
    url = requests.compat.urljoin(cfg["mreg"]["url"], "/dhcphosts/")
    hosts = cfg["mreg"]["hosts"]
    if hosts == "ipv4":
        param = "v4/all"
    elif hosts == "ipv6":
        param = "v6/all"
    else:
        param = hosts
    url = requests.compat.urljoin(url, param)
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


def dhcphosts(onefile):
    for dir in ('destdir', 'workdir',):
        mkdir(cfg['default'][dir])

    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        dhcphosts = get_dhcphosts()
        create_files(dhcphosts, onefile)
        lock.release()
    else:
        logging.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn
    parser = argparse.ArgumentParser(description="Create dhcp config from mreg.")
    parser.add_argument("--config",
                        default="get-dhcphosts.conf",
                        help="path to config file (default: get-dhcphosts.conf)")
    parser.add_argument("--one-file",
                        action="store_true",
                        help="Write all hosts to one file, instead of per domain")
    # ipv6 -> mac if host have ipv6. 
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    for i in ('default', 'mreg'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    if 'hosts' in cfg['mreg']:
        hosts = cfg['mreg']['hosts']
        if hosts not in ('ipv4', 'ipv6'):
            try:
                ipaddress.ip_network(hosts)
            except ValueError:
                error("'hosts' must be one of 'ipv4', 'ipv6', 'ip/mask'")
    else:
        error("Missing 'hosts' in mreg section of config")

    setup_logging()
    conn = common.connection.Connection(cfg['mreg'])
    dhcphosts(args.one_file)


if __name__ == '__main__':
    main()
