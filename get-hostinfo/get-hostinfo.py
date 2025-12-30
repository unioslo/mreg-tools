import argparse
import configparser
import io
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


def write_file(filename, f):
    filename = os.path.join(cfg['default']['destdir'], filename)
    common.utils.write_file(filename, f)


def create_hosts(host_data):
    hosts = io.StringIO()

    for host in host_data:
        # Handle new/old contact fields. 
        # We don't know which version we are running against.
        if contacts := host.get("contacts"):
            emails = " ".join(c.get("email", "") for c in contacts)
        else:
            emails = host.get("contact") or ""
        # TODO: Host comment could be usefull, but will need escaping
        hosts.write("{};{}\n".format(host['name'], emails))

    write_file("hosts.csv", hosts)


@common.utils.timing
def get_hosts(url):
    return conn.get_list(url + '?page_size=1000')


@common.utils.timing
def dump_hostinfo(force):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    hosts_url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/hosts/')

    lockfile = os.path.join(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        updated = False
        if common.utils.updated_entries(conn, hosts_url, 'hosts.json') or force:
            hosts = get_hosts(hosts_url)
            create_hosts(hosts)
            updated = True

        if updated and 'postcommand' in cfg['default']:
            common.utils.run_postcommand()
        else:
            logger.info("No updated hosts")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export host info from mreg as a textfiles.")
    parser.add_argument("--config",
                        default="get-hostinfo.conf",
                        help="path to config file (default: %(default)s)")
    parser.add_argument('--force',
                        action='store_true',
                        help='force update')
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read(args.config)

    for i in ('default', 'mreg',):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    dump_hostinfo(args.force)


if __name__ == '__main__':
    main()
