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
from common.LDIFutils import entry_string, make_head_entry


def create_ldif(hosts, ignore_size_change):
    f = io.StringIO()
    dn = cfg['ldif']['dn']
    head_entry = make_head_entry(cfg)
    f.write(entry_string(head_entry))
    for i in hosts:
        hostname = i['name']
        entry = {
            'dn': f'host={hostname},{dn}',
            'host': hostname,
            'objectClass': 'uioHostinfo',
            'uioHostComment':  i['comment'],
            'uioHostContact':  i['contact'],
            }
        mac = {ip['macaddress'] for ip in i['ipaddresses'] if ip['macaddress']}
        if mac:
            entry['uioHostMacAddr'] = sorted(mac)
        f.write(entry_string(entry))
        for cinfo in i['cnames']:
            cname = cinfo['name']
            entry['dn'] = f'host={cname},{dn}'
            entry['host'] = cname
            f.write(entry_string(entry))
    try:
        common.utils.write_file(cfg['default']['filename'], f,
                                ignore_size_change=ignore_size_change)
    except common.utils.TooManyLineChanges as e:
        error(e.message)


@common.utils.timing
def get_hosts(url):
    if '?' in url:
        url += '&'
    else:
        url += '?'
    url += 'page_size=1000&ordering=name'
    return conn.get_list(url)


@common.utils.timing
def hosts_ldif(args, url):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    if cfg.has_option('mreg', 'zone'):
        zones = cfg['mreg']['zone']
        url += f"?zone__name__in={zones}"

    lockfile = os.path.join(cfg['default']['workdir'], __file__ + 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        if common.utils.updated_entries(conn, url, 'hosts.json') or args.force_check:
            hosts = get_hosts(url)
            create_ldif(hosts, args.ignore_size_change)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand()
        else:
            logger.info("No updated hosts")
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
        error(f"Missing 'filename' in default section in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/hosts/')
    hosts_ldif(args, url)


if __name__ == '__main__':
    main()
