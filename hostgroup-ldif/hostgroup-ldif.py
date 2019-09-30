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


def create_ldif(hostgroups):
    def write_file(filename):
        common.utils.write_file(filename, f)

    f = io.StringIO()
    if cfg['mreg'].getboolean('make_make_head'):
        head_entry = make_head_entry(cfg)
        f.write(entry_string(head_entry))
        f.write('\n')
    for entry in create_hostgroupsentries(hostgroups):
        f.write(entry_string(entry))
        f.write('\n')
    write_file('hostgroups.ldif')


def create_hostgroupsentries(hostgroups):
    ret = []
    remove_domain = cfg['mreg'].get('domain', None)
    if remove_domain:
        remove_len = len(remove_domain) + 1
    dn = cfg['ldif']['dn']
    encoding = cfg['default'].get('fileencoding', '')

    for i in hostgroups:
        cn = i['name']
        desc = i['description'] or None
        if encoding == 'ascii':
            desc = common.LDIFutils.to_iso646_60(desc)

        entry = {
            'dn': f'cn={cn},{dn}',
            'cn': cn,
            'description': desc,
            'objectClass': ('top', 'nisNetgroup'),
            }
        if i['groups']:
            entry['memberNisNetgroup'] = [g['name'] for g in i['groups']]
        if i['hosts']:
            triple = []
            for host in i['hosts']:
                hostname = host['name']
                if remove_domain and hostname.endswith(remove_domain):
                    short = hostname[:-remove_len]
                    triple.append(f'({short},-,)')
                triple.append(f'({hostname},-,)')
            entry['nisNetgroupTriple'] = triple
        ret.append(entry)

    return ret


@common.utils.timing
def get_hostgroups(url):
    return conn.get_list(url + '?page_size=1000')


@common.utils.timing
def hostgroup_ldif(args, url):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    lockfile = os.path.join(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        if common.utils.updated_entries(conn, url, 'hostgroups.json') or args.force:
            hostgroups = get_hostgroups(url)
            create_ldif(hostgroups)
            if 'postcommand' in cfg['default']:
                common.utils.run_postcommand()
        else:
            logger.info("No updated hostgroups")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export hostgroups from mreg as a ldif.")
    parser.add_argument("--config",
                        default="hostgroup-ldif.conf",
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

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'])
    url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/hostgroups/')
    hostgroup_ldif(args, url)


if __name__ == '__main__':
    main()
