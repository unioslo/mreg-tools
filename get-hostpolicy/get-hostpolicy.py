import argparse
import configparser
import io
import os
import pathlib
import sys

from collections import defaultdict

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


def create_atoms(atoms):
    f = io.StringIO()
    for atom in atoms:
        f.write('{};{};;{}\n'.format(atom['name'], atom['description'], atom['create_date']))
    write_file("atoms.csv", f)


def create_roles(role_data):
    relationships = io.StringIO()
    roles = io.StringIO()
    hostpolicies = io.StringIO()

    host2roles = defaultdict(list)

    for role in role_data:
        role_name = role['name']
        atoms = [i['name'] for i in role['atoms']]
        for host in role["hosts"]:
            host2roles[host["name"] + "."].append(role_name)

        for atom in atoms:
            relationships.write(f"{role_name};hostpol_contains;{atom}\n")
        roles.write("{};{};;{};{}\n".format(role_name, role['description'],
                                            role['create_date'], ','.join(atoms)))

    for host in sorted(host2roles):
        host_roles = host2roles[host]
        hostpolicies.write("{};{}\n".format(host, ",".join(host_roles)))

    write_file("hostpolicies.csv", hostpolicies)
    write_file("relationships.csv", relationships)
    write_file("roles.csv", roles)


@common.utils.timing
def get_atoms(url):
    return conn.get_list(url + '?page_size=1000')


@common.utils.timing
def get_roles(url):
    return conn.get_list(url + '?page_size=1000')


@common.utils.timing
def dump_hostpolicies(force):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    atoms_url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/hostpolicy/atoms/')
    roles_url = requests.compat.urljoin(cfg["mreg"]["url"], '/api/v1/hostpolicy/roles/')

    lockfile = os.path.join(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        updated = False
        if common.utils.updated_entries(conn, atoms_url, 'atoms.json') or force:
            atoms = get_atoms(atoms_url)
            create_atoms(atoms)
            updated = True
        if common.utils.updated_entries(conn, roles_url, 'roles.json') or force:
            roles = get_roles(roles_url)
            create_roles(roles)
            updated = True

        if updated and 'postcommand' in cfg['default']:
            common.utils.run_postcommand()
        else:
            logger.info("No updated atoms or roles")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
    parser = argparse.ArgumentParser(description="Export hostpolicies from mreg as a textfiles.")
    parser.add_argument("--config",
                        default="get-hostpolicy.conf",
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
    dump_hostpolicies(args.force)


if __name__ == '__main__':
    main()
