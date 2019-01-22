import argparse
import configparser
import datetime
import ipaddress
import json
import logging
import os
import re
import sys

from collections import defaultdict

import requests

from intervaltree import IntervalTree

# TODO: shrink networks: net A -> net B [ C & D ]
# TODO: shrink/sletting: - hvis host kun en adresse. NUKE!
#                 - hvis host har flere adresser. Fjern adressen og alt er vel.
#                 - husk PTR!!!!!

session = requests.Session()
basepath = "/subnets/"

current_subnets = {}
import_v4 = {}
import_v6 = {}
location_tags = set()
category_tags = set()


def error(message):
    print("ERROR: " + message, file=sys.stderr)
    logging.error(message)
    sys.exit(1)


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
    filepath = os.path.join(logdir, filename)
    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=filepath,
                    level=logging.INFO)


def update_token():
    tokenurl = cfg['mreg']['url'] + "api/token-auth/"
    if 'user' not in cfg['mreg']:
        error("Need username in configfile")
    elif 'password' not in cfg['mreg']:
        error("Need password in configfile")
    user = cfg['mreg']['user']
    password = cfg['mreg']['password']
    result = requests.post(tokenurl, {'username': user, 'password': password})
    result_check(result, "post", tokenurl)
    token = result.json()['token']
    session.headers.update({"Authorization": f"Token {token}"})


def result_check(result, type, url):
    if not result.ok:
        message = f"{type} \"{url}\": {result.status_code}: {result.reason}"
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        error(message)


def _request_wrapper(type, path, data=None, first=True):
    url = requests.compat.urljoin(cfg['mreg']['url'], path)
    result = getattr(session, type)(url, data=data)

    if first and result.status_code == 401:
        update_token()
        return _request_wrapper(type, path, data=data)
    else:
        result_check(result, type.upper(), url)

    return result


def get(path: str) -> requests.Response:
    """Uses requests to make a get request."""
    return _request_wrapper("get", path)


def post(path: str, **kwargs) -> requests.Response:
    """Uses requests to make a post request. Assumes that all kwargs are data fields"""
    return _request_wrapper("post", path, data=kwargs)


def patch(path: str, **kwargs) -> requests.Response:
    """Uses requests to make a patch request. Assumes that all kwargs are data fields"""
    return _request_wrapper("patch", path, data=kwargs)


def delete(path: str) -> requests.Response:
    """Uses requests to make a delete request."""
    return _request_wrapper("delete", path)


def read_tags(filename):
    with open(filename, 'r') as tagfile:
        flag_re = re.compile("""^
                             ((?P<location>[a-zA-Z0-9]+)+\s+:\s+Plassering)
                             |(?P<category>[a-zA-Z0-9]+)
                             """, re.X)
        for line_number, line in enumerate(tagfile, 1):
            line = line.strip()
            if line.startswith("#"):
                continue

            res = flag_re.match(line)
            if res.group('location'):
                location_tags.add(res.group('location'))
            elif res.group('category'):
                category_tags.add(res.group('category'))
            else:
                error('In {}, wrong format on line: {} - {}'.format(
                    filename, line_number, line))


def overlap_check(network, tree, points):
    # Uses an IntervalTree to do fast lookups of overlapping networks.
    #
    # For one-host networks, as ipv4 /32 and ipv6 /128, IntervalTree causes a
    # bit extra work as it does not include upper bound in intervals when
    # searching, thus point search failes for a broadcast address.

    begin = int(network.network_address)
    end = int(network.broadcast_address)
    if tree[begin:end]:
        overlap = tree[begin:end]
        data = [str(i.data) for i in overlap]
        error(f"Network {network} overlaps {data}")
    elif network.version == 4 and network.prefixlen == 32 or \
         network.version == 6 and network.prefixlen == 128:
        if begin in points:
            error(f"Network {network} already in file")
        elif tree.overlaps(begin):
            error(f"Network {network} overlaps {tree[begin].pop().data}")
        elif tree.overlaps(begin-1):
            error(f"Network {network} overlaps {tree[begin-1].pop().data}")
        else:
            points.add(begin)
    else:
        tree[begin:end] = network


def read_subnets(filename):
    tree = IntervalTree()
    points = set()

    # Read in new subnet structure from file
    subnet_re = re.compile(r"""^
                            (?P<network>[\da-fA-F\.:]+/\d+) \s+
                            (novlan|vlan(?P<vlan>\d+)) \s+
                            (:(?P<tags>.*):\|)?                 # optional tags
                            (?P<description>.*)
                            """, re.X)
    with open(filename, 'r', encoding="latin-1") as subnetfile:
        for line_number, line in enumerate(subnetfile, 1):
            line = line.strip()
            if line.startswith("#"):
                continue
            res = subnet_re.match(line)
            if res:
                network_str = res.group('network').lower()
                try:
                    network = ipaddress.ip_network(network_str)
                except ValueError as e:
                    error(f"linenumber {line_number}, network is invalid: {e}")
                overlap_check(network, tree, points)
                vlan = res.group('vlan')
                if vlan:
                    vlan = int(vlan)
                desc = res.group('description')
                if not desc:
                    error(f"{line_number}: Missing description.")
                category = location = ''
                tags = res.group('tags')
                if tags:
                    for tag in tags.split(':'):
                        if tag in location_tags:
                            location = tag
                        elif tag in category_tags:
                            category += f" {tag}"
                        else:
                            logging.warning(
                                "{}: Invalid tag {}. Check valid in tags file.".format(
                                    line_number, tag))
                data = {
                    'range': network_str,
                    'description': desc.strip(),
                    'vlan': vlan,
                    'category': category.strip(),
                    'location': location
                }
                if network.version == 4:
                    import_v4[network_str] = data
                elif network.version == 6:
                    import_v6[network_str] = data
            else:
                error(f"{line_number}: Could not match string: {line}")


def compare_with_mreg(ipversion, import_data, current_subnets):

    print(f"ipv{ipversion}, len(import_data) {len(import_data)}, len(current_subnets) {len(current_subnets)}")  

    subnets_delete = current_subnets.keys() - import_data.keys()
    subnets_post = import_data.keys() - current_subnets.keys()
    print(f"subnets_delete: {len(subnets_delete)} {subnets_delete}")
    print(f"subnets_post: {len(subnets_post)} {subnets_post}")

    subnets_grow = defaultdict(set)
    subnets_shrink = defaultdict(set)

    # Check if a subnet destined for removal is actually just resized
    for existing in subnets_delete:
        existing_net = ipaddress.ip_network(existing)
        for new in subnets_post:
            new_net = ipaddress.ip_network(new)
            if existing_net.subnet_of(new_net):
                subnets_grow[new].add(existing)
            elif existing_net.supernet_of(new_net):
                subnets_shrink[existing].add(new)

    for newnet, oldnets in subnets_grow.items():
        subnets_delete -= oldnets
        subnets_post.remove(newnet)

    for k, v in subnets_shrink.items():
        error(f"Should shrink: {k} -> {v}, but not supported yet")

    print(f"subnets_grow: {len(subnets_grow)} {subnets_grow}")
    print(f"subnets_shrink: {len(subnets_shrink)}  {subnets_shrink}")
    print(f"subnets_delete: {len(subnets_delete)} {subnets_delete}")
    print(f"subnets_post: {len(subnets_post)} {subnets_post}")
    subnets_patch = defaultdict(dict)
    subnets_keep = import_data.keys() & current_subnets.keys()
    print(f"subnets_keep: {len(subnets_keep)}")

    # Check if subnets marked for deletion have any addresses in use
    for subnet in subnets_delete:
        used_list = get(f"{basepath}{subnet}?used_list").json()
        if used_list:
            error(
                "{} contains addresses that are in use. Remove hosts before deletion".format(
                    subnet))

    # Check if subnets marked for creation have any overlap with existing subnets
    # XXX: can this test ever pass? We also check this serverside.
    for subnet_new in subnets_post:
        subnet_object = ipaddress.ip_network(subnet_new)
        for subnet_existing in subnets_keep:
            if subnet_object.overlaps(ipaddress.ip_network(subnet_existing)):
                error(
                    f"Overlap found between new subnet {subnet_new} "
                    f"and existing subnet {subnet_existing}")

    # Check which existing subnets need to be patched
    for subnet in subnets_keep:
        current_data = current_subnets[subnet]
        new_data = import_data[subnet]
        for i in ('description', 'vlan', 'category', 'location'):
            if new_data[i] != current_data[i]:
                subnets_patch[subnet][i] = new_data[i]

    print(f"current_subnets = {len(current_subnets)}")

    return subnets_post, subnets_patch, subnets_delete, subnets_grow


def update_mreg(ipversion, num_current, import_data, subnets_post, subnets_patch, subnets_delete, subnets_grow, args):
    print(f"ipv{ipversion} num_current {num_current}")

    if len(subnets_delete) + len(subnets_patch) != 0:
        assert num_current > 0
        diffsize = sum(map(len, (subnets_delete, subnets_patch, subnets_grow))) / num_current
        diffsize *= 100
        if diffsize > args.max_size_change and not args.force_size_change:
            error(f"The import will change {diffsize:.0f}% of the subnets. "
                  f"Limit is {args.max_size_change}%. Requires force.")
        else:
            logging.info(f"Changing {diffsize:.0f}% of the subnets.")

    logging.info("------ API REQUESTS START ------")

    for newnet, oldnets in subnets_grow.items():
        # If the new network replaces multiple old ones, then first
        # patch the range to a not-in-use range and then delete. To
        # work around delete restrictions.
        replace = oldnets.pop()
        for oldnet in oldnets:
            if not args.dryrun:
                dummyrange = '255.255.255.0/32'
                path = f"{basepath}{oldnet}"
                patch(path, range=dummyrange)
                path = f"{basepath}{dummyrange}"
                delete(path)
            logging.info(f"REMOVED {oldnet} to make room for {newnet}")
        if not args.dryrun:
            patch(f"{basepath}{replace}", **import_data[newnet])
        logging.info(f"GREW {replace} to {newnet}")


    for subnet in subnets_delete:
        path = f"{basepath}{subnet}"
        delete(path)
        logging.info(f"DELETE {path}")

    for subnet in subnets_post:
        data = import_data[subnet]
        if not args.dryrun:
            post(basepath, range=data['range'],
                 description=data['description'],
                 vlan=data['vlan'],
                 category=data['category'],
                 location=data['location'])
        logging.info(f"POST {basepath} - {subnet} - {data['description']}")

    for subnet, data in subnets_patch.items():
        path = f"{basepath}{subnet}"
        if not args.dryrun:
            patch(path, **data)
        logging.info(f"PATCH {path} {data}")

    logging.info("------ API REQUESTS END ------")

def sync_with_mreg(args):
    read_tags(cfg['default']['tagsfile'])
    read_subnets(args.subnetfile)
    current_subnets = defaultdict(dict)
    res = get(basepath).json()
    for i in res:
        network = ipaddress.ip_network(i['range'])
        current_subnets[network.version][i['range']] = i
    for ipversion, import_data in ((4, import_v4), (6, import_v6)):
        post, patch, delete, grow = compare_with_mreg(ipversion, import_data, current_subnets[ipversion])
        if post or patch or delete or grow:
            update_mreg(ipversion, len(import_data), import_data, post, patch, delete, grow, args)


def main():
    global cfg
    parser = argparse.ArgumentParser()
    parser.add_argument("subnetfile",
                        help="File with all subnets")
    parser.add_argument('--config',
                        default='network-import.conf',
                        help='path to config file (default: network-import.conf)')
    parser.add_argument("--dryrun",
                        help="Dryrun",
                        action="store_true")
    parser.add_argument("--force-size-change",
                        help="Allow more than MAX_SIZE_CHANGE changes",
                        action="store_true")
    parser.add_argument("--max-size-change",
                        help="Max changes (change and delete) in percent",
                        type=int,
                        default=20)
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    setup_logging()
    sync_with_mreg(args)


main()
