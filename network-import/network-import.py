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
from operator import itemgetter

import requests

from intervaltree import IntervalTree

session = requests.Session()
basepath = "/networks/"

mreg_data = {}
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


def networksort(networks):
    return sorted(networks, key=lambda i: ipaddress.ip_network(i))


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
    tokenurl = requests.compat.urljoin(cfg['mreg']['url'], "/api/token-auth/")
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
    headers = {'content-type': 'application/json'}
    url = requests.compat.urljoin(cfg['mreg']['url'], path)
    jsondata = json.dumps(data)
    result = getattr(session, type)(url, data=jsondata, headers=headers)

    if first and result.status_code == 401:
        update_token()
        return _request_wrapper(type, path, data=data, first=False)

    result_check(result, type.upper(), url)
    return result


def get(path: str) -> requests.Response:
    """Uses requests to make a get request."""
    return _request_wrapper("get", path)


def post(path: str, data) -> requests.Response:
    """Uses requests to make a post request. Assumes that all kwargs are data fields"""
    return _request_wrapper("post", path, data)


def patch(path: str, data) -> requests.Response:
    """Uses requests to make a patch request. Assumes that all kwargs are data fields"""
    return _request_wrapper("patch", path, data)


def delete(path: str) -> requests.Response:
    """Uses requests to make a delete request."""
    return _request_wrapper("delete", path)


def read_tags():
    if 'tagsfile' in cfg['default']:
        filename = cfg['default']['tagsfile']
    else:
        return
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
    begin = int(network.network_address)
    end = int(network.broadcast_address)
    if tree[begin:end]:
        overlap = tree[begin:end]
        data = [str(i.data) for i in overlap]
        error(f"Network {network} overlaps {data}")
        # For one-host networks, as ipv4 /32 and ipv6 /128, IntervalTree causes
        # a bit extra work as it does not include upper bound in intervals when
        # searching, thus point search failes for a broadcast address. Also one
        # can not add a interval with begin == end, so keep track of one-host
        # networks in a seperate "points" set.
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


def removable(oldnet, newnets=[]):
    # An empty networks is obviously removable
    if empty_network(oldnet):
        return {}, {}, {}

    def ips_not_in_newnets(ips):
        res = []
        for ip in ips:
            ipaddr = ipaddress.ip_address(ip)
            for net in newnets:
                if ipaddr in net:
                    break
            else:
                res.append(ip)
        return res

    newnets = [ipaddress.ip_network(i) for i in newnets]
    ptr_list = get(f"{basepath}{oldnet}/ptroverride_list").json()
    used_list = get(f"{basepath}{oldnet}/used_list").json()
    ptrs = ips_not_in_newnets(ptr_list)
    ips = ips_not_in_newnets(used_list)

    problem_hosts = dict()
    for ptr in ptrs:
        host = get(f"/hosts/?ptr_overrides__ipaddress={ptr}").json()
        assert len(host) == 1
        problem_hosts[host[0]['name']] = host[0]

    for ip in ips:
        hosts = get(f"/hosts/?ipaddresses__ipaddress={ip}").json()
        for host in hosts:
            problem_hosts[host['name']] = host

    not_delete = defaultdict(list)
    delete_ips = defaultdict(list)
    delete_ptrs = defaultdict(list)
    delete_hosts = set()

    for hostname, host in problem_hosts.items():
        # Need to figure of if we should delete a host, or just remove
        # ip addresses and/or ptr overrides.
        # Criteria for host removal:
        # - All ip addresses in oldnet, and none in newnet.
        # - All ptr overrides in oldnet, and none in newnet.
        # - Not used as a target for naptr, srv or txt.
        for i in ("cnames", "txts",):
            if len(host[i]):
                not_delete[hostname].append(i)

        naptrs = get(f"/naptrs/?host__id={host['id']}").json()
        if len(naptrs):
            not_delete[hostname].append("naptrs")

        host_ips = list(map(itemgetter('ipaddress'), host['ipaddresses']))
        host_ptrs = list(map(itemgetter('ipaddress'), host['ptr_overrides']))

        if all(host_ip in ips for host_ip in host_ips) and \
           all(host_ptr in ptrs for host_ptr in host_ptrs):
            if hostname not in not_delete:
                delete_hosts.add(hostname)
                continue

        for info in host["ipaddresses"]:
            if info['ipaddress'] in ips:
                delete_ips[hostname].append((info["id"], info["ipaddress"]))
        for info in host["ptr_overrides"]:
            if info['ipaddress'] in ptrs:
                delete_ptrs[hostname].append((info["id"], info["ipaddress"]))

    if not_delete:
        message = f"Can not remove {oldnet} due to:"
        for hostname, reasons in not_delete.items():
            message += "\n\thost {}, reason(s): {}".format(hostname,
                                                           ", ".join(reasons))
        error(message)

    return delete_hosts, delete_ips, delete_ptrs


def shrink_networks(shrink, import_data, args):
    for oldnet, newnets in shrink.items():
        newnets = networksort(newnets)

        (delete_hosts, delete_ips, delete_ptrs) = removable(oldnet, newnets)
        logging.info(f"Shrinking: {oldnet} -> {newnets}")

        for hostname in delete_hosts:
            if not args.dryrun:
                delete(f"/hosts/{hostname}")
            logging.info(f"Deleted host {hostname}")
        for hostname, ipinfo in delete_ips.items():
            for ip_id, ip in ipinfo:
                if not args.dryrun:
                    delete(f"/ipaddresses/{ip_id}")
                logging.info(f"Deleted ip {ip} from host {hostname}")
        for hostname, ipinfo in delete_ptrs.items():
            for ip_id, ip in ipinfo:
                if not args.dryrun:
                    delete(f"/ptroverrides/{ip_id}")
                logging.info(f"Deleted ptr override {ip} from host {hostname}")

        first = True
        for newnet in newnets:
            # Patch the first to avoid deleting any entries we are keeping
            newdata = import_data[newnet]
            if first:
                path = f"{basepath}{oldnet}"
                if not args.dryrun:
                    patch(path, newdata)
                first = False
                logging.info(f"PATCHED {oldnet} to {newdata['range']}")
            elif not args.dryrun:
                post(basepath, newdata)


def read_networks(filename):

    def _error(message):
        error(f"{filename} line {line_number}: {message}")

    tree = IntervalTree()
    points = set()

    # Read in new network structure from file
    network_re = re.compile(r"""^
                            (?P<network>[\da-fA-F\.:]+/\d+) \s+
                            (novlan|vlan(?P<vlan>\d+)) \s+
                            (:(?P<tags>.*):\|)?                 # optional tags
                            (?P<description>.*)
                            """, re.X)
    with open(filename, 'r', encoding="latin-1") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if line.startswith("#"):
                continue
            res = network_re.match(line)
            if res:
                network_str = res.group('network').lower()
                try:
                    network = ipaddress.ip_network(network_str)
                except ValueError as e:
                    _error(f"Network is invalid: {e}")
                overlap_check(network, tree, points)
                vlan = res.group('vlan')
                if vlan:
                    vlan = int(vlan)
                desc = res.group('description')
                if not desc:
                    _error("Missing description.")
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
                _error(f"Could not match string: {line}")

def empty_network(network):
        used_count = get(f"{basepath}{network}/used_count").json()
        ptr_list = get(f"{basepath}{network}/ptroverride_list").json()
        if used_count == 0 and len(ptr_list) == 0:
            return True
        used_list = get(f"{basepath}{network}/used_list").json()
        if used_list:
            return False

        return True


def compare_with_mreg(ipversion, import_data, mreg_data):

    networks_delete = mreg_data.keys() - import_data.keys()
    networks_post = import_data.keys() - mreg_data.keys()

    networks_grow = defaultdict(set)
    networks_shrink = defaultdict(set)

    # Check if a network destined for removal is actually just resized
    for existing in networks_delete:
        existing_net = ipaddress.ip_network(existing)
        for new in networks_post:
            new_net = ipaddress.ip_network(new)
            if existing_net.subnet_of(new_net):
                networks_grow[new].add(existing)
            elif existing_net.supernet_of(new_net):
                networks_shrink[existing].add(new)

    for newnet, oldnets in networks_grow.items():
        networks_delete -= oldnets
        networks_post.remove(newnet)

    for oldnet, newnets in networks_shrink.items():
        removable(oldnet, newnets=newnets)
        networks_delete.remove(oldnet)
        networks_post -= newnets

    networks_patch = defaultdict(dict)
    networks_keep = import_data.keys() & mreg_data.keys()

    # Check if networks marked for deletion is removable
    for network in networks_delete:
        removable(network)

    # Check if networks marked for creation have any overlap with existing networks
    # We also check this serverside, but just in case...
    for network_new in networks_post:
        network_object = ipaddress.ip_network(network_new)
        for network_existing in networks_keep:
            if network_object.overlaps(ipaddress.ip_network(network_existing)):
                error(
                    f"Overlap found between new network {network_new} "
                    f"and existing network {network_existing}")

    # Check which existing networks need to be patched
    for network in networks_keep:
        current_data = mreg_data[network]
        new_data = import_data[network]
        for i in ('description', 'vlan', 'category', 'location'):
            if new_data[i] != current_data[i]:
                networks_patch[network][i] = new_data[i]

    return networks_post, networks_patch, networks_delete, networks_grow, networks_shrink


def grow_networks(grow, import_data, dryrun):
    for newnet, oldnets in grow.items():
        # If the new network replaces multiple old ones, then first
        # patch the range to a not-in-use range and then delete. To
        # work around delete restrictions.
        oldnets = networksort(oldnets)
        replace = oldnets.pop()
        for oldnet in oldnets:
            if not dryrun:
                dummyrange = '255.255.255.0/32'
                path = f"{basepath}{oldnet}"
                patch(path, range=dummyrange)
                path = f"{basepath}{dummyrange}"
                delete(path)
            logging.info(f"REMOVED {oldnet} to make room for {newnet}")
        if not dryrun:
            patch(f"{basepath}{replace}", import_data[newnet])
        logging.info(f"GREW {replace} to {newnet}")



def check_changes_size(ipversion, num_current, args, *changes):
    changed = sum(map(len, changes))
    if num_current and changed != 0:
        diffsize = (changed / num_current) * 100
        if diffsize > args.max_size_change and not args.force_size_change:
            error(f"The import will change {diffsize:.0f}% of the ipv{ipversion} networks. "
                  f"Limit is {args.max_size_change}%. Requires force.")
        else:
            logging.info(f"Changing {diffsize:.0f}% of the ipv{ipversion} networks.")


def update_mreg(import_data, args, *changes):
    networks_post, networks_patch, networks_delete, networks_grow, networks_shrink = changes
    logging.info("------ API REQUESTS START ------")

    grow_networks(networks_grow, import_data, args.dryrun)
    shrink_networks(networks_shrink, import_data, args)

    for network in networks_delete:
        path = f"{basepath}{network}"
        if not args.dryrun:
            delete(path)
        logging.info(f"DELETE {path}")

    for network in networksort(networks_post):
        data = import_data[network]
        if not args.dryrun:
            post(basepath, data)
        logging.info(f"POST {basepath} - {network} - {data['description']}")

    for network, data in networks_patch.items():
        path = f"{basepath}{network}"
        if not args.dryrun:
            patch(path, data)
        logging.info(f"PATCH {path} {data}")

    logging.info("------ API REQUESTS END ------")

def sync_with_mreg(args):
    logging.info(f"Starting import of {args.networkfile}")
    read_tags()
    read_networks(args.networkfile)
    mreg_data = defaultdict(dict)
    for i in get(basepath).json():
        network = ipaddress.ip_network(i['range'])
        mreg_data[network.version][i['range']] = i
    for ipversion, import_data in ((4, import_v4), (6, import_v6)):
        changes = compare_with_mreg(ipversion, import_data, mreg_data[ipversion])
        if any(len(i) for i in changes):
            check_changes_size(ipversion, len(mreg_data[ipversion]), args, *changes)
            update_mreg(import_data, args, *changes)
        else:
            logging.info(f"No changes for ipv{ipversion} networks")
    logging.info(f"Done import of {args.networkfile}")


def main():
    global cfg
    parser = argparse.ArgumentParser()
    parser.add_argument("networkfile",
                        help="File with all networks")
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
    cfg.read_file(open(args.config), args.config)

    setup_logging()
    sync_with_mreg(args)


main()