from __future__ import annotations

import configparser
import ipaddress
import logging
import re
from collections import defaultdict
from operator import itemgetter
from typing import Annotated

import requests
import typer
from intervaltree import IntervalTree

from mreg_tools import common
from mreg_tools.app import app
from mreg_tools.common.utils import error

basepath = "/api/v1/networks/"

import_v4 = {}
import_v6 = {}
location_tags = set()
category_tags = set()
delete_ips = defaultdict(list)
delete_ptrs = defaultdict(list)
delete_hosts = set()
unremoveable_networks = []


def networksort(networks):
    return sorted(networks, key=lambda i: ipaddress.ip_network(i))


def read_tags():
    if "tagsfile" in cfg["default"]:
        filename = cfg["default"]["tagsfile"]
    else:
        return
    with open(filename) as tagfile:
        flag_re = re.compile(
            r"""^
                             ((?P<location>[a-zA-Z0-9]+)+\s+:\s+Plassering)
                             |(?P<category>[a-zA-Z0-9]+)
                             """,
            re.X,
        )
        for line_number, line in enumerate(tagfile, 1):
            line = line.strip()
            if line.startswith("#") or len(line) == 0:
                continue

            res = flag_re.match(line)
            if res.group("location"):
                location_tags.add(res.group("location"))
            elif res.group("category"):
                category_tags.add(res.group("category"))
            else:
                error(f"In {filename}, wrong format on line: {line_number} - {line}")


# From python 3.7 Lib/ipaddress.py.
def _is_subnet_of(a, b):
    try:
        # Always false if one is v4 and the other is v6.
        if a._version != b._version:
            raise TypeError(f"{a} and {b} are not of the same version")
        return (
            b.network_address <= a.network_address
            and b.broadcast_address >= a.broadcast_address
        )
    except AttributeError:
        raise TypeError(f"Unable to test subnet containment between {a} and {b}")


def subnet_of(a, b):
    """Return True if this network is a subnet of other."""
    return _is_subnet_of(a, b)


def supernet_of(a, b):
    """Return True if this network is a supernet of other."""
    return _is_subnet_of(b, a)


# end backport from Python 3.7 ipaddress


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
    elif (
        network.version == 4
        and network.prefixlen == 32
        or network.version == 6
        and network.prefixlen == 128
    ):
        if begin in points:
            error(f"Network {network} already in file")
        elif tree.overlaps(begin):
            error(f"Network {network} overlaps {tree[begin].pop().data}")
        elif tree.overlaps(begin - 1):
            error(f"Network {network} overlaps {tree[begin - 1].pop().data}")
        else:
            points.add(begin)
    else:
        tree[begin:end] = network


def check_removable(oldnet, newnets=[]):
    # An empty networks is obviously removable
    if empty_network(oldnet):
        return

    def ips_not_in_newnets(ips):
        res = set()
        for ip in ips:
            ipaddr = ipaddress.ip_address(ip)
            for net in newnets:
                if ipaddr in net:
                    break
            else:
                res.add(ip)
        return res

    delete_hosts.clear()
    delete_ips.clear()
    delete_ptrs.clear()

    newnets = [ipaddress.ip_network(i) for i in newnets]
    ptr_list = conn.get(f"{basepath}{oldnet}/ptroverride_list").json()
    used_list = conn.get(f"{basepath}{oldnet}/used_list").json()
    ptrs = ips_not_in_newnets(ptr_list)
    ips = ips_not_in_newnets(used_list)

    problem_hosts = dict()
    for ptr in ptrs:
        host = conn.get_list(f"/api/v1/hosts/?ptr_overrides__ipaddress={ptr}")
        assert len(host) == 1
        problem_hosts[host[0]["name"]] = host[0]

    for ip in ips:
        hosts = conn.get_list(f"/api/v1/hosts/?ipaddresses__ipaddress={ip}")
        for host in hosts:
            problem_hosts[host["name"]] = host

    not_delete = defaultdict(list)

    for hostname, host in problem_hosts.items():
        # Need to figure of if we should delete a host, or just remove
        # ip addresses and/or ptr overrides.
        # Criteria for host removal:
        # - All ip addresses in oldnet, and none in newnet.
        # - All ptr overrides in oldnet, and none in newnet.
        # - Not used as a target for naptr, srv or txt.

        host_ips = set(map(itemgetter("ipaddress"), host["ipaddresses"]))
        host_ptrs = set(map(itemgetter("ipaddress"), host["ptr_overrides"]))

        # The host is used outside the network, so only remove ip/ptr
        if host_ips - ips or host_ptrs - ptrs:
            for info in host["ipaddresses"]:
                if info["ipaddress"] in ips:
                    delete_ips[hostname].append((info["id"], info["ipaddress"]))
            for info in host["ptr_overrides"]:
                ptr_ip = info["ipaddress"]
                if ptr_ip in ptrs and ptr_ip not in host_ips:
                    delete_ptrs[hostname].append((info["id"], ptr_ip))
            continue

        for i in (
            "cnames",
            "mxs",
        ):
            if len(host[i]):
                not_delete[hostname].append(i)

        if len(host["txts"]):
            if len(host["txts"]) == 1:
                # Ignore the default spf set on most hosts.
                if host["txts"][0]["txt"] != "v=spf1 -all":
                    not_delete[hostname].append("txts")
            else:
                not_delete[hostname].append("txts")

        for reason, url in (
            ("naptrs", f"/api/v1/naptrs/?host={host['id']}"),
            ("srvs", f"/api/v1/srvs/?host={host['id']}"),
        ):
            ret = conn.get_list(url)
            if len(ret):
                not_delete[hostname].append(reason)

        if hostname in not_delete:
            continue

        if host_ips & ips == host_ips and host_ptrs & ptrs == host_ptrs:
            delete_hosts.add(hostname)

    if not_delete:
        message = f"Can not remove {oldnet} due to:"
        for hostname, reasons in not_delete.items():
            message += "\n\thost {}, reason(s): {}\n".format(hostname, ", ".join(reasons))
        unremoveable_networks.append(message)


def shrink_networks(shrink, import_data, args):
    for oldnet, newnets in shrink.items():
        newnets = networksort(newnets)

        logging.info(f"Shrinking: {oldnet} -> {newnets}")

        first = True
        for newnet in newnets:
            # Patch the first to avoid deleting any entries we are keeping
            newdata = import_data[newnet]
            if first:
                path = f"{basepath}{oldnet}"
                if not args.dryrun:
                    conn.patch(path, newdata)
                first = False
                logging.info(f"PATCHED {oldnet} to {newdata['network']}")
            elif not args.dryrun:
                conn.post(basepath, newdata)


def read_networks(filename):
    def _error(message):
        error(f"{filename} line {line_number}: {message}")

    tree = IntervalTree()
    points = set()

    # Read in new network structure from file
    network_re = re.compile(
        r"""^
                            (?P<network>[\da-fA-F\.:]+/\d+) \s+
                            (novlan|vlan(?P<vlan>\d+)) \s+
                            (:(?P<tags>.*):\|)?                 # optional tags
                            (?P<description>.*)
                            """,
        re.X,
    )
    with open(filename, encoding="latin-1") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if line.startswith("#"):
                continue
            res = network_re.match(line)
            if res:
                network_str = res.group("network").lower()
                try:
                    network = ipaddress.ip_network(network_str)
                    network_str = str(network)
                except ValueError as e:
                    _error(f"Network is invalid: {e}")
                overlap_check(network, tree, points)
                vlan = res.group("vlan")
                if vlan:
                    vlan = int(vlan)
                desc = res.group("description").strip()
                if not desc:
                    _error("Missing description.")
                category = location = ""
                tags = res.group("tags")
                if tags:
                    for tag in tags.split(":"):
                        if tag in location_tags:
                            location = tag
                        elif tag in category_tags:
                            category += f" {tag}"
                        else:
                            logging.warning(
                                f"{line_number}: Invalid tag {tag}. Check valid in tags file."
                            )
                data = {
                    "network": network_str,
                    "description": desc,
                    "vlan": vlan,
                    "category": category.strip(),
                    "location": location,
                }
                if network.version == 4:
                    import_v4[network_str] = data
                elif network.version == 6:
                    import_v6[network_str] = data
            else:
                _error(f"Could not match string: {line}")


def empty_network(network):
    used_count = conn.get(f"{basepath}{network}/used_count").json()
    ptr_list = conn.get(f"{basepath}{network}/ptroverride_list").json()
    if used_count == 0 and len(ptr_list) == 0:
        return True
    used_list = conn.get(f"{basepath}{network}/used_list").json()
    if used_list:
        return False

    return True


def compare_with_mreg(ipversion, import_data, mreg_data):
    networks_delete = mreg_data.keys() - import_data.keys()
    networks_post = import_data.keys() - mreg_data.keys()
    networks_keep = import_data.keys() & mreg_data.keys()
    networks_patch = defaultdict(dict)

    networks_grow = defaultdict(set)
    networks_shrink = defaultdict(set)

    # Check if a network destined for removal is actually just resized
    for existing in networks_delete:
        existing_net = ipaddress.ip_network(existing)
        for new in networks_post:
            new_net = ipaddress.ip_network(new)
            if subnet_of(existing_net, new_net):
                networks_grow[new].add(existing)
            elif supernet_of(existing_net, new_net):
                networks_shrink[existing].add(new)

    for newnet, oldnets in networks_grow.items():
        networks_delete -= oldnets
        networks_post.remove(newnet)

    for oldnet, newnets in networks_shrink.items():
        check_removable(oldnet, newnets=newnets)
        networks_delete.remove(oldnet)
        networks_post -= newnets

    # Check if networks marked for deletion is removable
    for network in networks_delete:
        check_removable(network)

    if unremoveable_networks:
        error("".join(unremoveable_networks))

    # Check if networks marked for creation have any overlap with existing networks
    # We also check this serverside, but just in case...
    for network_new in networks_post:
        network_object = ipaddress.ip_network(network_new)
        for network_existing in networks_keep:
            if network_object.overlaps(ipaddress.ip_network(network_existing)):
                error(
                    f"Overlap found between new network {network_new} "
                    f"and existing network {network_existing}"
                )

    # Check which existing networks need to be patched
    for network in networks_keep:
        current_data = mreg_data[network]
        new_data = import_data[network]
        for i in ("description", "vlan", "category", "location"):
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
                dummyrange = "255.255.255.0/32"
                path = f"{basepath}{oldnet}"
                conn.patch(path, {"network": dummyrange})
                path = f"{basepath}{dummyrange}"
                conn.delete(path)
            logging.info(f"REMOVED {oldnet} to make room for {newnet}")
        if not dryrun:
            conn.patch(f"{basepath}{replace}", import_data[newnet])
        logging.info(f"GREW {replace} to {newnet}")


def check_changes_size(ipversion, num_current, args, *changes):
    changed = sum(map(len, changes))
    if num_current and changed != 0:
        diffsize = (changed / num_current) * 100
        if diffsize > args.max_size_change and not args.force_size_change:
            error(
                f"The import will change {diffsize:.0f}% of the ipv{ipversion} networks. "
                f"Limit is {args.max_size_change}%. Requires force."
            )
        else:
            logging.info(f"Changing {diffsize:.0f}% of the ipv{ipversion} networks.")


def update_mreg(mreg_data, import_data, args, *changes):
    networks_post, networks_patch, networks_delete, networks_grow, networks_shrink = (
        changes
    )
    logging.info("------ API REQUESTS START ------")

    for hostname in delete_hosts:
        if not args.dryrun:
            conn.delete(f"/api/v1/hosts/{hostname}")
        logging.info(f"Deleted host {hostname}")
    for hostname, ipinfo in delete_ips.items():
        for ip_id, ip in ipinfo:
            if not args.dryrun:
                conn.delete(f"/api/v1/ipaddresses/{ip_id}")
            logging.info(f"Deleted ip {ip} from host {hostname}")
    for hostname, ipinfo in delete_ptrs.items():
        for ip_id, ip in ipinfo:
            if not args.dryrun:
                conn.delete(f"/api/v1/ptroverrides/{ip_id}")
            logging.info(f"Deleted ptr override {ip} from host {hostname}")

    grow_networks(networks_grow, import_data, args.dryrun)
    shrink_networks(networks_shrink, import_data, args)

    for network in networks_delete:
        path = f"{basepath}{network}"
        if not args.dryrun:
            conn.delete(path)
        logging.info(f"DELETE {path} - {mreg_data[network]['description']}")

    for network in networksort(networks_post):
        data = import_data[network]
        if not args.dryrun:
            conn.post(basepath, data)
        logging.info(f"POST {basepath} - {network} - {data['description']}")

    for network, data in networks_patch.items():
        path = f"{basepath}{network}"
        if not args.dryrun:
            conn.patch(path, data)
        logging.info(f"PATCH {path} {data}")

    logging.info("------ API REQUESTS END ------")


def sync_with_mreg(args):
    logging.info(f"Starting import of {args.networkfile}")
    read_tags()
    read_networks(args.networkfile)
    mreg_data = defaultdict(dict)
    path = requests.compat.urljoin(basepath, "?page_size=1000")
    for i in conn.get_list(path):
        network = ipaddress.ip_network(i["network"])
        if i["category"].startswith("mreg-managed:"):
            continue
        mreg_data[network.version][i["network"]] = i
    for ipversion, import_data in ((4, import_v4), (6, import_v6)):
        changes = compare_with_mreg(ipversion, import_data, mreg_data[ipversion])
        if any(len(i) for i in changes):
            check_changes_size(ipversion, len(mreg_data[ipversion]), args, *changes)
            update_mreg(mreg_data[ipversion], import_data, args, *changes)
        else:
            logging.info(f"No changes for ipv{ipversion} networks")
    logging.info(f"Done import of {args.networkfile}")


@app.command("network-import", help="Import networks into mreg.")
def main(
    networkfile: Annotated[
        str,
        typer.Argument(help="File with all networks"),
    ],
    config: Annotated[
        str | None,
        typer.Option(None, help="(DEPRECATED) path to config file", hidden=True),
    ] = None,
    dryrun: Annotated[
        bool,
        typer.Option("--dryrun", help="Dryrun"),
    ] = False,
    force_size_change: Annotated[
        bool,
        typer.Option("--force-size-change", help="Allow more than MAX_SIZE_CHANGE changes"),
    ] = False,
    max_size_change: Annotated[
        int,
        typer.Option("--max-size-change", help="Max changes (change and delete) in percent"),
    ] = 20,
):
    global cfg, conn, logger

    cfg = configparser.ConfigParser()
    cfg.read_file(open(config or "network-import.conf"), config or "network-import.conf")

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg["mreg"], logger=logger)
    sync_with_mreg(args)


if __name__ == "__main__":
    main()
