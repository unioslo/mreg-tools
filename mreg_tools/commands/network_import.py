from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from collections.abc import Iterator
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from functools import cached_property
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Final
from typing import Literal
from typing import NoReturn
from typing import Protocol
from typing import TypeVar
from typing import final
from typing import override

import structlog.stdlib
import typer
from intervaltree import IntervalTree
from mreg_api.models import Host
from mreg_api.models import IPAddress
from mreg_api.models import Network
from mreg_api.models import PTR_override
from mreg_api.types import IP_AddressT
from mreg_api.types import IP_NetworkT

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import NetworkImportConfig
from mreg_tools.output import exit_err

COMMAND_NAME: Final[str] = "network-import"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)

IP_VERSION = Literal[4, 6]


network_re = re.compile(
    r"""^
                        (?P<network>[\da-fA-F\.:]+/\d+) \s+
                        (novlan|vlan(?P<vlan>\d+)) \s+
                        (:(?P<tags>.*):\|)?                 # optional tags
                        (?P<description>.*)
                        """,
    re.X,
)

flag_re = re.compile(
    r"""^
                        ((?P<location>[a-zA-Z0-9]+)+\s+:\s+Plassering)
                        |(?P<category>[a-zA-Z0-9]+)
                        """,
    re.X,
)

DEFAULT_TXT = "v=spf1 -all"


class HasIpNetwork(Protocol):
    """Protocol for an object that exposes an ip_network attribute."""

    @cached_property
    def ip_network(self) -> IP_NetworkT: ...  # noqa: D102


IpNetworkT = TypeVar("IpNetworkT", bound=HasIpNetwork)


def sort_networks(networks: Iterable[IpNetworkT]) -> list[IpNetworkT]:
    """Sort a list of network-like objects by their network address."""
    return sorted(networks, key=lambda i: i.ip_network)


@final
class NetworkIntervalTree:
    """Interval tree for efficiently checking for overlapping networks."""

    def __init__(self) -> None:
        self.tree = IntervalTree()
        self.points = set[int]()

    def check_overlap(
        self, network: ipaddress.IPv4Network | ipaddress.IPv6Network
    ) -> None:
        """Check if a network overlaps with any existing networks in the tree or points set.

        Adds the network to the tree if no overlap is detected.

        Exits with an error if overlap is detected.
        """
        # Uses an IntervalTree to do fast lookups of overlapping networks.
        #
        begin = int(network.network_address)
        end = int(network.broadcast_address)
        if self.tree[begin:end]:
            overlap = self.tree[begin:end]
            data = [str(i.data) for i in overlap]
            exit_err(f"Network {network} overlaps {data}")
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
            if begin in self.points:
                exit_err(f"Network {network} already in file")
            elif self.tree.overlaps(begin):
                exit_err(f"Network {network} overlaps {self.tree[begin].pop().data}")
            elif self.tree.overlaps(begin - 1):
                exit_err(f"Network {network} overlaps {self.tree[begin - 1].pop().data}")
            else:
                self.points.add(begin)
        else:
            self.tree[begin:end] = network


def read_network_file(filename: Path, imported_tags: ImportedTags) -> ImportedNetworks:
    """Import networks from file."""

    def line_error(message: str) -> NoReturn:
        """Exit with an error message including the line number."""
        exit_err(f"{filename} line {line_number}: {message}")

    if not filename.exists():
        exit_err(f"Network file {filename} does not exist.")

    logger.info("Reading network file", file=filename)

    try:
        content = filename.read_text(encoding="latin-1")  # TODO: don't hardcode?
    except Exception as e:
        exit_err(f"Failed to read network file {filename}: {e}")

    imported = ImportedNetworks()
    tree = NetworkIntervalTree()

    # Parse lines. Each line should contain a network definition
    for line_number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if line.startswith("#"):
            continue

        # Validate line
        res = network_re.match(line)
        if not res:
            line_error(f"Could not match string: {line}")

        # Network address
        network_str = str(res.group("network").lower())
        try:
            network = ipaddress.ip_network(network_str)
        except ValueError as e:
            line_error(f"Network is invalid: {e}")
        tree.check_overlap(network)

        # VLAN
        vlan = res.group("vlan")
        if vlan is not None:
            vlan = int(vlan)

        # Description
        desc = res.group("description").strip()
        if not desc:
            line_error("Missing description.")

        # Tags
        categories: list[str] = []
        locations: list[str] = []
        if tags := res.group("tags"):
            for tag in tags.split(":"):
                if tag in imported_tags.location:
                    locations.append(tag)
                elif tag in imported_tags.category:
                    categories.append(tag)
                else:
                    logger.warning(
                        f"{line_number}: Invalid tag {tag}. Check valid in tags file."
                    )

        # TODO: assign lists to category and location,
        # and handle formatting when actually importing the networks
        data = ImportedNetwork(
            network=network_str,
            description=desc,
            vlan=vlan,
            category=" ".join(categories),
            location=" ".join(locations),
        )

        if network.version == 4:
            imported.ipv4[network_str] = data
        elif network.version == 6:
            imported.ipv6[network_str] = data

    return imported


def read_tags_file(filename: Path) -> ImportedTags:
    """Read tags from tags file."""
    tags = ImportedTags()

    if not filename.exists():
        exit_err(f"Tags file {filename} does not exist.")

    try:
        # NOTE: no encoding specified in original script here!
        content = filename.read_text()
    except Exception as e:
        exit_err(f"Failed to read tags file {filename}: {e}")

    for line_number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if line.startswith("#") or len(line) == 0:
            continue

        res = flag_re.match(line)
        if not res:
            exit_err(f"{filename} line {line_number}: Could not match string: {line}")

        if res.group("location"):
            tags.location.add(res.group("location"))
        elif res.group("category"):
            tags.category.add(res.group("category"))

    return tags


# TODO: refactor all datastructures to be indepdendent of IP version?


@dataclass(frozen=True)
class ImportedNetwork:
    """An imported network from a network file."""

    network: str
    description: str
    vlan: int | None
    category: str
    location: str

    # HACK: a little clumsy to recreate the IPv{4,6}Network object here, but
    # it allows us to match the interface of `mreg_api.models.Network`
    @cached_property
    def ip_network(self) -> IP_NetworkT:
        """Return the network address as a ipaddress.IPv4Network or ipaddress.IPv6Network object."""
        return ipaddress.ip_network(self.network)

    @cached_property
    def ip_version(self) -> IP_VERSION:
        """Return the IP version of the network."""
        return self.ip_network.version

    def asdict(self) -> dict[str, Any]:
        """Return a dict representation of the imported network."""
        return asdict(self)


@dataclass
class ImportedTags:
    """Imported tags, categorized by type."""

    location: set[str] = field(default_factory=set)
    category: set[str] = field(default_factory=set)


@dataclass
class ImportedNetworks:
    """Impored networks, categorized by IP version."""

    ipv4: dict[str, ImportedNetwork] = field(default_factory=dict)
    ipv6: dict[str, ImportedNetwork] = field(default_factory=dict)


@dataclass
class MregNetworks:
    """Existing MREG networks, categorized by IP version."""

    ipv4: dict[str, Network] = field(default_factory=dict)
    ipv6: dict[str, Network] = field(default_factory=dict)


class NetworkStorage(MregDataStorage):
    """Storage for fetched network data."""

    def __init__(self, networks: MregData[Network]) -> None:
        self.networks = networks


@dataclass
class HostDeletionInfo:
    """Information about a host and its records slated for deletion."""

    host: Host
    ips: list[IPAddress] = field(default_factory=list)
    ptrs: list[PTR_override] = field(default_factory=list)

    delete_host: bool = False
    """Whether the host itself should be deleted, or just its associated records."""


@dataclass
class HostDeletions:
    """Tracks hosts and their associated resources pending deletion."""

    _entries: dict[str, HostDeletionInfo] = field(default_factory=dict, repr=False)

    def mark_host(self, host: Host) -> None:
        """Mark the host itself to be deleted."""
        self._get_or_create(host).delete_host = True

    def mark_ip(self, host: Host, ip: IPAddress) -> None:
        """Mark an IP address belonging to the host for deletion."""
        self._get_or_create(host).ips.append(ip)

    def mark_ptr(self, host: Host, ptr: PTR_override) -> None:
        """Mark a PTR record belonging to the host for deletion."""
        self._get_or_create(host).ptrs.append(ptr)

    def _get_or_create(self, host: Host) -> HostDeletionInfo:
        if host.name not in self._entries:
            self._entries[host.name] = HostDeletionInfo(host=host)
        return self._entries[host.name]

    def __iter__(self) -> Iterator[HostDeletionInfo]:
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)


@dataclass()
class NetworkChanges:
    """Changes to be made to align MREG with the imported network data."""

    keep: set[Network] = field(default_factory=set)
    create: set[ImportedNetwork] = field(default_factory=set)
    delete: set[Network] = field(default_factory=set)
    patch: list[tuple[Network, dict[str, Any]]] = field(default_factory=list)

    grow: defaultdict[ImportedNetwork, set[Network]] = field(
        default_factory=lambda: defaultdict(set)
    )
    shrink: defaultdict[Network, set[ImportedNetwork]] = field(
        default_factory=lambda: defaultdict(set)
    )
    unremovable: list[UnremovableNetwork] = field(default_factory=list)

    def number_of_changes(self) -> int:
        """Return the total number of changes (creates, deletes, patches, grow, shrink) to be made."""
        return (
            len(self.create)
            + len(self.delete)
            + len(self.patch)
            # NOTE: this way of counting changed networks based on keys is
            # carried over from original script. We could sum the len of
            # the values of these to get a more accurate number
            + len(self.grow)
            + len(self.shrink)
        )


@dataclass
class HostChanges:
    """Changes to be made to a host to align MREG with the imported network data."""

    delete_host: bool = False
    delete_ips: list[IPAddress] = field(default_factory=list)
    delete_ptrs: list[PTR_override] = field(default_factory=list)


@dataclass
class SyncPlan:
    """Complete plan for synchronising MREG with imported data for a given IP version."""

    ip_version: IP_VERSION
    networks: NetworkChanges = field(default_factory=NetworkChanges)
    hosts: HostDeletions = field(default_factory=HostDeletions)


@dataclass
class UnremovableNetwork:
    """A network that cannot be removed and the reasons for it."""

    network: Network
    reasons: set[str]

    def __str__(self) -> str:
        return f"Network {self.network.network} can not be removed due to:\n\t{'\n\t'.join(self.reasons)}"  # noqa: E501


@final
class NetworkImport(CommandBase[NetworkStorage]):
    """network-import command class."""

    def __init__(self, app_config: Config):
        super().__init__(app_config)
        self.data = NetworkStorage(
            networks=MregData(
                name="networks",
                type=Network,
                default=[],
                first_func=self.client.network.get_first,
                get_func=self.client.network.get_list,
                count_func=self.client.network.get_count,
            )
        )

        if not self.command_config.networkfile:
            exit_err(
                "Network file missing. Use --networkfile to specify the file to import."
            )

        if self.command_config.tagsfile:
            self.tags = read_tags_file(self.command_config.tagsfile)
        else:
            self.logger.debug("No tags file specified, skipping reading tags.")
            self.tags = ImportedTags()

        self.imported_networks = read_network_file(
            self.command_config.networkfile, self.tags
        )

    @override
    def should_run_postcommand(self) -> bool:
        """Run post-command if any zones were updated."""
        # TODO: add heuristic for checking if we have _imported_ any networks
        return self.is_updated

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> NetworkImportConfig:
        return self._app_config.network_import

    @property
    def dryrun(self) -> bool:
        """Dry run status."""
        return self.command_config.dryrun

    @override
    def run(self) -> None:
        # Categorize imported data by IP version
        mreg_networks = MregNetworks()
        for network in self.data.networks.data:
            if network.ip_network.version == 4:
                mreg_networks.ipv4[network.network] = network
            elif network.ip_network.version == 6:
                mreg_networks.ipv6[network.network] = network

        # Run sync
        self.sync_with_mreg(mreg_networks.ipv4, self.imported_networks.ipv4, 4)
        self.sync_with_mreg(mreg_networks.ipv6, self.imported_networks.ipv6, 6)

    def compare_with_mreg(
        self,
        import_data: dict[str, ImportedNetwork],
        mreg_data: dict[str, Network],
        ip_version: IP_VERSION,
    ) -> SyncPlan:
        """Compare imported data with current MREG data and create a sync plan.

        Args:
            import_data (dict[str, ImportedNetwork]): Imported networks
            mreg_data (dict[str, Network]): Current MREG networks
            ip_version (IP_VERSION): IP version of the networks being compared

        Returns:
            SyncPlan: Plan for synchronising MREG with imported data.
        """
        plan = SyncPlan(ip_version=ip_version)

        # Keep networks found in both mreg and import data
        # Create networks found in import data but not in mreg
        for nw_addr, network in import_data.items():
            if mreg_host := mreg_data.get(nw_addr):
                plan.networks.keep.add(mreg_host)
            else:
                plan.networks.create.add(network)

        # Delete networks found in mreg but not in import data
        for nw_addr, network in mreg_data.items():
            if nw_addr not in import_data:
                plan.networks.delete.add(network)

        # Check if a network slated for removal is an existing network
        # that is being resized via growing/shrinking its size
        for existing in plan.networks.delete:
            for new in plan.networks.create:
                # FIXME: Ensure IP versions are identical
                if existing.ip_network.subnet_of(new.ip_network):
                    plan.networks.grow[new].add(existing)
                elif existing.ip_network.supernet_of(new.ip_network):
                    plan.networks.shrink[existing].add(new)

        # Remove networks that are being resized from delete and create lists, and add to grow/shrink lists
        for newnet, oldnets in plan.networks.grow.items():
            plan.networks.delete -= oldnets
            plan.networks.create.remove(newnet)
        for oldnet, newnets in plan.networks.shrink.items():
            self.check_removable(plan, oldnet, newnets=newnets)
            plan.networks.delete.remove(oldnet)
            plan.networks.create -= newnets

        # Check if networks marked for deletion is removable
        for network in plan.networks.delete:
            self.check_removable(plan, network)

        # Exit with an error if any networks cannot be removed.
        if plan.networks.unremovable:
            exit_err("\n".join(str(n) for n in plan.networks.unremovable))

        # Check if networks marked for creation have any overlap with existing networks
        # We also check this serverside, but just in case...
        for nw_new in plan.networks.create:
            for nw_existing in plan.networks.keep:
                if nw_new.ip_network.overlaps(
                    ipaddress.ip_network(nw_existing.ip_network)
                ):
                    exit_err(
                        (
                            f"Overlap found between new network {nw_new.network} "
                            f"and existing network {nw_existing.network}"
                        )
                    )

        # Check if existing networks need to be updated with new data
        for network in plan.networks.keep:
            current_nw = mreg_data.get(network.network)
            new_nw = import_data.get(network.network)

            if not new_nw or not current_nw:
                exit_err(
                    f"Network {network.network} in keep list not found in both mreg and import data"
                )

            # NOTE: this is a little inelegant and hacky, but we are comparing
            # two different types of objects, so we need to convert them to a
            # common format OR create some interface type and a comparison function
            # which is more involved. That could be an option if this comparison
            # needs to include more fields in the future.
            new_data = {
                "description": new_nw.description,
                "vlan": new_nw.vlan,
                "category": new_nw.category,
                "location": new_nw.location,
            }
            current_data = {
                "description": current_nw.description,
                "vlan": current_nw.vlan,
                "category": current_nw.category,
                "location": current_nw.location,
            }
            if any(current_data[key] != new_data[key] for key in new_data):
                plan.networks.patch.append((current_nw, new_data))

        return plan

    def check_removable(
        self,
        plan: SyncPlan,
        oldnet: Network,
        newnets: set[ImportedNetwork] | None = None,
    ) -> None:
        """Check if a network is safe to remove.

        Exits with an error if network is not removable.

        Args:
            plan (SyncPlan): Plan containing networks to remove
            oldnet (Network): Network to check
            newnets (set[ImportedNetwork] | None, optional): New networks to replace old network with. Defaults to None.
        """
        # An empty network is obviously removable
        if self.is_empty_network(oldnet):
            return

        if not newnets:
            newnets = set()

        new_networks = set[IP_NetworkT](n.ip_network for n in newnets)

        def ips_not_in_newnets(ips: list[IP_AddressT]) -> set[IP_AddressT]:
            """Filter a list of IP addresses to those _not_ in any of the new networks."""
            res = set[IP_AddressT]()
            for ip in ips:
                ipaddr = ipaddress.ip_address(ip)
                for net in new_networks:
                    if ipaddr in net:
                        break
                else:
                    res.add(ip)
            return res

        # TODO: re-use ptrs and used-list retrieved in `is_empty_network()`
        # We re-fetch here, which is not ideal.
        ptr_list = oldnet.get_ptr_overrides()
        used_list = oldnet.get_used_list()

        ptrs = ips_not_in_newnets(ptr_list)
        ips = ips_not_in_newnets(used_list)

        problem_hosts = dict[str, Host]()
        for ptr in ptrs:
            host = self.client.host.get_by_query_unique_or_raise(
                {"ptr_overrides__ipaddress": str(ptr)}
            )
            problem_hosts[host.name] = host

        for ip in ips:
            hosts = self.client.host.get_list({"ipaddresses__ipaddress": str(ip)})
            for host in hosts:
                problem_hosts[host.name] = host

        not_delete = defaultdict[str, list[str]](list)
        """Hosts to not delete, with reasons for not deleting."""

        for hostname, host in problem_hosts.items():
            # Need to figure of if we should delete a host, or just remove
            # ip addresses and/or ptr overrides.
            # Criteria for host removal:
            # - All ip addresses in oldnet, and none in newnet.
            # - All ptr overrides in oldnet, and none in newnet.
            # - Not used as a target for naptr, srv or txt.

            host_ips = set(i.ipaddress for i in host.ipaddresses)
            host_ptrs = set(i.ipaddress for i in host.ptr_overrides)

            # The host is used outside the network, so only remove ip/ptr
            if host_ips - ips or host_ptrs - ptrs:
                for ip in host.ipaddresses:
                    if ip in ips:
                        plan.hosts.mark_ip(host, ip)
                for ptr in host.ptr_overrides:
                    ptr_ip = ptr.ipaddress
                    if ptr_ip in ptrs and ptr_ip not in host_ips:
                        plan.hosts.mark_ptr(host, ptr)
                continue

            # Hosts with associated DNS records will not be deleted
            record_reasons = {
                "cnames": host.cnames,
                "mxs": host.mxs,
                "naptrs": host.naptrs,
                "srvs": host.srvs,
            }
            for reason, records in record_reasons.items():
                if records:
                    not_delete[hostname].append(reason)
            if host.txts:
                if len(host.txts) == 1:
                    # Ignore the default spf set on most hosts.
                    if host.txts[0].txt != DEFAULT_TXT:
                        not_delete[hostname].append("txts")
                else:
                    not_delete[hostname].append("txts")

            if hostname in not_delete:
                continue  # skip deletion

            # If all of the host's IPs and PTRs are slated for deletion,
            # delete the host as well.
            if host_ips & ips == host_ips and host_ptrs & ptrs == host_ptrs:
                plan.hosts.mark_host(host)

        if not_delete:
            # TODO: refactor all this logic into UnremovableNetwork using tuple[str, list[str]]
            reasons = set[str]()
            for hostname, host_reasons in not_delete.items():
                reasons.add(f"host {hostname}, reason(s): {', '.join(host_reasons)}")
            plan.networks.unremovable.append(
                UnremovableNetwork(network=oldnet, reasons=reasons)
            )
            self.logger.error(
                "Network cannot be removed due to associated hosts",
                network=oldnet.network,
                hosts=not_delete,
            )

    def is_empty_network(self, network: Network) -> bool:
        """Determine if a network is empty."""
        used_list = network.get_used_list()
        ptr_list = network.get_ptr_overrides()
        if len(used_list) == 0 and len(ptr_list) == 0:
            return True
        # # NOTE: Why do we need to do this check?
        # # Surely it's covered by the previous checks?
        # if used_list:
        #     return False

        # # NOTE: Why is the default True?
        # # We should assume non-empty until proven otherwise, surely?
        # return True
        return False

    def sync_with_mreg(
        self,
        mreg_networks: dict[str, Network],
        imported_networks: dict[str, ImportedNetwork],
        ip_version: IP_VERSION,
    ) -> None:
        """Sync imported networks with MREG networks for a given IP version."""
        log = self.logger.bind(ip_version=ip_version)
        log.info("Comparing imported networks with MREG networks")

        plan = self.compare_with_mreg(imported_networks, mreg_networks, ip_version)
        if plan.networks.number_of_changes():
            self.validate_network_change_size(
                ip_version, len(mreg_networks), plan.networks
            )
            self.update_mreg(plan)
            log.info("Updated networks")
        else:
            log.info("No changes for networks.")

    def validate_network_change_size(
        self, ip_version: int, num_current: int, changes: NetworkChanges
    ):
        """Ensure number of network changes are within limits specified by command config."""
        changed = changes.number_of_changes()
        if num_current and changed != 0:
            diffsize = (changed / num_current) * 100
            if (
                # Size exceeds limit and force is not enabled:
                diffsize > self.command_config.max_size_change
                and not self.command_config.ignore_size_change
            ):
                exit_err(
                    (
                        f"The import will change {diffsize:.0f}% of the ipv{ip_version} networks. "
                        f"Limit is {self.command_config.max_size_change}%. Requires force."
                    )
                )
            self.logger.info(
                "Number of network changes within acceptable parameters",
                size_percent=diffsize,
                limit=self.command_config.max_size_change,
                force=self.command_config.ignore_size_change,
            )

    def update_mreg(self, plan: SyncPlan) -> None:
        """Update MREG according to the given sync plan.

        Args:
            plan (SyncPlan): Plan of changes to make in MREG.
        """
        self.delete_host_records(plan)
        self.grow_networks(plan)
        self.shrink_networks(plan)
        self.delete_networks(plan)  # IMPORTANT: delete before creating new!
        self.create_networks(plan)
        self.patch_networks(plan)

    def delete_host_records(self, plan: SyncPlan) -> None:
        """Delete host records (IPs, PTRs, and hosts) according to the given sync plan."""
        for host in plan.hosts:
            log = self.logger.bind(hostname=host.host.name)

            for ip in host.ips:
                if not self.dryrun:
                    ip.delete()
                log.info("Deleted IP address", ipaddress=ip.ipaddress)
            for ptr in host.ptrs:
                if not self.dryrun:
                    ptr.delete()
                log.info("Deleted PTR override", ipaddress=ptr.ipaddress)
            if host.delete_host:
                if not self.dryrun:
                    host.host.delete()
                log.info("Deleted host")

    def create_networks(self, plan: SyncPlan) -> None:
        """Create new MREG networks according to the sync plan."""
        for network in sort_networks(plan.networks.create):
            if not self.command_config.dryrun:
                self.client.network.create(network.asdict())
            self.logger.info(
                "Created network",
                network=network.network,
                description=network.description,
            )

    def delete_networks(self, plan: SyncPlan) -> None:
        """Delete existing MREG networks according to the sync plan."""
        for network in plan.networks.delete:
            if not self.dryrun:
                network.delete()
            self.logger.info(
                "Deleted network",
                network=network.network,
                description=network.description,
            )

    def patch_networks(self, plan: SyncPlan) -> None:
        """Patch existing MREG networks according to the sync plan."""
        for network, new_data in plan.networks.patch:
            if not self.command_config.dryrun:
                # TODO: use ImportedNetwork.asdict() here instead of passing
                # in a dict? Need to refactor NetworkModifications.patch for that.
                network.patch(new_data)
            self.logger.info(
                "Updated network", network=network.network, new_data=new_data
            )

    def grow_networks(self, plan: SyncPlan):
        """Grow existing networks to fit their new sizes in imported data."""
        for newnet, oldnets in plan.networks.grow.items():
            log = self.logger.bind(newnet=newnet.network)
            if not oldnets:
                log.error("No old networks found to grow from for new network")
                continue

            # Sort networks smallest to largest, pop off the smallest network,
            # then delete all other networks so we can grow the smallest network
            # to encompass the entire range.
            oldnets = sort_networks(oldnets)
            smallest_net = oldnets.pop()
            for oldnet in oldnets:
                # NOTE: Original comment left in place here:
                # If the new network replaces multiple old ones, then first
                # patch the range to a not-in-use range and then delete. To
                # work around delete restrictions.
                if not self.command_config.dryrun:
                    # NOTE: changed in mreg-tools v2: Only patches range if
                    # we know we have an IPv4 network
                    if oldnet.ip_network.version == 4:
                        oldnet = oldnet.patch(
                            {"network": self.command_config.dummy_range_ipv4}
                        )
                    oldnet.delete()
                log.info(
                    "Removed network to make room for larger network",
                    oldnet=oldnet.network,
                )

            if not self.command_config.dryrun:
                smallest_net.patch(newnet.asdict())
            log.info("Grew existing network.", oldnet=smallest_net.network)

    def shrink_networks(self, plan: SyncPlan) -> None:
        """Shrink existing networks to fit new imported networks.

        Creates new networks in the shrunk range if any imported networks overlap
        with the previous network's range.
        """
        for oldnet, newnets in plan.networks.shrink.items():
            log = self.logger.bind(oldnet=oldnet.network)
            if not newnets:
                log.error("No new networks found to shrink to for old network")
                continue

            newnets = sort_networks(newnets)

            log.info("Shrinking network", newnets=[n.network for n in newnets])

            for i, newnet in enumerate(newnets):
                # Shrink the existing network down to the size of the first imported network
                # then create new networks with from the remaining imported networks
                if i == 0:
                    if not self.command_config.dryrun:
                        oldnet.patch(newnet.asdict())
                    log.info("Shrunk existing network", newnet=newnet.network)
                else:
                    if not self.command_config.dryrun:
                        self.client.network.create(newnet.asdict())
                    log.info("Created new network in shrunk range", newnet=newnet.network)


@app.command("network-import", help="Import networks into mreg.")
def main(
    config: Annotated[
        str | None,
        typer.Option(help="(DEPRECATED) path to config file", hidden=True),
    ] = None,
    networkfile: Annotated[
        Path | None,
        typer.Argument(help="File with all networks"),
    ] = None,
    tagsfile: Annotated[
        Path | None,
        typer.Option("--tagsfile", help="File with valid tags for network import"),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="Use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            "--force-size-change",
            help="Ignore network size change limits. Takes precedence over --max-size-change",
        ),
    ] = None,
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="Force refresh of data from mreg"),
    ] = None,
    dryrun: Annotated[
        bool | None,
        typer.Option("--dryrun", help="Dryrun"),
    ] = None,
    max_size_change: Annotated[
        int | None,
        typer.Option(
            "--max-size-change",
            help="Maximum allowed size change in percent for the network import",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.network_import.force_check = force_check
    if ignore_size_change is not None:
        conf.network_import.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.network_import.use_saved_data = use_saved_data
    if networkfile is not None:
        conf.network_import.networkfile = networkfile
    if tagsfile is not None:
        conf.network_import.tagsfile = tagsfile
    if dryrun is not None:
        conf.network_import.dryrun = dryrun
    if max_size_change is not None:
        conf.network_import.max_size_change = max_size_change

    cmd = NetworkImport(conf)
    cmd()


if __name__ == "__main__":
    main()
