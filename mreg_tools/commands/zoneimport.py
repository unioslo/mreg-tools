from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Annotated
from typing import Final
from typing import final
from typing import override

import dns.rdatatype
import dns.zone
import structlog.stdlib
import typer
from dns.rdata import Rdata

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import ZoneImportConfig
from mreg_tools.output import exit_err

KNOWN_ZONES = (".uio.no",)

SUPPORTED_DATATYPES = (
    dns.rdatatype.SOA,
    dns.rdatatype.NS,
    dns.rdatatype.A,
    dns.rdatatype.AAAA,
    dns.rdatatype.CNAME,
    dns.rdatatype.MX,
    dns.rdatatype.NAPTR,
    dns.rdatatype.PTR,
    dns.rdatatype.SRV,
    dns.rdatatype.TXT,
)


def strip_trailing_dot(data: str) -> str:
    return data.rstrip(".")


def ip_from_reverse(rev: str) -> str:
    ip = ""
    if rev.endswith("ip6.arpa."):
        rev = rev.replace(".ip6.arpa.", "")
        splitted = rev.split(".")
        it = reversed(splitted)
        for i in it:
            if ip:
                ip += ":"
            ip += "%s%s%s%s" % (i, next(it, "0"), next(it, "0"), next(it, "0"))
    elif rev.endswith("in-addr.arpa."):
        ip = ".".join(reversed(rev.split(".")[0:4]))
    return str(ipaddress.ip_address(ip))


COMMAND_NAME: Final[str] = "zoneimport"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)

RdataTuple = tuple[int, Rdata]


@dataclass
class ImportedHost:
    name: str
    ttl: int
    ptrs: list[str] = field(default_factory=list)
    ips: list[Rdata] = field(default_factory=list)
    cnames: list[Rdata] = field(default_factory=list)
    srvs: list[Rdata] = field(default_factory=list)
    mxs: list[Rdata] = field(default_factory=list)
    naptrs: list[Rdata] = field(default_factory=list)
    txts: list[Rdata] = field(default_factory=list)


@dataclass
class ImportedZone:
    name: str
    email: str
    nameservers: list[str]
    ttl: int
    primary_ns: str | None = None
    email: str | None = None
    serialno: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    soa_ttl: int | None = None


@final
class ZoneFile:
    """Class representing a zone file to import.

    Can be a single file or a directory of files.
    """

    def __init__(self, zonefile: Path):
        self.zonefile = zonefile
        self.files: list[Path] = []

    def iter_files(self) -> list[Path]:
        """Iterate over the zone files to import."""
        if self.zonefile.is_file():
            logger.debug("Importing single zone file", zonefile=self.zonefile)
            return [self.zonefile]
        elif self.zonefile.is_dir():
            files = list(self.zonefile.glob("*"))
            logger.debug(
                "Importing zone files from directory", zonefile=self.zonefile, files=files
            )
            return files
        else:
            raise ValueError(f"Invalid zone file path: {self.zonefile}")


class ZoneDataStorage(MregDataStorage):
    """Empty class to satisfy the restrictive generic type of CommandBase."""


@final
class ZoneImport(CommandBase[ZoneDataStorage]):
    """zoneimport command class."""

    def __init__(self, app_config: Config):
        super().__init__(app_config)
        self.data = ZoneDataStorage()
        self.hosts: dict[str, ImportedHost] = {}

        if not self.command_config.zonefile:
            exit_err(
                (
                    "Must specify a zone file to import as first argument or in configuration file -> \n"
                    "  [zoneimport]\n"
                    "  zonefile = /path/to/zonefile\n"
                ),
                escape=True,
            )

        self.zonefile = ZoneFile(self.command_config.zonefile)
        self.console = app.get_console()
        self.dryrun = self.command_config.dryrun

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> ZoneImportConfig:
        return self._app_config.zoneimport

    @override
    def run(self) -> None:
        pass

    def get_host(self, name: str, ttl: int) -> ImportedHost:
        """Get or create a host with the given name and TTL.

        If a host with the given name already exists, it is returned.
        Otherwise, a new host is created with the given name and TTL,
        stored in the hosts dictionary, and returned.
        """
        if name in self.hosts:
            return self.hosts[name]
        host = ImportedHost(name=name, ttl=ttl)
        self.hosts[name] = host
        return host

    def generate_import_commands(self) -> None:
        """Create the zone files for all configured zones."""
        for zone_file in self.zonefile.iter_files():
            try:
                self.import_zone(zone_file)
            except Exception as e:
                exit_err(f"Failed to process zone file {zone_file}: {e}")

    def import_zone(self, zone_file: Path) -> None:
        """Import a single zone file."""
        zone = dns.zone.from_file(zone_file, relativize=False)

        zonename = str(zone.origin)[:-1]
        soans: list[RdataTuple] = []
        delegations = defaultdict[str, list[RdataTuple]](list)

        for name, ttl, data in zone.iterate_rdatas():
            name = name.to_text()
            if data.rdtype not in SUPPORTED_DATATYPES:
                self.console.print(f"NOT supported: {data!r}")

            if data.rdtype == dns.rdatatype.SOA:
                soadata = data
            elif data.rdtype == dns.rdatatype.NS:
                name = strip_trailing_dot(name)
                if name == zonename:
                    soans.append((ttl, data))
                    continue
                delegations[name].append((ttl, data))
            elif (
                target := str(getattr(data, "target", "")) or None
            ) and data.rdtype == dns.rdatatype.PTR:
                revip = str(name).lower()
                ip = ip_from_reverse(revip)
                host = self.get_host(target, ttl)
                host.ptrs.append(ip)
            elif target:
                host = self.get_host(target, ttl)
                if data.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    host.ips.append(data)
                elif data.rdtype == dns.rdatatype.TXT:
                    host.txts.append(data)
                elif data.rdtype == dns.rdatatype.MX:
                    host.mxs.append(data)
                elif data.rdtype == dns.rdatatype.SRV:
                    host.srvs.append(data)
                elif data.rdtype == dns.rdatatype.CNAME:
                    host.cnames.append(data)
                elif data.rdtype == dns.rdatatype.NAPTR:
                    host.naptrs.append(data)
                else:
                    print(f"Unhandled rdata type: {data.rdtype!r}, {data}")
            else:
                print(
                    f"Unhandled record without target hostname: {data.rdtype!r}, {data}"
                )

        # Replace first . with a @
        email = re.sub(r"\.", "@", strip_trailing_dot(soadata.rname), 1)
        nameservers = [strip_trailing_dot(str(i[1])) for i in soans]
        zone = self.client.zone.create_zone(
            zonename, email, primary_ns=nameservers, force=False
        )

        zone.update_soa(
            expire=getattr(soadata, "expire", None),
            retry=getattr(soadata, "retry", None),
            refresh=getattr(soadata, "refresh", None),
        )
        tmp = ""
        for attr in ("expire", "retry", "refresh"):
            tmp += f" -{attr} " + str(getattr(soadata, attr))
        print(f"zone set_soa {zonename} {tmp}")
        print(f"zone set_default_ttl {zonename} {soadata.minimum}")

        for name, nsdata in delegations.items():
            nameservers = " ".join([strip_trailing_dot(str(i[1])) for i in nsdata])
            print(f"zone delegation_create {zonename} {name} {nameservers}")

        for hostname, imported_host in self.hosts.items():
            host = self.client.host.get_by_any_means_or_raise(hostname)
            hostname = str(hostname)
            cmds = []
            for ip in imported_host.ips:
                ip = str(ip)
                ip_obj = ipaddress.ip_address(ip)
                logger.info("Adding IP address to host", hostname=host.name, ip=ip)
                if not self.dryrun:
                    host.add_ip(ip_obj)

            for mx in imported_host.mxs:
                exchange = strip_trailing_dot(mx.exchange)
                self.client.host.patch(
                    hostname,
                    {"mxs": [{"preference": mx.preference, "exchange": exchange}]},
                )
                cmds.append(f"host mx_add {hostname} {mx.preference} {exchange}")
            for realname in imported_host.cnames:
                cmds.append(f"host cname_add {realname} {hostname}")
            for txt in imported_host.txts:
                cmds.append(f"host txt_add {hostname} {txt}")
            for ptr in imported_host.ptrs:
                cmds.append(f"host ptr_add {ptr} {hostname} -force")
            for srv in imported_host.srvs:
                cmd = (
                    f"host srv_add -name {hostname} -priority {srv.priority} -weight {srv.weight} "
                    f"-port {srv.port} -host {srv.target}"
                )
                cmds.append(cmd)
            for naptr in imported_host.naptrs:
                flags = naptr.flags.decode("utf-8")
                service = naptr.service.decode("utf-8")
                regex = naptr.regexp.decode("utf-8")
                cmd = (
                    f"host naptr_add -name {hostname} -preference {naptr.preference} "
                    f"-order {naptr.order} -flag {flags} -service {service!r} "
                    f"-regex {regex!r} -replacement {naptr.replacement}"
                )
                cmds.append(cmd)
            if cmds and not (host.cnames or host.srvs):
                force = ""
                for zone in KNOWN_ZONES:
                    if hostname.endswith(zone):
                        break
                else:
                    force = "-force"
                cmds.insert(0, f"host add {hostname} {force}")
                if host.ttl != soadata.minimum:
                    cmds.append(f"host ttl_set {hostname} {host.ttl}")
            for cmd in cmds:
                print(cmd)


@app.command(
    COMMAND_NAME,
    help="Import zone files into mreg.",
)
def main(
    zonefile: Annotated[
        Path | None,
        typer.Argument(help="Path to the zone file or directory of files to import."),
    ] = None,
    dryrun: Annotated[
        bool | None,
        typer.Option(
            "--dry-run",
            "--dryrun",
            help="Perform a dry run without making changes to mreg",
        ),
    ] = None,
):
    conf = app.get_config()
    exit_err("This command is not yet implemented. If you need this, contact DIA.")
    # if zonefile is not None:
    #     conf.zoneimport.zonefile = zonefile
    # if dryrun is not None:
    #     conf.zoneimport.dryrun = dryrun

    # cmd = ZoneImport(conf)
    # cmd()
