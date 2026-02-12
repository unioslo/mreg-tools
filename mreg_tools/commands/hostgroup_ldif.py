from __future__ import annotations

import io
from typing import Annotated
from typing import Final
from typing import NotRequired
from typing import TypedDict
from typing import final
from typing import override

import structlog.stdlib
import typer
from mreg_api.models import HostGroup

from mreg_tools.app import app
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.common.ldif import LDIFBase
from mreg_tools.common.ldif import entry_string
from mreg_tools.common.ldif import to_iso646_60
from mreg_tools.config import Config
from mreg_tools.config import HostGroupLdifConfig

COMMAND_NAME: Final[str] = "hostgroup-ldif"

# Logger for the module independent of the LDIFBase logger
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class HostGroupLdifEntry(TypedDict):
    """Host group LDIF entry structure."""

    dn: str
    cn: str
    description: str | None
    objectClass: list[str]
    memberNisNetgroup: NotRequired[list[str]]
    nisNetgroupTriple: NotRequired[list[str]]


class HostGroupDataStorage(MregDataStorage):
    """Storage for fetched host group data."""

    def __init__(self, hostgroups: MregData[HostGroup]) -> None:
        self.hostgroups = hostgroups


@final
class HostGroupLDIF(LDIFBase[HostGroupDataStorage]):
    """Host group LDIF generator."""

    def __init__(self, app_config: Config) -> None:
        super().__init__(app_config)
        self.data = HostGroupDataStorage(
            hostgroups=MregData(
                name="hostgroups",
                type=HostGroup,
                default=[],
                first_func=self.client.host_group.get_first,
                get_func=self.client.host_group.get_list,
                count_func=self.client.host_group.get_count,
            )
        )
        self.domain: str = self.config.mreg.domain
        if self.domain and not self.domain.startswith("."):
            self.domain = f".{self.domain}"

    @property
    @override
    def command(self) -> str:
        return "hostgroup-ldif"

    @property
    @override
    def command_config(self) -> HostGroupLdifConfig:
        return self._app_config.hostgroup_ldif

    @override
    def create_ldif(self) -> io.StringIO:
        """Create the LDIF file from fetched data."""
        # Collect the LDIF entries
        entries: list[HostGroupLdifEntry] = []
        for hostgroup in self.data.hostgroups.data:
            entry = self.hostgroup_to_ldif_entry(hostgroup)
            entries.append(entry)

        # Construct the string to write to the LDIF file
        ldifs = io.StringIO()
        if self.config.ldif.make_head_entry:
            ldifs.write(entry_string(self.get_head_entry()))
        for entry in entries:
            ldifs.write(entry_string(entry))
        return ldifs

    def hostgroup_to_ldif_entry(self, hostgroup: HostGroup) -> HostGroupLdifEntry:
        # Determine description before creating the entry to guarantee
        # ordering of fields, so we maintain parity with the old script
        if hostgroup.description:
            if self.config.encoding == "ascii":
                description = to_iso646_60(hostgroup.description)
            else:
                description = hostgroup.description
        else:
            description = None
        entry: HostGroupLdifEntry = {
            "dn": f"cn={hostgroup.name},{self.config.ldif.dn}",
            "cn": hostgroup.name,
            "description": description,
            "objectClass": self.config.ldif.objectClass,
            "memberNisNetgroup": hostgroup.groups,  # omitted if empty
        }

        if hostgroup.hosts:
            triple: list[str] = []
            for hostname in hostgroup.hosts:
                if self.domain and hostname.endswith(self.domain):
                    # NOTE: this does not handle domains such as ifi.uio.no.
                    # the resulting "short name" is then <hostname>.ifi
                    # This behavior was present in the old script and is kept
                    # for parity with that version. Should this be improved?
                    short = hostname.removesuffix(self.domain)
                    triple.append(f"({short},-,)")
                triple.append(f"({hostname},-,)")
            entry["nisNetgroupTriple"] = triple
        return entry


@app.command("hostgroup-ldif", help="Export hostgroups from mreg as a ldif.")
def main(
    config: Annotated[
        str | None,
        typer.Option("--config", help="(DEPRECATED) path to config file", hidden=True),
    ] = None,
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="force refresh of data from mreg"),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="ignore size changes when writing the LDIF file",
        ),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="force use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
    filename: Annotated[
        str | None,
        typer.Option(
            "--filename",
            help="output filename for the ldif file",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.hostgroup_ldif.force_check = force_check
    if ignore_size_change is not None:
        conf.hostgroup_ldif.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.hostgroup_ldif.use_saved_data = use_saved_data
    if filename is not None:
        conf.hostgroup_ldif.filename = filename

    cmd = HostGroupLDIF(conf)
    with app.lock(cmd.config.workdir, COMMAND_NAME):
        cmd()


if __name__ == "__main__":
    main()
