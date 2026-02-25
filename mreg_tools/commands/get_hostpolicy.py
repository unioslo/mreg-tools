from __future__ import annotations

import io
from collections import defaultdict
from typing import Annotated
from typing import Final
from typing import final
from typing import override

import structlog.stdlib
import typer
from mreg_api.models import Atom
from mreg_api.models import Role

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import GetHostPolicyConfig

COMMAND_NAME: Final[str] = "get-hostpolicy"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class HostDataStorage(MregDataStorage):
    """Storage for fetched host data."""

    def __init__(self, roles: MregData[Role], atoms: MregData[Atom]) -> None:
        self.roles = roles
        self.atoms = atoms


@final
class GetHostPolicy(CommandBase[HostDataStorage]):
    """get-hostpolicy command class."""

    def __init__(self, app_config: Config):
        super().__init__(app_config)
        self.data = HostDataStorage(
            roles=MregData(
                name="roles",
                type=Role,
                default=[],
                first_func=self.client.role.get_first,
                get_func=self.client.role.get_list,
                count_func=self.client.role.get_count,
            ),
            atoms=MregData(
                name="atoms",
                type=Atom,
                default=[],
                first_func=self.client.atom.get_first,
                get_func=self.client.atom.get_list,
                count_func=self.client.atom.get_count,
            ),
        )

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> GetHostPolicyConfig:
        return self._app_config.get_hostpolicy

    @override
    def run(self) -> None:
        self.create_roles_csv(self.data.roles.data)
        self.create_policies_csv(self.data.roles.data)
        self.create_relationships_csv(self.data.roles.data)
        self.create_atom_csv(self.data.atoms.data)

    def create_atom_csv(self, atoms: list[Atom]) -> None:
        """Create the CSV file for atoms."""
        content = io.StringIO()
        for atom in atoms:
            content.write(f"{atom.name};{atom.description};;{atom.created_at}\n")
        self.write(content, filename="atoms.csv")

    def create_policies_csv(
        self,
        roles: list[Role],
    ) -> None:
        """Create the CSV file for hosts and their policies (roles)."""
        content = io.StringIO()

        # Map of hosts to their associated roles, used to build hostpolicies.csv
        host_map = defaultdict[str, list[str]](list)

        #
        for role in roles:
            for host in role.hosts:  # Add role to host map for each host
                host_map[host].append(role.name)

        for host in sorted(host_map):
            role_names = host_map[host]
            # NOTE: There is a period symbol following the host name.
            #       This behavior is ported from the original script.
            #       I don't know why it's there.
            content.write(f"{host}.;{','.join(role_names)}\n")

        self.write(content, filename="hostpolicies.csv")

    def create_relationships_csv(
        self,
        roles: list[Role],
    ) -> None:
        """Create the CSV file for role-atom relationships."""
        content = io.StringIO()
        for role in roles:
            for atom in role.atoms:
                content.write(f"{role.name};hostpol_contains;{atom}\n")
        self.write(content, filename="relationships.csv")

    def create_roles_csv(
        self,
        roles: list[Role],
    ) -> None:
        """Create the CSV file of all roles and their associated atoms."""
        content = io.StringIO()
        for role in roles:
            content.write(
                (
                    f"{role.name};{role.description};;"  # NOTE: why double ;;?
                    f"{role.created_at};{','.join(role.atoms)}\n"
                )
            )
        self.write(content, filename="roles.csv")


@app.command(
    COMMAND_NAME, help="Export roles, atoms and host policies from mreg as CSV files."
)
def main(
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="Force refresh of data from mreg"),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="Ignore size changes when writing the output files",
        ),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="Force use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.get_hostpolicy.force_check = force_check
    if ignore_size_change is not None:
        conf.get_hostpolicy.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.get_hostpolicy.use_saved_data = use_saved_data

    cmd = GetHostPolicy(conf)
    cmd()


if __name__ == "__main__":
    main()
