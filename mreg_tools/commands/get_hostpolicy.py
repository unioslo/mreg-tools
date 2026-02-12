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
        self.create_role_csv(self.data.roles.data)
        self.create_atom_csv(self.data.atoms.data)

    def role_csv_str(self, role: Role) -> str:
        """Create a CSV-formatted line for a given role."""
        return (
            f"{role.name};{role.description};;"  # NOTE: why double ;;?
            f"{role.created_at};{','.join(role.atoms)}\n"
        )

    def role_atom_csv_str(self, role: Role, atom: str) -> str:
        """Create a CSV-formatted line for a role-atom relationship."""
        return f"{role.name};hostpol_contains;{atom}\n"

    def host_roles_csv_str(self, host: str, policies: list[str]) -> str:
        """Create a CSV-formatted line for a host and its associated roles."""
        return f"{host};{','.join(policies)}\n"

    def create_atom_csv(self, atoms: list[Atom]) -> None:
        """Create the CSV file for atoms."""
        atom_csv = io.StringIO()
        for atom in atoms:
            atom_csv.write(f"{atom.name};{atom.description};;{atom.created_at}\n")
        self.write(atom_csv, filename="atoms.csv")

    def create_role_csv(
        self,
        roles: list[Role],
    ) -> None:
        """Create the CSV files for roles, hostpolicies, and role:atom relationships."""
        # String builders for the three CSV files
        roles_csv = io.StringIO()
        policies_csv = io.StringIO()
        relationships_csv = io.StringIO()

        # Map of hosts to their associated roles, used to build hostpolicies.csv
        host_map = defaultdict[str, list[str]](list)

        for role in roles:
            # Build roles.csv
            roles_csv.write(self.role_csv_str(role))

            # Build relationships.csv
            for atom in role.atoms:
                relationships_csv.write(self.role_atom_csv_str(role, atom))

            for host in role.hosts:  # Add role to host map for each host
                host_map[host].append(role.name)

        # Build hostpolicies.csv
        for host in sorted(host_map):
            role_names = host_map[host]
            policies_csv.write(self.host_roles_csv_str(host, role_names))

        self.write(roles_csv, filename="roles.csv")
        self.write(policies_csv, filename="hostpolicies.csv")
        self.write(relationships_csv, filename="relationships.csv")


@app.command(COMMAND_NAME, help="Export host info from mreg as a textfiles.")
def main(
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
        conf.get_hostpolicy.force_check = force_check
    if ignore_size_change is not None:
        conf.get_hostpolicy.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.get_hostpolicy.use_saved_data = use_saved_data
    if filename is not None:
        conf.get_hostpolicy.filename = filename

    cmd = GetHostPolicy(conf)
    with app.lock(cmd.config.workdir, COMMAND_NAME):
        cmd()


if __name__ == "__main__":
    main()
