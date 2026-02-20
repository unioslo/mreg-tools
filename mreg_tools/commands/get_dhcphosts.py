from __future__ import annotations

import io
from collections import defaultdict
from typing import Annotated, NamedTuple
from typing import Final
from typing import Sequence
from typing import final
from typing import override

from mreg_api.models.fields import MacAddress
from mreg_api.types import IP_AddressT
import structlog.stdlib
import typer
from mreg_api.models import DhcpHost
from mreg_api.models import DhcpHostIPv4
from mreg_api.models import DhcpHostIPv6
from mreg_api.models import DhcpHostIPv6ByIPv4

from mreg_tools.app import app
from mreg_tools.common.base import CommandBase
from mreg_tools.common.base import MregData
from mreg_tools.common.base import MregDataStorage
from mreg_tools.config import Config
from mreg_tools.config import GetDhcpHostsConfig
from mreg_tools.types import DhcpHostsType

COMMAND_NAME: Final[str] = "get-dhcphosts"
logger = structlog.stdlib.get_logger(command=COMMAND_NAME)


class DhcpHostStorage(MregDataStorage):
    """Storage for fetched dhcp hosts data."""

    def __init__(
        self,
        dhcp_hosts: MregData[DhcpHostIPv4]
        | MregData[DhcpHostIPv6]
        | MregData[DhcpHostIPv6ByIPv4],
    ) -> None:
        self.dhcp_hosts = dhcp_hosts


def mock_count() -> int:
    """Mock count function that always returns 0."""
    # NOTE: dhcphosts endpoint does not support pagination nor count
    # so get_first and get_count return
    return 0


@final
class GetDhcpHosts(CommandBase[DhcpHostStorage]):
    """get-dhcphosts command class."""

    def __init__(self, app_config: Config):
        # TODO: warn that this command should have caching enabled, so that
        #       we can call get_count without actually making an extra API call
        super().__init__(app_config)
        hosts_type = self.command_config.hosts
        if hosts_type == DhcpHostsType.IPV4:
            dhcp_hosts = MregData(
                name="dhcp_hosts_ipv4",
                type=DhcpHostIPv4,
                default=[],
                first_func=self.client.dhcp_host_ipv4.get_first,
                get_func=self.client.dhcp_host_ipv4.get_list,
                count_func=self.client.dhcp_host_ipv4.get_count,
            )
        elif hosts_type == DhcpHostsType.IPV6:
            dhcp_hosts = MregData(
                name="dhcp_hosts_ipv6",
                type=DhcpHostIPv6,
                default=[],
                first_func=self.client.dhcp_host_ipv6.get_first,
                get_func=self.client.dhcp_host_ipv6.get_list,
                count_func=self.client.dhcp_host_ipv6.get_count,
            )
        elif hosts_type == DhcpHostsType.IPV6BYIPV4:
            dhcp_hosts = MregData(
                name="dhcp_hosts_ipv6byipv4",
                type=DhcpHostIPv6ByIPv4,
                default=[],
                first_func=self.client.dhcp_host_ipv6byipv4.get_first,
                get_func=self.client.dhcp_host_ipv6byipv4.get_list,
                count_func=self.client.dhcp_host_ipv6byipv4.get_count,
            )
        else:
            raise ValueError(f"Invalid hosts type: {hosts_type}")

        self.data = DhcpHostStorage(dhcp_hosts=dhcp_hosts)

    @override
    def should_run_postcommand(self) -> bool:
        """Run post-command if any zones were updated."""
        return self.is_updated

    @property
    @override
    def command(self) -> str:
        return COMMAND_NAME

    @property
    @override
    def command_config(self) -> GetDhcpHostsConfig:
        return self._app_config.get_dhcphosts

    @override
    def run(self) -> None:
        self.create_dhcp_files(self.data.dhcp_hosts.data)

    def create_dhcp_files(self, hosts: Sequence[DhcpHost]) -> None:
        """Create the DHCP config files for all configured hosts."""
        # Categorize hosts by domain
        dhcphosts = defaultdict[str, list[DhcpHost]](list)
        added = set[str]()
        for host in hosts:
            if host.zone is not None:
                domain = host.zone
            else:
                if host.name.count(".") > 1:
                    # domain = host.name.partition(".")[2]
                    domain = host.name.split(".", 1)[1]
                else:
                    domain = host.name
            dhcphosts[domain].append(host)

        for domain, hosts in dhcphosts.items():
            self.create_dhcp_file_for_domain(domain, hosts)

    def create_dhcp_file_for_domain(self, domain: str, hosts: list[DhcpHost]) -> None:
        """Create the DHCP config file for a given domain."""
        added = set[str]()
        content = io.StringIO()
        content.write("group { \n")
        content.write(f'    option domain-name "{domain}";\n\n')
        for host in hosts:
            if host.ipaddress.version == 6 and self.command_config.use_option79:
                # Handle IPv6 with v6relopt (RFC6939):
                # host-identifier v6relopt 1 dhcp6.client-linklayer-addr 00:01:XX:XX:XX:XX:XX:XX;
                # Explanation:
                # - '00:01' => ARP hardware type = 1 (Ethernet)
                # - Followed by the actual 6-byte MAC
                mac79 = ":".join(["0", "1", *host.macaddress.split(":")])
                content.write(f"    host {host.name} {{\n")
                content.write(
                    f"        host-identifier v6relopt 1 dhcp6.client-linklayer-addr {mac79};\n"
                )
                content.write(f"        fixed-address6 {host.ipaddress};\n")
                content.write("    }\n")
            else:
                if host.name in added:
                    # If the hostname is already added, we need to make it unique by appending the MAC address without colons
                    host_name = f"{host.name}-{host.macaddress.replace(':', '')}"
                else:
                    host_name = host.name
                    added.add(host_name)
                content.write(
                    f"    host {host_name} {{ hardware ethernet {host.macaddress}; fixed-address{'6' if host.ipaddress.version == 6 else ''} {host.ipaddress}; }}\n"
                )
        content.write("}\n")
        self.write(content, filename=domain)


@app.command(COMMAND_NAME, help="Create dhcp config from mreg.")
def main(
    force_check: Annotated[
        bool | None,
        typer.Option("--force", "--force-check", help="force refresh of data from mreg"),
    ] = None,
    ignore_size_change: Annotated[
        bool | None,
        typer.Option(
            "--ignore-size-change",
            help="ignore size changes when writing the zone files",
        ),
    ] = None,
    use_saved_data: Annotated[
        bool | None,
        typer.Option(
            "--use-saved-data",
            help="force use saved data from previous runs. Takes precedence over --force",
        ),
    ] = None,
    hosts: Annotated[
        DhcpHostsType | None, typer.Option("--hosts", help="which hosts to export")
    ] = None,
):
    # Get config and add overrides from command line
    conf = app.get_config()
    if force_check is not None:
        conf.get_dhcphosts.force_check = force_check
    if ignore_size_change is not None:
        conf.get_dhcphosts.ignore_size_change = ignore_size_change
    if use_saved_data is not None:
        conf.get_dhcphosts.use_saved_data = use_saved_data
    if hosts is not None:
        conf.get_dhcphosts.hosts = hosts
    cmd = GetDhcpHosts(conf)
    cmd()


if __name__ == "__main__":
    main()
