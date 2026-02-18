"""Command modules for the CLI.

Each module defines a command that is registered to the global app object.
This module must be imported in order to register the commands.
"""

from __future__ import annotations

from mreg_tools.commands import get_hostinfo
from mreg_tools.commands import get_hostpolicy
from mreg_tools.commands import get_zonefiles
from mreg_tools.commands import hostgroup_ldif
from mreg_tools.commands import hosts_ldif
from mreg_tools.commands import network_ldif

__all__ = [
    "get_hostpolicy",
    "get_hostinfo",
    "get_zonefiles",
    "hosts_ldif",
    "hostgroup_ldif",
    "network_ldif",
]
