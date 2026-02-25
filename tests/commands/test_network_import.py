from __future__ import annotations

import ipaddress
from datetime import datetime

from mreg_api.models import IPAddress
from mreg_api.models import Network

from mreg_tools.commands.network_import import ImportedNetwork


def test_network_modification_number_of_changes():
    from mreg_tools.commands.network_import import NetworkModifications

    n = Network.dummy_network_from_ip(
        IPAddress(
            host=123,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            id=1234,
            ipaddress=ipaddress.IPv4Address("127.0.0.1"),
        )
    )
    i = ImportedNetwork(
        network="127.0.0.0/24",
        description="Test network",
        category="t1",
        location="tst",
        vlan=123,
    )
    # Frozen dataclass: Need to serialize to copy with modifications
    d = i.asdict()
    d["network"] = "127.0.1.0/24"
    i2 = ImportedNetwork(**d)

    mods = NetworkModifications(
        # This doesn't count towards changes:
        keep={n},
        # These count towards changes:
        create={i, i2},  # +2 = 2
        delete={n, n.model_copy(update={"id": 1235})},  # +2 = 4
        patch=[(n, {"spam": "eggs"}), (n, {"foo": "bar"})],  # +2 = 6
        # Init defaultdicts as normal dicts to avoid overly verbose inline types:
        grow={i: [{n}], i2: [{n}]},  # +2 = 8  # pyright: ignore[reportArgumentType]
        shrink={
            n: [i, i2],
            n.model_copy(update={"id": 1236}): [i, i2],
        },  # +2 = 10  # pyright: ignore[reportArgumentType]
    )
    assert mods.number_of_changes() == 10
