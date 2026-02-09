from __future__ import annotations

from mreg_api import MregClient

from mreg_tools.config import MregConfig
from mreg_tools.output import err_console


def _get_client(config: MregConfig) -> MregClient:
    """Create a MregClient from a MregConfig."""
    MregClient.reset_instance()
    return MregClient(
        url=config.url,
        timeout=600,  # TODO: make configurable?
        page_size=config.page_size,
    )


def get_client_and_login(config: MregConfig) -> MregClient:
    """Create and log in a MregClient from a MregConfig."""
    client = _get_client(config)
    try:
        client.login(username=config.username, password=config.get_password())
    except Exception as e:
        # TODO: use error printing function to print this!
        err_console.print(f"ERROR: Failed to log in to MREG: {e}")
        raise
    return client
