from __future__ import annotations

from mreg_api import MregClient
from mreg_api.exceptions import LoginFailedError

from mreg_tools.config import MregConfig
from mreg_tools.output import exit_err


def _get_client(config: MregConfig) -> MregClient:
    """Create an MregClient from an MregConfig."""
    MregClient.reset_instance()
    return MregClient(
        url=config.url,
        timeout=600,  # TODO: make configurable
        page_size=config.page_size,
    )


def get_client_and_login(config: MregConfig) -> MregClient:
    """Create and log in an MregClient from an MregConfig."""
    client = _get_client(config)
    try:
        client.login(username=config.username, password=config.get_password())
    except LoginFailedError as e:
        exit_err(f"Failed to log in to MREG: {e}")
    except Exception as e:
        exit_err(f"Failed to log in to MREG: {e}", exc_info=True)
    return client
