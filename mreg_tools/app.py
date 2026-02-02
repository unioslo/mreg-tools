from __future__ import annotations

import typer
from mreg_api import MregClient

from mreg_tools.config import Config
from mreg_tools.config import MregConfig


class MregToolsApp(typer.Typer):
    _config: Config | None = None  # Set by main callback
    _client: MregClient | None = None

    def set_config(self, config: Config) -> None:
        self._config = config

    def get_config(self) -> Config:
        if self._config is None:
            raise RuntimeError("Config not set")
        return self._config

    def login(self, mreg_config: MregConfig | None = None) -> None:
        """Alias for instantiating client and logging in without returning it."""
        _ = self.get_client(mreg_config)

    def get_client(self, mreg_config: MregConfig | None = None) -> MregClient:
        """Get the MREG API client. Creates new client and logs in if it doesn't exist.

        Args:
            mreg_config (MregConfig | None, optional): Alternative MREG config to pass in. Defaults to None.

        Returns:
            MregClient: Client instance
        """
        if mreg_config:
            return self._client_from_config(mreg_config)
        elif not self._client:
            self._client = self._client_from_config(self.get_config().mreg)
        return self._client

    def _client_from_config(self, config: MregConfig) -> MregClient:
        MregClient.reset_instance()
        client = MregClient(
            url=config.url,
            timeout=600,  # TODO: make configurable?
            page_size=config.page_size,
        )
        client.login(username=config.username, password=config.get_password())
        return client


app = MregToolsApp(
    help="mreg-tools",
    add_completion=False,
    no_args_is_help=True,
)
