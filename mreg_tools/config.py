"""Configuration classes for mreg-tools commands."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Literal
from typing import NamedTuple
from typing import Self
from typing import override

from pydantic import AfterValidator
from pydantic import AliasChoices
from pydantic import BaseModel
from pydantic import Field
from pydantic import SecretStr
from pydantic import field_validator
from pydantic_settings import BaseSettings
from pydantic_settings import PydanticBaseSettingsSource
from pydantic_settings import SettingsConfigDict
from pydantic_settings import TomlConfigSettingsSource

from mreg_tools.constants import DEFAULT_CONFIG_PATHS
from mreg_tools.constants import DEFAULT_DESTDIR
from mreg_tools.constants import DEFAULT_LOGDIR
from mreg_tools.constants import DEFAULT_WORKDIR
from mreg_tools.types import LDIFEntryValue

logger = logging.getLogger(__name__)


def to_path(value: Any) -> Path:
    """Convert a value to a Path object with expanded user and resolved symlinks."""
    try:
        p = Path(value)
        try:
            p = p.expanduser()
        except RuntimeError:  # no homedir
            pass
        return p.resolve()
    except Exception as e:
        raise ValueError(f"Invalid path {value}: {e}") from e


def to_path_optional(value: Any) -> Path | None:
    """Convert a value to a Path with user expansion and resolved symlinks, or None."""
    if value is None:
        return None
    return to_path(value)


ResolvedPath = Annotated[Path, AfterValidator(to_path_optional)]
"""Path type that is user expanded (~) and resolved (absolute) after validation."""


class MregConfig(BaseModel):
    """MREG API connection settings."""

    url: str = Field(default="https://mreg.uio.no", description="MREG API URL")
    username: str = Field(default="mreguser", description="MREG username")
    timeout: int = Field(default=20, description="API timeout in seconds")
    passwordfile: ResolvedPath | None = Field(
        default=None, description="Path to password file"
    )
    password: SecretStr | None = Field(
        default=None, description="MREG password (overrides passwordfile)"
    )
    page_size: int = Field(default=1000, description="Page size for API requests")

    def get_password(self) -> str:
        """Retrieve the password from the passwordfile or the password field."""
        if self.password is not None:
            return self.password.get_secret_value()
        elif self.passwordfile is not None:
            return self._read_passwordfile()
        else:
            raise ValueError("No password or passwordfile specified in MREG config")

    def _read_passwordfile(self) -> str:
        """Read the password from the passwordfile."""
        if self.passwordfile is None:
            raise ValueError("No passwordfile specified in MREG config")
        try:
            with self.passwordfile.open("r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            raise ValueError(
                f"Could not read password from file {self.passwordfile}: {e}"
            ) from e


class PathsConfig(BaseModel):
    """Path settings for working directories."""

    workdir: ResolvedPath = Field(
        default=DEFAULT_WORKDIR,
        description="Working directory for the command",
    )
    destdir: ResolvedPath = Field(
        default=DEFAULT_DESTDIR,
        description="Destination directory for output",
    )
    logdir: ResolvedPath = Field(
        default=DEFAULT_LOGDIR,
        description="Log directory for the command",
    )

    def dest(self, filename: str) -> Path:
        """Get the full path to a file in the destination directory."""
        return self.destdir / filename

    def work(self, filename: str) -> Path:
        """Get the full path to a file in the working directory."""
        return self.workdir / filename

    def log(self, filename: str) -> Path:
        """Get the full path to a file in the log directory."""
        return self.logdir / filename

    def create_dirs(self) -> None:
        """Create the workdir, destdir, and logdir if they don't exist."""
        for path in (self.workdir, self.destdir, self.logdir):
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                logger.info("Created directory: %s", str(path))


class CommandConfig(BaseModel):
    """Base configuration for all commands with optional overrides."""

    mreg: MregConfig | None = Field(
        default=None,
        description="MREG settings override for this command",
    )
    paths: PathsConfig | None = Field(
        default=None,
        description="Path settings override for this command",
    )
    postcommand: list[str] = Field(
        default_factory=list, description="Command to run after main command"
    )


class LdifSettings(BaseModel):
    """LDIF-specific settings for LDAP export commands."""

    dn: str = Field(default="", description="Distinguished name for the LDIF entry")
    cn: str = Field(default="", description="Common name")
    description: str = Field(default="", description="Description")
    ou: str | None = Field(default=None, description="Organizational unit")
    # TODO: add normalization for objectClass as str or list[str]
    objectClass: list[str] = Field(default=["top"], description="Object class(es)")

    @field_validator("objectClass", mode="before")
    @classmethod
    def normalize_object_class(cls, v: Any) -> list[str]:
        """Parse objectClass given as string, list, or tuple literal."""
        if isinstance(v, str) and v.startswith("(") and v.endswith(")"):
            # If argument is in tuple literal format, strip and split it
            v = [item for item in v.strip("() ").replace("'", "").split(",") if item]
        if isinstance(v, str):
            v = [v]
        return v

    def as_head_entry(self) -> dict[str, LDIFEntryValue]:
        """Return the LDIF head entry as a dictionary of LDIF entry primitive values."""
        return self.model_dump(mode="json")


class GetDhcphostsConfig(CommandConfig):
    """Configuration for get-dhcphosts command."""

    hosts: Literal["ipv4", "ipv6", "all"] = Field(
        default="ipv4",
        description="IP version to export",
    )


class GetHostinfoConfig(CommandConfig):
    """Configuration for get-hostinfo command."""

    encoding: str = Field(
        default="utf-8",
        description="File encoding for output files",
    )


class GetHostpolicyConfig(CommandConfig):
    """Configuration for get-hostpolicy command."""

    encoding: str = Field(
        default="utf-8",
        description="File encoding for output files",
    )


class ExportedZone(NamedTuple):
    """Representation of an exported DNS zone."""

    zone: str
    destname: str


class GetZonefilesConfig(CommandConfig):
    """Configuration for get-zonefiles command."""

    extradir: ResolvedPath | None = Field(
        default=None,
        description="Extra directory for additional files",
    )
    zones: list[ExportedZone] = Field(
        default_factory=list,
        description="Zones to export (use 'zone=destname' to override output filename)",
    )
    zones_exclude_private: list[ExportedZone] = Field(
        default_factory=list,
        description="Zones to export with private address ranges (RFC 1918) excluded",
    )

    @field_validator("zones", "zones_exclude_private", mode="before")
    @classmethod
    def parse_zones(cls, v: Any) -> list[ExportedZone]:
        """Parse zone specifications from strings or ExportedZone objects."""
        if not isinstance(v, list):
            raise TypeError("zones must be a list")
        result: list[ExportedZone] = []
        for item in v:
            if isinstance(item, ExportedZone):
                result.append(item)
            elif isinstance(item, str):
                if "=" in item:
                    zone, destname = item.split("=", 1)
                else:
                    zone = item
                    destname = item
                result.append(ExportedZone(zone=zone, destname=destname))
            else:
                raise TypeError(f"Invalid zone specification: {item}")
        return result


class LDIFCommandConfig(CommandConfig):
    """Base configuration for LDIF export commands."""

    ldif: LdifSettings = Field(
        default_factory=LdifSettings,
        description="LDIF settings",
    )


class HostgroupLdifConfig(LDIFCommandConfig):
    """Configuration for hostgroup-ldif command."""

    filename: str = Field(
        default="hostgroups.ldif",
        description="Output filename",
    )
    encoding: str = Field(
        default="utf-8",
        description="File encoding for output files",
    )
    domain: str | None = Field(
        default=None,
        description="If hostname ends with this domain, also add entry without domain",
    )
    ipv6networks: bool = Field(
        default=False,
        description="Include IPv6 networks",
    )
    make_head_entry: bool = Field(
        default=True,
        description="Create head entry in LDIF",
    )


class HostsLdifConfig(LDIFCommandConfig):
    """Configuration for hosts-ldif command."""

    filename: str = Field(
        default="hosts.ldif",
        description="Output filename",
    )
    max_line_change_percent: int = Field(
        default=10,
        description="Maximum percentage of line changes allowed (safety limit)",
    )
    zone: str | None = Field(
        default=None,
        description="Limit to specific zone",
    )
    force_check: bool = Field(
        default=False,
        description="Always fetch new data from API, ignoring saved data",
    )
    ignore_size_change: bool = Field(
        default=False,
        description="Ignore size changes when writing the LDIF file",
    )
    use_saved_data: bool = Field(
        default=False,
        description="Force use saved data from previous runs. Takes precedence over force_check",
    )


class NetworkImportConfig(CommandConfig):
    """Configuration for network-import command."""

    tagsfile: str | None = Field(
        default=None,
        description="Path to tags file",
    )


class NetworkLdifConfig(LDIFCommandConfig):
    """Configuration for network-ldif command."""

    filename: str = Field(
        default="networks.ldif",
        description="Output filename",
    )
    max_line_change_percent: int = Field(
        default=10,
        description="Maximum percentage of line changes allowed (safety limit)",
    )
    ipv6networks: bool = Field(
        default=False,
        description="Include IPv6 networks",
    )


class Config(BaseSettings):
    """Configuration class for mreg-tools."""

    # Global settings
    mreg: MregConfig = Field(default_factory=MregConfig, description="MREG API settings")
    paths: PathsConfig = Field(default_factory=PathsConfig, description="Path settings")

    # Command-specific configurations
    get_dhcphosts: GetDhcphostsConfig = Field(
        default_factory=GetDhcphostsConfig,
        validation_alias=AliasChoices("get-dhcphosts", "get_dhcphosts"),
    )
    get_hostinfo: GetHostinfoConfig = Field(
        default_factory=GetHostinfoConfig,
        validation_alias=AliasChoices("get-hostinfo", "get_hostinfo"),
    )
    get_hostpolicy: GetHostpolicyConfig = Field(
        default_factory=GetHostpolicyConfig,
        validation_alias=AliasChoices("get-hostpolicy", "get_hostpolicy"),
    )
    get_zonefiles: GetZonefilesConfig = Field(
        default_factory=GetZonefilesConfig,
        validation_alias=AliasChoices("get-zonefiles", "get_zonefiles"),
    )
    hostgroup_ldif: HostgroupLdifConfig = Field(
        default_factory=HostgroupLdifConfig,
        validation_alias=AliasChoices("hostgroup-ldif", "hostgroup_ldif"),
    )
    hosts_ldif: HostsLdifConfig = Field(
        default_factory=HostsLdifConfig,
        validation_alias=AliasChoices("hosts-ldif", "hosts_ldif"),
    )
    network_import: NetworkImportConfig = Field(
        default_factory=NetworkImportConfig,
        validation_alias=AliasChoices("network-import", "network_import"),
    )
    network_ldif: NetworkLdifConfig = Field(
        default_factory=NetworkLdifConfig,
        validation_alias=AliasChoices("network-ldif", "network_ldif"),
    )

    model_config = SettingsConfigDict(
        toml_file=["config.toml"],
    )

    @override
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003 # unused
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003 # unused
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Parse settings from usual sources + TOML file."""
        cls._sources = (
            env_settings,
            init_settings,
            TomlConfigSettingsSource(settings_cls),
        )
        return cls._sources

    @classmethod
    def load(cls, file: Path | None = None) -> Self:
        """Load configuration from the specified TOML file or default locations."""
        if file:
            config_files = [file]
        else:
            config_files = DEFAULT_CONFIG_PATHS
        if file:
            cls.model_config["toml_file"] = config_files
        return cls()
