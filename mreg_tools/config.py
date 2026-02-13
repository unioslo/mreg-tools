"""Configuration classes for mreg-tools commands."""

from __future__ import annotations

import logging
import shlex
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
from pydantic import BeforeValidator
from pydantic import Field
from pydantic import SecretStr
from pydantic import field_serializer
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
from mreg_tools.types import LogLevel

logger = logging.getLogger(__name__)


def parse_mode_before(v: Any) -> int | None:
    """Parse file mode from integer or octal string."""
    if v is None:
        return None
    if isinstance(v, int):
        try:
            return int(f"{v}", 8)
        except ValueError as e:
            raise ValueError(f"Invalid mode value: {v}") from e
    if isinstance(v, str):
        try:
            return int(v, 8)
        except ValueError as e:
            raise ValueError(f"Invalid mode value: {v}") from e
    return v  # let pydantic handle the error


ModeValue = Annotated[int | None, BeforeValidator(parse_mode_before)]


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
    domain: str = Field(
        default="uio.no", description="Domain for hostnames (used in some commands)"
    )
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


class CommandConfig(BaseModel):
    """Base configuration for all commands with optional overrides."""

    postcommand: list[str] | None = Field(
        default=None,
        description="Shell command to run after successful CLI command execution",
    )
    postcommand_timeout: int | float | None = Field(
        default=None,
        description="Timeout for postcommand in seconds (None means no timeout)",
    )
    filename: str = Field(
        # default specified by subclasses
        default="output_file",  # placeholder default, should be overridden by subclasses
        description="Output filename",
    )
    ignore_size_change: bool = Field(
        default=False,
        description="Ignore size changes when writing the output file",
    )
    force_check: bool = Field(
        default=False,
        description="Always fetch new data from API, ignoring saved data",
    )
    use_saved_data: bool = Field(
        default=False,
        description=(
            "Force use saved data from previous runs. Takes precedence over force_check"
        ),
    )

    # Optional overrides for main config:

    ## mreg
    mreg: MregConfig | None = Field(
        default=None,
        description="MREG settings override for this command",
    )

    ## Directories
    workdir: ResolvedPath | None = Field(
        default=None,
        description="Working directory for the command",
    )
    destdir: ResolvedPath | None = Field(
        default=None,
        description="Destination directory for output",
    )

    ## File settings
    encoding: str | None = Field(
        default=None,
        description="File encoding for output files",
    )
    mode: ModeValue = Field(
        default=None,
        description="File mode to set when creating files (e.g. 0o644).",
    )
    max_line_change_percent: int | None = Field(
        default=None,
        description="Maximum percentage of line changes allowed (safety limit)",
    )
    keepoldfile: bool | None = Field(
        default=None,
        description="Keep a backup of the old file when writing new files",
    )
    lock: bool | None = Field(
        default=None,
        description="Use file locking to prevent concurrent runs of the same command",
    )

    @field_validator("postcommand", mode="before")
    @classmethod
    def validate_postcommand(cls, v: Any) -> Any:
        """Process postcommand input as a string or list of strings."""
        if isinstance(v, str):
            return shlex.split(v)
        return v


class LdifSettings(BaseModel):
    """LDIF-specific settings for LDAP export commands."""

    dn: str = Field(default="", description="Distinguished name for the LDIF entry")
    cn: str = Field(default="", description="Common name")
    description: str = Field(default="", description="Description")
    ou: str = Field(default="", description="Organizational unit")
    objectClass: list[str] = Field(default=["top"], description="Object class(es)")
    make_head_entry: bool = Field(default=True, description="Create head entry in LDIF")

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
        return {
            "dn": self.dn,
            "cn": self.cn,
            "description": self.description,
            "ou": self.ou,
            "objectClass": self.objectClass,
        }


class GetDhcphostsConfig(CommandConfig):
    """Configuration for get-dhcphosts command."""

    hosts: Literal["ipv4", "ipv6", "all"] = Field(
        default="ipv4",
        description="IP version to export",
    )


class GetHostinfoConfig(CommandConfig):
    """Configuration for get-hostinfo command."""


class GetHostPolicyConfig(CommandConfig):
    """Configuration for get-hostpolicy command."""


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


class HostGroupLdifConfig(LDIFCommandConfig):
    """Configuration for hostgroup-ldif command."""


class HostsLdifConfig(LDIFCommandConfig):
    """Configuration for hosts-ldif command."""

    zone: str | None = Field(
        default=None,
        description="Limit to specific zone",
    )


class NetworkImportConfig(CommandConfig):
    """Configuration for network-import command."""

    tagsfile: str | None = Field(
        default=None,
        description="Path to tags file",
    )


class NetworkLdifConfig(LDIFCommandConfig):
    """Configuration for network-ldif command."""

    ipv6networks: bool = Field(
        default=True,
        description="Include IPv6 networks",
    )


class DefaultConfig(BaseModel):
    """Default configuration section."""

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
    encoding: str = Field(  # NOTE: add Literal for this?
        default="utf-8",
        description="File encoding for output files",
    )
    mode: ModeValue = Field(
        default=None,
        description="File mode to set when creating files (e.g. 0o644).",
    )
    max_line_change_percent: int | None = Field(
        default=None,
        description="Maximum percentage of line changes allowed (safety limit)",
    )
    keepoldfile: bool = Field(
        default=True,
        description="Keep a backup of the old file when writing new files",
    )
    lock: bool = Field(
        default=True,
        description="Use file locking to prevent concurrent runs of the same command",
    )


class LoggingHandlerConfig(BaseModel):
    """Base logging configuration section."""

    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Override level for this handler.",
    )
    enabled: bool = Field(
        default=True,
        description="Enable logging handler.",
    )


# TODO: remove separate file logging config and merge into main LoggingConfig.
#       We have no need for console logging, as we already manage output via
#       the output functions defined in output.py that also log to file.
class FileLoggingConfig(LoggingHandlerConfig):
    """File logging configuration section."""

    # NOTE: Base filename has been changed from a date-based filename
    # to a fixed filename to simplify log management and rotation.
    # Furthermore, this makes it easier to integrate the logs into
    # existing log management systems that expect a consistent filename.
    filename: str = Field(
        default="mreg-tools.log",
        description="Log filename (used if file logging is enabled)",
    )
    directory: ResolvedPath = Field(
        default=DEFAULT_LOGDIR,
        description="Directory for log files",
    )
    rotate: bool = Field(
        default=True,
        description="Use rotating file handler",
    )
    rotate: bool = Field(
        default=True,
        description="Whether to enable log rotation for the file logger.",
    )
    max_size_mb: int = Field(
        default=50,
        description="Maximum size of the log file in megabytes.",
    )
    max_logs: int = Field(
        default=5,
        description="Maximum number of log files to keep.",
    )

    @property
    def path(self) -> Path:
        """Get the full path to the log file."""
        return self.directory / self.filename

    def max_size_as_bytes(self) -> int:
        """Return the maximum size of the log file in bytes."""
        return self.max_size_mb * 1024 * 1024


class ConsoleLoggingConfig(LoggingHandlerConfig):
    """Console logging configuration section."""

    enabled: bool = Field(
        default=False,
        description="Enable logging handler.",
    )


class LoggingConfig(BaseModel):
    """Logging configuration section."""

    level: LogLevel = Field(
        default=LogLevel.INFO,
        description=(
            "Logging level for both console and file handlers. "
            "Individual handlers can override this level with their own 'level' setting."
        ),
    )
    console: ConsoleLoggingConfig = Field(
        default_factory=ConsoleLoggingConfig,
        description="Console logging settings",
    )
    file: FileLoggingConfig = Field(
        default_factory=FileLoggingConfig,
        description="File logging settings",
    )

    @field_serializer("level")
    def serialize_level(self, level: LogLevel) -> str:
        """Serialize the LogLevel enum to its name for better readability in config files."""
        return level.name

    @override
    def model_post_init(self, context: Any, /) -> None:
        # Set handler levels to the main level if they are not explicitly set
        for field in [self.console, self.file]:
            if "level" not in field.model_fields_set:
                field.level = self.level


class ResolvedCommandConfig(BaseModel):
    """Command configuration with all overrides resolved to final values."""

    workdir: Path
    destdir: Path
    logdir: Path
    encoding: str
    mode: int | None
    max_line_change_percent: int | None
    mreg: MregConfig
    keepoldfile: bool
    postcommand: list[str] | None
    postcommand_timeout: int | float | None
    force_check: bool
    use_saved_data: bool
    filename: str
    ignore_size_change: bool
    lock: bool


class ResolvedLdifCommandConfig(ResolvedCommandConfig):
    """Resolved configuration for LDIF export commands."""

    ldif: LdifSettings


class Config(BaseSettings):
    """Configuration class for mreg-tools."""

    # Global settings
    default: DefaultConfig = Field(
        default_factory=DefaultConfig,
        description="Default configuration settings",
    )
    mreg: MregConfig = Field(default_factory=MregConfig, description="MREG API settings")
    logging: LoggingConfig = Field(
        default_factory=LoggingConfig,
        description="Logging configuration settings",
    )

    # Command-specific configurations
    get_dhcphosts: GetDhcphostsConfig = Field(
        default_factory=GetDhcphostsConfig,
        validation_alias=AliasChoices("get-dhcphosts", "get_dhcphosts"),
    )
    get_hostinfo: GetHostinfoConfig = Field(
        default=GetHostinfoConfig(
            filename="hosts.csv",
        ),
        validation_alias=AliasChoices("get-hostinfo", "get_hostinfo"),
    )
    get_hostpolicy: GetHostPolicyConfig = Field(
        default=GetHostPolicyConfig(
            encoding="latin-1",  # NOTE: should this really be the default?
        ),
        validation_alias=AliasChoices("get-hostpolicy", "get_hostpolicy"),
    )
    get_zonefiles: GetZonefilesConfig = Field(
        default_factory=GetZonefilesConfig,
        validation_alias=AliasChoices("get-zonefiles", "get_zonefiles"),
    )
    hostgroup_ldif: HostGroupLdifConfig = Field(
        default=HostGroupLdifConfig(
            filename="hostgroups.ldif",
            ldif=LdifSettings(
                dn="cn=netgroups,cn=system,dc=uio,dc=no",
                objectClass=["top", "nisNetGroup", "uioHostgroup"],
                make_head_entry=False,
            ),
        ),
        validation_alias=AliasChoices("hostgroup-ldif", "hostgroup_ldif"),
    )
    hosts_ldif: HostsLdifConfig = Field(
        default=HostsLdifConfig(
            filename="hosts.ldif",
            ldif=LdifSettings(
                dn="cn=hosts,cn=system,dc=uio,dc=no",
                cn="hosts",
                description="Supplementary host-info not present in DNS",
                objectClass=["top", "uioUntypedObject"],
                make_head_entry=True,
            ),
        ),
        validation_alias=AliasChoices("hosts-ldif", "hosts_ldif"),
    )
    network_import: NetworkImportConfig = Field(
        default_factory=NetworkImportConfig,
        validation_alias=AliasChoices("network-import", "network_import"),
    )
    network_ldif: NetworkLdifConfig = Field(
        default=NetworkLdifConfig(
            filename="subnets.ldif",
            ldif=LdifSettings(
                # NOTE: these values are used to create the head entry
                # apart from DN, which is used as a prefix for all entries.
                dn="cn=subnets,cn=system,dc=uio,dc=no",
                cn="subnets",
                description="IP networks at UiO",
                objectClass=["top", "uioUntypedObject"],
                make_head_entry=True,
            ),
        ),
        validation_alias=AliasChoices("network-ldif", "network_ldif"),
    )

    model_config = SettingsConfigDict(
        toml_file=["config.toml"],
        extra="ignore",
        # Allows us to specify defaults for certain fields,
        # while still allowing them to be overridden by the config file.
        nested_model_default_partial_update=True,
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
        # TODO: use context manager to temporarily set the toml_file source for this load operation, instead of mutating the class variable
        if file:
            cls.model_config["toml_file"] = config_files
        return cls()

    def resolve(self, command_config: CommandConfig) -> ResolvedCommandConfig:
        """Resolve a CommandConfig by applying overrides to the default config."""
        return ResolvedCommandConfig(
            # Overrides for main config
            workdir=command_config.workdir or self.default.workdir,
            destdir=command_config.destdir or self.default.destdir,
            logdir=self.default.logdir,  # logdir is not overridden by command config
            encoding=command_config.encoding or self.default.encoding,
            mode=(
                command_config.mode
                if command_config.mode is not None
                else self.default.mode
            ),
            max_line_change_percent=(
                command_config.max_line_change_percent
                if command_config.max_line_change_percent is not None
                else self.default.max_line_change_percent
            ),
            mreg=command_config.mreg or self.mreg,
            keepoldfile=(
                command_config.keepoldfile
                if command_config.keepoldfile is not None
                else self.default.keepoldfile
            ),
            lock=(
                command_config.lock
                if command_config.lock is not None
                else self.default.lock
            ),
            # Command-specific options
            postcommand=command_config.postcommand,
            postcommand_timeout=command_config.postcommand_timeout,
            force_check=command_config.force_check,
            use_saved_data=command_config.use_saved_data,
            filename=command_config.filename,
            ignore_size_change=command_config.ignore_size_change,
        )

    def resolve_ldif(
        self, command_config: LDIFCommandConfig
    ) -> ResolvedLdifCommandConfig:
        """Resolve an LDIFCommandConfig by applying overrides to the default config."""
        base = self.resolve(command_config)
        return ResolvedLdifCommandConfig(
            # Base command config options
            workdir=base.workdir,
            destdir=base.destdir,
            logdir=base.logdir,
            encoding=base.encoding,
            mode=base.mode,
            max_line_change_percent=base.max_line_change_percent,
            mreg=base.mreg,
            keepoldfile=base.keepoldfile,
            postcommand=base.postcommand,
            postcommand_timeout=base.postcommand_timeout,
            force_check=base.force_check,
            use_saved_data=base.use_saved_data,
            filename=base.filename,
            ignore_size_change=base.ignore_size_change,
            lock=base.lock,
            # LDIF command options
            ldif=command_config.ldif,
        )
