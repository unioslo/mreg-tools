"""Rich markup styles and themes for CLI output and help text."""

from __future__ import annotations

from typing import Final
from typing import final

import structlog.stdlib
from pydantic import AliasChoices
from pydantic import BaseModel
from pydantic import Field
from rich.theme import Theme

logger = structlog.stdlib.get_logger()


class CliTheme(BaseModel):
    """Theme for styling CLI output and help text."""

    primary: str = "green"
    secondary: str = "cyan"
    tertiary: str = "magenta"

    primary_accent: str = "red"
    secondary_accent: str = "yellow"
    tertiary_accent: str = "blue"

    background: str | None = None

    # Status styles
    success: str = "green"
    warning: str = "yellow"
    error: str = "red"
    info: str = "default"

    # Overrides
    ## Typer help/output styles
    # These styles derive from primary/secondary/tertiary colors
    # if not specified.
    command: str | None = None
    option: str | None = None
    switch: str | None = None
    negative_option: str | None = None
    negative_switch: str | None = None
    metavar: str | None = None
    metavar_sep: str | None = None
    usage: str | None = None
    deprecated: str | None = None
    deprecated_command: str | None = None
    option_envvar: str | None = None
    required_long: str | None = None
    required_short: str | None = None

    value: str | None = Field(
        default=None, validation_alias=AliasChoices("value", "cli_value", "cli.value")
    )

    ## Custom
    config_option: str | None = Field(
        default=None,
        validation_alias=AliasChoices("config_option", "configopt", "config.opt"),
    )
    code: str | None = None
    example: str | None = None

    # tables
    table_header: str | None = Field(
        default=None, validation_alias=AliasChoices("table_header", "table.header")
    )

    @final
    def as_rich_theme(self) -> Theme:
        """Return a Rich Theme object based on the class attributes."""
        styles: dict[str, str] = {
            # Typer default styles
            "option": self.option or f"bold {self.secondary}",
            "switch": self.switch or f"bold {self.primary}",
            "negative_option": self.negative_option or f"bold {self.tertiary}",
            "negative_switch": self.negative_switch or f"bold {self.primary_accent}",
            "metavar": self.metavar or f"bold {self.secondary_accent}",
            "metavar_sep": self.metavar_sep or "dim",
            "usage": self.usage or f"bold {self.secondary}",
            # Undocumented typer styles
            "deprecated": self.deprecated or self.error,
            "deprecated_command": self.deprecated_command or f"dim {self.error}",
            "option_envvar": self.option_envvar or f"dim {self.secondary_accent}",
            "required_long": self.required_long or f"dim {self.error}",
            "required_short": self.required_short or self.error,
            # mreg-tools styles
            "example": self.example or f"bold {self.primary}",
            "command": self.command or f"bold {self.primary}",
            "value": self.value or f"bold {self.tertiary}",
            "config.opt": self.config_option or f"italic {self.secondary}",
            "code": self.code or f"bold {self.primary}",
            # Text styles
            "success": self.success,
            "info": self.info,
            "warning": self.warning,
            "error": self.error,
            # Rich built-in styles
            "table.header": self.table_header or f"bold {self.primary}",
        }
        if self.background:
            styles["background"] = f"on {self.background}"
        return Theme(styles)


TyperTheme = CliTheme()

DarkPlus = CliTheme(
    primary="#4FC1FF",
    secondary="#CE9178",
    tertiary="#4EC9B0",
    primary_accent="#D16969",
    secondary_accent="#9CDCFE",
    tertiary_accent="#C586C0",
    background="#1E1E1E",
    success="#4EC9B0",
    warning="#D7BA7D",
    error="#D16969",
)

Monokai = CliTheme(
    primary="#A6E22E",
    secondary="#E6DB74",
    tertiary="#66D9EF",
    primary_accent="#F92672",
    secondary_accent="#AE81FF",
    tertiary_accent="#FD971F",
    background="#272822",
    success="#A6E22E",
    warning="#E6DB74",
    error="#F92672",
)

Dracula = CliTheme(
    primary="#BD93F9",
    secondary="#8BE9FD",
    tertiary="#50FA7B",
    primary_accent="#FF5555",
    secondary_accent="#FFB86C",
    tertiary_accent="#FF79C6",
    background="#282A36",
    success="#50FA7B",
    warning="#FFB86C",
    error="#FF5555",
)

Nord = CliTheme(
    primary="#88C0D0",
    secondary="#81A1C1",
    tertiary="#A3BE8C",
    primary_accent="#BF616A",
    secondary_accent="#EBCB8B",
    tertiary_accent="#B48EAD",
    background="#2E3440",
    success="#A3BE8C",
    warning="#EBCB8B",
    error="#BF616A",
)

GruvboxDark = CliTheme(
    primary="#83A598",
    secondary="#B8BB26",
    tertiary="#8EC07C",
    primary_accent="#FB4934",
    secondary_accent="#FABD2F",
    tertiary_accent="#D3869B",
    background="#282828",
    success="#B8BB26",
    warning="#FABD2F",
    error="#FB4934",
)

OneDark = CliTheme(
    primary="#61AFEF",
    secondary="#98C379",
    tertiary="#56B6C2",
    primary_accent="#E06C75",
    secondary_accent="#E5C07B",
    tertiary_accent="#C678DD",
    background="#282C34",
    success="#98C379",
    warning="#E5C07B",
    error="#E06C75",
)

CatppuccinMocha = CliTheme(
    primary="#89B4FA",
    secondary="#A6E3A1",
    tertiary="#94E2D5",
    primary_accent="#F38BA8",
    secondary_accent="#F9E2AF",
    tertiary_accent="#CBA6F7",
    background="#1E1E2E",
    success="#A6E3A1",
    warning="#FAB387",
    error="#F38BA8",
)

TokyoNight = CliTheme(
    primary="#7AA2F7",
    secondary="#9ECE6A",
    tertiary="#7DCFFF",
    primary_accent="#F7768E",
    secondary_accent="#E0AF68",
    tertiary_accent="#BB9AF7",
    background="#1A1B2E",
    success="#9ECE6A",
    warning="#E0AF68",
    error="#F7768E",
)

SolarizedDark = CliTheme(
    primary="#268BD2",
    secondary="#2AA198",
    tertiary="#859900",
    primary_accent="#DC322F",
    secondary_accent="#B58900",
    tertiary_accent="#6C71C4",
    background="#002B36",
    success="#859900",
    warning="#B58900",
    error="#DC322F",
)


THEMES: dict[str, CliTheme] = {
    "catppuccin-mocha": CatppuccinMocha,
    "dark+": DarkPlus,
    "dracula": Dracula,
    "gruvbox-dark": GruvboxDark,
    "monokai": Monokai,
    "nord": Nord,
    "one-dark": OneDark,
    "solarized-dark": SolarizedDark,
    "tokyo-night": TokyoNight,
    "typer": TyperTheme,
    "default": OneDark,
}
"""Built-in themes."""

DEFAULT_THEME: Final[CliTheme] = THEMES["default"]


def get_theme(name: str, extra: dict[str, CliTheme] | None = None) -> CliTheme:
    """Get the CliTheme for the given name."""
    themes = THEMES.copy()
    if extra:
        themes.update(extra)

    theme = themes.get(name)
    if theme is None:
        logger.error("Theme not found, using default theme", theme=name)
        theme = DEFAULT_THEME

    return theme


# New styles can inherit from CliTheme and override specific members if needed
