# Rich markup styles for the CLI
from __future__ import annotations

from enum import StrEnum

from rich.theme import Theme
from typer.rich_utils import STYLE_OPTION

# NOTE: we define these enums to allow us to parse the markup text and
#       correctly convert it to markdown in the docs. Without this, we would
#       have to hard-code each style to correspond to a specific markdown formatting
#       in the docs generator, which would be error-prone and difficult to maintain.
#       E.g. [command]zabbix-cli hostgroup_remove foo[/] becomes `zabbix-cli hostgroup_remove foo`
#       while [example]zabbix-cli --version[/] becomes ```\nzabbix-cli --version\n``` (code block)


class CodeBlockStyle(StrEnum):
    """Names of styles for text representing code blocks.

    Displayed as a code block in markdown.
    """

    EXAMPLE = "example"
    """An example command."""

    # TODO: add language style here or as separate enum? if so, how to parse in docs?

    # NOTE: add "code" style here or in CodeStyle?


class CodeStyle(StrEnum):
    """Names of styles for text representing code, configuration or commands.

    Displayed as inline code-formatted text in markdown.
    """

    CONFIG_OPTION = "configopt"
    """Configuration file option/key/entry."""

    CLI_OPTION = "option"
    """CLI option, e.g. --verbose."""

    CLI_VALUE = "value"
    """CLI value, arg or metavar e.g. 'FILE'."""

    CLI_COMMAND = "command"
    """CLI command e.g. 'hostgroup_remove'."""

    CODE = "code"


class TextStyle(StrEnum):
    """Names of styles for non-code text"""

    WARNING = "warning"
    ERROR = "error"
    INFO = "info"
    SUCCESS = "success"


class TableStyle(StrEnum):
    """Names of styles for table headers, rows, etc."""

    HEADER = "table_header"


####################
# Colors
####################
# Colors should be used to colorize output and help define styles,
# but they should not contain any formatting (e.g. bold, italic, `x` on `y`, etc.)
####################


# TODO: refactor and define info, success, warning, error as STYLES, not COLORS.
#       Having multiple members with the same value is bad
class Color(StrEnum):
    INFO = "default"
    SUCCESS = "green"
    WARNING = "yellow"
    ERROR = "red"
    YELLOW = "yellow"
    GREEN = "green"
    RED = "red"
    MAGENTA = "magenta"
    CYAN = "cyan"
    BLUE = "blue"

    def __call__(self, message: str) -> str:
        return f"[{self.value}]{message}[/]"


class CliTheme:
    """Theme for styling CLI output and help text."""

    # Typer help/output styles
    CLI_COMMAND: str = "bold green"
    CLI_OPTION: str = STYLE_OPTION
    CLI_VALUE: str = "bold magenta"
    CONFIG_OPTION: str = "italic yellow"
    CODE: str = "bold green"
    EXAMPLE: str = "bold green"

    # Styles for different types of text output
    SUCCESS: str = "green"
    WARNING: str = "bold yellow"
    ERROR: str = "bold red"
    INFO: str = "default"

    # tables
    TABLE_HEADER: str = "bold green"

    @classmethod
    def as_rich_theme(cls) -> Theme:
        """Return a Rich Theme object based on the class attributes."""
        return Theme(
            {
                CodeBlockStyle.EXAMPLE.value: cls.EXAMPLE,
                CodeStyle.CLI_COMMAND.value: cls.CLI_COMMAND,
                CodeStyle.CLI_OPTION.value: cls.CLI_OPTION,
                CodeStyle.CLI_VALUE.value: cls.CLI_VALUE,
                CodeStyle.CONFIG_OPTION.value: cls.CONFIG_OPTION,
                CodeStyle.CODE.value: cls.CODE,
                TextStyle.SUCCESS.value: cls.SUCCESS,
                TextStyle.WARNING.value: cls.WARNING,
                TextStyle.ERROR.value: cls.ERROR,
                TextStyle.INFO.value: cls.INFO,
                TableStyle.HEADER.value: cls.TABLE_HEADER,
            }
        )


DEFAULT_THEME = CliTheme.as_rich_theme()

# New styles can inherit from CliTheme and override specific members if needed
