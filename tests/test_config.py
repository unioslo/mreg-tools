from __future__ import annotations

import logging
from typing import Any

import pytest

from mreg_tools.config import ConsoleLoggingConfig
from mreg_tools.config import FileLoggingConfig
from mreg_tools.config import LdifSettings
from mreg_tools.config import LoggingConfig
from mreg_tools.types import LogLevel


def _ldif_settings_object_class() -> list[tuple[Any, list[str]]]:
    return [
        # Default
        (None, ["top"]),
        # Single string
        ("person", ["person"]),
        # List of strings
        (["top", "person"], ["top", "person"]),
        # Parenthesized comma-separated string
        ("(top,person,inetOrgPerson)", ["top", "person", "inetOrgPerson"]),
        # Parenthesized comma-separated string with trailing comma
        ("(top,person,inetOrgPerson,)", ["top", "person", "inetOrgPerson"]),
        # Parenthesized comma-separated string with trailing comma and space
        ("(top,person,inetOrgPerson, )", ["top", "person", "inetOrgPerson"]),
        # Parenthesized single value
        ("(top)", ["top"]),
    ]


@pytest.mark.parametrize(
    "input_value, expected",
    [*_ldif_settings_object_class()],
)
def test_ldif_settings_object_class(input_value: Any, expected: list[str]):
    """Test LdifSettings.objectClass field normalization."""
    kwargs = {} if input_value is None else {"objectClass": input_value}
    settings = LdifSettings(**kwargs)
    assert settings.objectClass == expected


@pytest.mark.parametrize(
    "input_value, expected",
    [*_ldif_settings_object_class()],
)
def test_ldif_settings_as_head_entry(input_value: Any, expected: list[str]):
    """Test LdifSettings.as_head_entry() for objectClass field."""
    kwargs = {} if input_value is None else {"objectClass": input_value}
    settings = LdifSettings(**kwargs)
    head_entry = settings.as_head_entry()
    assert head_entry["objectClass"] == expected


@pytest.mark.parametrize(
    "inp, expected",
    [
        ("debug", LogLevel.DEBUG),
        ("DEBUG", LogLevel.DEBUG),
        (logging.DEBUG, LogLevel.DEBUG),
        ("info", LogLevel.INFO),
        ("INFO", LogLevel.INFO),
        (logging.INFO, LogLevel.INFO),
        ("warning", LogLevel.WARNING),
        ("WARNING", LogLevel.WARNING),
        (logging.WARNING, LogLevel.WARNING),
        ("error", LogLevel.ERROR),
        ("ERROR", LogLevel.ERROR),
        (logging.ERROR, LogLevel.ERROR),
        ("critical", LogLevel.CRITICAL),
        ("CRITICAL", LogLevel.CRITICAL),
        (logging.CRITICAL, LogLevel.CRITICAL),
    ],
)
def test_logging_config_level(inp: str | int, expected: LogLevel):
    """Test LogLevel parsing and serialization in logging config."""
    # Test validation
    config = LoggingConfig(level=inp)  # pyright: ignore[reportArgumentType]

    # Validates as a level for stdlib logging
    assert config.level == expected
    # But it is also an instance of our custom LogLevel enum
    assert isinstance(config.level, LogLevel)

    # Test serialization
    serialized = config.model_dump()
    assert serialized["level"] == expected.name


def test_logging_config_defaults_to_info():
    """All levels default to INFO when nothing is specified."""
    config = LoggingConfig()
    assert config.level == LogLevel.INFO
    assert config.console.level == LogLevel.INFO
    assert config.file.level == LogLevel.INFO


def test_logging_config_handlers_inherit_main_level():
    """Console and file handlers inherit the main level when not set."""
    config = LoggingConfig(level=LogLevel.WARNING)
    assert config.console.level == LogLevel.WARNING
    assert config.file.level == LogLevel.WARNING


def test_logging_config_file_inherits_when_console_is_set():
    """File handler inherits main level when only console level is overridden."""
    config = LoggingConfig(
        level=LogLevel.DEBUG, console=ConsoleLoggingConfig(level=LogLevel.ERROR)
    )
    assert config.console.level == LogLevel.ERROR
    assert config.file.level == LogLevel.DEBUG


def test_logging_config_console_inherits_when_file_is_set():
    """Console handler inherits main level when only file level is overridden."""
    config = LoggingConfig(
        level=LogLevel.DEBUG, file=FileLoggingConfig(level=LogLevel.ERROR)
    )
    assert config.file.level == LogLevel.ERROR
    assert config.console.level == LogLevel.DEBUG


def test_logging_config_explicit_handler_levels_override_main():
    """Explicit handler levels take precedence over the main level."""
    config = LoggingConfig(
        level=LogLevel.DEBUG,
        console=ConsoleLoggingConfig(level=LogLevel.ERROR),
        file=FileLoggingConfig(level=LogLevel.WARNING),
    )
    assert config.console.level == LogLevel.ERROR
    assert config.file.level == LogLevel.WARNING
