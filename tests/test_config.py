from __future__ import annotations

from typing import Any

import pytest

from mreg_tools.config import LdifSettings


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
