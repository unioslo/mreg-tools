from __future__ import annotations

import pytest
from inline_snapshot import snapshot

from mreg_tools.exceptions import DiffError
from mreg_tools.exceptions import LockFileError
from mreg_tools.exceptions import LockFileInUseError
from mreg_tools.exceptions import MregToolsError
from mreg_tools.exceptions import TooManyLineChanges
from mreg_tools.exceptions import TooSmallNewFile
from mreg_tools.exceptions import handle_exception


@pytest.mark.parametrize(
    "e",
    [
        MregToolsError,
        LockFileError,
        LockFileInUseError,
        DiffError,
    ],
)
def test_handle_exceptions_known(e: type[Exception], capsys: pytest.CaptureFixture[str]):
    """Test exception handling with mreg-tools exceptions."""
    with pytest.raises(SystemExit) as exc_info:
        handle_exception(e("Mreg Tools Exception!"))

    assert exc_info.value.code != 0

    assert capsys.readouterr().err == snapshot("✗ ERROR: Mreg Tools Exception!\n")


@pytest.mark.parametrize(
    "e",
    [
        TooManyLineChanges,
        TooSmallNewFile,
    ],
)
def test_handle_exceptions_known_file_exceptions(
    e: type[TooManyLineChanges | TooSmallNewFile], capsys: pytest.CaptureFixture[str]
):
    """Test exception handling with mreg-tools file exceptions."""
    with pytest.raises(SystemExit) as exc_info:
        handle_exception(e("file.txt", "Mreg Tools File Exception!"))

    assert exc_info.value.code != 0

    assert capsys.readouterr().err == snapshot("✗ ERROR: Mreg Tools File Exception!\n")


@pytest.mark.parametrize(
    "e",
    [
        AttributeError,
        OSError,
        ValueError,
    ],
)
def test_handle_exceptions_unknown_exceptions(
    e: type[Exception], capsys: pytest.CaptureFixture[str]
):
    """Test exception handling with unknown exceptions."""
    with pytest.raises(SystemExit) as exc_info:
        handle_exception(e("Non-mreg tools exception!"))

    assert exc_info.value.code != 0

    final_line = capsys.readouterr().err.splitlines()[-1]
    assert final_line == snapshot(
        "✗ ERROR: An unexpected error occurred: Non-mreg tools exception!"
    )
