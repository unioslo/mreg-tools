"""Compare files produced by old and new scripts to verify they produce the same output."""

import os
import subprocess
from pathlib import Path
from typing import Annotated
from typing import NamedTuple
from typing import final

import typer
from pydantic import BaseModel
from rich.console import Console
from typer import Typer

from mreg_tools.config import ResolvedPath

app = Typer(name="diff", help="Compare output files from old and new scripts.")


class CommandSpec(BaseModel):
    """A command to run and the directory where it writes output."""

    command: list[str | Path]
    destdir: ResolvedPath

    @property
    def command_args(self) -> list[str]:
        return [str(arg) for arg in self.command]

    @property
    def command_str(self) -> str:
        return " ".join(self.command_args)


class DiffTarget(NamedTuple):
    """A pair of new/old command specs to compare."""

    name: str
    new: CommandSpec
    old: CommandSpec


os.chdir(
    Path(__file__).parent.parent
)  # Ensure consistent working directory for relative paths


# TODO: make base paths configurable
OLD_DIR = Path(".dev/old")
OLD_DESTDIR = OLD_DIR / "dirs/destdir"
OLD_WORKDIR = OLD_DIR / "dirs/workdir"

NEW_DIR = Path(".dev/dirs")
NEW_DESTDIR = NEW_DIR / "dstdir"
NEW_WORKDIR = NEW_DIR / "workdir"


commands = [
    # DHCP (multi file)
    DiffTarget(
        name="get-dhcphosts (ipv4) (multi file)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv4",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv4",
                "--no-onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv4",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv4.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv4",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6) (multi file)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv6",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv6",
                "--no-onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv6",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv6.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv6",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6 by ipv4) (multi file)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv6byipv4",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv6byipv4",
                "--no-onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv6byipv4",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv6-by-ipv4.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv6byipv4",
        ),
    ),
    # DHCP (one file)
    DiffTarget(
        name="get-dhcphosts (ipv4) (onefile)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv4",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv4/onefile",
                "--onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv4/onefile",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv4-onefile.conf",
                "--force",
                "--one-file",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv4/onefile",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6) (onefile)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv6",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv6/onefile",
                "--onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv6/onefile",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv6-onefile.conf",
                "--force",
                "--one-file",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv6/onefile",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6 by ipv4) (onefile)",
        new=CommandSpec(
            command=[
                "mreg-tools",
                "get-dhcphosts",
                "--hosts",
                "ipv6byipv4",
                "--destdir",
                NEW_DESTDIR / "get-dhcphosts/ipv6byipv4/onefile",
                "--onefile",
            ],
            destdir=NEW_DESTDIR / "get-dhcphosts/ipv6byipv4/onefile",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-dhcphosts/get-dhcphosts.py",
                "--config",
                OLD_DIR / "get-dhcphosts/get-dhcphosts-ipv6-by-ipv4-onefile.conf",
                "--force",
                "--one-file",
            ],
            destdir=OLD_DESTDIR / "dhcp/ipv6byipv4/onefile",
        ),
    ),
    DiffTarget(
        name="get-zonefiles",
        new=CommandSpec(
            command=["mreg-tools", "get-zonefiles"],
            destdir=NEW_DESTDIR / "get-zonefiles",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-zonefiles/get-zonefiles.py",
                "--config",
                OLD_DIR / "get-zonefiles/get-zonefiles.conf",
            ],
            destdir=OLD_DESTDIR / "zones",
        ),
    ),
]

console = Console()


def normalize(path: Path) -> list[str]:
    """Remove empty lines, leading/trailing whitespace, and sort lines for consistent comparison."""
    return sorted(line.strip() for line in path.read_text().splitlines() if line.strip())


@final
class Differ:
    def __init__(self, target: DiffTarget, run_commands: bool) -> None:
        self.new = target.new
        self.old = target.old
        self.name = target.name
        self.run_commands = run_commands

    def run_command(self, command: CommandSpec) -> None:
        cmd_str = command.command_str
        console.print(f"Running command: [bold blue]{cmd_str}[/]")
        result = subprocess.run(command.command_args, text=True, capture_output=True)
        if result.returncode != 0:
            console.print(
                f"[bold red]Command failed with exit code {result.returncode}[/]"
            )
            console.print(f"[bold red]Stdout: {result.stdout}[/]")
            console.print(f"[bold red]Stderr: {result.stderr}[/]")
            raise typer.Abort(f"Command failed: {cmd_str}")

    def diff(self) -> None:
        console.rule(self.name)
        if self.run_commands:
            self.run_command(self.new)
            self.run_command(self.old)

        if not self.old.destdir.exists():
            console.print(f"Old directory {self.old.destdir} does not exist", style="red")
            return
        if not self.new.destdir.exists():
            console.print(f"New directory {self.new.destdir} does not exist", style="red")
            return

        old_files = {
            f.name
            for f in self.old.destdir.iterdir()
            if f.is_file() and not f.name.endswith("_old")
        }
        new_files = {
            f.name
            for f in self.new.destdir.iterdir()
            if f.is_file() and not f.name.endswith("_old")
        }
        only_old = old_files - new_files
        only_new = new_files - old_files
        common = old_files & new_files

        if only_old:
            console.print(f"Only in old ({len(only_old)}):", style="yellow")
            for name in sorted(only_old):
                console.print(f"  {name}", style="yellow")

        if only_new:
            console.print(f"Only in new ({len(only_new)}):", style="cyan")
            for name in sorted(only_new):
                console.print(f"  {name}", style="cyan")

        diffs = 0
        for name in sorted(common):
            old_lines = normalize(self.old.destdir / name)
            new_lines = normalize(self.new.destdir / name)
            if old_lines != new_lines:
                diffs += 1
                console.print(f"DIFF: {name}", style="bold red")
                old_set = set(old_lines)
                new_set = set(new_lines)
                for line in sorted(old_set - new_set):
                    console.print(f"  - {line}", style="red")
                for line in sorted(new_set - old_set):
                    console.print(f"  + {line}", style="green")

        if diffs:
            console.print(
                f"\n{len(common)} common files, [bold red]{diffs}[/] with differences"
            )
        else:
            console.print(f"\n{len(common)} common files, [bold green]0[/] differences")


def delete_directory(path: Path) -> None:
    """Delete all files in the given directory."""
    if path.exists() and path.is_dir():
        console.print(f"Deleting directory {path}", style="yellow")
        for f in path.iterdir():
            if f.is_file():
                f.unlink()
            elif f.is_dir():
                delete_directory(f)
        path.rmdir()


@app.command()
def main(
    run_commands: Annotated[
        bool,
        typer.Option(
            "--run-commands/--no-run-commands",
            help="Whether to run the commands before diffing",
        ),
    ] = True,
    wipe_workdirs: Annotated[
        bool,
        typer.Option(
            "--wipe-workdirs/--no-wipe-workdirs",
            help="Whether to wipe the workdirs before running commands",
        ),
    ] = True,
    wipe_destdirs: Annotated[
        bool,
        typer.Option(
            "--wipe-destdirs/--no-wipe-destdirs",
            help="Whether to wipe the destdirs before running commands",
        ),
    ] = True,
) -> None:
    if run_commands:
        if wipe_workdirs:
            for workdir in [OLD_WORKDIR, NEW_WORKDIR]:
                delete_directory(workdir)
        if wipe_destdirs:
            for destdir in [OLD_DESTDIR, NEW_DESTDIR]:
                delete_directory(destdir)

    for target in commands:
        differ = Differ(target, run_commands=run_commands)
        differ.diff()


if __name__ == "__main__":
    app()
