"""Compare files produced by old and new scripts to verify they produce the same output."""

import os
import subprocess
from enum import StrEnum
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


class Command(StrEnum):
    """Name of commands to run and compare output for."""

    GET_DHCPHOSTS = "get-dhcphosts"
    GET_HOSTINFO = "get-hostinfo"
    GET_HOSTPOLICY = "get-hostpolicy"
    GET_ZONEFILES = "get-zonefiles"
    HOSTGROUP_LDIF = "hostgroup-ldif"
    HOSTS_LDIF = "hosts-ldif"
    NETWORK_LDIF = "network-ldif"
    # NETWORK_IMPORT = "network-import"


class CommandSpec(BaseModel):
    """A command to run and the directory where it writes output."""

    command: list[str | Path]
    destdir: ResolvedPath
    encoding: str = "utf-8"

    @property
    def command_args(self) -> list[str]:
        return [str(arg) for arg in self.command]

    @property
    def command_str(self) -> str:
        return " ".join(self.command_args)


class DiffTarget(NamedTuple):
    """A pair of new/old command specs to compare."""

    name: str
    command: Command
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


ALL_COMMANDS: list[DiffTarget] = [
    # DHCP (multi file)
    DiffTarget(
        name="get-dhcphosts (ipv4) (multi file)",
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv4",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6) (multi file)",
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv6",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6 by ipv4) (multi file)",
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv6byipv4",
        ),
    ),
    # DHCP (one file)
    DiffTarget(
        name="get-dhcphosts (ipv4) (onefile)",
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv4/onefile",
        ),
    ),
    DiffTarget(
        name="get-dhcphosts (ipv6) (onefile)",
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv6/onefile",
        ),
    ),
    DiffTarget(
        command=Command.GET_DHCPHOSTS,
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
            destdir=OLD_DESTDIR / "get-dhcphosts/ipv6byipv4/onefile",
        ),
    ),
    # LDIF
    DiffTarget(
        command=Command.HOSTGROUP_LDIF,
        name="hostgroup-ldif",
        new=CommandSpec(
            command=["mreg-tools", "hostgroup-ldif"],
            destdir=NEW_DESTDIR / "hostgroup-ldif",
            encoding="latin-1",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "hostgroup-ldif/hostgroup-ldif.py",
                "--config",
                OLD_DIR / "hostgroup-ldif/hostgroup-ldif.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "hostgroup-ldif",
            encoding="latin-1",
        ),
    ),
    DiffTarget(
        command=Command.HOSTS_LDIF,
        name="hosts-ldif",
        new=CommandSpec(
            command=["mreg-tools", "hosts-ldif"],
            destdir=NEW_DESTDIR / "hosts-ldif",
            # encoding="latin-1",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "hosts-ldif/hosts-ldif.py",
                "--config",
                OLD_DIR / "hosts-ldif/hosts-ldif.conf",
                # "--force-check",
            ],
            destdir=OLD_DESTDIR / "hosts-ldif",
            # encoding="latin-1",
        ),
    ),
    DiffTarget(
        command=Command.NETWORK_LDIF,
        name="network-ldif",
        new=CommandSpec(
            command=["mreg-tools", "network-ldif"],
            destdir=NEW_DESTDIR / "network-ldif",
            # encoding="latin-1",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "network-ldif/network-ldif.py",
                "--config",
                OLD_DIR / "network-ldif/network-ldif.conf",
                # "--force-check",
            ],
            destdir=OLD_DESTDIR / "network-ldif",
            # encoding="latin-1",
        ),
    ),
    # Host info
    DiffTarget(
        command=Command.GET_HOSTINFO,
        name="get-hostinfo",
        new=CommandSpec(
            command=["mreg-tools", "get-hostinfo"],
            destdir=NEW_DESTDIR / "get-hostinfo",
            encoding="latin-1",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-hostinfo/get-hostinfo.py",
                "--config",
                OLD_DIR / "get-hostinfo/get-hostinfo.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "get-hostinfo",
            encoding="latin-1",
        ),
    ),
    # Host policy
    DiffTarget(
        command=Command.GET_HOSTPOLICY,
        name="get-hostpolicy",
        new=CommandSpec(
            command=["mreg-tools", "get-hostpolicy"],
            destdir=NEW_DESTDIR / "get-hostpolicy",
            encoding="latin-1",
        ),
        old=CommandSpec(
            command=[
                "python",
                OLD_DIR / "get-hostpolicy/get-hostpolicy.py",
                "--config",
                OLD_DIR / "get-hostpolicy/get-hostpolicy.conf",
                "--force",
            ],
            destdir=OLD_DESTDIR / "get-hostpolicy",
            encoding="latin-1",
        ),
    ),
    # Zone
    DiffTarget(
        command=Command.GET_ZONEFILES,
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
            destdir=OLD_DESTDIR / "get-zonefiles",
        ),
    ),
]

console = Console(highlight=False)


def normalize(path: Path, encoding: str = "utf-8") -> list[str]:
    """Remove empty lines, leading/trailing whitespace, and sort lines for consistent comparison."""
    return sorted(
        line.strip()
        for line in path.read_text(encoding=encoding).splitlines()
        if line.strip()
    )


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
            f.name: f
            for f in self.old.destdir.iterdir()
            if f.is_file() and not f.name.endswith("_old")
        }
        new_files = {
            f.name: f
            for f in self.new.destdir.iterdir()
            if f.is_file() and not f.name.endswith("_old")
        }
        only_old = old_files.keys() - new_files.keys()
        only_new = new_files.keys() - old_files.keys()
        common = old_files.keys() & new_files.keys()

        if only_old:
            console.print(f"Only in old ({len(only_old)}):", style="yellow")
            for name in sorted(only_old):
                if old := old_files.get(name):
                    console.print(f"  {old}", style="yellow")

        if only_new:
            console.print(f"Only in new ({len(only_new)}):", style="cyan")
            for name in sorted(only_new):
                if new := new_files.get(name):
                    console.print(f"  {new}", style="cyan")

        diffs = 0
        for name in sorted(common):
            old_filename = old_files[name]
            new_filename = new_files[name]
            old_lines = normalize(old_filename, self.old.encoding)
            new_lines = normalize(new_filename, self.new.encoding)
            if old_lines != new_lines:
                diffs += 1
                console.print(f"DIFF: {name}", style="bold red")
                old_set = set(old_lines)
                new_set = set(new_lines)

                console.print(f"[bold red]{old_filename}[/]")
                for line in sorted(old_set - new_set):
                    console.print(f"  - {line}", style="red")

                console.line()

                console.print(f"[bold green]{new_filename}[/]")
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
            help="Run the commands before diffing output",
        ),
    ] = True,
    wipe_workdirs: Annotated[
        bool,
        typer.Option(
            "--wipe-workdirs/--no-wipe-workdirs",
            help="Wipe the workdirs before running commands",
        ),
    ] = True,
    wipe_destdirs: Annotated[
        bool,
        typer.Option(
            "--wipe-destdirs/--no-wipe-destdirs",
            help="Wipe the destdirs before running commands",
        ),
    ] = True,
    commands: Annotated[
        list[Command],
        typer.Option(
            "--commands",
            "--command",
            "-C",
            help="Which commands to compare (default: all)",
            show_default=False,
        ),
    ] = list(Command),
) -> None:
    if run_commands:
        if wipe_workdirs:
            for workdir in [OLD_WORKDIR, NEW_WORKDIR]:
                delete_directory(workdir)
        if wipe_destdirs:
            for destdir in [OLD_DESTDIR, NEW_DESTDIR]:
                delete_directory(destdir)

    to_run = [cmd for cmd in ALL_COMMANDS if cmd.command in commands]

    for target in to_run:
        differ = Differ(target, run_commands=run_commands)
        differ.diff()


if __name__ == "__main__":
    app()
