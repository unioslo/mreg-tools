from __future__ import annotations

import configparser
import io
import os
from typing import Annotated

import fasteners
import requests
import typer

from mreg_tools import common
from mreg_tools.app import app
from mreg_tools.common.utils import error


def write_file(filename, f):
    filename = os.path.join(cfg["default"]["destdir"], filename)
    common.utils.write_file(filename, f)


def create_hosts(host_data):
    hosts = io.StringIO()

    for host in host_data:
        # Handle new/old contact fields.
        # We don't know which MREG server version we are running against.
        contacts = host.get("contacts")
        if contacts:
            emails = " ".join(c.get("email", "") for c in contacts)
        else:
            emails = host.get("contact") or ""
        # TODO: Host comment could be usefull, but will need escaping
        hosts.write("{};{}\n".format(host["name"], emails))

    write_file("hosts.csv", hosts)


@common.utils.timing
def get_hosts(url):
    return conn.get_list(url + "?page_size=1000")


@common.utils.timing
def dump_hostinfo(force):
    for i in (
        "destdir",
        "workdir",
    ):
        common.utils.mkdir(cfg["default"][i])

    hosts_url = requests.compat.urljoin(cfg["mreg"]["url"], "/api/v1/hosts/")

    lockfile = os.path.join(cfg["default"]["workdir"], "lockfile")
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        updated = False
        if common.utils.updated_entries(conn, hosts_url, "hosts.json") or force:
            hosts = get_hosts(hosts_url)
            create_hosts(hosts)
            updated = True

        if updated and "postcommand" in cfg["default"]:
            common.utils.run_postcommand()
        else:
            logger.info("No updated hosts")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


@app.command("get-hostinfo", help="Export host info from mreg as a textfiles.")
def main(
    config: Annotated[
        str | None,
        typer.Option(None, help="(DEPRECATED) path to config file", hidden=True),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="force update"),
    ] = False,
):
    global cfg, conn, logger

    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read(config or "get-hostinfo.conf")

    for i in (
        "default",
        "mreg",
    ):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg["mreg"])
    dump_hostinfo(force)


if __name__ == "__main__":
    main()
