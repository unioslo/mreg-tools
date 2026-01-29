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
from mreg_tools.common.LDIFutils import entry_string
from mreg_tools.common.LDIFutils import make_head_entry
from mreg_tools.common.utils import error


def create_ldif(hostgroups):
    def write_file(filename):
        common.utils.write_file(filename, f)

    f = io.StringIO()
    if cfg["mreg"].getboolean("make_head_entry"):
        head_entry = make_head_entry(cfg)
        f.write(entry_string(head_entry))
    for entry in create_hostgroupsentries(hostgroups):
        f.write(entry_string(entry))
    write_file(cfg["default"]["filename"])


def get_objectclass():
    return make_head_entry(cfg)["objectClass"]


def create_hostgroupsentries(hostgroups):
    ret = []
    remove_domain = cfg["mreg"].get("domain", None)
    if remove_domain:
        if not remove_domain.startswith("."):
            remove_domain = f".{remove_domain}"
        remove_len = len(remove_domain)
    objectclass = get_objectclass()
    dn = cfg["ldif"]["dn"]
    encoding = cfg["default"].get("fileencoding", "")

    for i in hostgroups:
        cn = i["name"]
        desc = i["description"] or None
        if encoding == "ascii":
            desc = common.LDIFutils.to_iso646_60(desc)

        entry = {
            "dn": f"cn={cn},{dn}",
            "cn": cn,
            "description": desc,
            "objectClass": objectclass,
        }
        if i["groups"]:
            entry["memberNisNetgroup"] = [g["name"] for g in i["groups"]]
        if i["hosts"]:
            triple = []
            for host in i["hosts"]:
                hostname = host["name"]
                if remove_domain and hostname.endswith(remove_domain):
                    short = hostname[:-remove_len]
                    triple.append(f"({short},-,)")
                triple.append(f"({hostname},-,)")
            entry["nisNetgroupTriple"] = triple
        ret.append(entry)

    return ret


@common.utils.timing
def get_hostgroups(url):
    return conn.get_list(url + "?page_size=1000")


@common.utils.timing
def hostgroup_ldif(args, url):
    for i in (
        "destdir",
        "workdir",
    ):
        common.utils.mkdir(cfg["default"][i])

    lockfile = os.path.join(cfg["default"]["workdir"], "lockfile")
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        if common.utils.updated_entries(conn, url, "hostgroups.json") or args.force:
            hostgroups = get_hostgroups(url)
            create_ldif(hostgroups)
            if "postcommand" in cfg["default"]:
                common.utils.run_postcommand()
        else:
            logger.info("No updated hostgroups")
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


@app.command("hostgroup-ldif", help="Export hostgroups from mreg as a ldif.")
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
    cfg.read(config or "hostgroup-ldif.conf")

    for i in ("default", "mreg", "ldif"):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    if "filename" not in cfg["default"]:
        error("Missing 'filename' in default section in config file", os.EX_CONFIG)

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg["mreg"])
    url = requests.compat.urljoin(cfg["mreg"]["url"], "/api/v1/hostgroups/")
    hostgroup_ldif(args, url)


if __name__ == "__main__":
    main()
