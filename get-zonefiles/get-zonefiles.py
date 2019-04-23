import argparse
import configparser
import datetime
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import fasteners
import requests

from functools import wraps
from os.path import join as opj
from time import time

# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection

def error(msg, code=os.EX_UNAVAILABLE):
    logging.error(msg)
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except PermissionError as e:
        error(f"{e}", code=e.errno)


def setup_logging():
    if cfg['default']['logdir']:
        logdir = cfg['default']['logdir']
    else:
        error("No logdir defined in config file")

    mkdir(logdir)
    filename = datetime.datetime.now().strftime('%Y-%m-%d.log')
    filepath = opj(logdir, filename)
    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=filepath,
                    level=logging.INFO)


def timing(f):
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        logging.info(f'func:{f.__name__} args:[{args}, {kw}] took: {te-ts:.4} sec')
        return result
    return wrap


def get_old_zoneinfo(name):
    filename = opj(cfg['default']['workdir'], f"{name}.json")
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, EOFError):
        logging.warning(f"Could read data from {filename}")
        return None


def write_old_zoneinfo(name, zoneinfo):
    filename = opj(cfg['default']['workdir'], f"{name}.json")
    try:
        with open(filename, 'w') as f:
            json.dump(zoneinfo, f)
    except PermissionError:
        error(f"No permission to write to {filename}")


def get_extradata(name):
    if cfg['default']['extradir']:
        extrafile = opj(cfg['default']['extradir'], f"{name}_extra")
        try:
            with open(extrafile, 'rb') as extra:
                return extra.read()
        except FileNotFoundError:
            pass
        except PermissionError as e:
            error(f"{e}", code=e.errno)
    return None


def update_zone(zone, name, zoneinfo):
    old_zoneinfo = get_old_zoneinfo(name)
    if old_zoneinfo:
        old_updated_at = parse_date(old_zoneinfo['updated_at'])
        old_serial_uat = parse_date(old_zoneinfo['serialno_updated_at'])
        updated_at = parse_date(zoneinfo['updated_at'])
        if zoneinfo['updated']:
            return True
        elif old_updated_at == updated_at:
            logging.info(f"{name}: unchanged updated_at: {updated_at}")
            return False
        # mreg will only update the serialnumber once per minute, so no need to
        # rush.  It will attempt to get it, hopefully with a new serialnumber,
        # in the next run.
        elif datetime.datetime.now(old_serial_uat.tzinfo) < \
                old_serial_uat + datetime.timedelta(minutes=1):
            logging.info(f"{name}: less than a minute since last "
                         f"serial {old_serial_uat}, skipping")
            return False
    return True


@timing
def get_zone(zone, name):
    zonefile = conn.get(f"zonefiles/{zone}").text
    zoneinfo = conn.get(f"zones/{zone}").json()
    with tempfile.TemporaryFile(dir=cfg['default']['workdir']) as f:
        f.write(zonefile.encode())
        dstfile = opj(cfg['default']['destdir'], name)
        if os.path.isfile(dstfile):
            os.rename(dstfile, f"{dstfile}_old")
        with open(dstfile, 'wb') as dest:
            extradata = get_extradata(name)
            f.seek(0)
            shutil.copyfileobj(f, dest)
            if extradata:
                dest.write(extradata)
        os.chmod(dstfile, 0o400)

    if zoneinfo['serialno'] % 100 == 99:
        logging.warning(f"{name}: reached max serial (99)")
    write_old_zoneinfo(name, zoneinfo)


@timing
def get_current_zoneinfo():
    zoneinfo = dict()
    ret = conn.get("/zones/")
    for zone in ret.json():
        zoneinfo[zone['name']] = zone
    return zoneinfo


@timing
def get_zonefiles(force):
    for dir in ('destdir', 'workdir',):
        mkdir(cfg['default'][dir])

    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        updated = False
        allzoneinfo = get_current_zoneinfo()
        for zone in cfg['zones']:
            if zone not in allzoneinfo:
                error(f"Zone {zone} not in mreg")
            if cfg['zones'][zone]:
                name = cfg['zones'][zone]
            else:
                name = zone
            if force or update_zone(zone, name, allzoneinfo[zone]):
                updated = True
                get_zone(zone, name)
        if updated and 'postcommand' in cfg['default']:
            run_postcommand()
        lock.release()
    else:
        logging.warning(f"Could not lock on {lockfile}")


@timing
def run_postcommand():
    command = json.loads(cfg['default']['postcommand'])
    subprocess.run(command)


def main():
    global cfg, conn
    parser = argparse.ArgumentParser(description="Download zonefiles from mreg.")
    parser.add_argument('--config',
                        default='get-zonefiles.conf',
                        help='path to config file (default: get-zonefiles.conf)')
    parser.add_argument('--force',
                        action='store_true',
                        default=False,
                        help='force update of all zones')
    args = parser.parse_args()

    cfg = configparser.ConfigParser(allow_no_value=True)
    cfg.read(args.config)

    for i in ('default', 'mreg', 'zones'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    conn = common.connection.Connection(cfg['mreg'])

    setup_logging()
    get_zonefiles(args.force)


main()
