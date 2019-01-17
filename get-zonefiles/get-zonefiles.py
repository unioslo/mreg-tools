import argparse
import configparser
import datetime
import json
import logging
import os
import shutil
import sys
import tempfile

import fasteners
import requests

from functools import wraps
from os.path import join as opj
from time import time


# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

cfg = None


def error(msg, code=os.EX_UNAVAILABLE):
    logging.error(msg)
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def timing(f):
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        logging.info(f'func:{f.__name__} args:[{args}, {kw}] took: {te-ts:.4} sec')
        return result
    return wrap


def get(url: str) -> requests.Response:
    result = requests.get(url)
    if not result.ok:
        message = f"GET \"{url}\": {result.status_code}: {result.reason}"
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        error(message)
    return result


def create_url(path):
    # XXX: add authentication / API-key
    url = cfg['mreg']['url'] + path
    return url


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


def get_zonefile(zone):
    return get(create_url(f"zonefiles/{zone}")).text


def get_zoneinfo(zone):
    return get(create_url(f"zones/{zone}")).json()


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


def update_zone(zone, name):
    old_zoneinfo = get_old_zoneinfo(name)
    if old_zoneinfo:
        old_updated_at = parse_date(old_zoneinfo['updated_at'])
        old_serial_uat = parse_date(old_zoneinfo['serialno_updated_at'])
        zoneinfo = get_zoneinfo(zone)
        updated_at = parse_date(zoneinfo['updated_at'])
        if old_updated_at == updated_at:
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
    zonefile = get_zonefile(zone)
    zoneinfo = get_zoneinfo(zone)
    with tempfile.TemporaryFile(dir=cfg['default']['workdir']) as f:
        f.write(zonefile.encode())
        with open(opj(cfg['default']['destdir'], name), 'wb') as dest:
            extradata = get_extradata(name)
            f.seek(0)
            shutil.copyfileobj(f, dest)
            if extradata:
                dest.write(extradata)

    if zoneinfo['serialno'] % 100 == 99:
        logging.warning(f"{name}: reached max serial (99)")
    write_old_zoneinfo(name, zoneinfo)


@timing
def get_zonefiles(force):
    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        for zone in cfg['zones']:
            if cfg['zones'][zone]:
                name = cfg['zones'][zone]
            else:
                name = zone
            if force or update_zone(zone, name):
                get_zone(zone, name)
        lock.release()
    else:
        logging.warning(f"Could not lock on {lockfile}")


def main():
    global cfg
    parser = argparse.ArgumentParser(description="Download zonefiles from mreg.")
    parser.add_argument('--config',
                        default='get-zonefiles.conf',
                        help='path to config file (default: get-zonefiles.conf)')
    parser.add_argument('--force',
                        action='store_true',
                        default=False,
                        help='force update of all zones')
    parser.add_argument('--logfile',
                        default='logfile',
                        help='path to logfile (default: logfile)')
    args = parser.parse_args()

    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=args.logfile,
                    level=logging.INFO)
    cfg = configparser.ConfigParser(allow_no_value=True)
    cfg.read(args.config)

    for i in ('default', 'mreg', 'zones'):
        if i not in cfg:
            error(f"Missing section {i} in config file", os.EX_CONFIG)

    get_zonefiles(args.force)


main()
