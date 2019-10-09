import argparse
import configparser
import datetime
import io
import os
import pathlib
import sys
from os.path import join as opj

import fasteners

# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection
import common.utils

from common.utils import error


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
    jsonfile = opj(cfg['default']['workdir'], f"{name}.json")
    old_zoneinfo = common.utils.read_json_file(jsonfile)
    if old_zoneinfo:
        old_updated_at = parse_date(old_zoneinfo['updated_at'])
        old_serial_uat = parse_date(old_zoneinfo['serialno_updated_at'])
        updated_at = parse_date(zoneinfo['updated_at'])
        if zoneinfo['updated']:
            return True
        elif old_updated_at == updated_at:
            logger.info(f"{name}: unchanged updated_at: {updated_at}")
            return False
        # mreg will only update the serialnumber once per minute, so no need to
        # rush.  It will attempt to get it, hopefully with a new serialnumber,
        # in the next run.
        elif datetime.datetime.now(old_serial_uat.tzinfo) < \
                old_serial_uat + datetime.timedelta(minutes=1):
            logger.info(f"{name}: less than a minute since last "
                        f"serial {old_serial_uat}, skipping")
            return False
    return True


@common.utils.timing
def get_zone(zone, name, force):
    zonefile = conn.get(f"/api/v1/zonefiles/{zone}").text
    if zone.endswith('.arpa'):
        path = f'/api/v1/zones/reverse/{zone}'
    else:
        path = f'/api/v1/zones/forward/{zone}'
    f = io.StringIO()
    zoneinfo = conn.get(path).json()
    f.write(zonefile)
    extradata = get_extradata(name)
    if extradata:
        f.write(extradata)

    if zoneinfo['serialno'] % 100 == 99:
        logger.warning(f"{name}: reached max serial (99)")
    try:
        common.utils.write_file(name, f, ignore_size_change=force)
    except common.utils.TooManyLineChanges as e:
        logger.error(e.message)
        print(f"ERROR: {e.message}", file=sys.stderr)
        return

    jsonfile = opj(cfg['default']['workdir'], f"{name}.json")
    common.utils.write_json_file(jsonfile, zoneinfo)


@common.utils.timing
def get_current_zoneinfo():
    zoneinfo = dict()
    for path in ('/api/v1/zones/forward/',
                 '/api/v1/zones/reverse/'):
        for zone in conn.get_list(path):
            zoneinfo[zone['name']] = zone
    return zoneinfo


@common.utils.timing
def get_zonefiles(force):
    for i in ('destdir', 'workdir',):
        common.utils.mkdir(cfg['default'][i])

    lockfile = opj(cfg['default']['workdir'], 'lockfile')
    lock = fasteners.InterProcessLock(lockfile)
    if lock.acquire(blocking=False):
        updated = False
        allzoneinfo = get_current_zoneinfo()
        for zone in cfg['zones']:
            if zone not in allzoneinfo:
                error(f"Zone {zone} not in mreg")
            # Check if using a overriden filename from config
            if cfg['zones'][zone]:
                filename = cfg['zones'][zone]
            else:
                filename = zone
            if update_zone(zone, filename, allzoneinfo[zone]) or force:
                updated = True
                get_zone(zone, filename, force)
        if updated and 'postcommand' in cfg['default']:
            common.utils.run_postcommand()
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


def main():
    global cfg, conn, logger
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

    common.utils.cfg = cfg
    logger = common.utils.getLogger()
    conn = common.connection.Connection(cfg['mreg'], logger=logger)
    get_zonefiles(args.force)

main()
