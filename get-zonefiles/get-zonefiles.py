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
from os.path import join as opj

import fasteners

# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

parentdir = pathlib.Path(__file__).resolve().parent.parent
sys.path.append(str(parentdir))
import common.connection
import common.utils


def error(msg, code=os.EX_UNAVAILABLE):
    if logger:
        logger.error(msg)
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
    logger = logging.getLogger(__name__)
    common.utils.logger = logger
    return logger


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
def get_zone(zone, name):
    zonefile = conn.get(f"/api/v1/zonefiles/{zone}").text
    if zone.endswith('.arpa'):
        path = f'/api/v1/zones/reverse/{zone}'
    else:
        path = f'/api/v1/zones/forward/{zone}'
    zoneinfo = conn.get(path).json()
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
        logger.warning(f"{name}: reached max serial (99)")
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
        mkdir(cfg['default'][i])

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
                get_zone(zone, filename)
        if updated and 'postcommand' in cfg['default']:
            run_postcommand()
        lock.release()
    else:
        logger.warning(f"Could not lock on {lockfile}")


@common.utils.timing
def run_postcommand():
    command = json.loads(cfg['default']['postcommand'])
    subprocess.run(command)


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

    logger = setup_logging()
    conn = common.connection.Connection(cfg['mreg'], logger=logger)
    get_zonefiles(args.force)

main()
