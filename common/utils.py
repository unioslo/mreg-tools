import datetime
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile

from difflib import unified_diff
from functools import wraps
from time import time

# replace in python 3.7 with datetime.fromisoformat
from iso8601 import parse_date

cfg = None
logger = None
# Maximum size change in percent for each line count threshold
COMPARE_LIMITS_LINES = {50: 50,
                        100: 20,
                        1000: 15,
                        10000: 10,
                        sys.maxsize: 10}
# Absolute minimum file size, in lines
ABSOLUTE_MIN_SIZE = 10


class TooManyLineChanges(Exception):
    def __init__(self, newfile, message):
        self.newfile = newfile
        self.message = message


class TooSmallNewFile(Exception):
    def __init__(self, newfile, message):
        self.newfile = newfile
        self.message = message


def UmaskNamedTemporaryFile(*args, **kwargs):
    f = tempfile.NamedTemporaryFile(*args, **kwargs)
    oldmask = None
    if cfg.has_option('default', 'umask'):
        umask = int(cfg['default']['umask'], 8)
        oldmask = os.umask(umask)
        os.chmod(f.name, 0o666 & ~umask)
    return f, oldmask


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


def getLogger():
    global logger
    if cfg['default']['logdir']:
        logdir = cfg['default']['logdir']
    else:
        error("No logdir defined in config file")

    mkdir(logdir)
    filename = datetime.datetime.now().strftime('%Y-%m-%d.log')
    filepath = os.path.join(logdir, filename)
    logging.basicConfig(
                    format='%(asctime)s %(levelname)-8s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=filepath,
                    level=logging.INFO)
    logger = logging.getLogger(__name__)
    return logger


def timing(f):
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        logging.info(f'func:{f.__name__} args:[{args}, {kw}] took: {te-ts:.4} sec')
        return result
    return wrap


def compare_file_size(oldfile, newfile, newlines):
    """
    Compare filesizes with the new and old file, and if difference
    above values in COMPARE_LIMITS_LINES, raise an exception.
    """
    with open(oldfile, 'r') as old:
        oldlines = old.readlines()

    difference = list(unified_diff(oldlines, newlines, n=0))
    if len(difference) == 0:
        return
    old_count = len(oldlines)
    diff_limit = cfg['default'].getfloat('max_line_change_percent')
    if diff_limit is None:
        for linecount, limit in COMPARE_LIMITS_LINES.items():
            if old_count < linecount:
                diff_limit = limit
                break

    diff_percent = (len(newlines)-old_count)/old_count*100
    if abs(diff_percent) > diff_limit:
        raise TooManyLineChanges(newfile,
                f"New file {newfile} changed too much: {diff_percent:.2f}%, limit {diff_limit}%")


def write_file(filename, f, ignore_size_change=False):
    dstfile = os.path.join(cfg['default']['destdir'], filename)
    encoding = cfg['default'].get('fileencoding', 'utf-8')

    tempf, oldmask = UmaskNamedTemporaryFile(delete=False, mode='w',
                                             encoding=encoding,
                                             dir=cfg['default']['workdir'],
                                             prefix=f'{filename}.')
    f.seek(0)
    newlines = f.readlines()
    if len(newlines) < ABSOLUTE_MIN_SIZE:
        raise TooSmallNewFile(tempf.name, f'new file less than {ABSOLUTE_MIN_SIZE} lines')
    # Write first to make sure the workdir can hold the new file
    f.seek(0)
    shutil.copyfileobj(f, tempf)
    tempf.close()

    if os.path.isfile(dstfile):
        if not ignore_size_change:
            compare_file_size(dstfile, tempf.name, newlines)
        if cfg['default'].getboolean('keepoldfile', True):
            oldfile = f"{dstfile}_old"
            if os.path.isfile(oldfile):
                os.chmod(oldfile, stat.S_IRUSR | stat.S_IWUSR)
            shutil.copy2(dstfile, oldfile)
            os.chmod(oldfile, stat.S_IRUSR)
    shutil.move(tempf.name, dstfile)
    if oldmask is not None:
        # restore umask
        os.umask(oldmask)
    else:
        os.chmod(dstfile, stat.S_IRUSR)


def read_json_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, EOFError):
        logging.warning(f"Could not read data from {filename}")
        return None


def write_json_file(filename, info):
    try:
        with open(filename, 'w') as f:
            return json.dump(info, f)
    except PermissionError:
        error(f"No permission to write to {filename}")


@timing
def updated_entries(conn, url, filename, obj_filter='?page_size=1&ordering=-updated_at') -> bool:
    """Check if first entry is unchanged"""

    filename = os.path.join(cfg['default']['workdir'], filename)
    url += obj_filter
    new_data = conn.get(url).json()
    if new_data['count'] == 0:
        error(f"No entries at: {url}")
    old_data = read_json_file(filename)
    if old_data is None:
        write_json_file(filename, new_data)
        return True

    old_updated_at = parse_date(old_data['results'][0]['updated_at'])
    new_updated_at = parse_date(new_data['results'][0]['updated_at'])
    if old_data['count'] != new_data['count'] or \
       old_data['results'][0]['id'] != new_data['results'][0]['id'] or \
       old_updated_at < new_updated_at:
        write_json_file(filename, new_data)
        return True
    return False


@timing
def run_postcommand():
    command = json.loads(cfg['default']['postcommand'])
    subprocess.run(command)
