from __future__ import annotations

from pathlib import Path

from platformdirs import PlatformDirs

_pdir = PlatformDirs(appname="mreg-tools")

# Base directories
CONFIG_DIR = _pdir.user_config_path
LOG_DIR = _pdir.user_log_path
CACHE_DIR = _pdir.user_cache_path
DATA_DIR = _pdir.user_data_path

# Default directories for command input/output files
DEFAULT_DESTDIR = DATA_DIR / "output"
DEFAULT_EXTRADIR = DATA_DIR / "extra"
DEFAULT_WORKDIR = CACHE_DIR
DEFAULT_LOGDIR = LOG_DIR

# Config file defaults + search paths
DEFAULT_CONFIG_FILENAME = "config.toml"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.toml"
DEFAULT_CONFIG_PATHS = [
    DEFAULT_CONFIG_PATH,
    Path.cwd() / DEFAULT_CONFIG_FILENAME,
    Path.home() / ".config" / "mreg-tools" / DEFAULT_CONFIG_FILENAME,
    Path("/etc/mreg-tools/") / DEFAULT_CONFIG_FILENAME,
]
