from __future__ import annotations

from pathlib import Path

from platformdirs import PlatformDirs

# TODO: use platformdirs, override these in actual configs
# DEFAULT_WORKDIR = Path("/tmp/mreg-tools/workdir")
# DEFAULT_DESTDIR = Path("/tmp/mreg-tools/dstdir")
# DEFAULT_LOGDIR = Path("/tmp/mreg-tools/logdir")
DEFAULT_WORKDIR = Path("/tmp/mreg/workdir")
DEFAULT_DESTDIR = Path("/tmp/mreg/dstdir")
DEFAULT_LOGDIR = Path("/tmp/mreg/logdir")

_pdir = PlatformDirs(appname="mreg-tools")


CONFIG_DIR = _pdir.user_config_path
LOG_DIR = _pdir.user_log_path
CACHE_DIR = _pdir.user_cache_path
DATA_DIR = _pdir.user_data_path

DEFAULT_CONFIG_FILENAME = "config.toml"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.toml"
DEFAULT_CONFIG_PATHS = [
    DEFAULT_CONFIG_PATH,
    Path.cwd() / DEFAULT_CONFIG_FILENAME,
    Path.home() / ".config" / "mreg-tools" / DEFAULT_CONFIG_FILENAME,
    Path("/etc/mreg-tools/") / DEFAULT_CONFIG_FILENAME,
]
