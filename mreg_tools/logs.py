from __future__ import annotations

import logging
import logging.config
from typing import TYPE_CHECKING
from typing import Any

import structlog
from structlog.typing import EventDict

from mreg_tools.common.utils import mkdir
from mreg_tools.config import Config
from mreg_tools.config import ConsoleLoggingConfig
from mreg_tools.config import FileLoggingConfig

if TYPE_CHECKING:
    from logging.config import _DictConfigArgs


type HandlerDict = dict[str, Any]


def _serialize_sets(logger, method_name, event_dict: EventDict) -> EventDict:
    """Convert sets to lists for JSON serialization."""
    for key, value in event_dict.items():
        if isinstance(value, set):
            event_dict[key] = list(value)
    return event_dict


timestamper = structlog.processors.TimeStamper(fmt="iso")

pre_chain = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    timestamper,
    structlog.stdlib.ExtraAdder(),
    _serialize_sets,
]
"""Pre chain for non-structlog loggers (e.g. standard library)."""


def get_console_handler_config(config: ConsoleLoggingConfig) -> HandlerDict:
    """Get a dict config for a console handler based on the configuration."""
    return {
        "level": config.level,
        "class": "logging.StreamHandler",
        "formatter": "console",
    }


def get_file_handler_config(config: FileLoggingConfig) -> HandlerDict:
    """Get a dict config for a file handler based on the configuration."""
    handler_config: HandlerDict = {
        "class": (
            "logging.handlers.RotatingFileHandler"
            if config.rotate
            else "logging.FileHandler"
        ),
        "filename": str(config.path),
        "encoding": "utf8",
        "level": config.level,
        "formatter": "file",
    }
    if config.rotate:
        handler_config.update(
            {
                "maxBytes": config.max_size_as_bytes(),
                "backupCount": config.max_logs,
            }
        )
    return handler_config


# TODO: remove console logging! We already have the rich console!


def configure_logging(config: Config) -> None:
    # Create the root logger and clear its default handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(config.logging.level)

    # Build handlers conditionally based on config
    handlers: dict[str, HandlerDict] = {}
    if config.logging.console.enabled:
        handlers["default"] = get_console_handler_config(config.logging.console)
    if config.logging.file.enabled:
        # NOTE: logdir MUST exist at this point, as the log file is created
        # upon configuring the file handler. We create it right here now, but
        # it should be handled elsewhere ideally.
        mkdir(config.logging.file.directory)
        handlers["file"] = get_file_handler_config(config.logging.file)

    config_dict: _DictConfigArgs = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.dev.ConsoleRenderer(colors=True),
                ],
                "foreign_pre_chain": pre_chain,
            },
            "file": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.processors.dict_tracebacks,
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                "foreign_pre_chain": pre_chain,
            },
        },
        "handlers": handlers,
        "loggers": {
            "": {
                "handlers": list(handlers),
                "level": "DEBUG",  # handlers filter by their own level
                "propagate": True,
            },
        },
    }

    logging.config.dictConfig(config_dict)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            _serialize_sets,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Show which file is being logged to (if any)
    if config.logging.file.enabled:
        structlog.stdlib.get_logger().debug(
            "Logging to file",
            file=str(config.logging.file.path),
            level=config.logging.file.level,
        )
