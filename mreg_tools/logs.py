from __future__ import annotations

import logging
import logging.config
from pathlib import Path
from types import NoneType
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

JsonPrimitives = (str, int, float, bool, NoneType)


def _transform(value: Any) -> Any:
    """Transform a value into a JSON-serializable form if it is a non-primitive type."""
    # Primitive type - return as is
    if isinstance(value, JsonPrimitives):
        return value

    # Special considerations for certain types
    if isinstance(value, Path):
        return str(value)

    # Recursively transform collections into lists/dicts of primitives
    if isinstance(value, set):
        return [_transform(v) for v in value]
    if isinstance(value, dict):
        return {k: _transform(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_transform(v) for v in value]
    return value  # let serializer handle/fail


def transform_types(logger, method_name, event_dict: EventDict) -> EventDict:
    """Transform non-primitive types in the event dict into JSON-serializable forms."""
    for k, v in event_dict.items():
        event_dict[k] = _transform(v)
    return event_dict


timestamper = structlog.processors.TimeStamper(fmt="iso")

pre_chain = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    timestamper,
    structlog.stdlib.ExtraAdder(),
    transform_types,
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
            transform_types,
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
