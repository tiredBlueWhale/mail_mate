# logger.py
"""
Tiny logger that reads its enabled state and threshold from config.config.log_level.

Usage:
    from logger import log
    log("something happened")                 # tagged as INFO by default
    log("debug detail", level=LogLevel.DEBUG) # explicit level
"""

import sys
from datetime import datetime

from config import config, LogLevel


def log(message: str, *args, level: LogLevel = LogLevel.INFO) -> None:
    """
    Print a timestamped log line if the message's level is <= config.log_level.

    Args:
        message: The text to log (supports printf-style % formatting).
        *args:   Optional arguments for %-formatting the message.
        level:   A LogLevel. Defaults to LogLevel.INFO.
    """
    if config.log_level == LogLevel.OFF or level > config.log_level:
        return

    if args:
        message = message % args

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stream = sys.stderr if level in (LogLevel.ERROR, LogLevel.WARN) else sys.stdout
    # print(f"[{ts}] [{level.name:5}] {message}", file=stream)
    print(f"{message}", file=stream)
