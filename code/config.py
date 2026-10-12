# config.py
from dataclasses import dataclass
from enum import IntEnum

class LogLevel(IntEnum):
    """Log levels, ordered from least to most verbose."""
    OFF = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4

@dataclass
class Config:
    is_en: bool = False
    log_level: LogLevel = LogLevel.DEBUG
    log_heading_defense: bool = True

config = Config()  # single shared instance