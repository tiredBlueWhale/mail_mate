# config.py
from dataclasses import dataclass

@dataclass
class Config:
    is_en: bool = False
    verbose: bool = False

config = Config()  # single shared instance