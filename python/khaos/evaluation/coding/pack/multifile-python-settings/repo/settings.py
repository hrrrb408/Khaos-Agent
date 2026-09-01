from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    timeout: int = 10
