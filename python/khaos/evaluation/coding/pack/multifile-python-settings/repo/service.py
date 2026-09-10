from settings import Settings


def load_settings(raw: dict[str, str]) -> Settings:
    return Settings(timeout=int(raw.get("timeout", 10)))
