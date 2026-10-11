"""Run the core: python -m core   (AKTOOL_MODE=local by default, bound to 127.0.0.1:8765)."""

import uvicorn

from core.api import create_app
from core.settings import Settings

if __name__ == "__main__":
    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
