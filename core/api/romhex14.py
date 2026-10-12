"""romHEX14 cloud API wire protocol (same paths, fields and response shapes as romHEX14's server/app.py).

Mounted at /v1 so romHEX14's "Cloud Tools > Configure" server URL can be the core itself, e.g.
http://127.0.0.1:8765. In server mode the API key goes either in the URL (https://host/rx14/<key>, needed
for the DTC calls, which romHEX14 sends without a token) or as romHEX14's Pro token (Bearer).
"""

from __future__ import annotations

import hmac
import time
from urllib.parse import quote
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from fastapi import APIRouter, Depends, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from core.compat.romhex14 import CompatError, Patched, Rx14Engine
from core.errors import AktoolError
from core.settings import Settings

SERVICE = "aktool"


def build_router(settings: Settings, db: Callable[..., Iterator[Session]], engine: Rx14Engine) -> APIRouter:
    router = APIRouter()

    def caller(request: Request, authorization: str | None = Header(default=None)) -> str:
        if settings.mode == "local":
            return "romhex14-local"
        key = request.path_params.get("key")
        if key is None and authorization and authorization.startswith("Bearer "):
            key = authorization[7:].strip()
        if not key or not hmac.compare_digest(key, settings.api_key or ""):
            raise CompatError(401, "invalid or missing token", "UNAUTHORIZED")
        return "romhex14"

    async def read_rom(rom: UploadFile | None) -> bytes:
        data = await rom.read(settings.max_bin_bytes + 1) if rom is not None else b""
        if not data:
            raise CompatError(400, "missing 'rom' field", "MISSING_ROM")
        if len(data) > settings.max_bin_bytes:
            raise CompatError(413, "payload too large", "FILE_TOO_LARGE", {"limit": settings.max_bin_bytes})
        return data

    @router.get("/health")
    def health(_: str = Depends(caller)) -> dict[str, Any]:
        return {"ok": True, "service": SERVICE, "ts": int(time.time()), "engine": "ready",
                "checksum_families": engine.checksums.families(), "checksum_policy": settings.rx14_checksum}

    @router.post("/dtc/analyze")
    async def dtc_analyze(rom: UploadFile | None = File(None), family: str | None = Form(None),
                          session: Session = Depends(db), who: str = Depends(caller)) -> dict[str, Any]:
        data = await read_rom(rom)
        with _compat_errors():
            return engine.analyze(session, data, _family(family), who)

    @router.post("/dtc/disable")
    async def dtc_disable(rom: UploadFile | None = File(None), codes: str = Form(""),
                          family: str | None = Form(None), session: Session = Depends(db),
                          who: str = Depends(caller)) -> Response:
        data = await read_rom(rom)
        wanted = [c.strip() for c in codes.split(",") if c.strip()]
        if not wanted:
            raise CompatError(400, "missing 'codes' field", "MISSING_CODES")
        with _compat_errors():
            return _binary(engine.disable_dtcs(session, data, wanted, _family(family), who), len(data), "free")

    @router.post("/features/detect")
    async def features_detect(rom: UploadFile | None = File(None), family: str | None = Form(None),
                              session: Session = Depends(db), who: str = Depends(caller)) -> dict[str, Any]:
        data = await read_rom(rom)
        with _compat_errors():
            return engine.detect_features(session, data, _family(family), who)

    @router.post("/features/apply")
    async def features_apply(rom: UploadFile | None = File(None), features: str = Form(""),
                             family: str | None = Form(None), session: Session = Depends(db),
                             who: str = Depends(caller)) -> Response:
        data = await read_rom(rom)
        wanted = [f.strip() for f in features.split(",") if f.strip()]
        if not wanted:
            raise CompatError(400, "missing 'features' field", "MISSING_FEATURES")
        with _compat_errors():
            return _binary(engine.apply_features(session, data, wanted, _family(family), who), len(data), "pro")

    @router.post("/module/apply")
    def module_apply(_: str = Depends(caller)) -> JSONResponse:
        raise CompatError(501, "engine has no module support", "NOT_SUPPORTED")

    return router


async def compat_error_handler(_: Request, exc: CompatError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


@contextmanager
def _compat_errors() -> Iterator[None]:
    try:
        yield
    except AktoolError as exc:
        raise CompatError(exc.status_code, exc.message, exc.code, exc.details or None) from exc


def _family(raw: str | None) -> str | None:
    return (raw or "").strip().upper() or None


def _binary(result: Patched, size_in: int, tier: str) -> Response:
    return Response(content=result.data, media_type="application/octet-stream", headers={
        "X-cloudfx-tier": tier, "X-cloudfx-bytes-in": str(size_in), "X-cloudfx-bytes-out": str(len(result.data)),
        "X-cloudfx-checksum": result.checksum, "X-cloudfx-family": result.family,
        "X-cloudfx-firmware-id": str(result.firmware_id),
        "X-cloudfx-records": quote(",".join(result.record_ids), safe=",-_.:")})
