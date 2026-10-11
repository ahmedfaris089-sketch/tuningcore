"""Stable, testable error codes. Every API error is {"error": {code, message, field, details}}."""

from __future__ import annotations

from typing import Any


class AktoolError(Exception):
    status_code = 400

    def __init__(self, code: str, message: str, field: str | None = None, details: dict[str, Any] | None = None,
                 status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code

    def to_dict(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "field": self.field, "details": self.details}}


class NotFound(AktoolError):
    status_code = 404
