from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from core.db import AuditEvent


def record(session: Session, actor: str, action: str, object_type: str, object_id: Any, **details: Any) -> None:
    session.add(AuditEvent(actor=actor, action=action, object_type=object_type, object_id=str(object_id),
                           details=json.dumps(details, default=str, sort_keys=True) if details else None))
