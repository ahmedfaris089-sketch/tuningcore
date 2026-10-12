"""Review queue (FR-08): a person accepts, edits or rejects proposed records.

Every decision adds a new immutable revision through the JSON factory, so an accepted record is checked
against its BIN again before it is stored, and nothing earlier is overwritten. The decision itself is kept
with the revision it judged and the revision it produced.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core import audit
from core.db import Definition, DefinitionRevision, ReviewDecision
from core.errors import AktoolError
from core.jsonfactory import CONCEPT_FIELD, JsonFactory

# Identity and bookkeeping fields a reviewer cannot change through an edit.
PROTECTED_FIELDS = ("schema_version", "record_id", "revision", "category", "sha256", "md5", "file_size",
                    "review_state", "reviewer", "created_at", "updated_at", "provenance")
REVIEW_STEP = "human review"


def queue(session: Session, category: str | None = None, sha256: str | None = None, q: str | None = None,
          limit: int = 50) -> list[dict[str, Any]]:
    """Definitions whose latest revision is still a draft, oldest first."""
    latest = (select(DefinitionRevision.definition_id, func.max(DefinitionRevision.revision).label("rev"))
              .group_by(DefinitionRevision.definition_id).subquery())
    stmt = (select(Definition, DefinitionRevision)
            .join(latest, latest.c.definition_id == Definition.id)
            .join(DefinitionRevision, (DefinitionRevision.definition_id == Definition.id)
                  & (DefinitionRevision.revision == latest.c.rev))
            .where(DefinitionRevision.review_state == "draft"))
    if category:
        stmt = stmt.where(Definition.category == category)
    if sha256:
        stmt = stmt.where(Definition.sha256 == sha256.lower())
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Definition.record_id.ilike(like) | Definition.concept_key.ilike(like)
                          | DefinitionRevision.payload.ilike(like))
    rows = session.execute(stmt.order_by(Definition.id).limit(limit)).all()
    return [_queue_item(d, rev) for d, rev in rows]


def decide(session: Session, factory: JsonFactory, record_id: str, decision: str, actor: str,
           expected_revision: int, note: str | None = None, changes: dict[str, Any] | None = None,
           approve: bool = True) -> dict[str, Any]:
    definition = factory.get(session, record_id)
    current = definition.revisions[-1]
    if current.revision != expected_revision:
        raise AktoolError("STALE_REVIEW", f"record is at revision {current.revision}, not {expected_revision}",
                          field="revision", details={"latest": current.revision}, status_code=409)
    record = json.loads(current.payload)
    state = current.review_state
    changed: list[str] = []

    if decision == "accept":
        if state != "draft":
            raise AktoolError("NOT_A_DRAFT", f"only drafts can be accepted; this record is {state}", status_code=409)
        new_state = "approved"
    elif decision == "edit":
        if state == "deprecated":
            raise AktoolError("RECORD_REJECTED", "a rejected record cannot be edited", status_code=409)
        if not changes:
            raise AktoolError("NO_CHANGES", "an edit needs at least one changed field", field="changes")
        blocked = sorted(set(changes) & set(PROTECTED_FIELDS + (CONCEPT_FIELD[definition.category],)))
        if blocked:
            raise AktoolError("FIELD_NOT_EDITABLE", "these fields cannot be changed in a review",
                              field="changes", details={"fields": blocked})
        changed = sorted(k for k, v in changes.items() if record.get(k) != v)
        if not changed:
            raise AktoolError("NO_CHANGES", "the edit does not change anything", field="changes")
        record = {**record, **copy.deepcopy(changes)}
        new_state = "approved" if approve else "draft"
    elif decision == "reject":
        if state == "deprecated":
            raise AktoolError("RECORD_REJECTED", "this record is already rejected", status_code=409)
        if not (note and note.strip()):
            raise AktoolError("NOTE_REQUIRED", "say why the record is rejected", field="note")
        new_state = "deprecated"
    else:
        raise AktoolError("UNKNOWN_DECISION", "decision must be one of accept, edit, reject", field="decision")

    record["revision"] = current.revision + 1
    record["review_state"] = new_state
    record["reviewer"] = actor
    record["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if new_state == "approved" and REVIEW_STEP not in record.get("validation_steps", []):
        record["validation_steps"] = [*record.get("validation_steps", []), REVIEW_STEP]
    rev, checked = factory.add_revision(session, record_id, record, actor)

    row = ReviewDecision(definition_id=definition.id, from_revision_id=current.id, to_revision_id=rev.id,
                         decision=decision, reviewer=actor, note=note,
                         changed_fields=json.dumps(changed) if changed else None)
    session.add(row)
    audit.record(session, actor, f"review.{decision}", "definition", record_id, from_revision=current.revision,
                 to_revision=rev.revision, review_state=new_state, changed_fields=changed or None)
    session.commit()
    return {"record_id": record_id, "decision": decision, "from_revision": current.revision,
            "revision": rev.revision, "review_state": rev.review_state, "binary_verified": rev.binary_verified,
            "changed_fields": changed, "warnings": [w.to_dict() for w in checked.warnings]}


def history(session: Session, factory: JsonFactory, record_id: str) -> list[dict[str, Any]]:
    definition = factory.get(session, record_id)
    by_id = {r.id: r.revision for r in definition.revisions}
    rows = session.scalars(select(ReviewDecision).where(ReviewDecision.definition_id == definition.id)
                           .order_by(ReviewDecision.id))
    return [{"decision": r.decision, "reviewer": r.reviewer, "note": r.note,
             "from_revision": by_id[r.from_revision_id], "to_revision": by_id[r.to_revision_id],
             "changed_fields": json.loads(r.changed_fields) if r.changed_fields else [],
             "created_at": r.created_at.isoformat()} for r in rows]


def _queue_item(d: Definition, rev: DefinitionRevision) -> dict[str, Any]:
    p = json.loads(rev.payload)
    return {"record_id": d.record_id, "revision": rev.revision, "category": d.category, "name": p.get("name"),
            "concept_key": d.concept_key, "sha256": d.sha256, "software_id": d.software_id,
            "file_offset": p.get("file_offset"), "confidence": p.get("confidence"),
            "binary_verified": rev.binary_verified,
            "evidence_sources": sorted({e.get("source_type") for e in p.get("evidence", [])}),
            "created_by": rev.created_by, "created_at": rev.created_at.isoformat()}
