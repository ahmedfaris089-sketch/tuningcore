"""Phase 1 tables: firmware blobs, firmware records, relations, audit log."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

RELATION_TYPES = ("original_of", "modified_from", "variant_of", "same_software", "same_calibration", "supersedes")
FILE_ROLES = ("original", "modified", "unknown")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class FirmwareBlob(Base):
    __tablename__ = "firmware_blob"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    md5: Mapped[str] = mapped_column(String(32), index=True)
    size: Mapped[int] = mapped_column(Integer)
    vault_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FirmwareRecord(Base):
    __tablename__ = "firmware_record"

    id: Mapped[int] = mapped_column(primary_key=True)
    blob_id: Mapped[int] = mapped_column(ForeignKey("firmware_blob.id"), unique=True)
    file_name_original: Mapped[str] = mapped_column(Text)
    file_role: Mapped[str] = mapped_column(String(16), default="unknown")
    software_id: Mapped[str | None] = mapped_column(String(64), index=True)
    calibration_id: Mapped[str | None] = mapped_column(String(64), index=True)
    ecu_label: Mapped[str | None] = mapped_column(String(128))
    vehicle_brand: Mapped[str | None] = mapped_column(String(64))
    vehicle_model: Mapped[str | None] = mapped_column(String(64))
    ecu_vendor: Mapped[str | None] = mapped_column(String(64))
    ecu_family: Mapped[str | None] = mapped_column(String(64), index=True)
    processor: Mapped[str | None] = mapped_column(String(64))
    base_address: Mapped[int | None] = mapped_column(Integer)
    read_tool: Mapped[str | None] = mapped_column(String(64))
    read_method: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    deleted: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    blob: Mapped[FirmwareBlob] = relationship()

    __table_args__ = (CheckConstraint(f"file_role IN {FILE_ROLES}", name="ck_file_role"),)


class FirmwareRelation(Base):
    __tablename__ = "firmware_relation"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("firmware_record.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("firmware_record.id"))
    relation_type: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(64), default="manual")
    reviewer: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relation_type", name="uq_relation"),
        CheckConstraint("source_id <> target_id", name="ck_no_self_link"),
        CheckConstraint(f"relation_type IN {RELATION_TYPES}", name="ck_relation_type"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_confidence"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[str] = mapped_column(String(64))
    details: Mapped[str | None] = mapped_column(Text)


DEFINITION_CATEGORIES = ("function_on_off", "function_map_table", "bosch_dtc", "non_bosch_dtc")
REVIEW_STATES = ("draft", "approved", "validated", "deprecated")


class Definition(Base):
    """Logical identity of a knowledge record; stable across revisions."""

    __tablename__ = "definition"

    id: Mapped[int] = mapped_column(primary_key=True)
    record_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    concept_key: Mapped[str] = mapped_column(String(128), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    software_id: Mapped[str | None] = mapped_column(String(64), index=True)
    calibration_id: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    revisions: Mapped[list["DefinitionRevision"]] = relationship(
        back_populates="definition", order_by="DefinitionRevision.revision")

    __table_args__ = (CheckConstraint(f"category IN {DEFINITION_CATEGORIES}", name="ck_definition_category"),)


class DefinitionRevision(Base):
    """Immutable payload snapshot. Rows are only ever inserted, never updated."""

    __tablename__ = "definition_revision"

    id: Mapped[int] = mapped_column(primary_key=True)
    definition_id: Mapped[int] = mapped_column(ForeignKey("definition.id"))
    revision: Mapped[int] = mapped_column(Integer)
    parent_revision_id: Mapped[int | None] = mapped_column(ForeignKey("definition_revision.id"))
    review_state: Mapped[str] = mapped_column(String(16))
    payload: Mapped[str] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    binary_verified: Mapped[bool] = mapped_column(default=False)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    definition: Mapped[Definition] = relationship(back_populates="revisions")

    __table_args__ = (
        UniqueConstraint("definition_id", "revision", name="uq_definition_revision"),
        CheckConstraint("revision >= 1", name="ck_revision_positive"),
        CheckConstraint(f"review_state IN {REVIEW_STATES}", name="ck_review_state"),
    )


class ExportArtifact(Base):
    __tablename__ = "export_artifact"

    id: Mapped[int] = mapped_column(primary_key=True)
    revision_id: Mapped[int] = mapped_column(ForeignKey("definition_revision.id"))
    schema_version: Mapped[str] = mapped_column(String(16))
    filename: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


REVIEW_DECISIONS = ("accept", "edit", "reject")


class ReviewDecision(Base):
    """A human decision on a definition: which revision was reviewed, which revision it produced, and why.

    Kept next to the proposal it judged so accepted, corrected and rejected proposals can later be used to
    measure and improve the AI.
    """

    __tablename__ = "review_decision"

    id: Mapped[int] = mapped_column(primary_key=True)
    definition_id: Mapped[int] = mapped_column(ForeignKey("definition.id"), index=True)
    from_revision_id: Mapped[int] = mapped_column(ForeignKey("definition_revision.id"))
    to_revision_id: Mapped[int] = mapped_column(ForeignKey("definition_revision.id"))
    decision: Mapped[str] = mapped_column(String(16))
    reviewer: Mapped[str] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(Text)
    changed_fields: Mapped[str | None] = mapped_column(Text)  # JSON list of top-level keys an edit changed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (CheckConstraint(f"decision IN {REVIEW_DECISIONS}", name="ck_review_decision"),)
