from typing import Optional

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, str_100, str_150


class CVSSScore(Base):
    """Single source of truth for CVSS scores (v2.0 and v3.1 only)."""

    __tablename__ = "cvss_scores"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )

    version: Mapped[str] = mapped_column(String(10), nullable=False)  # "2.0" or "3.1"

    base_score: Mapped[Optional[float]] = mapped_column(index=True)
    base_severity: Mapped[Optional[str]] = mapped_column(String(20), index=True)
    vector_string: Mapped[Optional[str_150]]

    exploitability_score: Mapped[Optional[float]]
    impact_score: Mapped[Optional[float]]

    cve: Mapped["CVE"] = relationship(back_populates="cvss_scores")
    details_v2: Mapped[Optional["CVSSv2"]] = relationship(
        back_populates="score", cascade="all, delete-orphan"
    )
    details_v31: Mapped[Optional["CVSSv31"]] = relationship(
        back_populates="score", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "version", name="uq_cvss_cve_version"),
        Index("ix_cvss_cve_version", "cve_id", "version"),
        Index("ix_cvss_score_severity", "base_score", "base_severity"),
    )


class CVSSv2(Base):
    __tablename__ = "cvss_v2_details"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cvss_score_id: Mapped[int] = mapped_column(
        ForeignKey("cvss_scores.id", ondelete="CASCADE"), nullable=False
    )

    access_vector: Mapped[Optional[str_100]]
    access_complexity: Mapped[Optional[str_100]]
    authentication: Mapped[Optional[str_100]]
    confidentiality_impact: Mapped[Optional[str_100]]
    integrity_impact: Mapped[Optional[str_100]]
    availability_impact: Mapped[Optional[str_100]]

    score: Mapped["CVSSScore"] = relationship(back_populates="details_v2")


class CVSSv31(Base):
    __tablename__ = "cvss_v31_details"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cvss_score_id: Mapped[int] = mapped_column(
        ForeignKey("cvss_scores.id", ondelete="CASCADE"), nullable=False
    )

    attack_vector: Mapped[Optional[str_100]]
    attack_complexity: Mapped[Optional[str_100]]
    privileges_required: Mapped[Optional[str_100]]
    user_interaction: Mapped[Optional[str_100]]
    scope: Mapped[Optional[str]] = mapped_column(String(20))
    confidentiality_impact: Mapped[Optional[str_100]]
    integrity_impact: Mapped[Optional[str_100]]
    availability_impact: Mapped[Optional[str_100]]

    score: Mapped["CVSSScore"] = relationship(back_populates="details_v31")
