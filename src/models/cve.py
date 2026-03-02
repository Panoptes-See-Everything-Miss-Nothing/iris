from datetime import datetime
from typing import List, Optional

from sqlalchemy import Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, str_4000


class CVE(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)

    published: Mapped[Optional[datetime]] = mapped_column(index=True)
    last_modified: Mapped[Optional[datetime]] = mapped_column(index=True)

    description: Mapped[Optional[str_4000]]
    vuln_status: Mapped[Optional[str]] = mapped_column(String(70))
    source: Mapped[Optional[str]] = mapped_column(String(100))

    # Relationships
    packages: Mapped[List["VulnerablePackage"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )

    cvss_scores: Mapped[List["CVSSScore"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_cve_published", "published"),
        Index("ix_cve_last_modified", "last_modified"),
    )
