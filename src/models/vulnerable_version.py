from typing import Optional

from sqlalchemy import ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, str_100


class VulnerableVersion(Base):
    __tablename__ = "vulnerable_versions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    package_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerable_packages.id", ondelete="CASCADE"), nullable=False
    )

    fixed_version: Mapped[Optional[str_100]]
    including_version_start: Mapped[Optional[str_100]]
    excluding_version_end: Mapped[Optional[str_100]]
    including_version_end: Mapped[Optional[str_100]]
    operator: Mapped[Optional[str]] = mapped_column(String(20))
    negate: Mapped[Optional[bool]] = mapped_column(default=False)

    package: Mapped["VulnerablePackage"] = relationship(back_populates="versions")

    __table_args__ = (
        Index(
            "uq_version_range_per_package",
            "package_id",
            text("COALESCE(fixed_version, '')"),
            text("COALESCE(including_version_start, '')"),
            text("COALESCE(excluding_version_end, '')"),
            text("COALESCE(including_version_end, '')"),
            text("COALESCE(operator, '')"),
            unique=True,
        ),
        Index("ix_version_package_id", "package_id"),
    )
