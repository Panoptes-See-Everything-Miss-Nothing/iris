from sqlalchemy import (
    Boolean,
    Column,
    String,
    ForeignKey,
    Integer,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .base import Base


class VulnerableVersion(Base):
    __tablename__ = "vulnerable_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    package_id = Column(
        Integer,
        ForeignKey("vulnerable_packages.id", ondelete="CASCADE"),
        nullable=False,
    )
    fixed_version = Column(String(100), nullable=True)
    including_version_start = Column(String(100), nullable=True)
    excluding_version_end = Column(String(100), nullable=True)
    including_version_end = Column(String(100), nullable=True)
    operator = Column(String(100), nullable=True)
    negate = Column(Boolean, default=False, nullable=False)

    package = relationship("VulnerablePackage")

    __table_args__ = (
        UniqueConstraint(
            "package_id",
            "fixed_version",
            "including_version_start",
            "excluding_version_end",
            "including_version_end",
            "operator",
            "negate",
            name="uq_version_range_per_package",  # ← give it a name
        ),
        # Speed up queries
        Index("ix_version_package_id", "package_id"),
    )
