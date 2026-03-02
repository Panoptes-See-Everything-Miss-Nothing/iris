from typing import List, Optional

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class VulnerablePackage(Base):
    __tablename__ = "vulnerable_packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )

    category: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    vendor_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("vendors.id"), nullable=True, index=True
    )
    cpe_string: Mapped[str] = mapped_column(String(500), nullable=False)

    cve: Mapped["CVE"] = relationship(back_populates="packages")
    vendor: Mapped[Optional["Vendor"]] = relationship(back_populates="packages")
    versions: Mapped[List["VulnerableVersion"]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "cpe_string", name="uq_vulnerable_package_cve_cpe"),
        Index("idx_vendor_package", "vendor_id", "package_name"),
        Index("ix_package_cve", "cve_id"),
    )
