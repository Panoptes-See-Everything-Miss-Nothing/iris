from sqlalchemy import Column, String, ForeignKey, Integer, Index
from sqlalchemy.orm import relationship

from .base import Base


class VulnerablePackage(Base):
    __tablename__ = "vulnerable_packages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(
        String, ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )
    category = Column(String, nullable=False, index=True)
    package_name = Column(String, nullable=False, index=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True, index=True)
    cpe_string = Column(String, nullable=False)

    cve = relationship("CVE", back_populates="packages")
    vendor = relationship("Vendor", back_populates="packages")

    versions = relationship(
        "VulnerableVersion",
        back_populates="package",
        cascade="all, delete-orphan",
        lazy="selectin",  # often better than default lazy loading
    )

    __table_args__ = (
        Index("idx_vendor_package", "vendor_id", "package_name"),
        Index("ix_package_cve", "cve_id"),
    )
