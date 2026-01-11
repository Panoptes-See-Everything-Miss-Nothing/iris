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
    vendor = Column(String, nullable=True)
    cpe_string = Column(String, nullable=False)

    cve = relationship("CVE", back_populates="packages")
    ranges = relationship(
        "VulnerableRange", back_populates="package", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("idx_ecosystem_package", vendor, package_name),)
