from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import relationship

from .base import Base


class CVE(Base):
    __tablename__ = "cves"

    cve_id = Column(String, primary_key=True, nullable=False)
    published = Column(DateTime(timezone=True), nullable=True)
    last_modified = Column(DateTime(timezone=True), nullable=True)
    description = Column(String, nullable=True)
    vuln_status = Column(String(70), nullable=True)
    source = Column(String, nullable=True)

    packages = relationship(
        "VulnerablePackage", back_populates="cve", cascade="all, delete-orphan"
    )

    cvss_v2 = relationship("CVSSv2", back_populates="cve", uselist=False)
    cvss_v3 = relationship("CVSSv31", back_populates="cve", uselist=False)
