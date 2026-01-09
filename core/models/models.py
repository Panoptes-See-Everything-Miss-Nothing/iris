from sqlalchemy import Column, String, DateTime

from settings import Base


class CVE(Base):
    __tablename__ = "cves"

    cve_id = Column(String, primary_key=True, nullable=False)
    published = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    description = Column(String, nullable=True)
    vuln_status = Column(String, nullable=True)

    # package = relationship("AffectedPackage", back_populates="ranges")


# class AffectedPackage(Base):
#     __tablename__ = "affected_packages"

#     id = Column(Integer, primary_key=True, autoincrement=True)
#     cve_id = Column(String, ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False)
#     ecosystem = Column(String, nullable=False, index=True)
#     package_name = Column(String, nullable=False, index=True)
#     vendor = Column(String, nullable=True)

#     cve = relationship("CVE", back_populates="packages")
#     ranges = relationship("VulnerableRange", back_populates="package", cascade="all, delete-orphan")

#     __table_args__ = (
#         Index('idx_ecosystem_package', ecosystem, package_name),
#     )

# class AffectedVersion(Base):
