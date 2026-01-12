from sqlalchemy import Boolean, Column, String, ForeignKey, Integer
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
    negate = Column(Boolean, nullable=True)

    package = relationship("VulnerablePackage")
