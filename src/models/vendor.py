from sqlalchemy import Column, String, Integer
from sqlalchemy.orm import relationship

from .base import Base


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)

    packages = relationship(
        "VulnerablePackage",
        back_populates="vendor",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
