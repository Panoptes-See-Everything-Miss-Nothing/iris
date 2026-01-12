from sqlalchemy import Column, String, Integer

from .base import Base


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)
