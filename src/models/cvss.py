from sqlalchemy import (
    Column,
    String,
    Float,
    ForeignKey,
    Integer,
    Boolean,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declared_attr

from .base import Base


class CVSSBase(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)

    cve_id = Column(
        String,
        ForeignKey("cves.cve_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )

    # Common to both v2 and v3
    version = Column(String(10), nullable=False)
    base_score = Column(Float, nullable=True)
    base_severity = Column(String(20), nullable=True, index=True)
    vector_string = Column(String(150), nullable=True)
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)

    @declared_attr
    def cve(cls):
        return relationship(
            "CVE",
            back_populates="cvss_v2" if cls.__name__ == "CVSSv2" else "cvss_v3",
            uselist=False,
        )


class CVSSv2(CVSSBase):
    __tablename__ = "cvss_v2"

    access_vector = Column(String(30), nullable=True)
    access_complexity = Column(String(30), nullable=True)
    authentication = Column(String(30), nullable=True)
    confidentiality_impact = Column(String(30), nullable=True)
    integrity_impact = Column(String(30), nullable=True)
    availability_impact = Column(String(30), nullable=True)

    ac_insuf_info = Column(Boolean, nullable=True)
    obtain_all_privilege = Column(Boolean, nullable=True)
    obtain_user_privilege = Column(Boolean, nullable=True)
    obtain_other_privilege = Column(Boolean, nullable=True)
    user_interaction_required = Column(Boolean, nullable=True)

    __table_args__ = (UniqueConstraint("cve_id", name="uq_cvss_v2_cve"),)


class CVSSv3(CVSSBase):
    __tablename__ = "cvss_v3"

    attack_vector = Column(String(30), nullable=True)
    attack_complexity = Column(String(30), nullable=True)
    privileges_required = Column(String(30), nullable=True)
    user_interaction = Column(String(30), nullable=True)
    scope = Column(String(20), nullable=True)
    confidentiality_impact = Column(String(30), nullable=True)
    integrity_impact = Column(String(30), nullable=True)
    availability_impact = Column(String(30), nullable=True)

    __table_args__ = (UniqueConstraint("cve_id", name="uq_cvss_v3_cve"),)


# TODO CVSS_v30
# TODO CVSS_v4
