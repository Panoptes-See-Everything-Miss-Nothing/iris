"""redesigned schema

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-02-28 00:01:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop old tables if they exist (fresh start)
    op.execute("DROP TABLE IF EXISTS cvss_v31 CASCADE")
    op.execute("DROP TABLE IF EXISTS cvss_v2 CASCADE")
    op.execute("DROP TABLE IF EXISTS vulnerable_versions CASCADE")
    op.execute("DROP TABLE IF EXISTS vulnerable_packages CASCADE")
    op.execute("DROP TABLE IF EXISTS cves CASCADE")
    op.execute("DROP TABLE IF EXISTS vendors CASCADE")

    # --- vendors ---
    op.create_table(
        "vendors",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_vendors_name", "vendors", ["name"])

    # --- cves ---
    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.Column("last_modified", sa.DateTime(), nullable=True),
        sa.Column("description", sa.String(4000), nullable=True),
        sa.Column("vuln_status", sa.String(70), nullable=True),
        sa.Column("source", sa.String(100), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_index("ix_cve_published", "cves", ["published"])
    op.create_index("ix_cve_last_modified", "cves", ["last_modified"])

    # --- cvss_scores ---
    op.create_table(
        "cvss_scores",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column("version", sa.String(10), nullable=False),
        sa.Column("base_score", sa.Float(), nullable=True),
        sa.Column("base_severity", sa.String(20), nullable=True),
        sa.Column("vector_string", sa.String(150), nullable=True),
        sa.Column("exploitability_score", sa.Float(), nullable=True),
        sa.Column("impact_score", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.cve_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id", "version", name="uq_cvss_cve_version"),
    )
    op.create_index("ix_cvss_cve_version", "cvss_scores", ["cve_id", "version"])
    op.create_index(
        "ix_cvss_score_severity", "cvss_scores", ["base_score", "base_severity"]
    )
    op.create_index("ix_cvss_scores_base_score", "cvss_scores", ["base_score"])
    op.create_index("ix_cvss_scores_base_severity", "cvss_scores", ["base_severity"])

    # --- cvss_v2_details ---
    op.create_table(
        "cvss_v2_details",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cvss_score_id", sa.Integer(), nullable=False),
        sa.Column("access_vector", sa.String(100), nullable=True),
        sa.Column("access_complexity", sa.String(100), nullable=True),
        sa.Column("authentication", sa.String(100), nullable=True),
        sa.Column("confidentiality_impact", sa.String(100), nullable=True),
        sa.Column("integrity_impact", sa.String(100), nullable=True),
        sa.Column("availability_impact", sa.String(100), nullable=True),
        sa.ForeignKeyConstraint(
            ["cvss_score_id"], ["cvss_scores.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cvss_score_id", name="uq_cvss_v2_details_score"),
    )

    # --- cvss_v31_details ---
    op.create_table(
        "cvss_v31_details",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cvss_score_id", sa.Integer(), nullable=False),
        sa.Column("attack_vector", sa.String(100), nullable=True),
        sa.Column("attack_complexity", sa.String(100), nullable=True),
        sa.Column("privileges_required", sa.String(100), nullable=True),
        sa.Column("user_interaction", sa.String(100), nullable=True),
        sa.Column("scope", sa.String(20), nullable=True),
        sa.Column("confidentiality_impact", sa.String(100), nullable=True),
        sa.Column("integrity_impact", sa.String(100), nullable=True),
        sa.Column("availability_impact", sa.String(100), nullable=True),
        sa.ForeignKeyConstraint(
            ["cvss_score_id"], ["cvss_scores.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cvss_score_id", name="uq_cvss_v31_details_score"),
    )

    # --- vulnerable_packages ---
    op.create_table(
        "vulnerable_packages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column("category", sa.String(10), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("vendor_id", sa.Integer(), nullable=True),
        sa.Column("cpe_string", sa.String(500), nullable=False),
        sa.ForeignKeyConstraint(["cve_id"], ["cves.cve_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vendor_id"], ["vendors.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "cve_id", "cpe_string", name="uq_vulnerable_package_cve_cpe"
        ),
    )
    op.create_index(
        "ix_vulnerable_packages_category", "vulnerable_packages", ["category"]
    )
    op.create_index(
        "ix_vulnerable_packages_package_name", "vulnerable_packages", ["package_name"]
    )
    op.create_index(
        "ix_vulnerable_packages_vendor_id", "vulnerable_packages", ["vendor_id"]
    )
    op.create_index(
        "idx_vendor_package", "vulnerable_packages", ["vendor_id", "package_name"]
    )
    op.create_index("ix_package_cve", "vulnerable_packages", ["cve_id"])

    # --- vulnerable_versions ---
    op.create_table(
        "vulnerable_versions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("package_id", sa.Integer(), nullable=False),
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Column("including_version_start", sa.String(100), nullable=True),
        sa.Column("excluding_version_end", sa.String(100), nullable=True),
        sa.Column("including_version_end", sa.String(100), nullable=True),
        sa.Column("operator", sa.String(20), nullable=True),
        sa.Column("negate", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(
            ["package_id"], ["vulnerable_packages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_version_package_id", "vulnerable_versions", ["package_id"])
    op.execute(
        "CREATE UNIQUE INDEX uq_version_range_per_package ON vulnerable_versions "
        "(package_id, COALESCE(fixed_version, ''), COALESCE(including_version_start, ''), "
        "COALESCE(excluding_version_end, ''), COALESCE(including_version_end, ''), "
        "COALESCE(operator, ''))"
    )


def downgrade() -> None:
    op.drop_table("vulnerable_versions")
    op.drop_table("vulnerable_packages")
    op.drop_table("cvss_v31_details")
    op.drop_table("cvss_v2_details")
    op.drop_table("cvss_scores")
    op.drop_table("cves")
    op.drop_table("vendors")
