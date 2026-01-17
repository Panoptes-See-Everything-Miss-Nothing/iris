"""renamed cvss_v3 to cvss_v31

Revision ID: abe1e8bf3b5f
Revises: d2706dbc2387
Create Date: 2026-01-17 08:17:49.541100

"""

from typing import Sequence, Union


# revision identifiers, used by Alembic.
revision: str = "abe1e8bf3b5f"
down_revision: Union[str, Sequence[str], None] = "d2706dbc2387"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
