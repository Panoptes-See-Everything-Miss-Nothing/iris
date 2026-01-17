"""corrected relationship name in cve model

Revision ID: e6e74f534873
Revises: abe1e8bf3b5f
Create Date: 2026-01-17 08:36:25.961891

"""

from typing import Sequence, Union


# revision identifiers, used by Alembic.
revision: str = "e6e74f534873"
down_revision: Union[str, Sequence[str], None] = "abe1e8bf3b5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
