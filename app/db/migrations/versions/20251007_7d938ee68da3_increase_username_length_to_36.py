"""increase username length to 36

Revision ID: 7d938ee68da3
Revises: 57eba0a293f2
Create Date: 2025-10-07 14:36:48.652003

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7d938ee68da3'
down_revision = '57eba0a293f2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # تغییر طول ستون username به 36
    op.alter_column(
        'users',
        'username',
        type_=sa.String(length=36, collation='utf8mb4_bin'),
        nullable=True
    )



def downgrade() -> None:
    op.alter_column(
        'users',
        'username',
        type_=sa.String(length=32, collation='utf8mb4_bin'),
        nullable=True
    )
