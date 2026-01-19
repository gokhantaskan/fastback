"""add_user_status_and_timestamps

Revision ID: 6bf28084b358
Revises: a7b74804c2a5
Create Date: 2026-01-18 23:58:48.170892

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '6bf28084b358'
down_revision: Union[str, Sequence[str], None] = 'a7b74804c2a5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create the enum type first (PostgreSQL)
    userstatus_enum = sa.Enum('pending', 'active', 'inactive', name='userstatus')
    userstatus_enum.create(op.get_bind(), checkfirst=True)

    # Add new columns with server defaults for existing rows
    op.add_column('users', sa.Column(
        'status',
        userstatus_enum,
        nullable=False,
        server_default='active',  # Existing users are assumed active
    ))
    op.add_column('users', sa.Column(
        'created_at',
        sa.DateTime(),
        server_default=sa.text('CURRENT_TIMESTAMP'),
        nullable=False,
    ))
    op.add_column('users', sa.Column(
        'updated_at',
        sa.DateTime(),
        server_default=sa.text('CURRENT_TIMESTAMP'),
        nullable=False,
    ))

    # Migrate is_active=False to status='inactive'
    op.execute("UPDATE users SET status = 'inactive' WHERE is_active = false")

    # Drop the old column
    op.drop_column('users', 'is_active')


def downgrade() -> None:
    """Downgrade schema."""
    # Add back is_active column with default True
    op.add_column('users', sa.Column(
        'is_active',
        sa.BOOLEAN(),
        nullable=False,
        server_default='true',
    ))

    # Migrate status='inactive' back to is_active=False
    op.execute("UPDATE users SET is_active = false WHERE status = 'inactive'")

    # Drop the new columns
    op.drop_column('users', 'updated_at')
    op.drop_column('users', 'created_at')
    op.drop_column('users', 'status')

    # Drop the enum type (PostgreSQL)
    userstatus_enum = sa.Enum('pending', 'active', 'inactive', name='userstatus')
    userstatus_enum.drop(op.get_bind(), checkfirst=True)
