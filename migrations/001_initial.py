"""
WireGuard Module - Initial Database Migration

Creates WireGuard tables using direct engine access.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel


async def upgrade(session: AsyncSession) -> None:
    """Create WireGuard module tables."""
    # Import models to register them in SQLModel metadata
    from modules.wireguard.models import (
        WgInstance, WgClient, WgGroup,
        WgGroupMember, WgGroupRule, WgMagicToken
    )
    
    # Import the engine directly from database module
    from core.database import engine
    
    # Use the engine directly for DDL operations
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    print("WireGuard module tables created")


async def downgrade(session: AsyncSession) -> None:
    """Drop WireGuard module tables."""
    from core.database import engine
    from sqlalchemy import text
    
    tables = ["wg_magic_token", "wg_group_rule", "wg_group_member", 
              "wg_client", "wg_group", "wg_instance"]
    
    async with engine.begin() as conn:
        for table in tables:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
