import asyncio
from gds_api.db import engine
from gds_api.models import Base

async def create():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

asyncio.run(create())
print('All tables created successfully')
