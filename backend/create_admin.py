import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import asyncio
from backend.database import AsyncSessionLocal
from backend.models import User
from backend.auth import get_password_hash
from sqlalchemy.future import select

async def create_admin():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == "okechuwkujoel44@gmail.com"))
        user = result.scalars().first()
        if not user:
            user = User(
                email="okechuwkujoel44@gmail.com",
                hashed_password=get_password_hash("Scientist44@"),
                role="Admin",
                subscription_tier="Premium"
            )
            db.add(user)
        else:
            user.hashed_password = get_password_hash("Scientist44@")
            user.role = "Admin"
            user.subscription_tier = "Premium"
        await db.commit()
        print("Admin user successfully provisioned or updated.")

if __name__ == "__main__":
    asyncio.run(create_admin())
