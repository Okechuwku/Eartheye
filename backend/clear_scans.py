import asyncio
import asyncpg

async def main():
    conn = await asyncpg.connect(user="postgres", password="Scientist44@.", database="eartheye", host="localhost", port=5432)
    await conn.execute("UPDATE scans SET status='Failed' WHERE status='Pending' OR status='Running'")
    await conn.close()
    print("Orphan scans cleared.")

asyncio.run(main())
