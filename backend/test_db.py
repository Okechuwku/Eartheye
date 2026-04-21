import asyncio
import asyncpg
import urllib.parse

async def main():
    p = "Scientist44@."
    try:
        conn = await asyncpg.connect(user="postgres", password=p, host="localhost", port=5432, database="eartheye")
        print("Database 'eartheye' exists.")
        await conn.close()
    except asyncpg.exceptions.InvalidCatalogNameError:
        print("Database 'eartheye' does not exist. Creating it...")
        sys_conn = await asyncpg.connect(user="postgres", password=p, host="localhost", port=5432, database="postgres")
        await sys_conn.execute('CREATE DATABASE eartheye')
        await sys_conn.close()
        print("Created database 'eartheye'")

asyncio.run(main())
