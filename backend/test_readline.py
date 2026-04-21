import asyncio
import sys

async def main():
    proc = await asyncio.create_subprocess_exec(
        sys.executable, '-c', 'print("A" * 70000)',
        stdout=asyncio.subprocess.PIPE,
        limit=65536
    )
    
    attempts = 0
    while True:
        try:
            line = await proc.stdout.readline()
            if not line:
                break
            print("Read line of len:", len(line))
        except ValueError as e:
            attempts += 1
            print(f"ValueError! Attempt {attempts}, Error: {e}")
            if attempts > 3:
                print("Infinite loop detected!")
                break
            continue

asyncio.run(main())
