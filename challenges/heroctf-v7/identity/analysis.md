# Identity Challenge Analysis - HeroCTF v7

## Challenge Overview

- **Description**: "I added a protection layer in front of my database, it's safe now... right? Right??"
- **Flag Format**: `Hero{\S+}`
- **Author**: 25kGoldn

## Architecture

The challenge consists of two binaries running under supervisord:

1. **identityd** (port 5555) - Main database service handling user queries
2. **securityd** (Unix socket `/tmp/securityd.sock`) - Security daemon that validates operations

### Communication Flow

```
Client -> identityd (TCP 5555) -> securityd (Unix socket) -> identityd -> SQLite DB
```

### Database Schema

```sql
CREATE TABLE users(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    system_uid INTEGER,
    email      TEXT,
    role       TEXT
);
```

**Initial Data**:
```
1|John|1000|John@doe.com|user
2|Bob|1001|bob@gmail.com|user
1337|root|666|Hero{FLAG}|root   <-- FLAG IS IN EMAIL FIELD OF ROOT USER
```

## Binary Analysis

### identityd

**Security Mitigations**:
- Full RELRO
- Stack Canary
- NX enabled
- PIE enabled

**Protocol**: Text-based commands over TCP
- `GET <id>` - Retrieve user by ID
- `ADD <username> <uid> <email> <role>` - Add new user
- `UPDATE <id> <username> <uid> <email> <role>` - Update user
- `DELETE <id>` - Delete user
- `QUIT` / `EXIT` - Close connection

### securityd

**Security Mitigations**:
- Partial RELRO
- **No canary**
- NX enabled
- **No PIE** (base at 0x400000)

**Seccomp Rules** (blocklist mode with `SCMP_ACT_ALLOW` default):
- Blocks syscall 59 (execve)
- Blocks syscall 322 (execveat)
- Blocks syscall 32 (dup)
- Blocks syscall 33 (dup2)
- Blocks syscall 292 (dup3)

## Security Logic Analysis

### Handler Function Pointer Table

securityd stores handler function pointers in a table computed as:
```c
handler = *(g_state + (op + 0x170) * 8)
```

Handler addresses (fixed due to no PIE):
- handler[1] at 0x405d28: `op_check_delete` (0x402039)
- handler[2] at 0x405d30: `op_check_add` (0x401e97)
- handler[3] at 0x405d38: `op_check_update` (0x401f62)
- handler[4] at 0x405d40: `op_check_get` (0x401dc9)

### TCC (Transparency, Consent, and Control) System

When an operation involves uid=666 (root), securityd triggers a "TCC" approval flow:
1. Creates a session in `g_state`
2. Spawns a thread that reads from stdin for "allow"/"deny"
3. Times out after 10 seconds (defaults to deny)

### Operation Checks

**op_check_get(id, system_uid, caller_uid)**:
```c
if (system_uid == 666) {
    run_tcc();  // Blocks waiting for approval
} else {
    return 1;   // ALLOW
}
```

**op_check_add(new_uid, 0, caller_uid)**:
```c
if (new_uid == 666) {
    run_tcc();
} else {
    return 1;   // ALLOW - checks arg1 (new_uid) against 666
}
```

## The Vulnerability: Session Table Overflow

### Memory Layout

```
g_state:           0x4051a0 (3008 bytes for sessions)
g_next_session_idx: 0x405d60
g_last_role:       0x405d80 (256 bytes)

Session structure (0x170 bytes each):
  +0x00: arg1 (4 bytes)
  +0x04: arg2 (4 bytes)
  +0x08: arg3 (4 bytes)
  +0x0c: role (256 bytes, copied from g_last_role)
  +0x10c: done flag
  +0x110: result
  +0x118: mutex
  +0x140: cond var
```

### Session Index Bounds Check Bug

In `tcc_session_create`:
```c
int idx = g_next_session_idx++;
if (idx > 8) idx = 8;  // Clamps to 8, but 8 is still used!
session = g_state + idx * 0x170;
```

Session boundaries:
- Sessions 0-7: 0x4051a0 - 0x405d20 (within g_state)
- **Session 8: 0x405d20** - overlaps with handler table!

### The Overlap

When session 8 is created at 0x405d20:
```
Session 8 offset 0x00 (0x405d20) = arg1  -> overlaps handler[0]
Session 8 offset 0x04 (0x405d24) = arg2  -> overlaps handler[0] high bytes
Session 8 offset 0x08 (0x405d28) = arg3  -> overlaps handler[1]
Session 8 offset 0x0c (0x405d2c) = role  -> overlaps handler[1]+4 onwards

handler[4] (GET) at 0x405d40 = role[20:28]
```

**We control the role field, so we can overwrite handler[4]!**

## Exploitation

### Attack Strategy

1. Create 8 TCC sessions (indices 0-7) by triggering operations with uid=666
2. Create session 8 with a crafted role field that overwrites handler[4]
3. Set handler[4] to point to `op_check_add` (0x401e97)
4. When GET 1337 is called:
   - Handler is now `op_check_add`
   - `op_check_add` checks `arg1` (id=1337) against 666
   - 1337 != 666, so it returns ALLOW!

### Why op_check_add Works

The key insight is that different handlers check different arguments:
- `op_check_get` checks `arg2` (system_uid) against 666
- `op_check_add` checks `arg1` (new_uid) against 666

For a GET request, arguments are: `(id, system_uid, caller_uid)`
- If handler is `op_check_get`: checks system_uid=666 -> TCC required -> BLOCKED
- If handler is `op_check_add`: checks id=1337 -> 1337 != 666 -> ALLOWED!

### Exploit Steps

1. Create test user: `ADD testuser 999 test@test.com testrole`
2. Fill sessions 0-7 by sending 8 UPDATE commands with new_uid=666 (triggers TCC)
3. Send 9th UPDATE with crafted role containing `p64(0x401e97)` at offset 20
4. While session 8 is active, send `GET 1337`
5. The corrupted handler allows the request
6. Flag is returned in the email field!

### Payload Construction

```python
role_payload = b"A" * 20           # Padding to handler[4] offset
role_payload += p64(0x00401e97)    # op_check_add address
role_payload += b"B" * (100 - len(role_payload))
```

## Solution

See `solve.py` for the complete exploit.

```bash
# Local testing
python3 solve.py

# Remote
python3 solve.py <host> <port>
```

## Flag

```
Hero{FAKEFLAGFAKEFLAGFAKEFLAG}  # Local test flag
```

## Key Takeaways

1. **Session management bugs**: Improper bounds checking on session indices can lead to memory corruption
2. **Handler table corruption**: When function pointers are stored in data sections, adjacent overflows can redirect execution
3. **Type confusion via handler swapping**: Different handlers interpret arguments differently, allowing security bypasses
4. **No PIE = Fixed addresses**: Made exploitation straightforward since handler addresses are predictable
