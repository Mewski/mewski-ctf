# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pwntools",
#     "tqdm"
# ]
# ///
import math
import string
import threading
from concurrent.futures import ThreadPoolExecutor

import tqdm
from pwn import *

context.log_level = "error"

HOST, PORT = "crypto.heroctf.fr", 9002
SEPARATOR = ""
alphabet = string.ascii_letters + string.digits + "_}"


def make_conn():
    p = remote(HOST, PORT)
    p.recvuntil(b"Quit\n")
    return p


def reconnect(idx):
    with locks[idx]:
        try:
            conns[idx].close()
        except:
            pass
        conns[idx] = make_conn()


def query(args):
    idx, content = args
    for _ in range(3):
        try:
            with locks[idx]:
                p = conns[idx]
                p.sendlineafter(b"> ", b"1")
                p.sendlineafter(b"> ", b"2")
                p.sendlineafter(b"Filename: ", b"")
                p.sendlineafter(b"Content: ", content.encode().hex().encode())
                p.sendlineafter(b"> ", b"3")
                p.recvuntil(b"Encrypted content: ")
                return len(bytes.fromhex(p.recvline().strip().decode()))
        except EOFError:
            reconnect(idx)
    raise Exception(f"Connection {idx} failed after 3 retries")


conns = [make_conn() for _ in tqdm.tqdm(range(18), desc="Connecting")]
locks = [threading.Lock() for _ in range(18)]
known_flag = "Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_"

with ThreadPoolExecutor(max_workers=18) as ex:
    while True:
        scores = {}
        for char in tqdm.tqdm(alphabet, desc=f"Testing (known={len(known_flag)})"):
            tasks = [
                (x % 18, SEPARATOR + known_flag + char + "##" * x) for x in range(32)
            ]
            scores[char] = sum(ex.map(query, tasks))

        min_score = min(scores.values())
        total = sum(math.exp(min_score - s) for s in scores.values())
        probs = {c: math.exp(min_score - s) / total for c, s in scores.items()}

        print("\nTop 10 candidates:")
        for c, p in sorted(probs.items(), key=lambda x: -x[1])[:10]:
            logp = math.log(p)
            bar = "█" * int(p * 50)
            print(f"  {c!r:4} score={scores[c]:5}  p={p:.4f}  logp={logp:+.2f}  {bar}")

        best_char = max(probs, key=probs.get)
        known_flag += best_char
        print(f"\n{best_char} -> {known_flag}\n")
        if best_char == "}":
            break

for p in conns:
    p.close()

# Hero{5h0uld_h4v3_u53d_3ncryp7_7h3n_c0mpr355_1n5734d}
