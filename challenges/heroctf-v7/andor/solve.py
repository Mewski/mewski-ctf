from pwn import *

io = remote("crypto.heroctf.fr", 9000)

a_acc = 0
o_acc = None

for _ in range(100):
    io.recvuntil(b"a = ")
    a = bytes.fromhex(io.recvline().decode().strip())
    io.recvuntil(b"o = ")
    o = bytes.fromhex(io.recvline().decode().strip())
    io.sendline(b"")

    a_acc = int.from_bytes(a, "big") | a_acc
    if o_acc is None:
        o_acc = int.from_bytes(o, "big")
    else:
        o_acc = int.from_bytes(o, "big") & o_acc

l = len(a)
flag = a_acc.to_bytes(l, "big") + o_acc.to_bytes(l, "big")

print(flag.decode())

# Hero{y0u_4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4g_4nd_p01n75}
