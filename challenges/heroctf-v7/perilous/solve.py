from pwn import *

io = remote("crypto.heroctf.fr", 9001)

io.recvuntil(b"flag k: ")
io.sendline(b"41" * 5)
flag_ct = bytes.fromhex(io.recvline().decode().strip())
flag_len = len(flag_ct)

io.recvuntil(b"k: ")
io.sendline(b"41" * 32)
io.recvuntil(b"m: ")
io.sendline(b"00" * flag_len)
c_zeros = bytes.fromhex(io.recvline().decode().strip())

flag = bytes(a ^ b for a, b in zip(flag_ct, c_zeros))
print(flag)

# Hero{7h3_p3r1l5_0f_r3p3471n6_p4773rn5}
