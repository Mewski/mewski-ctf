from pwn import *

HOST = "reverse.heroctf.fr"
PORT = 7002

with open("solve.c", "rb") as f:
    code = f.read()

conn = remote(HOST, PORT)
print(conn.recvuntil(b":").decode())
conn.send(code)
conn.shutdown("send")
print(conn.recvall(timeout=30).decode())
conn.close()

# Hero{Yu0_f0rG3d_y0uR_oWn_p47H_4pPr3nT1cE}
