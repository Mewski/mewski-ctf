from pwn import *

HOST = "reverse.heroctf.fr"
PORT = 7001

with open("solve.c", "rb") as f:
    code = f.read()

conn = remote(HOST, PORT)
print(conn.recvuntil(b":").decode())
conn.send(code)
conn.shutdown("send")
print(conn.recvall(timeout=30).decode())
conn.close()

# Flag: Hero{Yu0_f0uNd_tH3_W4Y_oU7_0f_Th3_50rC3Rer_M4z3}
