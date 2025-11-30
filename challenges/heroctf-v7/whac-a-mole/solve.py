import base64
import io as stdio

import cv2
import numpy as np
from PIL import Image
from pwn import *


def count_moles(b64img):
    img = Image.open(stdio.BytesIO(base64.b64decode(b64img)))
    hsv = cv2.cvtColor(
        cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR), cv2.COLOR_BGR2HSV
    )
    mask = cv2.bitwise_not(
        cv2.inRange(hsv, np.array([35, 100, 50]), np.array([60, 255, 255]))
    )
    num_labels, _, stats, _ = cv2.connectedComponentsWithStats(mask)
    return sum(
        1 for i in range(1, num_labels) if 350 < stats[i, cv2.CC_STAT_AREA] < 50000
    )


io = remote("prog.heroctf.fr", 8000)

while True:
    line = io.recvline()
    if b"IMAGE:" in line:
        b64img = io.recvline().strip()
        io.recvuntil(b">> ")
        io.sendline(str(count_moles(b64img)).encode())
    elif b"Hero" in line or b"Wrong" in line:
        print(line.decode().strip())
        break

# Hero{c0l0r_m4sk1ng_4_c1u5t3r1ng_30cbdb51ae9a289fadcaa7be2f534151}
