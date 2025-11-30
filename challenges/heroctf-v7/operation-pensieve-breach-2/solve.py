import base64
import json

from Crypto.Cipher import AES

key = b"ec6c34408ae2523fe664bd1ccedc9c28"
iv = b"ecb2b0364290d1df"

creds = [
    "mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K",
    "U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==",
]

for i, enc in enumerate(creds, 1):
    encrypted = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]
    data = json.loads(decrypted.decode("utf-8"))
    print(
        f"Piece {i}: Field1(login)={data['login']}, Field2(password)={data['password']}"
    )

print()

file1 = "/var/www/glpi/src/Auth.php"
file2 = "/var/www/glpi/pics/screenshots/example.gif"
value = "FawkesPhoenix#9!"

flag = f"Hero{{{file1};{file2};{value}}}"
print(flag)
