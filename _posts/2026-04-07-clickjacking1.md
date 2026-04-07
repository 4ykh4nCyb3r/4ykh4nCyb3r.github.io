---
title: "Lab 1: Basic clickjacking with CSRF token protection"
date: 2026-04-07
categories: [portswigger, Clickjacking] 
tags: [clickjacking]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
---

## 1. Executive Summary

**Vulnerability:** Clickjacking (UI Redressing).

**Description:** The application relies entirely on CSRF (Cross-Site Request Forgery) tokens to protect state-changing actions like "Delete Account". While this prevents an attacker from forging a background request, the application fails to restrict whether it can be embedded within an `<iframe>` on an external site. This allows an attacker to load the target page invisibly over a decoy website, tricking the victim into clicking the hidden "Delete Account" button.

**Impact:** Unintended State Changes. Because the victim clicks the real button within the invisible iframe, the browser automatically includes their valid session cookies and the CSRF token. This bypasses the CSRF protection and forces the victim to delete their own account.

## 2. The Attack

**Objective:** Trick the victim into clicking the "Delete Account" button by overlaying an invisible iframe on top of a decoy "Click Me" button.

1. **Reconnaissance:**
    - I logged in as `wiener`.
    - I inspected the `/my-account` page and noticed the "Delete Account" button.
    - I checked the HTTP response headers for the page. It was missing both `X-Frame-Options` and `Content-Security-Policy` (specifically the `frame-ancestors` directive), meaning the page could be framed by any domain.
2. **Payload Construction:**
    - I went to the Exploit Server and created a malicious HTML page.
    - I used CSS to create two overlapping layers.
    - **Layer 1 (The Decoy):** A visible `<div>` containing the text "Click me", placed at `z-index: 1` (the bottom layer).
    - **Layer 2 (The Trap):** An `<iframe>` loading the target `/my-account` page. I set its `z-index: 2` (so it sat on top of the decoy), positioned it absolutely, and set `opacity: 0.1` so I could see it faintly.
3. **Alignment & Exploitation:**
    - I adjusted the `top` and `left` pixel values of the decoy `<div>` until the "Click me" text sat perfectly underneath the faint "Delete account" button in the iframe.
    - Once aligned, I changed the iframe's opacity to `0.0001`, making it completely invisible.
    - I delivered the exploit to the victim. When the victim clicked the visible "Click me" text, their cursor actually registered a click on the invisible "Delete account" button layered directly above it.

## 3. Code Review

*This section analyzes why the application is vulnerable. Unlike logic bugs, Clickjacking is an infrastructure/header misconfiguration.*

**Vulnerability Analysis (Explanation):**

Clickjacking vulnerabilities exist because the server fails to instruct the browser to block framing. Modern web frameworks often enable these protections by default, meaning developers must actively misconfigure or disable them for the vulnerability to exist.

### Java (Spring Security)

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/my-account").authenticated()
                .and()
            // VULNERABLE: The developer explicitly disabled frame options
            // allowing the site to be embedded in external iframes.
            .headers().frameOptions().disable(); 
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`.headers().frameOptions().disable()`**: By default, Spring Security automatically injects the `X-Frame-Options: DENY` header into every HTTP response. If a developer needs to frame a specific widget (e.g., a YouTube player or an internal dashboard), they sometimes lazily disable the protection globally using this method. This strips the header, making every page—including sensitive account pages—vulnerable to UI redressing.

### C# (ASP.NET Core)

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // ... other middleware
    
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();
    
    // VULNERABLE: Missing Security Headers Middleware.
    // ASP.NET Core does not inject X-Frame-Options or CSP headers by default.
    // The developer relied solely on app.UseEndpoints() and AntiForgery tokens.

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

**Technical Flow & Syntax Explanation:**

- **Missing Middleware**: Unlike Spring, ASP.NET Core does not automatically apply anti-framing headers out-of-the-box in the standard middleware pipeline. If the developer does not explicitly add custom middleware or use a library (like `NetEscapades.AspNetCore.SecurityHeaders`) to append `X-Frame-Options`, the responses are served without framing restrictions, leaving the UI defenseless.

### Mock PR Comment

The `/my-account` page is currently vulnerable to Clickjacking. The HTTP responses are missing the `X-Frame-Options` and `Content-Security-Policy` headers. While the CSRF tokens protect against cross-site background requests, they do not prevent an attacker from embedding the UI in a malicious iframe and redressing it.

**Recommendation:** Enforce anti-framing headers globally. Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and configure `Content-Security-Policy: frame-ancestors 'none';` to instruct modern browsers to block rendering if the page is embedded.

## 4. The Fix

**Explanation of the Fix:**

We must instruct the victim's browser to refuse to render the page if it is loaded inside an iframe.

### Secure Java

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // ... auth setup
            .headers()
                // SECURE: Ensures X-Frame-Options: SAMEORIGIN is sent
                .frameOptions().sameOrigin()
                .and()
                // SECURE: The modern approach using CSP
                .contentSecurityPolicy("frame-ancestors 'self'");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`.frameOptions().sameOrigin()`**: Instructs the browser that this page can only be framed by pages sharing the exact same origin (domain, protocol, port). It blocks attackers on `evil.com`.
- **`.contentSecurityPolicy("frame-ancestors 'self'")`**: This is the modern standard that supersedes `X-Frame-Options`. It provides more granular control and is respected by all modern browsers.

### Secure C#

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // SECURE: Adding custom middleware to inject headers on every response
    app.Use(async (context, next) =>
    {
        // Legacy Support
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        // Modern Standard Support
        context.Response.Headers.Add("Content-Security-Policy", "frame-ancestors 'none'");
        
        await next();
    });

    app.UseRouting();
    // ...
}
```

**Technical Flow & Syntax Explanation:**

- **`context.Response.Headers.Add(...)`**: This intercepts the HTTP pipeline and attaches the security headers to the outgoing response before it reaches the client. `DENY`/`'none'` strictly forbids framing anywhere, providing the maximum level of UI protection.

## 5. Automation

*Since clickjacking requires human interaction, we cannot automate the attack itself simply. However, we can write a Python tool to quickly scan endpoints for missing anti-framing headers.*

```csharp
#!/usr/bin/env python3
import argparse
import requests
import sys

def check_clickjacking(url):
    print(f"[*] Scanning {url} for Clickjacking protections...")
    
    try:
        resp = requests.get(url)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        
        vulnerable = True
        
        # Check Legacy X-Frame-Options
        xfo = headers.get('x-frame-options')
        if xfo in ['deny', 'sameorigin']:
            print(f"[+] Found X-Frame-Options: {xfo.upper()}")
            vulnerable = False
        else:
            print("[-] Missing or weak X-Frame-Options header.")

        # Check Modern Content-Security-Policy
        csp = headers.get('content-security-policy', '')
        if 'frame-ancestors' in csp:
            print(f"[+] Found CSP frame-ancestors directive.")
            vulnerable = False
        else:
            print("[-] Missing CSP frame-ancestors directive.")

        print("-" * 40)
        if vulnerable:
            print("[!!!] VULNERABLE: The page can be framed. Clickjacking is possible.")
        else:
            print("[*] SECURE: Anti-framing headers are present.")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Scan an endpoint for Clickjacking vulnerability (missing headers).")
    parser.add_argument("url", help="Target URL (e.g., the /my-account page)")
    args = parser.parse_args()

    check_clickjacking(args.url)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

### Java Rule

```yaml
rules:
  - id: java-spring-xframeoptions-disabled
    languages: [java]
    message: |
      Spring Security's X-Frame-Options protection has been explicitly disabled. 
      This leaves the application vulnerable to Clickjacking (UI Redressing).
      Remove this configuration to restore the default protection, or use '.sameOrigin()'.
    severity: ERROR
    patterns:
      - pattern: |
          $HTTP. ... .headers(). ... .frameOptions().disable()
```

**Technical Flow & Syntax Explanation:**

- **`.frameOptions().disable()`**: This pattern specifically hunts for the exact method chain where a developer intentionally turns off the framework's built-in clickjacking defense.

### C# Rule

```yaml
rules:
  - id: csharp-missing-security-headers
    languages: [csharp]
    message: |
      The application configuration lacks global security headers middleware.
      Ensure you inject 'X-Frame-Options' or 'Content-Security-Policy: frame-ancestors' 
      to protect against Clickjacking.
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

- **`pattern-inside`**: Targets the main ASP.NET Core configuration block where middleware is wired up.
- **`pattern-not-inside`**: This logic flags the entire block *unless* it detects known safe patterns, such as the use of a security headers library (`UseSecurityHeaders`) or manual header injection (`Headers.Add("X-Frame-Options")`).