---
title: "Lab 05: URL-based access control can be circumvented"
date: 2025-12-16
categories: [portswigger, access_control]
tags: [HTTP_Header_Spoofing, X-Original-URL] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-16-lab05_access_control/
---

## 1. Executive Summary

**Vulnerability:** URL-based Access Control Bypass (HTTP Header Spoofing).

**Description:** The application framework supports non-standard HTTP headers (specifically `X-Original-URL`) to override the requested path. While a front-end security system blocks direct requests to `/admin`, it fails to inspect these headers. An attacker can send a request to a valid URL (like `/`) but instruct the backend to process it as `/admin` using the header.

**Impact:** Attackers can completely bypass front-end access controls (WAFs/ACLs) and access restricted administrative endpoints.

## 2. The Attack

**Objective:** Access the hidden admin panel and delete `carlos`.

1. **Reconnaissance:** I attempted to visit `/admin`, but the request was blocked (likely "403 Forbidden" by the front-end system). I then tested for header-based overrides by sending a request to the home page (`/`) while adding the `X-Original-URL: /invalid` header. The application returned a "404 Not Found," confirming that the backend was trying to route based on my header, not the actual URL line.
2. **Exploitation:**
    - I sent a request to `/` (allowed).
    - I added the header: `X-Original-URL: /admin`.
    - The backend served the Admin Dashboard.
3. **Action:** The delete link usually looks like `/admin/delete?username=carlos`. To execute this:
    - I kept the real path as `/` (to pass the front-end).
    - I moved the query parameter to the real URL: `/?username=carlos`.
    - I set the header to the restricted path: `X-Original-URL: /admin/delete`.
    
    ![image.png](image.png)
    
4. **Result:** The backend executed the delete action on `carlos`.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
This issue often arises in frameworks (like Symfony, ASP.NET Core with specific middleware, or older Java frameworks) intended to sit behind a reverse proxy. They allow headers to override the request path so the app knows the "original" URL the user requested.

- **The Flaw:** The "Trust Boundary" is broken. The application trusts these headers implicitly, assuming they were sanitized by the front-end proxy.
- **The Reality:** The front-end proxy (WAF) only checks the Request Line (`GET / HTTP/1.1`). It ignores the headers. The backend then uses the headers to decide which Controller to run.

### Java (Spring Boot / Custom Filter)

```java
public class HeaderOverrideFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) 
            throws ServletException, IOException {
        
        // VULNERABLE: Trusting the client-provided header to define the path.
        String originalUrl = request.getHeader("X-Original-URL");
        
        if (originalUrl != null) {
            // The app creates a wrapper that reports the spoofed URL as the request URI.
            // Spring Security might check access rules against this NEW path, 
            // or the routing logic uses it, bypassing the WAF that checked the OLD path.
            HttpServletRequest wrapper = new HttpServletRequestWrapper(request) {
                @Override
                public String getRequestURI() {
                    return originalUrl;
                }
            };
            chain.doFilter(wrapper, response);
        } else {
            chain.doFilter(request, response);
        }
    }
}
```
**Technical Flow & Syntax Explanation:**
- `OncePerRequestFilter`: This is a standard Spring component that intercepts every single HTTP request before it reaches your Controllers (business logic).
- `request.getHeader("X-Original-URL")`: The code explicitly looks for this specific header. If an attacker sends it, the variable `originalUrl` gets populated (e.g., with `/admin`).
- `HttpServletRequestWrapper`: In Java, the Request object is read-only. To change the URL, the developer must "wrap" the original request in a new object and override the `getRequestURI()` method.
- `chain.doFilter(wrapper, response)`: This is the critical moment. The filter passes the modified (wrapped) request to the next part of the filter chain.
- **Result**: When the security check (Spring Security) runs later, it calls `getRequestURI()`. It sees `/admin` (from the header), but the WAF (which sat in front of this app) only saw `/` (from the actual URL line) and let it through.

### C# (ASP.NET Core Middleware)

```csharp
public class UrlOverrideMiddleware
{
    private readonly RequestDelegate _next;

    public UrlOverrideMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // VULNERABLE: If this runs before Authentication/Authorization middleware.
        var originalUrl = context.Request.Headers["X-Original-URL"];

        if (!string.IsNullOrEmpty(originalUrl))
        {
            // The path is effectively changed to /admin
            context.Request.Path = originalUrl;
        }

        await _next(context);
    }
}
```
**Technical Flow & Syntax Explanation:**
- **Middleware Pipeline** (`Invoke` / `_next`): ASP.NET Core handles requests like a chain of handlers. `Invoke` is the method called when a request hits this middleware. `_next(context)` passes the baton to the next handler.
- `context.Request.Headers["X-Original-URL"]`: The code blindly reads the header value provided by the client.
- `context.Request.Path = originalUrl`: This is the "setter" that rewrites reality. The `Request.Path` property determines which Controller Action (method) will be executed.
- **The Bypass**: If this Middleware runs before the Authorization Middleware, the request path is changed to `/admin` internally. However, because the external request line was /, the external firewall allowed it.

### Mock PR Comment

I noticed we are processing the `X-Original-URL` header to rewrite the request path. Currently, this logic runs blindly on any incoming request.

This creates a security gap: our WAF/Load Balancer blocks `/admin` in the URL line, but it allows requests to `/` with `X-Original-URL: /admin`. This bypasses our front-end access controls.

**Recommendation:** If we must support this header (e.g., for a specific reverse proxy), we should configure the WAF to strip this header from external traffic, or validate inside the app that the request creates from a trusted internal IP.

## 4. The Fix

**Explanation of the Fix:**
The best fix is usually infrastructure-level (stripping the header at the gateway). However, in code, we can disable support for these headers if not needed, or ensure we do not trust them from untrusted sources.

### Secure Java

If you don't need header-based overriding, simply remove the custom filter or configuration. If you must use it, ensure strictly defined trust.

```java
// SECURE: Do not read override headers, or validate them.
// Only allow overrides if the request comes from a trusted proxy IP (e.g., 10.0.0.5)
String originalUrl = request.getHeader("X-Original-URL");
String remoteIp = request.getRemoteAddr();

if (originalUrl != null && TRUSTED_PROXIES.contains(remoteIp)) {
    // Process override
}
```

**What changed**: We added an `if` condition that checks `request.getRemoteAddr()`. This ensures that if a random hacker on the internet (IP 1.2.3.4) sends the header, it is ignored. It is only honored if it comes from our internal infrastructure.

### Secure C#

In ASP.NET Core, ensure the `ForwardedHeadersMiddleware` is configured strictly, rather than writing custom middleware that blindly accepts headers.

```csharp
// Startup.cs
public void Configure(IApplicationBuilder app)
{
    // SECURE: Only process forwarded headers from known networks.
    var options = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
        KnownNetworks = { new IPNetwork(IPAddress.Parse("10.0.0.0"), 8) } // Trust only internal LB
    };
    
    // Do NOT include X-Original-URL in custom logic unless absolutely necessary and validated.
    app.UseForwardedHeaders(options); 
}
```
**What changed**: We replaced the manual "Header Reading" code with a standard configuration object (`ForwardedHeadersOptions`). We explicitly defined `KnownNetworks` (Safe IPs). The framework now handles the validation automatically, rejecting headers from untrusted sources.

## 5. Automation

*A Python script to check if the application respects the spoofing header.*

```python
import requests

def exploit_header_spoofing(url):
	print(f"[*] Testing {url} for X-Original-URL vulnerability ...")
	
	verification_headers = {'X-Original-URL': '/this-does-not-exist-999'}
	resp = requests.get(url, headers=verification_headers)
	
	if resp.status_code == 404:
		print(f"[+] Vulnerability Confirmed: Server processes X-Original-URL.")
		
		print("[*] Attempting to bypass restriction to access /admin...")
		exploit_headers = {'X-Original-URL': '/admin'}
		admin_resp = requests.get(url, headers=exploit_headers)
		
		if admin_resp.status_code == 200 and "admin" in admin_resp.text.lower():
			print("[!!!] SUCCESS: Admin panel accesses via header spoofing!")
		
			#delete user	
			delete_url = f"{url}?username=carlos"
			delete_headers = {'X-Original-URL': '/admin/delete'}
			print("[+] Delete payload sent")
		else:
			print(f"[-] /admin access failed. Status: {admin_resp.status_code}")
	else:
		print("[-] Server ignores X-Original-URL (returned 200 for invalid path)")
		
# Usage
# exploit_header_spoofing("https://YOUR-LAB-ID.web-security-academy.net")
		 
```

## 6. Static Analysis (Semgrep)

*Rules to detect code that manually extracts and uses URL-overriding headers.*

**The Logic:**
We look for code that retrieves specific HTTP headers known for overriding paths (`X-Original-URL`, `X-Rewrite-URL`) and then uses that value to modify the Request object or routing context.

### Java Rule

```yaml
rules:
  - id: java-header-based-routing
    languages: [java]
    message: "Detected use of X-Original-URL/X-Rewrite-URL. Ensure this is only accepted from trusted proxies."
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: $REQ.getHeader("X-Original-URL")
          - pattern: $REQ.getHeader("X-Rewrite-URL")
          - pattern: $REQ.getHeader("X-Forwarded-Prefix")
```

### C# Rule

```yaml
rules:
  - id: csharp-header-based-routing
    languages: [csharp]
    message: "Detected access to X-Original-URL header. Verify trust boundaries for header-based routing."
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: $CTX.Request.Headers["X-Original-URL"]
          - pattern: $CTX.Request.Headers["X-Rewrite-URL"]
```
