---
title: "Lab 02: Unprotected admin functionality with unpredictable URL"
date: 2025-12-15
categories: [portswigger, access_control]
tags: [unpredictable_url, unprotected-admin-panel] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-15-lab02_access_control/
---

## 1. Executive Summary

**Vulnerability:** Unprotected Admin Functionality (Security by Obscurity).  
**Description:** The application attempts to secure the admin panel by using a long, random, unpredictable URL (e.g., `/admin-km2dj1`) instead of proper access controls. However, this URL is disclosed in the client-side JavaScript.  
**Impact:** Attackers can discover the hidden URL by inspecting the application's source code and gain full administrative access without credentials.  

## 2. The Attack

**Objective:** Access the admin panel and delete `carlos`.

1. **Reconnaissance:** I reviewed the client-side code. I opened the browser Developer Tools (F12) and viewed the Page Source of the main landing page.
2. **Discovery:** Inside a `<script>` block, I found JavaScript logic that constructs a link to the admin panel. The "secret" URL was hardcoded directly in the source:JavaScript
    
    ![image.png](image.png)
    
3. **Exploitation:** I copied the path `/admin-km2dj1` and pasted it into the address bar.
4. **Result:** The application loaded the Admin Dashboard without asking for a login. I successfully deleted the user `carlos`.
    
    ![image.png](image%201.png)
    

## 3. Code Review

**Vulnerability Analysis (Explanation):**
In the examples below, the developer has mapped the Controller to a specific, obscure URL string. They are relying entirely on the assumption that an attacker cannot guess this string.

- **The Flaw:** The security model is tied to the *secrecy of the path*, not the *identity of the user*. Once the path is known (leaked in JS, logs, or browser history), the security is gone.
- **The Reality:** The method is public. The server executes it for any incoming request that matches the URL, regardless of whether the user is an admin or an anonymous visitor.

### Java (Spring Boot)

```java
@Controller
public class AdminController {

    // The developer relies on the randomness of "km2dj1" to hide the page.
    // There are no security annotations here.
    // If you know the URL, you are the admin.
    @GetMapping("/admin-km2dj1")
    public String adminPanel(Model model) {
        return "admin_dashboard";
    }
}
```

### C# (ASP.NET Core)

```csharp
public class AdminController : Controller
{
    // The Route matches the secret URL found in the JS.
    // Missing [Authorize] attribute means the Identity of the caller is ignored.
    [HttpGet]
    [Route("admin-km2dj1")]
    public IActionResult Index()
    {
        return View();
    }
}
```

### Mock PR Comment

The endpoint `/admin-km2dj1` lacks server-side authorization checks. Relying on an unpredictable URL string constitutes Security by Obscurity, which is insufficient as the URL is exposed in client-side assets. Implement role-based access control (RBAC) to verify that the requesting session belongs to an administrator.

## 4. The Fix

**Explanation of the Fix:**
To secure this, we abandon the "secret URL" strategy. We can rename the path to something standard like `/admin`. The security is enforced by **Middleware** or **Interceptors** which intercept the request before it reaches the controller logic. They check the user's session claims for the `ADMIN` role.

```java
@Controller
public class AdminController {

    // SECURE: We use a standard URL.
    // @PreAuthorize checks the SecurityContext for the 'ADMIN' authority.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminPanel(Model model) {
        return "admin_dashboard";
    }
}
```

### C# (ASP.NET Core)

```java
// SECURE: The [Authorize] attribute acts as a gatekeeper.
// If the user's claims do not include Role="Admin", the server returns 403 Forbidden.
[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    [HttpGet]
    [Route("admin")]
    public IActionResult Index()
    {
        return View();
    }
}
```

## 5. Automation

*A Python script to scrape a webpage and use Regex to look for "hidden" or interesting paths inside JavaScript variables or `href` attributes.*

```python
import requests
import re

def find_hidden_admin_panel(base_url):
	print(f"[*] Scanning {base_url} for hidden links...")
	
	try:
		response = requests.get(base_url);
		if response.status_code != 200:
			print("[-] Could not load page.")
			return
		pattern = re.compile(r"['\"](/admin[a-zA-Z0-9-]+)['\"]") #match admin panel pattern
		matches = pattern.findall(response.text) #find this pattern in response html file
		if not matches:
			print("[-] No suspicious admin paths found in the source code")
			return
		
		for match in matches:
			print("[!!!] Found potential hidden path in Source:{match}")
			
			full_url = base_url + match
			print("[*] Veryfying access to: {full_url}")
			check = requests.get(full_url)
			
			if check.status_code == 200:
				print(f"  -> CONFIRMED: {full_url} is accessible (200 OK)!")
			else:
				print(f"  -> Path returned {check.status_code}")
				
	except Exception as e:
	print(f"Error:{e}")
	
# Usage
# find_hidden_admin_panel("https://LAB-ID.web-security-academy.net")
```
