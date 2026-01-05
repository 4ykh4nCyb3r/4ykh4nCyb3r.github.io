---
title: "Object-Oriented Design Principles"
date: 2026-01-01
categories: [softeng, OO Software Design] 
tags: [SOLID, OOP, design_patterns]
image: oo_design_principle.jpeg
media_subpath: /assets/img/posts/2026-01-01-design_principles/
---

You write a feature, it works perfectly, and you deploy it. Two months later, a simple requirement change comes in, and suddenly you’re rewriting half the application. Why? Because while the code *worked*, it wasn't *designed* to handle change.

Here I will cover everything from the famous **SOLID** principles to high-level **Package Architecture** and practical rules like **DRY** and **Tell, Don't Ask**.

## 1. The SOLID Foundation

The resource heavily emphasizes the SOLID principles. These are the bread and butter of maintainable object-oriented programming.

![image.png](image.png)

### S - Single Responsibility Principle (SRP)

**The Concept:** A class should have one, and only one, reason to change.
**The Mistake:** Mixing "business logic" with "infrastructure" (like logging or saving to a file).
**Better Example:**
Imagine an `Order` class that calculates total price *and* generates a PDF invoice. If you change the PDF library, you risk breaking the calculation logic.

```csharp
// Bad: Two responsibilities
public class Order {
    public void CalculateTotal() { /* ... */ }
    public void GeneratePdfInvoice() { /* ... */ } 
}

// Good: Split them up
public class Order {
    public double CalculateTotal() { /* ... */ }
}

public class InvoiceGenerator {
    public void GeneratePdf(Order order) { /* ... */ }
}
```

### O - Open/Closed Principle (OCP)

**The Concept:** Software entities should be open for extension, but closed for modification.
**The Goal:** Add new features by adding *new* code, not by changing *old* code.
**Better Example:**
You have a discount calculator. Instead of a giant `if-else` block that you have to modify every time a new seasonal sale starts, use polymorphism.

```csharp
// The Abstraction
public interface IDiscountStrategy {
    double ApplyDiscount(double originalPrice);
}

// Extension 1: No change to existing code needed to add this!
public class BlackFridayDiscount : IDiscountStrategy {
    public double ApplyDiscount(double price) => price * 0.5;
}

// Extension 2
public class SeniorCitizenDiscount : IDiscountStrategy {
    public double ApplyDiscount(double price) => price * 0.8;
}
```

### L - Liskov Substitution Principle (LSP)

**The Concept:** Subtypes must be substitutable for their base types.
**The Warning:** Just because "A is a B" in English doesn't mean "A inherits B" in code.
**Better Example:**
The classic "Ostrich problem." If you have a `Bird` class with a `Fly()` method, and you inherit `Ostrich` from it, you are in trouble. If you override `Fly()` to throw an exception, you have violated LSP because the caller expected the bird to fly.

```csharp
// Violation
public void MakeBirdFly(Bird bird) {
    bird.Fly(); // Crushes if bird is an Ostrich!
}
```

*Solution:* Separate the interfaces. Have a `Bird` class and an `IFlyingBird` interface.

### I - Interface Segregation Principle (ISP)

**The Concept:** Clients should not be forced to depend on methods they do not use.
**The Mistake:** Creating "God Interfaces" that do everything.
**Better Example:**
Imagine a `MultiFunctionPrinter`. If you have a simple interface `IMachine`, a basic printer shouldn't be forced to implement `Fax()` or `Scan()`.

```csharp
// Bad
interface IMachine {
    void Print();
    void Scan(); // OldPrinter has to throw NotImplementedException here
    void Fax();
}

// Good: Segregate!
interface IPrinter { void Print(); }
interface IScanner { void Scan(); }

// Now OldPrinter only implements what it needs
class OldPrinter : IPrinter { ... }
```

### D - Dependency Inversion Principle (DIP)

**The Concept:** High-level modules `should not` depend on low-level modules; both should depend on abstractions.
**The Practicality:** Your business logic shouldn't care if you are saving data to an SQL Database or a text file.

```csharp
// Bad: High level (Notification) depends on Low level (GmailService)
class NotificationService {
    private GmailService _gmail = new GmailService(); // Hard dependency
}

// Good: Depend on Abstraction
class NotificationService {
    private IMessageSender _sender;
    
    // Inject the dependency
    public NotificationService(IMessageSender sender) {
        _sender = sender;
    }
}
```

---

## 2. Organizing the Architecture (Package Principles-REP,CCP,ADP)

Here we discuss how we organize classes into packages or namespaces. This is often overlooked but crucial for large systems.

- **The Release Reuse Equivalency Principle (REP):** If you want to reuse code, it must be tracked, versioned, and released properly. You can't just copy-paste files; you need packages (like NuGet or npm).
- **The Common Closure Principle (CCP):** "Classes that change together, belong together". If changing a database schema requires you to update 5 different packages, your closure is bad. Group related concepts.
- **Common Reuse Principle (CRP):** Classes that aren’t reused together should not be grouped together
- **The Acyclic Dependencies Principle (ADP):** Avoid cycles in your dependency graph. If Package A depends on B, and B depends on C, and C depends on A you can never release them independently.
    
    ![image.png](image1.png)
    

---

## 3. Practical Hygiene: DRY and TDA

Finally, the resource touches on two "golden rules" of daily coding.

### DRY (Don't Repeat Yourself)

Every piece of knowledge must have a single representation.

- **Correction:** It’s not just about copy-pasting lines of code. It’s about duplicating *logic*. If you have a tax calculation logic repeated in the Frontend JS and the Backend C#, you are violating DRY.

### Tell, Don't Ask (TDA)

Don't ask an object for its data and then do the work yourself. *Tell* the object to do the work.

```csharp
// Bad: Asking for state and acting on it
if (wallet.Balance > amount) {
    wallet.Balance -= amount;
}

// Good: TDA (Encapsulation)
wallet.Debit(amount); // The wallet manages its own state logic
```

---

## Summary

The difference between a junior and a senior developer is often the ability to spot where these principles are violated *before* the code is written. Whether it's adhering to **SOLID** to ensure classes are manageable or following **ADP** to ensure your architecture doesn't become a tangled web, these principles are your toolkit for longevity.

---

**Source Acknowledgment:***This post is based on my personal notes and interpretation of the "Object-Oriented Design Principles" lecture materials by Dr. Balázs Simon (BME, IIT).*
