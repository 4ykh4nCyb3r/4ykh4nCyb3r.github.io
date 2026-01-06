---
title: "Immutability: Architecting Safer, Thread-Safe Systems"
date: 2026-01-04
categories: [softeng, OO Software Design] 
tags: [OOP, immtutability]
image: immu.jpeg
media_subpath: /assets/img/posts/2026-01-04-immutability/
---

In modern software engineering, particularly within imperative languages like Java or C#, we are conditioned to think in terms of state changes. We instantiate an object, and then we modify it. However, as distributed systems and concurrency become the norm, the "modify-in-place" paradigm introduces significant complexity.

Today, I want to explore the architectural implications of **Immutability**. An object is considered immutable if its state cannot be modified after it is constructed. This simple constraint—initializing state solely in the constructor and removing all setters—fundamentally shifts how we handle thread safety, memory management, and API design.

### The Hidden Costs of Mutability

Before discussing *how* to implement immutability, we must understand *why* mutability is often a liability. While mutable objects feel intuitive, they introduce a host of subtle bugs and architectural weaknesses.

### 1. The Reference Trap

In languages like C# or Java, declaring a field `readonly` or `final` protects the reference, not the object itself.

Consider a `serverConfig` object marked as read-only. While you cannot swap out the entire configuration object, nothing prevents a rogue method from accessing that reference and changing the `Port` property internally. This creates a false sense of security.

### 2. Defensive Copying Overhead

When a class exposes its internal state (e.g., returning a raw array or list), external callers can modify that state, corrupting the host object. To prevent this, developers often implement "defensive copying"—cloning data before returning it. While this preserves encapsulation, it is highly inefficient, forcing a full memory allocation for every read operation.

```csharp
public class SecuritySystem
{
    // This is "private" internal state
    private List<string> _admins = new List<string> { "Alice", "Bob" };

    // BAD PRACTICE: Returning the direct reference
    public List<string> GetAdmins()
    {
        return _admins; 
    }
}

// ... Elsewhere in the code ...
var system = new SecuritySystem();
List<string> exposedList = system.GetAdmins();

// DANGER: The caller modifies the list!
exposedList.Clear(); 
exposedList.Add("Hacker");

// The internal state of 'system' is now corrupted. 
// Alice and Bob are gone, and "Hacker" is now an admin.
```
To stop this, developers use "Defensive Copying." Instead of returning the real list, the method creates a brand new list, copies all the items into it, and returns that copy. If the caller modifies this new list, the original object remains safe because they are looking at a clone, not the original
```csharp
public class SecuritySystem
{
    private List<string> _admins = new List<string> { "Alice", "Bob" };

    // SAFER: Returning a defensive copy
    public List<string> GetAdmins()
    {
        // We create a NEW list in memory and copy the data
        return new List<string>(_admins);
    }
}

// ... Elsewhere ...
var system = new SecuritySystem();
var safeCopy = system.GetAdmins();

safeCopy.Add("Hacker"); // Only modifies the copy.
// The internal '_admins' list inside 'system' is still safe.
```
While defensive copying creates safety, it destroys performance. Imagine if `_admins` contained 1,000,000 items. Every single time you call `GetAdmins()` just to read the names, the computer has to allocate memory for a new list of 1,000,000 items. It has to copy them over one by one.
The Garbage Collector (GC) eventually has to clean up that massive duplicate list.
If you call this method inside a loop or frequently (e.g., 60 times a second in a game), your application will slow down significantly due to "memory pressure".

**The Immutable Solution**
If you use an `ImmutableList`, you can return it directly . Since it is impossible to modify an `ImmutableList`, you don't need to copy it to protect it. You get the safety of defensive copying with the speed of returning a direct reference.

### 3. Threading and Temporal Coupling

Mutable objects are inherently unsafe in multi-threaded environments as this leads to **Race Conditions**. If two threads attempt to modify a collection simultaneously, the internal state becomes inconsistent requiring complex locking mechanisms.To prevent this, you have to use Locks. You force Thread B to wait until Thread A is finished. This kills performance and introduces "Deadlocks" (where threads wait on each other forever). Furthermore, mutability leads to **temporal coupling**: if an object must be configured in a specific order (e.g., set URL, then set Method, then set Body), the code implicitly relies on a sequence that isn't enforced by the compiler. 

**"Temporal"** means related to time. **"Coupling"** means dependency. Temporal Coupling happens when your code breaks unless methods are called in a specific order of time, but the compiler doesn't stop you from doing it wrong.

```csharp
// Mutable approach
var request = new Request();
request.Method = "POST";  // Step 1
request.Url = "http://api.com"; // Step 2
request.Body = "{ data: 123 }"; // Step 3
request.Send(); // Step 4
```
**The Problem:** Because the object is mutable, nothing prevents you from calling Send() too early, or forgetting a step.
**The Immutable Solution:** Immutable objects force you to provide all necessary dependencies at the moment of creation (in the constructor). You cannot create a "half-baked" object.
```csharp
// The compiler forces you to provide everything at once.
// You literally cannot call Send() on an incomplete object.
var request = new HttpRequest("POST", "http://api.com", "{ data: 123 }");
request.Send();
```
This removes the "hidden order." If the code compiles, the object is valid.

### The Immutable Advantage

By forbidding state changes, we gain several architectural benefits immediately:

- **Implicit Thread Safety:** Immutable objects can be read by thousands of threads simultaneously without locks because no thread can change the state.
- **Failure Atomicity:** An object is either created in a valid state via its constructor, or it isn't created at all. You never end up with a "half-broken" object after an exception occurs during a property set.
- **Safe HashMap Keys:** The identity and hash code of an immutable object are constant. Unlike mutable objects, which can disappear from a `Dictionary` or `HashMap` if their internal fields (and thus their hash codes) change, immutable objects are stable keys.

### Implementing Immutable Patterns

Since we cannot use setters, we must adopt different patterns to manage data.

### The "Wither" Pattern

Instead of modifying an existing instance, we use methods that calculate the new state and return a **new instance**. This is often called the `"Fluent API"` or `"Wither"` pattern.

*Imagine a network configuration object:*

```csharp
// Immutable Configuration
public class ServerConfig 
{
    public string Host { get; }
    public int Port { get; }

    public ServerConfig(string host, int port) { ... }

    // Returns a NEW object, leaving the current one untouched
    public ServerConfig WithPort(int newPort) 
    {
        return new ServerConfig(this.Host, newPort);
    }
}
```

In this scenario, `config.WithPort(8080)` does not change `config`; it produces a distinct version.

### The Builder Pattern

One criticism of immutability is the "plumbing" overhead—constructors with many arguments can be unwieldy. To solve this, we pair immutable classes with a **Builder**.

The **Builder** is a mutable object used only during the construction phase. It allows you to set properties in any order. Once finished, you call a method like `ToImmutable()`, which freezes the state into the final immutable instance. This is particularly useful for complex objects where you might perform heavy logic before finalizing the data.

You can read  more about Builder Design Pattern here: [Object Oriented Design Patterns - Builder](https://4ykh4ncyb3r.github.io/posts/design_patterns/#builder)

### Structural Sharing: Why Immutability Isn't Slow

A common misconception is that immutability is wasteful because every change requires copying the entire object. This is true for array-backed structures, but not for modern immutable collections.

Advanced immutable collections (like `ImmutableList<T>`) use **Balanced Binary Trees** rather than arrays.

> **Balanced Binary Tree:** a tree data structure where the height of the left and right subtrees of any node differs by at most one.
{ : .prompt-info }

![image.png](image.png)

When you "add" an item to an immutable list, the system does not copy the entire list. Instead, it creates a new node for the added item and creates a new path to the root. **All unchanged nodes are shared between the old list and the new list**.

- **Memory Efficiency:** The vast majority of the memory is reused between versions.
- **Performance:** Operations like adding or removing items take `O(log n)` time due to the tree structure, rather than the `O(n)` copying required by array-based lists.

### Choosing the Right Collection

In the .NET ecosystem (specifically `System.Collections.Immutable`), choosing the right data structure is critical for performance.

| **Collection Type** | **Underlying Structure** | **Complexity (Add/Insert)** | **Best Use Case**                                                 |
| ------------------- | ------------------------ | --------------------------- | ----------------------------------------------------------------- |
| **ImmutableArray**  | Array wrapper            | `O(n)` (Copy on write)      | High iteration speed, rare updates, small datasets (<16 items).   |
| **ImmutableList**   | Balanced Binary Tree     | `O(log n)`                  | Frequent updates, large datasets, modification speed is critical. |

### Summary: When to Switch?

Immutability requires a shift in mindset. It demands more boilerplate code (unless using generators) and forces you to rethink object life cycles. However, for domain objects, configuration settings, and multi-threaded data processing, the benefits of safety and stability vastly outweigh the costs.

---

***Attribution:** This post is based on the lecture material "Object-oriented software design: Immutability" by Dr. Balázs Simon, BME, IIT.*
