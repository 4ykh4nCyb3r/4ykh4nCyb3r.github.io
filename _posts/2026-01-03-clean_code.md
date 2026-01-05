---
title: "The Art of Clean Code"
date: 2026-01-03
categories: [softeng, OO Software Design] 
tags: [SOLID, OOP, clean_code]
image: clean_code.jpeg
media_subpath: /assets/img/posts/2026-01-03-clean_code/
---

In the fields of software engineering and application security, we often focus heavily on architecture, algorithms, or vulnerability scanning. However, a massive, often overlooked factor in the security and stability of a system is the cleanliness of its code.

I recently reviewed extensive material on **Clean Object-Oriented Design**, and I want to share the core insights. The premise is simple: code is read far more often than it is written—some estimates suggest a ratio of **10:1** or higher . If the code is messy ("dirty"), it becomes hard to understand, difficult to maintain, and prone to bugs that security auditors (or attackers) can exploit .

Here are the key takeaways from my notes on how to write code that is robust, readable, and secure.

## 1. Naming: The First Line of Documentation

The most fundamental rule is that names should reveal intent. If a name requires a comment to explain it, the name itself has failed .

### Avoid Mental Mapping

We often see variables named with single letters or vague terms because it was faster to type. This forces the reader to mentally map the variable to a concept, increasing cognitive load.

- **Poor Practice:** `int t; // timeout in seconds`
- **Clean Approach:** `int timeoutInSeconds;`

### Pronounceable and Searchable

If you cannot pronounce a variable name, you cannot discuss it with your team. Avoid mashing words together into unreadable abbreviations.

- **Poor Practice:** `cstmrRcrd` or `genTs` (generation timestamp).
- **Clean Approach:** `customerRecord` or `generationTimestamp`.

Furthermore, avoid single-letter names like `e` or `x` in broad scopes. Trying to search a codebase for the letter "e" to find a bug is effectively impossible .

### Meaningful Distinctions

Do not use "noise words" that add no value. A class named `UserData` or `AccountInfo` is rarely different from `User` or `Account`. If you have `Product` and `ProductData` in the same scope, no developer will know which one to use without digging into the implementation .

## 2. Functions: Atomic and Focused

From a security audit perspective, large functions are dangerous. They hide logic errors and side effects.

### The "One Thing" Rule

A function should do one thing, and do it well . If a function is performing input validation, parsing a file, *and* updating a database, it is doing too much. You should be able to extract sections of the function into smaller functions with descriptive names . Ideally, functions should be very small—rarely more than 20 lines .

### Separation of Command and Query

Functions should either do something (change state) or answer something (return information), but never both .

- **Bad Example:** A function `ValidateUser(credentials)` that returns `true` but also silently starts a session and logs the user in.
- **Why it’s bad:** A developer might call `ValidateUser` just to check if an account exists, inadvertently triggering a login session (a side effect) .

### Argument Limits

The ideal number of arguments for a function is zero. One or two is acceptable. Three or more should be avoided whenever possible . If you find yourself passing three or more arguments (e.g., `x`, `y`, `z`), it is a strong signal that those arguments should be wrapped into their own class (e.g., `Point3D`) .

## 3. Comments: The "Code Smell"

A provocative concept in clean code philosophy is that comments are often an apology for poor code .

- **Don't Explain, Rewrite:** If you write a complex block of code and feel the need to add a comment explaining *what* it does, you should instead rewrite the code to be self-explanatory .
- **The Rotting Comment:** Code changes frequently; comments rarely do. A comment that explains logic that was deleted months ago is worse than no comment—it is active disinformation .
- **Avoid Noise:** Do not add comments for the sake of it, such as `// Constructor` above a constructor, or `// increment i` above `i++`. This trains the brain to ignore comments entirely .
- **Dead Code:** Never leave commented-out code in the source files. It confuses future developers who are afraid to delete it. Trust your Version Control System (Git) to remember history .
- **Journal Comments:** These are long lists of log entries added to the start of a file every time it is edited. They track dates, author initials, and descriptions of changes (e.g., "11-Oct-2001: Re-organised the class...").
- **Banner Comments:** These are comments used to create visual separators between different sections of code (e.g., // Properties ///// or // Methods /////).

**Exceptions: When to Comment** While code should explain what is happening, comments are vital for explaining why it is happening or for clarifying obscure formats.

- **Explanation of Intent:** Use this when the code does something that might look like a mistake or an arbitrary choice to a new developer. You are explaining the decision, not the syntax.
  ```csharp
  // We force a 50ms delay here because the external payment gateway
  // rejects requests that happen too instantly after a token generation.
  await Task.Delay(50)
  ```
- **Clarification:** Use this to make obscure formats or arguments readable. This is common for Regular Expressions or complex string formats.
  ```csharp
  // Cron pattern: At 04:00 on every 1st day-of-month.
  string monthlyReportSchedule = "0 4 1 * *";
  ```
- **Warning of Consequences:** Use this when a function has a side effect or performance cost that isn't obvious from its name.
  ```csharp
  // WARNING: This method loads the full transaction history into memory.
  // Do not call this on the main thread or for accounts with >10k records.
  public List<Transaction> ExportAllHistory() { ... }
  ```
- **Amplification**: Use this to highlight a line of code that looks redundant or trivial but is actually critical for correctness.
  ```csharp
  fileStream.Flush(); // Crucial! If we don't flush before the close, the footer byte is lost.
  fileStream.Close();
  ```
- **TODOs (Contextual):** Use this to mark technical debt with a clear path to resolution.
  ```csharp
  // TODO: Refactor to use the bulk-insert API once the database team upgrades to v4.5.
  // Currently limited to row-by-row insertion.
  foreach (var item in items) { ... }
  ```

## 4. Error Handling: Stability and Clarity

Proper error handling is distinct from business logic. Mixing the two creates "spaghetti code."

- **Exceptions over Error Codes:** Returning error codes (like `1` or `false`) forces the caller to check the return value immediately, cluttering the logic. Use exceptions to separate the "happy path" from error handling .
- **Context matters:** When throwing exceptions, provide context. A generic "System Error" is useless for debugging. The exception should explain the intent and the failure .
- **Design for the Caller:** Define exception classes based on the **caller’s needs**, not the implementation details. If a caller handles three different low-level errors (like `SocketTimeout`, `ConnectionRefused`, `DnsFailure`) in the exact same way, wrap them in a single high-level exception (e.g., `PortDeviceFailure`). This prevents the calling code from being polluted with multiple repetitive catch blocks.
- **The Null Problem:**
    - **Don't Return Null:** Returning `null` forces every caller to add a null check. If one check is missed, the application crashes. Return an empty list or a special "Null Object" instead .
    - **Don't Pass Null:** Unless an API explicitly expects it, passing `null` is the fastest way to generate runtime errors .

## 5. Objects vs. Data Structures

There is a distinct architectural difference between an Object and a Data Structure.

- **Data Structures** (like DTOs) expose their data but have no significant behavior .
- **Objects** hide their data (encapsulation) and expose behaviors/methods to manipulate that data .

**The Law of Demeter** suggests that a module should not know the inner details of the objects it manipulates. We want to avoid "train wrecks"—chains of calls like `car.GetEngine().GetFuelSystem().GetTankCapacity()`. This tightly couples the code to the internal structure of the `Car` .

**Regarding choosing Object-Oriented or Procedural approaches:** Both of them are perfectly OK just make sure to chose the approach that is the best for the job at hand.
**Procedural code** (using data structures) is actually preferred when "new functions are frequently added but the data structure is stable," whereas **Object-Oriented code** is preferred when "internal data representation can change" or "new functions are rarely added"

In an application developed in an object-oriented programming language there can be data structures developed in a procedural way such as `DTOs`.

## Summary

Writing clean code is about reducing the cognitive load on the reader. By using meaningful names, keeping functions atomic, relying on self-documenting code rather than comments, and handling errors gracefully, we build systems that are not only easier to maintain but significantly harder to break.

---

**Source Acknowledgment:***This post is based on my personal notes and interpretation of the "Object-Oriented Design Clean Code" lecture materials by Dr. Balázs Simon (BME, IIT).*
