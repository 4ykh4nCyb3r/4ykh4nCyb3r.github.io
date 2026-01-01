---
title: "Textual Modeling for Security Pros"
date: 2025-12-27
categories: [softeng, Automated Software Engineering] 
tags: [MDE, SoftwareArchitecture, AppSec, Langium, Engineering, DevSecOps]
image: text_modelin.jpeg
media_subpath: /assets/img/posts/2025-12-27-textual_modeling/
---

If you’ve followed my posts on penetration testing and app sec, you know the struggle of architectural diagrams. You draw a "Secure Network" on a whiteboard or in [Visio](https://www.microsoft.com/en-us/microsoft-365/visio): a Firewall here, a Database there, and a line showing traffic flow.

But to a computer, that Visio diagram is just pixels. It doesn't *know* that a Database shouldn't connect directly to the Internet.

In Model-Driven Engineering (MDE), we fix this by moving from **drawing pictures** to **defining languages**. Today, I’m going to show you how to build a **Domain Specific Language (DSL)** to model a secure network.

We will cover Grammars, Parser Rules, Terminals, and Cross-References.

## The Goal: "NetworkDSL"

We want to create a language that lets us define a corporate network like this:

```java
network MyZeroTrustCorp {
    // Define our assets
    firewall edgeFW
    webserver publicFrontend
    database sensitiveDB sensitivity PII

    // Define allowed traffic (The rules)
    connect edgeFW -> publicFrontend
    connect publicFrontend -> sensitiveDB

```

To make this work, we need to write a **Grammar**. In frameworks like **Langium** or **Xtext**, the grammar is the DNA of your language. It defines valid syntax and simultaneously generates the code structure (AST) to hold the data.

Let's break it down, line by line.

## 1. The Container (The Entry Point)

Every textual model needs a root. In our case, it’s the `Network`.

```java
grammar NetworkDSL

entry Model:
    (tags += SensitiveTag | networks += Network)*;

SensitiveTag: "tag" name=ID;

Network:
    "network" name=ID "{"
        (assets += Asset)* (connections += Connection)*
    "}";
```

### The Concepts:

- **`grammar`**: Defines the name of your language.
- **`entry`**: Tells the parser "Start reading here."
- **`+=` (Assignment)**: This is crucial. It tells the parser to take whatever it finds and **add it to a list**. `assets += Asset` means "The Network object has a list called `assets`."
- **`*`(Cardinality)**: Means "Zero or more". You can have a network with 100 assets or 0 assets.
- **`{ }`**:  they are just characters we force the user to type to organize their code blocks.

## 2. The Nodes (Polymorphism in Text)

In a diagram, you drag a "Firewall" shape or a "Database" shape. In text, we define these as **Parser Rules**.

```java
// The Abstract Rule
Asset: WebServer | Database | Firewall;

// The Concrete Rules
WebServer: "webserver" name=ID;
Firewall:  "firewall"  name=ID;

Database:  "database"  name=ID ("sensitivity" sensitivity=[SensitiveTag])?;
```

### TheConcepts:

- **Dispatch Rules (`|`)**: The `Asset` rule doesn't have its own keywords. It creates a "Union Type" (or inheritance). It says: "An Asset is either a WebServer OR a Database OR a Firewall."
- **Optional Groups (`?`)**: Look at the Database. The `(...)?` means the sensitivity part is optional. You can define a DB without tagging it as sensitive.
- **Attributes (`name=ID`)**: We are capturing the identifier the user types (e.g., "usersDB") and saving it in the `name` property.

## 3. The Edges (Cross-References)

This is the most powerful part of MDE. How do we draw a line between two text definitions? We use **Cross-References**.

```java
Connection:
    "connect" from=[Asset] "->" to=[Asset];
```

### The Concepts:

- **`[...]` (Square Brackets)**: This syntax creates a **Reference**, not a definition.
- **How it works**: When the parser sees `from=[Asset]`, it pauses. It looks at the text inside the brackets (e.g., "edgeFW"), searches the rest of the file for an Asset defined with that **name**, and links them in memory.
- **Why it matters**: If you type `connect nonExistentServer -> DB`, the editor gives you an error automatically. You get "Spell check" for your architecture.

## 4. The Building Blocks (Terminals)

Finally, how does the parser know what an "ID" is? We define **Terminals** (Regex rules).

```java
// "hidden" means we skip whitespace automatically
hidden terminal WS: /\s+/; 

// ID starts with a letter, followed by letters or numbers
terminal ID: /[_a-zA-Z][\w_]*/;

// INT returns a number, not a string
terminal INT returns number: /[0-9]+/;
```

## 5. Final State of the Model
```java
grammar NetworkDSL

entry Model:
    (tags += SensitiveTag | networks += Network)*;

SensitiveTag: "tag" name=ID;

Network:
    "network" name=ID "{"
        (assets += Asset)* (connections += Connection)*
    "}";

// The Abstract Rule
Asset: WebServer | Database | Firewall;

// The Concrete Rules
WebServer: "webserver" name=ID;
Firewall:  "firewall"  name=ID;

Database:  "database"  name=ID ("sensitivity" sensitivity=[SensitiveTag])?;

Connection:
    "connect" from=[Asset] "->" to=[Asset];

// "hidden" means we skip whitespace automatically
hidden terminal WS: /\s+/; 

// ID starts with a letter, followed by letters or numbers
terminal ID: /[_a-zA-Z][\w_]*/;

// INT returns a number, not a string
terminal INT returns number: /[0-9]+/;
```

With the following model:
```java
tag PII
tag PCI

network MyZeroTrustCorp {

    firewall edgeFW
    webserver publicFrontend
    database sensitiveDB sensitivity PII
    database logsDB

    connect edgeFW -> publicFrontend
    connect publicFrontend -> sensitiveDB
    connect publicFrontend -> logsDB
}
```

Final State of the Grammer can be seen here: [Langium](https://langium.org/playground?grammar=OYJwhgthYgBAcgUwC4HcD2IDWARAygDIBQRiAdsiAJ6wCy6AJogDYBcRsnsAFMmMAGdYAagC8sPOQEBLZNIBuiACr9YAH1hkUGbELEJtmLAEoAVAG4SksjLmKVwVrABEfYM82REogJI5LREhoRuxcLlrB2B5kXr44LgDezhxhXNxgAgIoeuIAgpkoZjwAxuhkWsVyZTmwAMJlFVVkZimczgC%2BzgEA9N2wSgAWiLC5AEYClGCVsABKAK7MiET5WchOAOqIo5IginAaOGB8oxnDGgBi0iCIqGDMzD19g8P1ZMXXyMPziwJEm9uIXaApzOVBbLJAkDRWJ%2BSyXa63e5OFwAMyuNzuzA8ngg3lhJEOx1OyOcDCOYBOWWxMVxcR4ziyNlkClkVA8jNsLOQVFEAG1rJz7PwALrGAD8AVejWkZVCXGcpXKiEqHhRIHQED5KxQwpcAFoAHweZDoLUFZDCx4uAbSBhMMgeXFgGywMGwARYaQAB1dNs%2BAi9U2GYDmJugcmKmKoRBtdvIsE%2BIAg0hizFg6zwTm6AB0BMJuuZYCRerA-O6%2BCBkEJULIBrAwLBFshEwAaWAo9D3dBghiwUY0JuJoSYTRzCCjQG-RPJ1OlnBZ3kAfTAeoAXrk9QAtYW87OoRfC0wF4t9HzwJSwD5zEAuhtkMcTkBtsjoZD18sgFPAIjTlN3UvnpeKDXi697jsCsDdLyAAMeoAJzCvm5hAA&content=C4Qw5gBACgkjBQpJQMIPgOwKbAO4HsAnAawgFkBPALS0PwBVCBXAZ2BSIAcIBveeCIIgAzAJaEsuEABtpELABMwWAGIB1AUNxYARi1oA3WhE5Md00QGMVdDMCwYFmwQpCgdIfRH0YWo4KJGACIAQt4OfgEG-hTQcM4Qru6eWBDS%2BGAsofxCEJb4GNiWwPJKqmoQALQAfCZmFta29o4J%2BYVYxXXmVjYFzQpVtT6RgVjZuW1FJabdjX0OAzVpGVkh8AC%2BQA)

## Why This Matters for Security

Why go through this trouble instead of just writing a Python script or drawing a diagram?

**1. Impossible States:**
In a drawing tool, I can draw a line from the "Internet" straight to my "Secret Database." In my Grammar, I can write a **Validation Rule** (a simple TypeScript function) that says:

> Error: A generic Asset cannot connect to a Database with sensitivity PII unless it is a WebServer.
> 

**2. Code Generation:**
Once I have this text model, I can write a generator that reads my secure network design and **automatically outputs Terraform code** or **Firewall Rules** (iptables).

## Summary Cheat Sheet

| **Concept**     | **Syntax**               | **Meaning**                                                       |
| --------------- | ------------------------ | ----------------------------------------------------------------- |
| **Assignment**  | `property = Rule`        | "Consume the next token and store it here."                       |
| **List Add**    | `list += Rule`           | "Add the next item to this array."                                |
| **Reference**   | `ref = [Type]`           | "Find an existing object with this name; don't create a new one." |
| **Cardinality** | `*`, `+`, `?`            | Zero-or-more, One-or-more, Optional.                              |
| **Terminal**    | `terminal NAME: /regex/` | How to read raw characters (Words, Numbers).                      |
