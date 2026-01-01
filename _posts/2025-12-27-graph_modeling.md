---
title: "Graph Modeling & Logic Solvers"
date: 2025-12-27
categories: [softeng, Automated Software Engineering] 
tags: [MDE, SoftwareArchitecture, AppSec, Refinery, Engineering]
image: graph_modelin.jpeg
media_subpath: /assets/img/posts/2025-12-27-graph_modeling/
---

If you’ve ever tried to secure a complex system, you know the struggle: you draw a diagram on a whiteboard, you *think* it looks secure, but you missed one hidden path that allows an attacker to bypass the firewall.

Whiteboards are dumb. They don’t know that a "Database" shouldn't talk directly to the "Internet."

This is where **Model-Driven Engineering (MDE)** and **Graph Modeling** come in. Instead of drawing dumb pictures, we write **logic**. We treat our architecture as a mathematical graph, allowing us to mathematically *prove* our design is valid before we write a single line of code.

In this post, I’ll guide you through the basics of Graph Modeling using **Refinery**, moving from "drawing boxes" to "generating secure architectures automatically."

## 1. The Metamodel: Defining the Rules of Engagement

In MDE, we don't start by drawing. We start by defining the **grammar** of our world. This is called the **Metamodel**.

Think of it as the "Legend" on a map. You define what objects *can* exist and how they are *allowed* to connect.

Let's imagine we are building a simple network. We need:

1. **Services** (Web Servers, APIs)
2. **Datastores** (SQL, Redis)
3. **Firewalls** (The gatekeepers)

Here is how we define that in Refinery code:

```java
// The Container (The Network)
class Network {
    contains Asset[0..*] assets
}

// The Abstract Asset (Generic Hardware)
abstract class Asset {
    Asset[0..*] connectsTo
}

class SensitiveTag {}

// The Concrete Assets
class WebServer extends Asset {}

class Database extends Asset {
    SensitiveTag[0..1] hasSensitivity
}

class Firewall extends Asset {}
```

**What did we just do?**
We created a rulebook. We said that `Assets` can connect to other `Assets`. We haven't built a specific network yet; we’ve just defined the building blocks.

The current state of the model can be observed here: [Refinery](https://refinery.services/#/1/KLUv_WCDAM0GAIKLJCFAq6QNOGstdgi7dYmRtDLYk5vJsfHmMzY07qDuGMVdbg4Vx7HnqQgaVqlF7FBcrbG1gQd-Ge78JN9ojgCBSFbtmGTP9Ps8XAwBihWM-UStUnxjMbp3xHWGEE97HmkGPpXHFxy8Z7naLAKcEkIVpGZHYlkAEvaqC-vZNqJY1ZxDiIVcz_7g4DwqW1wMP8J4UTilGwBLIB4ze-RQKVAAhmdgWC0gijiNEhSsrK2RtJpxwWAY7B6GPh1ARoBgcEgjgYoGa8BgUYQxHRwLc7yE-tSIAakSTCY=)

## 2. The Instance Model: Drawing the Blueprint

Now that we have the rules, we can build a specific scenario. This is called an **Instance Model**. This is equivalent to drawing the actual diagram for a specific client.

```java
// Create the Network
Network(myCorpNet).

// Create the Assets
WebServer(publicWeb).
Firewall(edgeFirewall).
Database(usersDB).

// Create the 'PII' Tag
SensitiveTag(PII).

// Mark the DB as sensitive by connecting them
hasSensitivity(usersDB, PII).

// Create the Connections
connectsTo(edgeFirewall, publicWeb).
connectsTo(publicWeb, usersDB).
```

In a Graph Modeling tool, this text instantly renders as a visual diagram: `Firewall -> Web -> DB`.

The current state of the model can be observed here: [Refinery](https://refinery.services/#/1/KLUv_WDfAUULAIbRNyQgyagNs6b-3rFycYS9g3ITYOkzzfySkQD0tdZczXhJEIKGAAEsACsALgA8JQT-PIgLyHkIgOMEILQyJ87t_1HhzFk1bChrYVoZ7KvPZT8Luk6kO4g_T1fzq7y6JWvrtmdBAwqnUtKLa8dPHZbE3fQ9qyU2uomJbBq8udWnBezdcjvTZWHITtPKsKwFZSoM-9qpC1VVYnQdQaYd5-QQhHJO2bmIPO0E_epl1THpQyIJP_yA_CwH_YAV6rnMdD7nFQvK5kEUNRhSKd0QRQ2DYsGrfDF0GqUiytBpJn00VwU3IDBCYhzUA90pqJVAGwANh0WeYM9W9Qf_NTbqRlwiTEhwiY1WvZE-87IgzySzLWhKIC3PqUoGkGg08pEXvnQFJ0q75dvX5h1DWEA8VnskqRQKwACDiRYQIE6VoHBZW0labdwb_GD3Dn0OIA8QhEOaBMoG6xgsE8YwOCbmuKE-HPGRKgFnAg==)

### The "Closed World" Assumption

Here is the critical security concept. By default, logic solvers operate in an **Open World** (assuming invisible things might exist). In security, we need a **Closed World** (if it isn't on the diagram, it doesn't exist).

We explicitly tell the solver:

```java
// Do not invent ghost servers
!exists(Network::new).
!exists(WebServer::new).
!exists(SensitiveTag::new).
!exists(Database::new).
!exists(Firewall::new).

// Default: Assume no connections exist unless explicitly drawn
default !assets(*, *).
// Ensures Zero Trust: there shouldn't be a connection between internet and database
default !connectsTo(*, *).
default !hasSensitivity(*, *).
```

So the model generation code will look like the following:

```java
// 1. The Container (The Network)
class Network {
    contains Asset[0..*] assets
}

// 2. The Abstract Asset (Generic Hardware)
abstract class Asset {
    Asset[0..*] connectsTo
}

class SensitiveTag {}

// 3. The Concrete Assets
class WebServer extends Asset {}

class Database extends Asset {
    SensitiveTag[0..1] hasSensitivity
}

class Firewall extends Asset {}

// Do not invent ghost servers
!exists(Network::new).
!exists(WebServer::new).
!exists(SensitiveTag::new).
!exists(Database::new).
!exists(Firewall::new).

// Default: Assume no connections exist unless explicitly drawn
default !assets(*, *).
// Ensures Zero Trust: there shouldn't be a connection between internet and database
default !connectsTo(*, *).
default !hasSensitivity(*, *).

// --- Instance Model (The Blueprint) ---
Network(myCorpNet).
Firewall(edgeFirewall).
WebServer(publicWeb).
Database(usersDB).
SensitiveTag(PII).

// The network "owns" these devices
assets(myCorpNet, edgeFirewall).
assets(myCorpNet, publicWeb).
assets(myCorpNet, usersDB).

// Mark the database as holding sensitive data
hasSensitivity(usersDB, PII).

// Traffic flows from Firewall -> Web -> DB
connectsTo(edgeFirewall, publicWeb).
connectsTo(publicWeb, usersDB).
```

The current state of the model can be observed here: [Refinery](https://refinery.services/#/1/KLUv_WDZA4URAMadViUgkdMB80aWSPvQ5M8tIkoiPJiMgenh4Q2QbT-wJaY61gAhXHMTSwBKAEgAtmDlGbZM8xOuohs900W4nD-spIcOjth7vqHxRvhWIYQCSyRrdSxFXzyeZ8Bir4pgjWx7cVgVW7QcjOeqfUTj92S46RT8S8UPgSWSmo659DOoyTYKpz9O9ZxMGl1lGgdYql51F4s3n0nmdWlHaQ2rP8awsUzx4guCK0K4SJHyq3G_Z94noFNME7XqhtRGqN-_KJ2CAUcPc6oltEsOwo8SV_PBkUhEspTofb5vMudf7SGjD3kFUmqUu6j_fllPVqlXsXuvsP5RmguP8zDk0QBYWlnhk7zRlkWsYfQtKTsrgXIQsTPcm6yVa5MjNk34DFlqSzKpuYsVjfEQwpClj1jmkq8BmpULcD48SDTrcRIo-q5Usx4HOkXEGkRhmvU4t0hv1uPsIzDPKWxkNMvZZAFdqAGSQUSGSEY0SZo5IEKCFNsbEDhjxkhakBYDQ4FaR6I_XRobwgi6t2Nxe5FTVIhZSK7TQOaGZMZKXVvAWxSFuVGLnEQhP8wcFvKS9TNWgsNZvI0r5n-D7okZYHAO1RP3MviIDj85iyrRtlPnr2Mkfo12qZcKeJRmzyJyG2A9OKNiYckelM9PFE-V35PV8s2IUdAxyxgTjcmhYnLo3QgLu8QYlgQFgIE1RYdAps9TSH_bxwq7gIUvO_XWRa6A2rSbelcDLymxrmPU_d-8eR2jMt0f)

## 3. Predicates: Visualizing Attack Paths

This is where Graph Modeling beats a whiteboard. We can write queries (Predicates) to find patterns in the graph.

Let’s write a "rule" to detect if a path exists between two nodes.

```java
// A simple recursive logic rule to find a path
pred canReach(x, y) <->
    connectsTo+(x, y).
```

I added the following test case to test the predicate:

```java
pred testFirewallToDB() <-> canReach(edgeFirewall, usersDB).
```

After that click `Generate` on the upper right corner of the Refinery tool.

![image.png](image.png)

Now, the tool can highlight every single path data takes through your network, even paths you didn't notice visually.

This image is the perfect proof of **Lateral Movement**.

- **The `connectsTo` arrows** show your **intended design** (which looks safe because the DB is "hidden" behind the Web Server).
- **The `canReach` arrows** show the **attacker's reality** (if they breach the Firewall, they *have a path* to the Database).

You can view the current model here: [Refinery](https://refinery.services/#/1/KLUv_WB3BNUTAMaiYyUAk5sDbtaxiSW0Qm5atDRCP72Xmv07VgDQ5xAGzOXA4f9_-w8lWABYAFkAq36M2sb0-9gSMiB4GMMs37h1mreAFt32TNjYeh5ZFUUG4ebi8w-Ot7G4elk4sESy1sdSZo0BCCrI2KsuWJttLw-rstfWsxFhtZ9wHJ-ObUIGf7IYMrBEEtZHSrMBegYMGXAAHK2sWIzc8dY19zT6l5StCR1MP0NN9lFMOvRUz8nE0VXHcYCl6lU4Ybz5TTovTMPKe6x6dA4d65RN1jC4sgtbVonyy3HHb-ItLr-QJCpZwQBnRASFs6CHUtF4pZwFPZdfNPculMZZ0HNMdGdBz35CEyFDR8ZZz6aLmlOP8h5BCb8lW80IRyKRyFEy7zN-0zn_an8x8y9egYweBSf146f1ZJWKFsN4jA6lAi2r3wURKEQS_HQYwuFMjb0iWXP0qFnTMo2Zo3SS4fqPim4OA5-_cRqp9ug_TcapFxalohCxMzBK1go-yc1JEouGLDUmXfTgZGXeiEzCkKVvbvPI1wANZqixFULGDJGMyEjSTGMgQoIU09sQMMNQ0bQgLQYhw9BNedjrGnLhmUO7FCTtJegJDrfVQyT626S2JoygjnG8h17IPjowpMhFEurdBM3wrP0WVQvjYGrMTiYoSI8SxoJREiXjiyAPC4hx5fEvLp6cBS9y_kvEvlFMOoQTuhAStfb63CnG1LtaSy9-wIfSDBchgIB9AjAUkZAEmNLygQKlNG-TlXv3yKZIwC2jtlS6w8nktHY1WJYSm1bqCnuGjKlzZDt9skJOW8HWLAV9nuysNxRyDtROK6jr6tglE6s6Rg_9oDfxwL04lwY=)

## 4. Constraints: Banning Bad Architectures

We can define **Error Predicates**—configurations that are strictly forbidden.

Let's ban any architecture where the **Internet** can reach a **Database** without going through a **Firewall**.

```java
// --- METAMODEL ---
class Network {
    contains Asset[0..*] assets
}

abstract class Asset {
    Asset[0..*] connectsTo
}

class SensitiveTag {}

class WebServer extends Asset {}
class Database extends Asset {
    SensitiveTag[0..1] hasSensitivity
}
class Firewall extends Asset {}

// For simplicity define the Internet as a type of Asset
class Internet extends Asset {} 

// --- CLOSED WORLD ASSUMPTIONS ---
!exists(Network::new).
!exists(WebServer::new).
!exists(SensitiveTag::new).
!exists(Database::new).
!exists(Firewall::new).
!exists(Internet::new). // <--- Add this line!

default !assets(*, *).
default !connectsTo(*, *).
default !hasSensitivity(*, *).

// Instance model
// --- INSTANCE MODEL ---
Network(myCorpNet).
Firewall(edgeFirewall).
WebServer(publicWeb).
Database(usersDB).
SensitiveTag(PII).

// NEW: Create the Internet Object
Internet(thePublicInternet).

// Link everything to the Network container
assets(myCorpNet, edgeFirewall).
assets(myCorpNet, publicWeb).
assets(myCorpNet, usersDB).
assets(myCorpNet, thePublicInternet). // <--- Add it to the network map

// Tag the DB
hasSensitivity(usersDB, PII).

// --- WIRES ---
// Normal Traffic: Internet -> Firewall -> Web -> DB
connectsTo(thePublicInternet, edgeFirewall).
connectsTo(edgeFirewall, publicWeb).
connectsTo(publicWeb, usersDB).

// Transitive Logic
pred canReach(x, y) <->
    connectsTo+(x, y).
```

```java
// ERROR: A "Leaked" Database
// This error triggers if the Internet can reach a PII-Database
// directly or via a path that bypasses the Firewall.
error pred unsecuredDatabase(db) <->
    Database(db),
    hasSensitivity(db, tag),           // It is sensitive
    canReach(thePublicInternet, db),   // The Internet can get to it
    !canReach(edgeFirewall, db).       // BUT the Firewall cannot reach it (implies bypass)
```

If you try to model a network that violates this rule, the tool will scream at you. You have effectively "compiled" your security policy.

## 5. Partial Modeling: The "Auto-Complete" for Architecture

This is the magic trick. Instead of designing the network yourself, you can use **Partial Modeling** to let the AI solve it for you.

You tell the tool:

> "I need 1 WebServer, 1 Database, and 1 Firewall. Make sure the Database is secure."
> 

```java
// The Requirements
scope WebServer = 1.
scope Database = 1.
scope Firewall = 1.
```

The whole code can be written like the following:

```java
class Network { contains Asset[0..*] assets }
abstract class Asset { Asset[0..*] connectsTo }
class Internet extends Asset {}
class Firewall extends Asset {}
class WebServer extends Asset {}
class Database extends Asset {
    SensitiveTag[0..1] hasSensitivity
}
class SensitiveTag {}

scope Network = 1.
scope Internet = 1.
scope Firewall = 1.
scope WebServer = 1.
scope Database = 1.
scope SensitiveTag = 1.
```

The Refinery tool will use a graph solver to run through thousands of combinations and generate a diagram that satisfies all your connection rules and passes all your security constraints. It automatically places the Firewall in the correct spot to protect the Database.

You can view the current model here: [Refinery](https://refinery.services/#/1/KLUv_WCYAM0FAHJJHRxwa3N1BGvE5gup95NPmF2XvLe0JYyHurD076UGahlRy8gbjmlKEeT02Ka48LIUqNxp2zSf2Ha6IoOLg3fnPWF-aBp8_hohkV_Hvc_3zUKK7BRd9kzHIHsZvlUGU2RFLwClAoi9qsCaDTcdM2TGc8_eYFVsWBoAfjhwYyD2CuAY6L0NYCBpCtwYqL4CbDIBoYVNBbghYPEIyaFy-oIFCCcCeADgoV6wla6VGv5Th0fdQKv5flCe)

## 6. Summary

Graph Modeling isn't just about drawing circles and arrows. It is about:

1. **Structure:** Defining a rigid Metamodel (the rules).
2. **Logic:** Using a Closed World assumption (no "magic" objects).
3. **Verification:** Writing Constraints to ban bad designs (loops, leaks, broken flows).
4. **Automation:** Using Partial Modeling to generate valid solutions.
