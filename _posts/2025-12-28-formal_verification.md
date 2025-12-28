---
title: "Hacking Code with Pure Math - Formal Verification"
date: 2025-12-28
categories: [softeng] 
tags: [AppSec, formal_verification, SMT, SAT, Z3, Engineering, DevSecOps]
image: formal_ver.jpeg
media_subpath: /assets/img/posts/2025-12-28-formal_verification/
---

As penetration testers and software engineers, we spend a lot of time breaking things. We write unit tests, we run fuzzers, and we manually hammer APIs looking for edge cases.

But there is always that nagging doubt: *Did I miss something?*

If a function takes a 32-bit integer as input, there are over 4 billion possible inputs. You can’t test them all. You test the happy path, maybe `0`, `-1`, and a massive number. If those pass, you ship it.

But what if the bug only triggers when the input is exactly `2,147,483,647`? A unit test will miss it. A fuzzer might miss it for days.

This post is about a different approach. It’s about stopping the guessing game and treating code not as instructions to be executed, but as mathematical equations to be solved. This is the world of **Formal Verification**.

### The Paradigm Shift: Code = Math

The fundamental idea of formal verification is simple but radical: **Don't run the code.**

When you run code (dynamic analysis), you are observing one specific path through the maze. When you verify code formally (static analysis), you are looking at the blueprint of the entire maze at once.

We translate programming constructs into logical formulas:

- `x = y + 5;` becomes the mathematical fact: $x = y+5$
- `if (x > 10) { ... }` becomes a logical implication: $x>10 ==> ...$

Once your program is converted into a giant pile of math equations, we can use powerful engines to ask questions about it.

## The Engine Room: SMT Solvers

You don't solve these equations by hand. You use an **SMT Solver** (Satisfiability Modulo Theories). The most famous one is Microsoft Research's **Z3**.

Think of Z3 as a "Reverse Calculator" or a "Logic Detective."

- **Normal Calculator:** Here are numbers `5` and `10`. What is `5 + 10`? -> `15`.
- **SMT Solver:** I need two numbers, `x` and `y`. The rules are: `x + y = 15` AND `x > y`. Find them. -> Z3 will report: `SAT` (Satisfiable) and give you a model, e.g., `x=8, y=7`.

In security and verification, we use Z3 backwards. We don't ask it to prove our code works. **We ask it to prove our code is broken.**

We say: *"Here is the math representing my program. Here is a mathematical definition of a BUG (e.g., a crash). Is it possible to satisfy both?"*

- If Z3 says **SAT (Satisfiable)**: It means "Yes, I found input values that satisfy the bug condition." **You just found a vulnerability.**
- If Z3 says **UNSAT (Unsatisfiable)**: It means "I have searched the entire mathematical universe defined by your constraints, and a bug is logically impossible." **You have proven the code safe.**

## A Security Example: The "Invisible" Overflow

Let's look at a classic C bug that is notoriously hard to catch with simple tests.

```c
// A seemingly innocent check
int is_safe_increment(int current_value, int increment_amount) {
    // We want to make sure current + increment doesn't exceed a max limit
    if (current_value + increment_amount > MAX_LIMIT) {
        return 0; // Unsafe!
    }
    return 1; // Safe to proceed
}
```

A developer might test this with `current=100, increment=50` (Safe) and `current=MAX_LIMIT, increment=1` (Unsafe). Looks good.

As a pen-tester, you know the flaw: **Signed Integer Overflow**. If `current_value` and `increment_amount` are both huge positive numbers, adding them together might wrap around and become a *negative* number. A negative number is definitely not greater than `MAX_LIMIT`, so the check passes, and the program proceeds with corrupted data.

How do we catch this with math using Z3 (in Python)? We don't use abstract math integers; we use **Bit-Vectors** to simulate real 32-bit CPU behavior.

```python
from z3 import *

# 1. Define our variables as 32-bit integers (just like the C code)
current_val = BitVec('current_val', 32)
incr_amt = BitVec('incr_amt', 32)
MAX_LIMIT = 2147483647 # The largest signed 32-bit integer

# 2. Define the math of the addition AS THE CPU DOES IT
result = current_val + incr_amt

# 3. Define the "Bug Condition"
# We are looking for a state where we added two positive numbers,
# but the result ended up being NEGATIVE (overflow happened).
# Note: In Z3 BitVecs, we must use signed comparisons ( <s ) specifically.
bug_trigger = And(
    current_val > 0,
    incr_amt > 0,
    result <s 0  # The result wrapped around to negative
)

# 4. Ask the detective
s = Solver()
s.add(bug_trigger)

if s.check() == sat:
    print("Vulnerability found! Here is the exploit input:")
    print(s.model())
else:
    print("Code is mathematically safe from overflow.")
```

If you run this, Z3 instantly spits out:

`[incr_amt = 1, current_val = 2147483647]`

It found the exact edge case that breaks the logic. We didn't guess inputs; we defined the *properties* of a failure, and the solver found the inputs for us.

## The Landscape: Three Ways to Use the Math

In practice, you don't usually write raw Z3 code for whole applications. You use tools that do the translation for you. These tools generally fall into three categories, depending on how they view the program.

### 1. Symbolic Execution

Instead of running the program with concrete numbers like `x=5`, the tool runs it with a "symbol" `x=N`. As it moves through the code, it builds up a mathematical formula of the path it took.

- **The vibe:** Exploring a maze with clones. Every time you hit an `if`, you clone yourself; one explores the "true" path, one explores the "false" path.
- **Best for:** Automatically generating high-coverage test cases and finding crashing bugs without knowing the code deeply.
- **Disadvantage: Path Explosion.** The tool tries to explore every possible execution path. If the program has many loops or complex `if-else`chains, the number of paths grows exponentially (2, 4, 8, 16...), causing the tool to hang or run out of memory before finishing.
- **Tools:** KLEE, Angr.

### 2. Model Checking

This approach treats the program as a giant state machine (a graph of every possible value for every variable at every line of code). It tries to explore the entire graph to see if a "bad state" (like a deadlock or crash) is reachable.

- **The vibe:** Scanning a satellite map of the maze looking for traps, rather than walking through it.
- **Best for:** Concurrency bugs, race conditions, and hardware verification.
- **Disadvantage**: **State Space Explosion.** Since it tracks the entire "state" of the program (every variable value at every step), complex programs with large variables (like 64-bit integers or arrays) create a "map" too huge to scan completely, forcing tools to approximate or give up.
- **Tools:** CBMC, TLA+.

### 3. Deductive Verification

This is the most rigorous approach. You annotate your functions with "contracts": **Preconditions** (what must be true before running) and **Postconditions** (what the function guarantees to be true after). The tool then tries to mathematically prove that the code actually honors the contract.

- **The vibe:** Proving a mathematical theorem. If the proof holds, the bugs are logically impossible.
- **Best for:** Critical cryptographic libraries, financial systems, or high-assurance kernels (like seL4).
- **Disadvantage:** **Human Bottleneck.** It is not fully automated. It requires a developer to manually write complex mathematical proofs (like "loop invariants") for the code. If the human cannot figure out the math behind why their loop works, the tool cannot verify it.
- **Tools:** Dafny, Frama-C.

## The Defense in Depth

If Formal Verification is the mathematical "truth," why do we still bother with unit tests or fuzzers? The answer lies in the trade-off between **cost** and **assurance**. In modern software engineering, we layer these methods to catch different types of bugs at different stages.

- **Unit Tests (The sanity check):**
    - **Role:** These are cheap, fast, and verify that the "happy path" works as expected.
    - **Limitation:** They only prove the specific examples you wrote. If you forgot to test input `1`, the unit test won't save you.
- **SAST (Static Application Security Testing):**
    - **Role:** This is the "spell checker" for code. It scans millions of lines quickly to find known bad patterns (like SQL injection or hardcoded passwords) without running the app.
    - **Limitation:** It is notorious for "false positives" and misses complex logic errors that involve multiple steps.
- **DAST (Dynamic Application Security Testing):**
    - **Role:** This is the "hacker simulation." It attacks your running application from the outside to see how it reacts to weird inputs.
    - **Limitation:** It is slow and happens late in the process. It can only find bugs in paths that it manages to hit randomly.
- **Formal Verification (The Nuclear Option):**
    - **Role:** This is reserved for the code that **cannot fail**—cryptographic cores, smart contracts, or avionics systems. It provides the highest level of assurance possible.
    - **Limitation:** It is expensive in terms of human time. You wouldn't formally verify a UI button animation, but you *must* verify the encryption algorithm behind it.

**`The Bottom Line:`** You don't choose one; you use them all. You unit test for functionality, SAST for hygiene, DAST for resilience, and Formal Verification for the critical logic that keeps the system secure.

## Conclusion

Formal verification isn't a silver bullet that replaces testing. But for security-critical code, where a single edge case can lead to a compromise, relying on fuzzing and unit tests is a gamble.

Learning to think in terms of invariants, preconditions, and mathematical constraints will make you a better developer and a sharper penetration tester, even if you never run Z3 in production. It teaches you to look past the "happy path" and see the mathematical reality of what the code *actually* does.
