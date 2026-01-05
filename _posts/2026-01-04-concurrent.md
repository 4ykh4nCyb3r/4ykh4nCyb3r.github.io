---
title: "Concurrent and Distributed Design Patterns"
date: 2026-01-04
categories: [softeng, OO Software Design] 
tags: [OOP, thread]
image: concurren.jpeg
media_subpath: /assets/img/posts/2026-01-04-concurrent/
---

In the transition from monolithic, single-threaded applications to distributed systems and high-concurrency environments, the rules of engagement change drastically. The deterministic nature of local memory access is replaced by the unpredictability of network latency, partial failures, and race conditions. In this post I have synthesized a collection of essential patterns that bridge the gap between unstable infrastructure and reliable software.

This post explores the critical synchronization, context, and event-handling patterns necessary for building robust concurrent systems.

## The Distributed Object Paradigm

The fundamental challenge in distributed object-oriented design is the separation of memory spaces. In a local context, a client calls a server object directly. In a distributed context, we must rely on intermediaries to bridge the gap between different address spaces and potentially different languages.

### The Proxy and Adapter Duo

To make remote calls transparent, we rely on two primary structural components:

1. **The Proxy (Stub):** Resides in the client's memory space. It masquerades as the remote service, handling the serialization of parameters and network communication, effectively deceiving the client into believing the object is local.
2. **The Adapter:** Resides in the server's memory space. It listens for network requests, deserializes inputs, and invokes the actual implementation, effectively "publishing" the service.

This abstraction hides the inherent complexities of networking—latency, heterogeneity, and partial failures—though developers must remain vigilant regarding data integrity and the impossibility of shared pointers across boundaries .

## Synchronization Patterns: Taming Shared State

When multiple execution threads access mutable shared state, we encounter race conditions. To maintain consistency without sacrificing performance, we employ a hierarchy of synchronization mechanisms.

### 1. Atomic Operations

At the lowest level, we need operations that appear instantaneous to the rest of the system. These are hardware-supported instructions that guarantee isolation. Instead of using standard arithmetic operators which are not thread-safe, we use atomic primitives for counters or state flags.

**Scenario:** A high-frequency hit counter for a web cache.

```csharp
// Thread-safe increment without heavy locks
private int _activeRequestCount = 0;

public void RegisterRequest()
{
    // C# Example: Atomic increment
    Interlocked.Increment(ref _activeRequestCount);
}
```

### 2. Scoped Locking and Critical Sections

Atomic operations are insufficient for complex logic. We use **Scoped Locking** to define critical sections—blocks of code where only one thread can execute at a time. This ensures atomicity for compound operations.

```java
// Java Example: Protecting a financial transaction
private final Object transactionLock = new Object();

public void transferFunds(Account from, Account to, BigDecimal amount) {
    synchronized (transactionLock) {
        if (from.getBalance().compareTo(amount) >= 0) {
            from.debit(amount);
            to.credit(amount);
        }
    }
}
```

### 3. The Balking Pattern

Sometimes, if a resource is not in the correct state, the best strategy is to do nothing. The **Balking** pattern returns immediately if a job is already in progress or the state is invalid, rather than waiting.

**Scenario:** A background auto-save feature. If a save is already running, triggering another one immediately is redundant.

```java
private bool _isSaving = false;
private object _saveLock = new object();

public void AutoSave()
{
    lock (_saveLock)
    {
        if (_isSaving) 
        {
            return; // Balk: The job is already being handled
        }
        _isSaving = true;
    }

    try 
    {
        PerformDiskWrite();
    }
    finally 
    {
        lock (_saveLock) { _isSaving = false; }
    }
}
```

### 4. Guarded Suspension

Unlike Balking, **Guarded Suspension** waits for a specific precondition to be met before proceeding. This is fundamental for producer-consumer queues.

**Scenario:** A message processor waiting for a queue to have items.

```java
public synchronized Message retrieveMessage() {
    // Loop prevents "spurious wakeups" and re-checks condition
    while (queue.isEmpty()) {
        try {
            wait(); // Release lock and wait for signal
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    return queue.poll();
}
```

### 5. Double-Checked Locking

This pattern is an optimization for lazy initialization, ensuring a lock is acquired only when absolutely necessary (e.g., the first time a singleton is created). It is notoriously difficult to implement correctly due to compiler reordering and memory visibility issues.

**Modern Implementation Note:** In Java (5+) and .NET (2.0+), the `volatile` keyword or memory barriers are required to prevent reading a partially constructed object.

```java
// C# Lazy Initialization Pattern
private static volatile DatabaseConnection _instance;
private static object _syncRoot = new object();

public static DatabaseConnection GetInstance()
{
    if (_instance == null) // First check (no lock)
    {
        lock (_syncRoot)
        {
            if (_instance == null) // Second check (inside lock)
            {
                _instance = new DatabaseConnection();
            }
        }
    }
    return _instance;
}
```
**The "Partial Publication" Trap**
One of the most subtle yet devastating bugs in double-checked locking occurs when an object requires initialization steps after its constructor runs. If you assign the shared static variable before these steps are complete, you risk "publishing" a broken object to other threads.

Consider a **DatabaseService** that needs to open a connection immediately after creation.
```csharp
public static DatabaseService GetInstance()
{
    if (_instance == null)
    {
        lock (_syncRoot)
        {
            if (_instance == null)
            {
                // FATAL FLAW: The object is assigned to the static field immediately...
                _instance = new DatabaseService();
                
                // ...but the actual connection happens here.
                // A second thread can now see '_instance' is NOT null, skip the lock,
                // and try to use the service before this line finishes executing!
                _instance.OpenConnection(); 
            }
        }
    }
    return _instance;
}
```
**Why this fails:**

1. Thread A enters the lock and executes `_instance = new DatabaseService()`. The variable `_instance` is now non-null.
2. Thread A begins the slow `OpenConnection()` method.
3. Thread B checks if (`_instance == null`). Since it is not null, Thread B returns the instance immediately.
4. The Crash: Thread B tries to run a query on `_instance`, but the connection is not yet open because Thread A is still working on it.
**The Fix:** **Use a Local Variable** Always fully initialize the object in a local variable (which is invisible to other threads) before assigning it to the shared static field.

```csharp
lock (_syncRoot)
{
    if (_instance == null)
    {
        // 1. Create and initialize internally (Thread-Safe)
        var tempService = new DatabaseService();
        tempService.OpenConnection();

        // 2. Publish to the world only when fully ready
        // (Volatile write ensures the initialized state is visible together with the reference)
        Thread.MemoryBarrier(); //Memory barrier prevents the compiler optimization to put this line earlier
        _instance = tempService;
    }
}
```

## Signaling and Coordination

Beyond simple exclusion, threads often need to coordinate workflow.

- **Semaphores:** Limit access to a resource pool (e.g., limiting concurrent database connections to 10).
- **ManualResetEvent:** Acts like a gate. Once opened (signaled), any number of threads can pass through until it is manually closed.
- **AutoResetEvent:** Acts like a turnstile. It lets one thread pass and then automatically closes, effectively handing off control to a single worker.

## Context Patterns: Managing State Scope

In distributed environments, passing state (like User IDs or Transaction IDs) through every method argument is impractical.

### Thread-Local Context

Thread-Local Storage (TLS) acts as a global dictionary where the key is the current thread. This allows us to attach context to a specific execution path without global static variables interfering with other concurrent requests.

**Scenario:** Request tracing in a web server.

```csharp
public static class RequestContext
{
    // Each thread sees its own version of this field
    private static ThreadLocal<string> _requestId = new ThreadLocal<string>();

    public static string CurrentRequestId 
    {
        get => _requestId.Value;
        set => _requestId.Value = value;
    }
}
```

## Asynchronous Request Patterns

Asynchronous programming introduces non-blocking I/O, where the caller is notified upon completion rather than waiting idly.

### 1. Asynchronous Completion Token (ACT)

When a client initiates multiple async operations, responses may arrive out of order. The ACT pattern involves passing a unique token (ID) with the request, which the server echoes back with the result. This allows the client to correlate responses to their original requests.

### 2. Cancellation Token

Long-running operations (like compiling code or rendering video) may become obsolete before finishing. A Cancellation Token is a shared object passed to the async task. The task periodically checks if the token has been "cancelled" and, if so, aborts gracefully.
**The "Zombie Thread" Risk**
You might be tempted to implement cancellation simply by using a boolean flag. This is a common mistake that often leads to threads that refuse to die.
In this manual implementation, the compiler or CPU optimizes the loop by caching the `_stop` variable. The thread never looks at the main memory again, so it never sees that you set `_stop = true`.
```csharp
// ANTI-PATTERN: Manual Boolean Flag
public class Worker
{
    // MISSING 'volatile': The thread creates a cached copy of this false value
    private bool _stop = false; 

    public void DoWork()
    {
        // The loop runs forever because it reads the cached 'false' value
        while (!_stop) 
        {
            // Do work...
        }
    }

    public void Stop() { _stop = true; } // The worker thread ignores this update
}
```
The **Cancellation Token** pattern handles these memory visibility complexities for you. It guarantees that the cancellation request is propagated correctly across threads without you needing to worry about CPU registers or the `volatile` keyword.
```csharp
// PATTERN: Cancellation Token
public void DoWork(CancellationToken token)
{
    // Safe, standard, and handles memory visibility automatically
    while (!token.IsCancellationRequested)
    {
        // Do work...
    }
}
```

### 3. Future / Task / Promise

A **Future** (or Task in .NET) represents a "read-only view" of an operation that hasn't finished yet. It allows the caller to query the state (Running, Completed, Faulted) or wait for the result.

**Scenario:** Fetching user data and dashboard configuration in parallel.

```csharp
public async Task<Dashboard> LoadDashboardAsync()
{
    // Start both operations concurrently
    Task<UserProfile> userTask = _userService.GetUserAsync();
    Task<Config> configTask = _configService.GetConfigAsync();

    // Wait for all to complete
    await Task.WhenAll(userTask, configTask);

    // Construct result using the "Futures" that are now resolved
    return new Dashboard(userTask.Result, configTask.Result);
}
```
Using raw threads (the pre-pattern approach) is dangerous because their execution paths are completely independent. If a raw thread throws an exception, it cannot be caught by the code that started it:
```csharp
// THE ANTI-PATTERN: Raw Threads
try {
    // If 'Go' throws, this catch block sees NOTHING.
    // The exception stays on the background thread and might terminate the app.
    new Thread(Go).Start(); 
} 
catch (Exception ex) { ... }
```
The **Task/Future pattern** solves this by treating an Exception as just another type of "Result."
1. The background operation throws an error.
2. The Task object **catches and stores** that error (transitioning to a `Faulted` state).
3. When the main thread asks for the result (`task.Wait()` or `await task`), the Task **re-throws** the stored exception, allowing you to handle it gracefully.
```csharp
public async Task CorrectErrorHandlingAsync()
{
    try
    {
        // GOOD: The Task object wraps the operation.
        // If it fails, the Task transitions to a 'Faulted' state
        // and safely stores the exception inside itself.
        Task calculation = Task.Run(() => 
        {
            throw new InvalidOperationException("Calculation failed!");
        });

        // The 'await' keyword unboxes the result or the exception.
        // It sees the Task failed and re-throws the error right here.
        await calculation;
    }
    catch (Exception ex)
    {
        // This line IS reached successfully.
        // You can now handle the error, log it, or retry.
        Console.WriteLine($"Caught error: {ex.Message}");
    }
}
```

## Conclusion

Building distributed, concurrent systems requires a shift in mental models. We must move from assuming safe, sequential execution to defensive programming using **Synchronization Primitives** for safety, **Context Patterns** for state management, and **Asynchronous Patterns** for responsiveness. Mastering these patterns is not just about writing code that runs; it's about writing code that survives the chaos of concurrency.

---

**Source Acknowledgment:**: *This blog post is based on my interpretation of "Concurrent and Distributed Patterns" educational materials by Dr. Balázs Simon (BME, IIT).*
