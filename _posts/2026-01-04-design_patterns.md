---
title: "Object-Oriented Design Patterns"
date: 2026-01-04
categories: [softeng, OO Software Design] 
tags: [OOP, design_patterns]
image: design_pattern.jpeg
media_subpath: /assets/img/posts/2026-01-04-design_patterns/
---

As software engineers and security researchers, we often encounter the same recurring structural problems: 

- How do we manage object lifecycles securely?
- How do we decouple implementations to allow for safe testing?
- How do we manage state transitions without creating spaghetti code?

The answer often lies in **Design Patterns**. These are not just "best practices"; they are battle-tested blueprints for solving architectural problems. Based on my recent analysis of object-oriented design principles, I want to break down the three major categories of patterns—Creational, Structural, and Behavioral—and demonstrate how they can be applied to build robust, scalable, and secure systems.

---

## 1. Creational Patterns

Creational patterns abstract the instantiation process. They help make a system independent of how its objects are created, composed, and represented, which is critical when we need to strictly control object lifecycles or manage dependencies in complex environments.

### Singleton

The **Singleton** ensures a class has only one instance and provides a global point of access to it. While often debated, it is essential for resources that must have a single source of truth, such as a centralized security configuration manager.

- **Scenario:** A `SecurityContext` that loads firewall rules. You cannot have multiple instances conflicting on which rules are active.
- **Pros:** strict control over the instance, lazy initialization.
- **Cons:** difficult to unit test and implement correctly in multi-threaded environments.
    
    ```csharp
    public sealed class Logger
    {
        private static readonly Lazy<Logger> _instance =
            new Lazy<Logger>(() => new Logger());
    
        public static Logger Instance => _instance.Value;
    
        // Private constructor prevents external instantiation
        private Logger() { }
    
        public void Log(string message)
        {
            Console.WriteLine($"[LOG] {message}");
        }
    }
    	
    ```
    

### Factory Method (Virtual Constructor)

This pattern defines an interface for creating an object but lets subclasses alter the type of objects that will be created.

- **Scenario:** A `ReportGenerator` abstract class. Subclasses like `PdfReportGenerator` or `HtmlReportGenerator` decide which concrete object to instantiate.
- **Benefit:** The client code (the reporting service) doesn't need to know the specific class of the report it's generating, adhering to the Open-Closed Principle (OCP).
    
    **Interface**
    
    ```csharp
    public interface IReport
    {
        void Render();
    }
    ```
    
    **Concrete Products**
    
    ```csharp
    public class PdfReport : IReport
    {
        public void Render() => Console.WriteLine("Rendering PDF report...");
    }
    
    public class HtmlReport : IReport
    {
        public void Render() => Console.WriteLine("Rendering HTML report...");
    }
    ```
    
    **Abstract Creator - Factory Method**
    
    ```csharp
    public abstract class ReportGenerator
    {
        // Factory Method — subclasses override this
        protected abstract IReport CreateReport();
    
        // Template method using the factory method
        public void Generate()
        {
            var report = CreateReport();  // creation delegated to subclass
            report.Render();
        }
    }
    ```
    
    **Concrete creators**
    
    ```csharp
    public class PdfReportGenerator : ReportGenerator
    {
        protected override IReport CreateReport() => new PdfReport();
    }
    
    public class HtmlReportGenerator : ReportGenerator
    {
        protected override IReport CreateReport() => new HtmlReport();
    }
    ```
    
    **Client Code**
    
    ```csharp
    public class ReportingService
    {
        public void Run(ReportGenerator generator)
        {
            generator.Generate();  // works with ANY report type
        }
    }
    ```
    

### Abstract Factory

This interface creates families of related or dependent objects without specifying their concrete classes.

- **Scenario:** A cross-platform UI toolkit. A `WidgetFactory` interface could have implementations like `MacOSFactory` and `WindowsFactory`. The `MacOSFactory` ensures that when you ask for a button and a scrollbar, they match visually (both are MacOS style).

### Builder

The **Builder** separates the construction of a complex object from its representation. This is ideal when an object requires many configuration steps before it is valid.

- **Scenario:** An `HttpRequestBuilder`. You might need to set headers, the body, the method, and timeout settings step-by-step before finally building the request object.
- **Key Difference:** Unlike factories which create objects in one go, the Builder constructs them step-by-step.
    
    ```csharp
    // Hard to read: Is "5000" the timeout or the port? Is "null" the body or the header?
    var request = new HttpRequest("https://api.com", "POST", null, 5000, true, "application/json");
    
    var request = new HttpRequestBuilder()
        .SetUrl("https://api.com")      
        .SetMethod("POST")              
        .SetTimeout(5000)                
        .Build();                        
    ```
    

### Dependency Injection (DI)

DI is a technique where an object receives its dependencies from an external source rather than creating them itself.

- **Scenario:** A `PaymentService` that requires a `FraudDetector`. Instead of `new FraudDetector()` inside the service, the detector is passed via the constructor.
- **Benefit:** This drastically improves testability, as we can inject a mock `FraudDetector` during unit tests.
    
    **Without DI (Coupled):**
    
    ```csharp
    class PaymentService {
        private FraudDetector _detector;
        public PaymentService() {
            _detector = new FraudDetector(); // Hard-coded dependency
        }
    }
    ```
    
    **With DI (Decoupled):**
    
    ```csharp
    class PaymentService {
        private FraudDetector _detector;
        // Dependency is received from outside
        public PaymentService(FraudDetector detector) {
            _detector = detector;
        }
    }
    ```
    

### Prototype

This pattern specifies the kinds of objects to create using a prototypical instance and creates new objects by copying this prototype.

- **Scenario:** In a game, spawning hordes of enemies. Instead of running a costly initialization script for every goblin, you clone a "master goblin" and tweak the location coordinates.
    
    ```csharp
    // 1. The Interface
    public interface IEnemyPrototype {
        IEnemyPrototype Clone();
    }
    
    // 2. The Concrete Class
    public class Goblin : IEnemyPrototype {
        public int Health;
        public int Damage;
        // Heavy resource (e.g., 3D model data)
        private byte[] _heavyTexture; 
    
        public Goblin(int health, int damage) {
            Health = health;
            Damage = damage;
            // EXPENSIVE OPERATION: Simulating loading a file
            Console.WriteLine("Loading 3D Texture from disk... (Slow)");
            _heavyTexture = new byte[1024]; 
        }
    
        // The Clone Method
        public IEnemyPrototype Clone() {
            // FAST OPERATION: Just does a memory copy of the object
            Console.WriteLine("Cloning Goblin... (Fast)");
            
            // 'MemberwiseClone' is a built-in C# method for shallow copying
            return (Goblin)this.MemberwiseClone(); 
        }
    }
    
    // 3. Usage
    public class GameLoader {
        public void SpawnHorde() {
            // Slow: Happens only ONCE
            Goblin masterGoblin = new Goblin(100, 15); 
    
            for (int i = 0; i < 10; i++) {
                // Fast: Creates a new independent copy instantly
                Goblin minion = (Goblin)masterGoblin.Clone();
                
                // Tweak the unique state (Location)
                // minion.Location = ... 
            }
        }
    }
    ```
    

### Object Pool

This creates a set of initialized objects ready for use, rather than allocating and destroying them on demand.

- **Scenario:** A pool of database connections. Creating a connection is expensive; reusing an existing one from the pool improves performance significantly.

---

## 2. Structural Patterns

Structural patterns deal with object composition, helping to ensure that if one part of a system changes, the entire structure doesn't need to do the same.

### Adapter (Wrapper)

The **Adapter** allows objects with incompatible interfaces to collaborate.

- **Scenario:** You have a legacy `XmlInventorySystem` but your new frontend expects JSON. An `InventoryAdapter` wraps the XML system and translates its output to JSON for the client.

### Bridge

This pattern decouples an abstraction from its implementation so the two can vary independently.

- **Scenario:** A `RemoteControl` (Abstraction) and `Device` (Implementation). The `RemoteControl` hierarchy (BasicRemote, AdvancedRemote) can evolve independently from the `Device` hierarchy (TV, Radio, SmartLight).

### Composite

**Composite** lets you compose objects into tree structures and treat individual objects and compositions uniformly.

- **Scenario:** A file system. A `Folder` contains files and other folders. You can call `getSize()` on a single file or a folder, and the folder will recursively sum the size of its contents.

### Decorator

**Decorator** attaches additional responsibilities to an object dynamically.

- **Scenario:** A `DataStream`. You can wrap it with a `CompressionDecorator` and then an `EncryptionDecorator`. The client just writes data, unaware it is being compressed and encrypted on the fly.
- **Comparison:** Unlike inheritance, which is static, decorators allow adding behavior at runtime.

### Facade

The **Facade** provides a simplified interface to a library or complex set of classes.

- **Scenario:** A `VideoConverter` facade. Internally, it might handle codecs, audio syncing, and compression ratios, but the client only sees a simple method: `convert(file, format)`.

### Flyweight

**Flyweight** shares common state to support large numbers of objects efficiently.

- **Scenario:** A text editor rendering millions of characters. Instead of a new object for every letter 'A', the system shares a single 'A' object (intrinsic state) and only stores the position (extrinsic state) separately.
    
    ```csharp
    // the Flyweight (SHARED)
    // heavy-immutable data
    public class MarineModel {
        private byte[] _heavyTexture; // 50MB of data
        private byte[] _3dMesh;
    
        public MarineModel() {
            // Expensive loading happens once
            _heavyTexture = LoadTexture(); 
        }
    
        // The method requires the unique state to be passed in as arguments
        public void Draw(int x, int y, int health) {
            Console.WriteLine($"Drawing Marine at {x},{y} with {health} HP using shared texture.");
        }
    }
    
    // the Context (UNIQUE)
    // tt holds the unique state and a reference to the shared model.
    public class Marine {
        private MarineModel _model; // Reference to the shared Flyweight
        
        // EXTRINSIC STATE (Unique to this instance)
        public int X;
        public int Y;
        public int Health = 100; 
    
        public Marine(MarineModel model, int x, int y) {
            _model = model; // Point to the single shared instance
            X = x;
            Y = y;
        }
    
        public void TakeDamage(int amount) {
            // this modifies the UNIQUE variable 'Health' in this specific instance.
            // it does NOT touch the shared '_model'.
            Health -= amount; 
        }
    
        public void Render() {
            // We pass the unique state to the shared model
            _model.Draw(X, Y, Health);
        }
    }
    ```
    

### Proxy

A **Proxy** provides a surrogate or placeholder for another object to control access to it.

- **Scenario:** A `SecureDocumentProxy`. It checks the user's access level before actually loading the heavy `RealDocument` from the database.

---

## 3. Behavioral Patterns

Behavioral patterns focus on algorithms and the assignment of responsibilities between objects.

### Chain of Responsibility

This pattern passes a request along a chain of handlers.

- **Scenario:** Technical support ticketing. Level 1 support tries to handle the ticket; if they can't, it passes to Level 2, then Level 3.

### Command

**Command** encapsulates a request as an object, allowing for parameterization and queuing.

- **Scenario:** A Smart Home app. "Turn on lights" is wrapped in a Command object. This allows the app to queue the command, log it, or even undo it later.

![image.png](image.png)

### Interpreter & Iterator

While Interpreter deals with grammar, **Iterator** provides a way to access elements of a collection sequentially without exposing the underlying representation.

- **Scenario:** A media player playlist. The iterator lets you press "Next" regardless of whether the playlist is a Linked List, an Array, or a Tree.

### Mediator

**Mediator** restricts direct communications between objects and forces them to collaborate only via a mediator object.

- **Scenario:** An Air Traffic Control tower. Planes (Components) do not talk to each other to decide who lands first; they talk to the Tower (Mediator).

### Memento

**Memento** captures and externalizes an object's internal state so the object can be restored to this state later.

- **Scenario:** The "Save Game" feature. It saves the snapshot of the world without exposing the private variables of every game entity.

### Observer

**Observer** defines a subscription mechanism to notify multiple objects about events.

- **Scenario:** A YouTube channel. When a creator uploads a video (Subject), all subscribers (Observers) get a notification.

### State

**State** allows an object to alter its behavior when its internal state changes.

- **Scenario:** A vending machine. If the state is `NoCoin`, pressing "Buy" asks for money. If the state is `HasCoin`, pressing "Buy" dispenses the item.

### Strategy

**Strategy** defines a family of algorithms and makes them interchangeable.

- **Scenario:** A navigation app. You can choose a `FastestRouteStrategy`, `ScenicRouteStrategy`, or `FuelEfficientStrategy`. The input (A to B) is the same, but the algorithm differs.

### Template Method

This defines the skeleton of an algorithm in a superclass but lets subclasses override specific steps.

- **Scenario:** A `DataMiner` class. The steps `openFile()`, `extractData()`, and `closeFile()` are defined. Subclasses like `PdfMiner` or `CsvMiner` only override the `extractData()` step.

### Visitor

**Visitor** lets you separate algorithms from the objects on which they operate.

- **Scenario:** A tax calculation system. You have different items (Food, Electronics, Books). A `TaxVisitor` can iterate over them and apply the correct tax logic to each class without changing the item classes themselves.

---

## Choosing the Right Tool

It is crucial to understand the nuances between similar patterns:

- **Facade vs. Mediator:** A Facade abstracts a subsystem for a client, whereas a Mediator manages communication *between* system components.
- **Strategy vs. State:** Strategy allows you to swap algorithms (how something is done), while State is about changing behavior based on internal conditions (what state the object is in).
- **Decorator vs. Proxy:** Decorators add responsibilities; Proxies control access.

Mastering these patterns allows us to write code that is resilient to change and easier to understand—a necessity for any high-quality software architecture.

---

**Source Acknowledgment:** This post is based on my interpretation of the Design Patterns educational material by Dr. Simon Balázs, BME, IIT.
