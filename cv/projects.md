---
layout: page
title: "Projects"
permalink: /cv/projects/
---
## <i class="fas fa-shield-alt"></i> Cybersecurity & DevSecOps

### <i class="fas fa-file"></i> [Secure File Transfer (SiFT) Protocol](https://github.com/4ykh4nCyb3r/SiFT-Secure-File-Transfer-)
Secure File Transfer (SiFT) v1.1 is a secure file transfer protocol I developed in Python for client-server communication over TCP/IP. Using standard libraries like `socket`, `os`, and `cryptography`, it supports commands (`pwd`, `lst`, `chd`, `mkd`, `del`, `upl`, `dnl`) with AES-GCM encryption and persistent storage. Key features include:

- ✅ Execute file operations securely with cryptographic protection.
- ✅ Authenticate users and establish keys via a Login Protocol.
- ✅ Persistent command logging in text files.

This project deepens my expertise in Python programming, network security, and protocol design, delivering a robust file transfer solution.

### <i class="fas fa-server"></i> [CI/CD Pipeline for URL Shortener](https://github.com/4ykh4nCyb3r/url-shortener-devops)  
I implemented a complete CI/CD pipeline for a containerized URL shortener application using modern DevOps practices with **AWS, Jenkins, Docker, Ansible, and Terraform**. The pipeline automates build, deployment, and infrastructure provisioning, ensuring scalable and repeatable delivery. Key features include:  

- ✅ Provision cloud infrastructure with Terraform (EC2 instances, networking).  
- ✅ Automate deployments via Ansible, including configuration management.  
- ✅ Build, test, and push Docker images with Jenkins (Blue Ocean).  
- ✅ Manage containerized services with Docker and docker-compose.  
- ✅ Maintain modular and branch-separated workflow for app, infra, and automation.  

This project strengthened my expertise in **DevOps, cloud deployment, automation, and containerization**, delivering a fully automated and reliable CI/CD workflow.

### <i class="fas fa-spider"></i> [XSS Web Scanner](https://github.com/4ykh4nCyb3r/XSS-Web-Scanner)
XSS Web Scanner is a lightweight web crawler and Cross-Site Scripting (XSS) vulnerability scanner I developed in Python. Built using libraries like `requests` for HTTP handling, `BeautifulSoup` for HTML parsing, and `urllib.parse` for URL manipulation, it automates the process of identifying XSS vulnerabilities in web applications. The scanner recursively crawls a target website, extracts forms and URL parameters, and tests them with a basic XSS payload (`<script>alert('XSS')</script>`). Key features include:

- ✅ Recursive crawling to discover internal links using a queue-based mechanism.
- ✅ Form extraction and dynamic testing with GET/POST requests.
- ✅ URL parameter testing for XSS vulnerabilities.
- ✅ Features to skip specified links (e.g., logout pages) and prevent infinite loops.
- ✅ Efficient handling to avoid re-scanning duplicate URLs.

This project strengthened my skills in web security, Python programming, and vulnerability assessment, providing practical experience in developing tools for penetration testing.

### <i class="fas fa-lock"></i> [Password Vault Manager](https://github.com/4ykh4nCyb3r/Secure-Password-Vault)
Password Vault Manager is a secure, GUI-based password management tool I developed in Java, designed to store and manage passwords safely. Utilizing `AES` encryption for secure storage, `Swing` for the graphical interface, and `java.util.regex` for password analysis, it provides a user-friendly solution for password management. Key features include:

- ✅ Secure password storage with AES encryption in a vault file.
- ✅ Password strength analysis based on length, complexity, and patterns.
- ✅ Detection of password reuse to enhance security.
- ✅ Master password authentication for vault access.
- ✅ Load and save functionality for persistent storage.
- 
This project deepened my expertise in Java, encryption, and GUI development, while reinforcing my understanding of secure password management practices in cybersecurity.

### <i class="fas fa-keyboard"></i> [Keylogger](https://github.com/4ykh4nCyb3r/Keylogger)
Keylogger is a simple yet effective keylogging tool I developed in Python to capture and log keystrokes, demonstrating my understanding of monitoring techniques in cybersecurity. Leveraging the `pynput` library for keystroke capturing and `smtplib` for email functionality, it records all keystrokes and sends logs to a specified email at regular intervals. Key features include:

- ✅ Captures all keystrokes, including special keys, with accurate logging.
- ✅ Sends logs to a specified email address at user-defined intervals.
- ✅ Runs discreetly in the background using threading for uninterrupted operation.
- ✅ Utilizes `MIMEMultipart` for structured email reporting.

This project enhanced my skills in Python, threading, and email automation, while deepening my knowledge of monitoring tools and their ethical applications in cybersecurity testing.

## <i class="fas fa-code"></i> Software Engineering

### <i class="fas fa-exchange-alt"></i> [Latin-Morse Converter](https://github.com/4ykh4nCyb3r/Morse-Code)
Latin-Morse Converter is a command-line tool I developed in C to convert Latin characters (A-Z, 0-9) into Morse code. Using standard C libraries like `stdio.h`, `stdlib.h`, and `string.h`, it features dynamic memory management with `malloc` to handle large inputs. The program offers a menu-driven interface for user interaction. Key features include:

- ✅ Converts Latin characters (A-Z, 0-9) to Morse code.
- ✅ Menu-driven interface for easy operation.
- ✅ Dynamic memory allocation to handle large text inputs.

This project improved my skills in C programming, memory management, and user interface design, providing practical experience in building efficient command-line applications.

### <i class="fas fa-tasks"></i> [Task Management System](https://github.com/4ykh4nCyb3r/Task-Manager)
Task Management System is a console-based application I developed in C++ to manage tasks across categories like My Day, Assigned To Me, Important, and Planned. Using standard C++ libraries such as `iostream`, `fstream`, and `vector`, it supports task creation, updates, removal, and display with persistent storage in text files. Key features include:

- ✅ Add, remove, and update tasks with attributes like title, deadline, and priority.
- ✅ Display tasks by category or view all tasks in the database.
- ✅ Persistent storage using text files for data retention.

This project enhanced my skills in C++ programming, file handling, and object-oriented design, focusing on efficient task management solutions.
