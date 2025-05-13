---
title: Quackerjack
date: 2025-05-13
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, rconfig-rce, CVE-2020-12255, SUID-find-privesc ] 
image: Quackerjack.png
media_subpath: /assets/img/posts/2025-05-13-quackerjark/
---

## Introduction

In this walkthrough, we target a vulnerable instance of **rConfig** to achieve **remote code execution**. By leveraging a known vulnerability in the application, we are able to upload a malicious PHP script and gain initial access to the system.

Post-exploitation enumeration reveals a **misconfigured SUID binary** — specifically, the `find` utility with the SUID bit set. Using standard privilege escalation techniques associated with `find`, we exploit this misconfiguration to **elevate privileges to root**, gaining full control over the machine.

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

### Port 21 (FTP)

Version - vsftpd 3.0.2

Anonymous login is allowed but trying to listing contents does not return anything:

![image.png](image%203.png)

### Port 22 (SSH)

Version - OpenSSH 7.4 (protocol 2.0)

We usually skip SSH.

### Port 111 (NFS)

111 is one of the ports of NFS, but trying to list  mounted shares does not return anything:

```bash
showmount -e $IP
```

### Port 139/445 (SMB)

- smbclient
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    ![image.png](image%204.png)
    
    Just default shares.
    
- enum4linux
    
    ```bash
    enum4linux $IP
    ```
    

### Port 3306 (MySQL)

Version - Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)

```bash
mysql -h $IP -u anonympous -p --ssl=0
```

Just trying to connect MySQL database, returns that our host is not allowed to connect to the database.

## Web

### Port 80

Version - Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)

### Port 8001

Version - Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)

## Exploitation

Navigating to the site we are presented with login page of rconfig where we can find a version `3.9.4` I found the following exploit for it:

[rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/48261&ved=2ahUKEwiG4rz1j6CNAxXA_rsIHegLOKQQFnoECBcQAQ&usg=AOvVaw0EbKRismdPy5kjdOlm8ft7)

but it didn’t work, then I found the following:

[Rconfig File Upload RCE Exploit](https://gist.github.com/farid007/9f6ad063645d5b1550298c8b9ae953ff)

In the new exploit we should first use another one to change admin user password so that we can login, for that we can use [rConfig 3.9.5 - Remote Code Execution (Unauthenticated)](https://www.exploit-db.com/exploits/48878)

![image.png](image%205.png)

With Ivan Sincek it didn’t succeed so I used [PHP-Reverse-Shell](https://github.com/xdayeh/Php-Reverse-Shell/blob/master/PHP-Reverse-Shell.php)

Now we have a shell:

![image.png](image%206.png)

## Lateral Movement

[rconfig-management](https://kashz.gitbook.io/kashz-jewels/services/rconfig-management)

`[/home]/rconfig/config/config.inc.php` I can see credentials for MySQL database:

![image.png](image%207.png)

I am trying to run the following command to get access to MySQL:

```bash
mysql -u rconfig_user -p 
```

but it doesn’t work. I thought maybe it is because of unstable shell but there is no `netcat`. `socat`, even bash does not return a normal shell I couldn’t get a stable shell.

## Credentials

```bash
rconfig_user : RconfigUltraSecurePass
```

I used the same password for gaining shell access as `rconfig` but it didn’t work.

## Privilege Escalation

Checking SUID binaries I see `find` that means we don’t even need that found credentials:

![image.png](image%208.png)

[GTFOBins-SUID-find](https://gtfobins.github.io/gtfobins/find/#suid)

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

![image.png](image%209.png)

That’s it we are root.

## Mitigation

- **Update rConfig** to the latest secure version and apply any vendor-provided security patches.
- Use a **Web Application Firewall (WAF)** and implement input validation and authentication controls to reduce exposure to remote code execution vulnerabilities.
- Regularly **audit file permissions**, especially SUID binaries. Remove the SUID bit from utilities like `find` unless absolutely necessary.
- Implement **principle of least privilege**, ensuring users and binaries only have the permissions they strictly need.
- Use **monitoring tools** to detect abnormal privilege escalation attempts or the execution of unusual binaries with elevated privileges.
