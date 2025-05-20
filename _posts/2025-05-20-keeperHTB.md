---
title: Keeper
date: 2025-05-20
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, enumeration, KeePass-.dmp-memory-dump, Putty-to-SSH ] 
image: keeper.png
media_subpath: /assets/img/posts/2025-05-20-keeperHTB/
---


### Introduction

In this walkthrough, we target a support ticketing system running on the machine, which uses **default credentials**. After logging in, we discover **cleartext credentials** within the interface that grant us **SSH access**. Once on the machine, we find a **KeePass database dump**, which we used to extract possible master secrets and then brute-force them secret using hashcat. The KeePass database contains the **root user's SSH private key in Putty format**, which we will convert to OPENSSH format using putty-tools, extracted private-key allows us to authenticate as root and gain full access to the system.

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

### Port 22 (SSH)

Version -OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - nginx 1.18.0 (Ubuntu)

Add the domain to `/etc/hosts`  file:

![image.png](image%202.png)

We are redirected to login page, I used the following credentials to login:

`root : password` which are default credentials for application Request Tracker.

I found the following vulnerability but failed to exploit because every time i wanted to intercept the request it redirected me to Jenkins where I don’t know any credentials.

[Request Tracker - 'ShowPending' SQL Injection](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/38459&ved=2ahUKEwi5mqLJ37GNAxWhnf0HHVO9K3gQFnoECAkQAQ&usg=AOvVaw1W-TfWxfoSo-Rp7_LodWge)

After some time spent on enumerating the website I found under users that we actually have 2 users, 

`lnorgaard` and `root`.

And more interestingly I found that user password in their description;

![image.png](image%203.png)

I used these credentials to gain SSH access and was successful.

![image.png](image%204.png)

## Privilege Escalation

- **OSCP Checklist**
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
    

After checking my groups and sudo privileges. I decided to enumerate the file that is under our user directory called `RT30000.zip`. Unzipping the file I can see two files:

![image.png](image%205.png)

As we have kdbx file we can try to crack it using hashcat but first we need to convert it to hashcat compatible format using `python2john`. 

```bash
keepass2john passcodes.kdbx > keepass.hash
```

![image.png](image%206.png)

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

But it took a long time to crack that means we did something wrong. I analysed that this `.dmp` file could mean, and found many resources that this is related to vulnerability in KeePass.


> While typing out the master key to unlock a KeePass database, the value of the input box is stored in memory. While it is visually hidden using '●' characters, the last character was briefly visible in memory and keeps being stored there ([CVE-2023-3278](https://nvd.nist.gov/vuln/detail/CVE-2023-32784), fixed in [KeePass 2.54](https://keepass.info/news/n230603_2.54.html) released June 3rd 2023). 
{: .prompt-info }

[keepass-dump-extractor](https://github.com/JorianWoltjer/keepass-dump-extractor?tab=readme-ov-file)

I downloaded Linux version from releases and run the tool:

```bash
./keepass-dump-extractor ../KeePassDumpFull.dmp -f all > wordlist.txt
```

```bash
hashcat -m 13400 ../keepass.hash wordlist.txt
```

![image.png](image%207.png)

Now we cracked it.

Then download `KeepassXC` to open keepass file in Linux.

I found passwords for users `root` and our current user, but root user password didn’t work that’s why I decided to use their private key:

![image.png](image%208.png)

But this key format is `.ppk` file format which us Putty file format, we should convert it to SSH private key format using `putty-tools`.

```bash
sudo apt install putty-tools
```

After that use:

```bash
puttygen key.ppk -O private-openssh -o key_id_rsa
```

![image.png](image%209.png)

Now we are root!

## Credentials

```bash
#SSH
lnorgaard : Welcome2023!

#Keepass
rødgrød med fløde
```

## Mitigation

- **Change all default credentials** immediately after deploying any service.
- Avoid storing **plaintext credentials** in web interfaces or configuration files.
- **Encrypt sensitive files** (such as KeePass databases) with strong, unique passwords.
- Secure SSH access using **key-based authentication**, and avoid placing private keys on the system.
- Implement **least privilege access controls** and monitor for abnormal access patterns.
