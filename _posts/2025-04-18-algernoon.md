---
title: Algernoon
date: 2025-04-18
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough] 
image: algernoon.jpg
media_subpath: /assets/img/posts/2025-04-18-algernoon/
---
## Introduction
In this walkthrough we will be solving Proving Grounds Easy Windows box Algernoon. Let’s start ..


## Nmap

### TCP

Run a quick Nmap TCP scan:

```bash
sudo nmap --open $IP
```

![image.png](image.png)

### UDP

Check first 100 UDP ports:

```bash
 sudo nmap -sU -F $IP
```

![image.png](image%201.png)

### **Detailed Nmap scan**

```bash
sudo nmap -sVC -vvv $IP --script vuln
```

## Services

### Port 21

**Anonymous access is allowed**

```bash
ftp $IP
```

Directories:

![image.png](image%202.png)

Only Logs directory is not NULL:

![image.png](image%203.png)

I am gonna put findings in Loot.

### Port 445/139

Couldn’t login with NULL and anonymous session:

![image.png](image%204.png)

## Web

### Port 80

Microsoft IIS httpd 10.0 

Just http IIS server , no public exploits found

**Gobuster didn’t give anything**

```bash
gobuster dir -u http://$IP/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 42
```

### Port 9998

9998/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

**Gobuster fuzzing:**

```bash
gobuster dir -u http://$IP:9998/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 42
```

![image.png](image%205.png)

> Credentials are needed to login to the service, I checked all found directories nothing useful can be found, so I switched to analyzing FTP service, no credentials are found in FTP service either.
{: .prompt-warning}

**Nothing useful here, I checked all logs in FTP service, and found nothing.**

## Loot

- **delivery.log**
    
    02:21:28.847 Updating ClamAV database...
    03:03:25.597 Updating the ClamAV database has completed successfully
    
- **Maintenance.log**
    
    02:21:35.159 Compressed c:\SmarterMail\Logs\2025.01.29-delivery.log
    02:21:35.159 Compressed c:\SmarterMail\Logs\2025.01.29-imapLog.log
    02:21:35.159 Compressed c:\SmarterMail\Logs\2025.01.29-popLog.log
    02:21:35.159 Compressed c:\SmarterMail\Logs\2025.01.29-smtpLog.log
    02:21:35.159 Compressed c:\SmarterMail\Logs\2025.01.29-xmppLog.log
    

## Exploitation

Then I checked if **smartermai**l has any public exploits `searchsploit smartermail`

![image.png](image%206.png)

and have found some.

I needed to identify service build (version), I looked at found directories but nothing useful, then I looked at page source code, and found build number which is **6919**.

![image.png](image%207.png)

I found one RCE exploit that works for version 6985, but we are gonna check for this version too as sometimes exploits work on older versions. Moreover, from Metasploit documentation we see that it works on older versions too:

![image.png](image%208.png)

[https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/http/smartermail_rce.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/http/smartermail_rce.md)

[SmarterMail Build 6985 - Remote Code Execution](https://www.exploit-db.com/exploits/49216)

```bash
python3 exploit.py
```

![image.png](image%209.png)
