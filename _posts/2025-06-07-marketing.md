---
title: Marketing
date: 2025-06-07
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, Linux, LimeSurvey-RCE, mlocatedb, mlocate-group] 
image: marketing.jpg
media_subpath: /assets/img/posts/2025-06-07-marketing/
---

## Introduction

On this intermediate PG Practice Linux box, I discovered a **vulnerable LimeSurvey instance**, which I exploited to gain initial access. During enumeration, I found **plaintext credentials in configuration files**, allowing me to log in as a local user. I discovered a **binary executable as another user**, which I used to read a **sensitive file**, the path to which I retrieved using `mlocate.db`. The file contained a password for a second user, who had unrestricted **`sudo` access**, enabling me to escalate to **root**.

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

Version - OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.41 ((Ubuntu))

**Gobuster Scan**

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -t 30 -x .html,.php -b 404,403
```

![image.png](image%203.png)

Visiting `/old` directory I don’t see anything much interesting, but inspecting the source code I can find subdomain:

![image.png](image%204.png)

Add the subdomain to `/etc/hosts` file.

**Gobuster Scan**

![image.png](image%205.png)

Navigating to `admin` directory we are greeted with login panel, access to any other directory is forbidden. I am gonna search for default credentials for limesurvey, I found `admin:kamote1234`, it didn’t work then I tried `admin:password`  and it worked.

## Exploitation

I see the version of the application displayed on the bottom right:

![image.png](image%206.png)

Found this vulnerability:

[LimeSurvey 5.2.4 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50573)

```bash
python3 exploit.py http://customers-survey.marketing.pg/ admin password 80
```

![image.png](image%207.png)

Here you can read about exploitation technique in more detailed way:

[[CVE-2021-44967] LimeSurvey RCE](https://ine.com/blog/cve-2021-44967-limesurvey-rce)

[Limesurvey-RCE](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE/tree/main)

![image.png](image%208.png)

I have a shell now.

## Shell as www-data

Let’s make a shell more interactive using python:

```powershell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Reading `/var/www/LimeSurvey/application/config/config.php` I discovered:

![image.png](image%209.png)

Which turns out password for `t.miller`user.

## Shell as t.miller

Checking sudo privileges of `t.miller` I discovered:

![image.png](image%2010.png)

I am gonna create just a txt file with content just some single character and then run commad so m.sander:

![image.png](image%2011.png)

- **Command Injection**
    
    I see here that bash variable is not enclosed into quotes we can leverage it for command injection:
    
    ```bash
    #! /bin/bash
    
    if [ -z $1 ]; then
        echo "error: note missing"
        exit
    fi
    
    note=$1
    
    if [[ "$note" =~ .*m.sander.* ]]; then
        echo "error: forbidden"
        exit
    fi
    
    difference=$(diff /home/m.sander/personal/notes.txt $note)
    
    if [[ -z $difference ]]; then
        echo "no update"
        exit
    fi
    
    echo "Difference: $difference"
    
    cp $note /home/m.sander/personal/notes.txt
    
    echo "[+] Updated."
    ```
    
    ![image.png](image%2012.png)
    
    I tried this but it seems it is always gonna return an error as filename is parsed as an argument to `diff`:
    
    ```bash
    sudo -u m.sander /usr/bin/sync.sh 'local.txt; id'
    ```
    
- **Sensitive file copy**
    
    I suppose we should find a sensitive file readable by `m.sander`;
    
    Listing db files I see and interesting one:
    
    ```bash
    find / -name "*.db" -exec ls -l {} + 2>/dev/null
    ```
    
    ![image.png](image%2013.png)
    
    `mlocate.db`
    
    - It's a **custom binary index format** specifically designed for fast filename lookups.
    - It uses compression and a special structure optimized for quick searching, not an SQL-based format.
    - The file is usually located at `/var/lib/mlocate/mlocate.db`.
    - You should always use the **`locate` command**, which knows how to read and query that database.
    - If you want to peek inside, you can try:
        
        ```bash
        strings /var/lib/mlocate/mlocate.db | less
        ```
        
        but this just dumps all readable strings, not a structured view.
        
    
    Searching for `personal` inside I found the following:
    
    ![image.png](image%2014.png)
    
    Let’s check personal.txt as  I should include `/home/m.sander` part and it won’t allow me this way I am gonna use symlink to read the file.
    
    ```bash
    ln --symbolic /path/to/file_or_directory path/to/symlink
    ```
    
    ```bash
    ln -s /home/m.sander/personal/personal.txt link
    ```
    
    It returned:
    
    ![image.png](image%2015.png)
    
    Let’s now check for file `/home/m.sander/personal/creds-for-2022.txt`:
    
    ```bash
    ln -s /home/m.sander/personal/creds-for-2022.txt link1
    ```
    
    Now it returned this:
    
    ![image.png](image%2016.png)
    
    Checking all I found password for shell is: `EzPwz2022_12345678#!`.
    

## Shell as m.sander

We are inside of `sudo` group that means we can run anything as root, so let’s just change the user:

```bash
sudo su
```

![image.png](image%2017.png)

Now we are root!

## Credentials

```powershell
t.miller : EzPwz2022_dev1$$23!!

m.sander : EzPwz2022_12345678#!
```

## Beyond Root

- P**ATH Hijacking**
    
    `cp` command is used without its absolute path inside `/usr/bin/sync.sh`:
    
    ```bash
    #! /bin/bash                                                                                                        
                                                                                                                        
    if [ -z $1 ]; then                                                                                                  
        echo "error: note missing"                                                                                      
        exit                                                                                                            
    fi                                                                                                                  
                                                                                                                        
    note=$1                                                                                                             
                                                                                                                        
    if [[ "$note" =~ .*m.sander.* ]]; then                                                                              
        echo "error: forbidden"                                                                                         
        exit                                                                                                            
    fi
    
    difference=$(diff /home/m.sander/personal/notes.txt $note)
    
    if [[ -z $difference ]]; then
        echo "no update"
        exit
    fi
    
    echo "Difference: $difference"
    
    cp $note /home/m.sander/personal/notes.txt
    
    echo "[+] Updated."
    
    ```
    
    That means we can potentially change `PATH` and make the script use our malicious binary, BUT here we are running the command with `sudo` that means this attack will only work if `secure_path` is not enfored by `/etc/sudoers` file. When you use `sudo`, the system can **override your PATH** and force a safer, fixed PATH defined by `secure_path`.
    Checking `/etc/sudoers` file we can see that secure path is enforced:
    
    ![image.png](image%2018.png)
    

## Mitigation

- Keep LimeSurvey updated and avoid exposing outdated versions.
- Never store plaintext credentials in config files.
- Apply strict file permissions to limit cross-user access.
- Avoid using `mlocate` or ensure its database is permission-restricted.
- Enforce least-privilege principle for `sudo` access.
