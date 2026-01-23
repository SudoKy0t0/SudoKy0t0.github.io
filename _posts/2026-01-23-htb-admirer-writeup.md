---
layout: default
title: "HTB — Admirer Writeup"
date: 2026-01-23
tags: [htb, writeup, linux, web]
categories: [ctf]
---

## Overview

- **Machine:** Admirer
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

Admirer is an easy machine on HackTheBox that shows the importance of basic directory fuzzing and file enumeration, as well as core understanding of the configuration in sudo and the interaction between Linux and Python.

---

## Enumeration

### Nmap Scan

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer/utility-scripts]
└─$ sudo nmap -p- -sVC 10.129.4.46

Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-20 12:29 EST
Nmap scan report for admirer.htb (10.129.4.46)
Host is up (0.033s latency).
Not shown: 65532 closed tcp ports (reset)

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|   256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/admin-dir
| http-server-header: Apache/2.4.25 (Debian)
| http-title: Admirer
Service Info: OS: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 29.14 seconds
```


Nmap reveals a few interesting ports, starting with port 21, FTP, where anonymous access is not allowed, so that is as far as we can go there.
Next stop, port 80. Clicking around doesn’t reveal anything interesting and the contact form seems to not be implemented yet. Running feroxbuster in the background while I play around with the page.

<p align="center">
  <img src="/assets/images/admirer/Captura2.PNG" width="700">
</p>

Nmap showed us that there’s a robots.txt. Taking a look at it reveals an interesting directory, `/admin-dir`, however it returns a 403 — forbidden.

<p align="center">
  <img src="/assets/images/admirer/Captura5.PNG" width="700">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura3.PNG" width="700">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura4.PNG" width="700">
</p>

Beyond that, it displays some interesting information:  
> “This folder contains personal contacts and creds”.

I waited around 10 minutes for my initial feroxbuster scan to finish, but nothing interesting popped up:


```bash
┌──(kali㉿kali)-[~/hackthebox/admirer/utility-scripts]
└─$ feroxbuster \
    -u http://admirer.htb \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php -q

301      GET      91l     28w      311c http://admirer.htb/images        -> /images/
301      GET      91l     28w      314c http://admirer.htb/admin-dir     -> /admin-dir/
301      GET      91l     28w      318c http://admirer.htb/assets        -> /assets/

200      GET    1531l    529w    6051c http://admirer.htb/index.php
200      GET      21l     87w    2439c http://admirer.htb/assets/js/jquery.min.js
200      GET    2050l   4273w   44147c http://admirer.htb/assets/css/main.css

200      GET    2811l   1437w   99825c http://admirer.htb/images/thumbs/thmb_mus01.jpg
200      GET    4091l   2427w  158968c http://admirer.htb/images/fulls/mind02.jpg
```

My instant thought after reading the comment in `robots.txt` was scanning the `admin-dir` directly, with new extensions like `.txt` or `.pdf` that could contain the mentioned “contacts” and “creds”.

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ feroxbuster \
    -u http://admirer.htb/admin-dir \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x txt,pdf

──────────────────────────────────────────────────────────────
Target URL            : http://admirer.htb/admin-dir
Threads               : 50
Wordlist              : directory-list-2.3-medium.txt
Status Codes          : All
Timeout               : 7s
User-Agent            : feroxbuster/2.11.0
Extensions            : txt, pdf
HTTP Methods          : GET
Recursion Depth       : 4
──────────────────────────────────────────────────────────────

301      GET      91l     28w      314c http://admirer.htb/admin-dir/ -> /admin-dir/
200      GET      29l     39w      350c http://admirer.htb/admin-dir/contacts.txt
200      GET      11l     13w      136c http://admirer.htb/admin-dir/credentials.txt
```

**Credentials.txt**

<p align="center">
  <img src="/assets/images/admirer/Captura7.PNG" width="700">
</p>

**Contacts.txt**

<p align="center">
  <img src="/assets/images/admirer/Captura8.PNG" width="700">
</p>

The most interesting information here is the FTP user. As we saw earlier, there is an FTP server that doesn’t allow anonymous access. With our newly obtained credentials, we can now log in:

<p align="center">
  <img src="/assets/images/admirer/Captura9.PNG" width="700">
</p>

These two files both look interesting, so I transferred them to my machine for further analysis:

<p align="center">
  <img src="/assets/images/admirer/Captura10.PNG" width="700">
</p>

I had high expectations for `dump.sql`, but it doesn’t reveal anything interesting. As stated, it’s just a backup for a database named `admirerdb` that contains only one table with the contents of the main page.

<p align="center">
  <img src="/assets/images/admirer/Captura11.PNG" width="700">
</p>



```bash
┌──(kali㉿kali)-[~/hackthebox/admirer/utility-scripts]
└─$ cat dump.sql
```
```sql
-- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: admirerdb
-- ------------------------------------------------------
-- Server version       10.1.41-MariaDB-0+deb9u1

DROP TABLE IF EXISTS `items`;
CREATE TABLE `items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thumb_path` text NOT NULL,
  `image_path` text NOT NULL,
  `title` text NOT NULL,
  `text` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;

INSERT INTO `items` VALUES
(1,'images/thumbs/thmb_art01.jpg','images/fulls/art01.jpg','Visual Art','A pure showcase of skill and emotion.'),
(2,'images/thumbs/thmb_eng02.jpg','images/fulls/eng02.jpg','The Beauty and the Beast','Besides the technology, there is also the eye candy...'),
(3,'images/thumbs/thmb_nat01.jpg','images/fulls/nat01.jpg','The uncontrollable lightshow','When the sun decides to play at night.'),
(4,'images/thumbs/thmb_arch02.jpg','images/fulls/arch02.jpg','Nearly Monochromatic','One could simply spend hours looking at this indoor square.'),
(5,'images/thumbs/thmb_mind01.jpg','images/fulls/mind01.jpg','Way ahead of his time','You probably still use some of his inventions... 500yrs later.'),
(6,'images/thumbs/thmb_mus02.jpg','images/fulls/mus02.jpg','The outcomes of complexity','Seriously, listen to Dust in Interstellar''s OST. Thank me later.'),
(7,'images/thumbs/thmb_arch01.jpg','images/fulls/arch01.jpg','Back to basics','And centuries later, we want to go back and live in nature... Sort of.'),
(8,'images/thumbs/thmb_mind02.jpg','images/fulls/mind02.jpg','We need him back','He might have been a loner who allegedly slept with a pigeon, but that brain...'),
(9,'images/thumbs/thmb_eng01.jpg','images/fulls/eng01.jpg','In the name of Science','Some theories need to be proven.'),
(10,'images/thumbs/thmb_mus01.jpg','images/fulls/mus01.jpg','Equal Temperament','Because without him, music would not exist (as we know it today).');
```


We also obtained an `html.tar.gz`. Extracting its contents reveals a backup of the website:

<p align="center">
  <img src="/assets/images/admirer/Captura13.PNG" width="700">
</p>

The most interesting files here are our already reviewed `contacts.txt` and `credentials.txt`.  
The `index.php` file also contains some credentials, but they don’t seem to work anywhere.

More importantly, a new directory is revealed: `/utility-scripts`.  
Accessing it through Firefox also returns a forbidden response:

<p align="center">
  <img src="/assets/images/admirer/Captura14.PNG" width="700">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura15.PNG" width="700">
</p>

Nonetheless, we now know that the directory contains four PHP scripts:
- `admin_tasks.php`
- `db_admin.php`
- `info.php`
- `phptest.php`

Out of these, the most interesting ones are `admin_tasks.php` and `db_admin.php`.

```php
<?php
$servername = "localhost";
$username   = "waldo";
$password   = "Wh3r3_1s_w4ld0?";

// Create connection
$conn = new mysqli($servername, $username, $password);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "Connected successfully";

// TODO: Finish implementing this or find a better open source alternative
?>
```


Why is this interesting? I tried the given credentials via SSH and FTP but had no success.  
Despite looking plain at first, accessing it returns a 404. Looking at the comment at the bottom, it seems they already found a “better open source alternative”:

<p align="center">
  <img src="/assets/images/admirer/Captura17.PNG" width="700">
</p>

Why is `admin_tasks.php` interesting?  
Beyond being the longest of the four scripts, this one actually has functionality — it executes system commands.

```php
<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>

<h3>Admin Tasks Web Interface (v0.01 beta)</h3>

<?php
// Web interface to the admin_tasks script

if (isset($_REQUEST['task'])) {

    $task = $_REQUEST['task'];

    if ($task == '1' || $task == '2' || $task == '3' ||
        $task == '4' || $task == '5' || $task == '6' || $task == '7') {

        /*
        **********************************************************************
        Available options:
          1) View system uptime
          2) View logged in users
          3) View crontab (current user only)
          4) Backup passwd file (not working)
          5) Backup shadow file (not working)
          6) Backup web data (not working)
          7) Backup database (not working)

        NOTE: Options 4-7 are currently NOT working because they need root
              privileges. I'm leaving them in the valid tasks in case I figure
              out a way to securely run code as root from PHP.
        **********************************************************************
        */

        echo str_replace(
            "\n",
            "<br />",
            shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1")
        );

    } else {
        echo("Invalid task.");
    }
}
?>

<p>
<h4>Select task:</h4>
<form method="POST">
  <select name="task">
    <option value="1">View system uptime</option>
    <option value="2">View logged in users</option>
    <option value="3">View crontab</option>
    <option value="4" disabled>Backup passwd file</option>
    <option value="5" disabled>Backup shadow file</option>
    <option value="6" disabled>Backup web data</option>
    <option value="7" disabled>Backup database</option>
  </select>
  <input type="submit" value="Submit">
</form>

</body>
</html>
```

<p align="center">
  <img src="/assets/images/admirer/Captura19.PNG" width="700">
</p>

After reviewing `admin_tasks.php`, I initially thought about some form of RCE, but reading through the code didn’t help much. The script is protected against common attack paths.

While experimenting with this, I also ran another scan against `/utility-scripts`, this time focusing specifically on PHP files, to check if there were any scripts missing from our backup.

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ feroxbuster \
    -u http://admirer.htb/utility-scripts \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php

──────────────────────────────────────────────────────────────
Target URL            : http://admirer.htb/utility-scripts
Threads               : 50
Wordlist              : directory-list-2.3-medium.txt
Status Codes          : All
Timeout               : 7s
User-Agent            : feroxbuster/2.11.0
Extensions            : php
HTTP Methods          : GET
Recursion Depth       : 4
──────────────────────────────────────────────────────────────

403      GET      91l     28w      320c http://admirer.htb/utility-scripts/
403      GET      91l     28w      314c http://admirer.htb/admin-dir/
200      GET    9621l   4963w   83740c http://admirer.htb/utility-scripts/info.php
200      GET      11l      8w       32c http://admirer.htb/utility-scripts/phptest.php
```



At this point I wasn’t satisfied, so I tried another wordlist (I actually tested four in total, and this one finally paid off):

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ feroxbuster \
    -u http://admirer.htb/utility-scripts \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
    -x php -q

403      GET      91l     31w      276c http://admirer.htb/utility-scripts/
403      GET      91l     28w      320c http://admirer.htb/admin-dir/
200      GET    9621l   4963w   83740c http://admirer.htb/utility-scripts/info.php
200      GET     961l    493w    83740c http://admirer.htb/utility-scripts/adminer.php   <-- interesting
200      GET      11l      8w       32c http://admirer.htb/utility-scripts/phptest.php
```



**Adminer.php**

<p align="center">
  <img src="/assets/images/admirer/Captura22.PNG" width="700">
</p>

Adminer is a lightweight, single-file PHP script that serves as a powerful web-based tool for managing multiple types of databases, acting as a simpler alternative to tools like phpMyAdmin, supporting systems like MySQL, PostgreSQL, SQLite, MS SQL, MongoDB, and more, allowing for database creation, table management, data editing, SQL execution, and user administration via a web browser. I tried every credential gathered till now:

<p align="center">
  <img src="/assets/images/admirer/Captura23.PNG" width="700">
</p>

However, when I replace “localhost” with my local IP, I do receive a call

<p align="center">
  <img src="/assets/images/admirer/Captura24.PNG" width="700">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura25.PNG" width="700">
</p>



MySQL configuration:

To make this connection work the first we have to do is initiate a functional sql server. This is fairly easy in kali:

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ sudo service mysql start  

──(kali㉿kali)-[~/hackthebox/admirer]
└─$ sudo mysql -u root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 11.4.5-MariaDB-1 Debian n/a

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> create database admirertest;
Query OK, 1 row affected (0.000 sec)

MariaDB [(none)]> create user 'admirertest'@'10.129.229.101' identified by 'passwordtest';
Query OK, 0 rows affected (0.004 sec)

MariaDB [(none)]> GRANT ALL on admirertest.* TO 'admirertest'@'10.129.229.101';
Query OK, 0 rows affected (0.002 sec)

MariaDB [(none)]> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.000 sec)
```


After this, we get a permission denied from the adminer page. This is because mysql doesn’t listen on a routable interface, meaning, it will only accept connections locally. How do we fix this? Simple enough, we just need to change a configuration file (I followed this post). It’s important to note that this change must be reverted after finishing the machine, as it can be a security issue for us. Configuration files are usually in the directory /etc, and we can find /mysql inside:


