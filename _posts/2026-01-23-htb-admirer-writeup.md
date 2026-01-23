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

Admirer is an easy machine on HackTheBox that shows the importance of basic directory fuzzing and file enumeration, as well as core understanding of the configuration in sudo and the interaction between linux and python.
---

## Enumeration

Nmap Scan:

<img src="/assets/images/admirer/Captura.PNG" width="550">

Nmap reveals a few interesting ports, starting with port 21, ftp, where anonymous access is not allowed, so that is as far as we can go there.
Next stop, port 80, clicking around doesn’t reveal anything interesting and the contact form seems to not be implemented yet. Running feroxbuster in the background while I play around with the page.

![Nmap scan results](/assets/images/admirer/Captura2.PNG)

Nmap showed us that there’s a robots.txt, take a look at it, reveals an interesting dir /admin-dir, however, returns a 403, it’s forbidden.

![Nmap scan results](/assets/images/admirer/Captura3.PNG)
![Nmap scan results](/assets/images/admirer/Captura4.PNG)

Beyond that, it displays some interesting information: “This folder contains personal contacts and creds”. I waited 10 minutes till my initial feroxbuster scan finished but nothing interesting popped:

![Nmap scan results](/assets/images/admirer/Captura5.PNG)

My instant thought after reading the comment in robots.txt was scanning the admin-dir directly, with new extensions like .txt or .pdf that can contain the before mentioned “contacts” and “creds”

![Nmap scan results](/assets/images/admirer/Captura6.PNG)
Credentials.txt
![Nmap scan results](/assets/images/admirer/Captura7.PNG)
Contacts.txt
![Nmap scan results](/assets/images/admirer/Captura8.PNG)

The most interesting here is the ftp user, because as we saw before, we have an ftp server that doesn’t allow anonymous access. With our newly obtained credentials, we can now login:

![Nmap scan results](/assets/images/admirer/Captura9.PNG)

These two files both look interesting, I will transfer them to my machine and take a closer look:

![Nmap scan results](/assets/images/admirer/Captura10.PNG)

I had high expectations on the dump.sql, but it doesn’t reveal anything interesting. As it is stated, it’s just a backup for a database named “admirerdb” that contains only one table with the contents of the main page.

![Nmap scan results](/assets/images/admirer/Captura11.PNG)

We also obtained a html.tar.gz, extracted it’s contents to reveal a backup of the site

![Nmap scan results](/assets/images/admirer/Captura12.PNG)
![Nmap scan results](/assets/images/admirer/Captura13.PNG)

The most interesting files would be our already read contacts.txt and credentials.txt, the index.php contains some credentials too (that don’t work anywhere) and of course a new directory is revealed to us “/utility-scripts”. Upon accessing to it through firefox, it’s also forbidden:

![Nmap scan results](/assets/images/admirer/Captura14.PNG)
![Nmap scan results](/assets/images/admirer/Captura15.PNG)

Nonetheless, we have some interesting information about it, with four php scripts inside of it:
admin_tasks is a php script that runs commands effectively, db_admin seems like a configuration file for the database, info.php is just phpinfo.php and phptest is a test script with nothing of value. Reviewing them, the ones that get my attention is admin_tasks.php and db_admin.php

![Nmap scan results](/assets/images/admirer/Captura16.PNG)

Why is this interesting? I tried the given credentials in ssh and ftp but got no success. Despite looking plain at first, when trying to access it, it returns a 404, and looking at the comment on the bottom, it looks like they already found a “better open source alternative”:

![Nmap scan results](/assets/images/admirer/Captura17.PNG)

Why’s admin_tasks interesting? Beyond being the longest of the four, this one actually has functionality, meaning it can effectively execute commands:

![Nmap scan results](/assets/images/admirer/Captura18.PNG)
![Nmap scan results](/assets/images/admirer/Captura19.PNG)

Upon reviewing admin_tasks, I thought about some sort of RCE but reading through it didn’t help. The script is secured against common attack paths that lead to RCE. While I spent some time trying to abuse this script, I also decided to run another scan against the directory /utility-scripts, this time with the php extension, to see if I could find another script that was not in our obtained backup.

![Nmap scan results](/assets/images/admirer/Captura20.PNG)

I’m definitely not satisfied with this, I will try another wordlist just in case (I actually tried 4 different wordlists, and this one beared fruits):

![Nmap scan results](/assets/images/admirer/Captura21.PNG)

Adminer.php

![Nmap scan results](/assets/images/admirer/Captura22.PNG)










