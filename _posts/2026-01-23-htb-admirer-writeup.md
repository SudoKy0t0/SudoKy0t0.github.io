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

<p align="center">
  <img src="/assets/images/admirer/Captura.PNG" width="600">
</p>

Nmap reveals a few interesting ports, starting with port 21, FTP, where anonymous access is not allowed, so that is as far as we can go there.
Next stop, port 80. Clicking around doesn’t reveal anything interesting and the contact form seems to not be implemented yet. Running feroxbuster in the background while I play around with the page.

<p align="center">
  <img src="/assets/images/admirer/Captura2.PNG" width="600">
</p>

Nmap showed us that there’s a robots.txt. Taking a look at it reveals an interesting directory, `/admin-dir`, however it returns a 403 — forbidden.

<p align="center">
  <img src="/assets/images/admirer/Captura3.PNG" width="600">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura4.PNG" width="600">
</p>

Beyond that, it displays some interesting information:  
> “This folder contains personal contacts and creds”.

I waited around 10 minutes for my initial feroxbuster scan to finish, but nothing interesting popped up:

<p align="center">
  <img src="/assets/images/admirer/Captura5.PNG" width="600">
</p>

My instant thought after reading the comment in `robots.txt` was scanning the `admin-dir` directly, with new extensions like `.txt` or `.pdf` that could contain the mentioned “contacts” and “creds”.

<p align="center">
  <img src="/assets/images/admirer/Captura6.PNG" width="600">
</p>

**Credentials.txt**

<p align="center">
  <img src="/assets/images/admirer/Captura7.PNG" width="600">
</p>

**Contacts.txt**

<p align="center">
  <img src="/assets/images/admirer/Captura8.PNG" width="600">
</p>

The most interesting information here is the FTP user. As we saw earlier, there is an FTP server that doesn’t allow anonymous access. With our newly obtained credentials, we can now log in:

<p align="center">
  <img src="/assets/images/admirer/Captura9.PNG" width="600">
</p>

These two files both look interesting, so I transferred them to my machine for further analysis:

<p align="center">
  <img src="/assets/images/admirer/Captura10.PNG" width="600">
</p>

I had high expectations for `dump.sql`, but it doesn’t reveal anything interesting. As stated, it’s just a backup for a database named `admirerdb` that contains only one table with the contents of the main page.

<p align="center">
  <img src="/assets/images/admirer/Captura11.PNG" width="600">
</p>

We also obtained an `html.tar.gz`. Extracting its contents reveals a backup of the website:

<p align="center">
  <img src="/assets/images/admirer/Captura12.PNG" width="600">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura13.PNG" width="600">
</p>

The most interesting files here are our already reviewed `contacts.txt` and `credentials.txt`.  
The `index.php` file also contains some credentials, but they don’t seem to work anywhere.

More importantly, a new directory is revealed: `/utility-scripts`.  
Accessing it through Firefox also returns a forbidden response:

<p align="center">
  <img src="/assets/images/admirer/Captura14.PNG" width="600">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura15.PNG" width="600">
</p>

Nonetheless, we now know that the directory contains four PHP scripts:
- `admin_tasks.php`
- `db_admin.php`
- `info.php`
- `phptest.php`

Out of these, the most interesting ones are `admin_tasks.php` and `db_admin.php`.

<p align="center">
  <img src="/assets/images/admirer/Captura16.PNG" width="600">
</p>

Why is this interesting? I tried the given credentials via SSH and FTP but had no success.  
Despite looking plain at first, accessing it returns a 404. Looking at the comment at the bottom, it seems they already found a “better open source alternative”:

<p align="center">
  <img src="/assets/images/admirer/Captura17.PNG" width="600">
</p>

Why is `admin_tasks.php` interesting?  
Beyond being the longest of the four scripts, this one actually has functionality — it executes system commands.

<p align="center">
  <img src="/assets/images/admirer/Captura18.PNG" width="600">
</p>

<p align="center">
  <img src="/assets/images/admirer/Captura19.PNG" width="600">
</p>

After reviewing `admin_tasks.php`, I initially thought about some form of RCE, but reading through the code didn’t help much. The script is protected against common attack paths.

While experimenting with this, I also ran another scan against `/utility-scripts`, this time focusing specifically on PHP files, to check if there were any scripts missing from our backup.

<p align="center">
  <img src="/assets/images/admirer/Captura20.PNG" width="600">
</p>

At this point I wasn’t satisfied, so I tried another wordlist (I actually tested four in total, and this one finally paid off):

<p align="center">
  <img src="/assets/images/admirer/Captura21.PNG" width="600">
</p>

**Adminer.php**

<p align="center">
  <img src="/assets/images/admirer/Captura22.PNG" width="600">
</p>
