---
layout: posts
title: "HTB — Pov Writeup"
date: 2026-02-01
tags: [htb, writeup, windows, web]
categories: [ctf]
---

## Overview

- **Machine:** Pov
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Medium

Pov is a medium-difficulty machine that serves as an excellent introduction to deserialization vulnerabilities. The initial foothold is straightforward, while still teaching us an interesting and important concept that's been going around for years. From a privilege-escalation perspective, it reinforces why keeping credentials secure is critical.

---

## Initial Enumeration

### Nmap scan

```bash
┌──(kali㉿kali)-[~/hackthebox/pov]
└─$ sudo nmap -p- -sVC 10.129.41.38

Nmap scan report for 10.129.41.38
Host is up (0.030s latency).
Not shown: 65534 filtered tcp ports (no-response)

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

The initial scan shows only one port open and I ran an udp scan after seeing only one port open. It didn't show anything interesting.

### Port 80

<p align="center">
  <a href="/assets/images/pov/Captura.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura.PNG" width="700">
  </a>
</p>

The website is running on Microsoft IIS 10.0, as shown by the Nmap scan. Clicking around the page doesn’t really lead anywhere, since all the buttons seem to be non-functional. There’s also a contact form at the bottom, but it doesn’t appear to do anything either, submitting it doesn’t even trigger a request. I'll run a dirbuster scan in the meanwhile.

<p align="center">
  <a href="/assets/images/pov/Captura2.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura2.PNG" width="700">
  </a>
</p>

Dirbuster doesn’t show anything out of the ordinary, just the standard directories used by the site.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov]
└─$ dirb http://10.129.41.38

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb  3 13:14:04 2026
URL_BASE: http://10.129.41.38/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.129.41.38/ ----
==> DIRECTORY: http://10.129.41.38/css/                                                                                                                                                                                                    
==> DIRECTORY: http://10.129.41.38/img/                                                                                                                                                                                                    
+ http://10.129.41.38/index.html (CODE:200|SIZE:12330)                                                                                                                                                                                     
==> DIRECTORY: http://10.129.41.38/js/                                                                                                                                                                                                     
                                                                                                                                                                                                                                           
---- Entering directory: http://10.129.41.38/css/ ----
                                                                                                                                                                                                                                           
---- Entering directory: http://10.129.41.38/img/ ----
                                                                                                                                                                                                                                           
---- Entering directory: http://10.129.41.38/js/ ----
                                                                                                                                                                                                                                           
-----------------
END_TIME: Tue Feb  3 13:27:18 2026
DOWNLOADED: 18448 - FOUND: 1
```

Something that did caught my attention was the email provided in the contact us section, `sfitz@pov.htv`. Whenever I see a non-standard email domain, it usually hints at an additional virtual host or application logic tied to that hostname. I'll add the domain to my /etc/hosts, and take note of the username.

<p align="center">
  <a href="/assets/images/pov/Captura3.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura3.PNG" width="700">
  </a>
</p>

Now that we have a domain, we can start fuzzing for additional virtual hosts. I'll use ffuf for this task, as it is quicker to fine-tune and to scan.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov]
└─$ ffuf -u http://pov.htb -H "Host: FUZZ.pov.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 12330

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pov.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.pov.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 12330
________________________________________________

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 31ms]
```

After a couple of seconds, something pops up. I'll add this to my /etc/hosts and start exploring it.

### dev.pov.htb

<p align="center">
  <a href="/assets/images/pov/Captura4.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura4.PNG" width="700">
  </a>
</p>

It seems like the portfolio for our previously anotated user `sfitz`. This time, we do have a button with functionality: `Download CV` will download a PDF containing the resume of sftiz. In this case, I’ll run a feroxbuster scan, since this virtual host seems more promising. As the server is running Microsoft IIS, I’ll include the .aspx extension.

<p align="center">
  <a href="/assets/images/pov/Captura5.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura5.PNG" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/pov/Captura6.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura6.PNG" width="700">
  </a>
</p>

Feroxbuster shows two interesting .aspx pages, `"default"` and `"contact"`.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov]
└─$ feroxbuster -u http://dev.pov.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -q -C 404 -r -x aspx

404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      423l     1217w    21371c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      106l      271w     4691c http://dev.pov.htb/portfolio/Contact.aspx
200      GET       32l       73w      782c http://dev.pov.htb/portfolio/assets/js/steller.js
200      GET     1081l     1807w    16450c http://dev.pov.htb/portfolio/assets/vendors/themify-icons/css/themify-icons.css
200      GET    11646l    23442w   242029c http://dev.pov.htb/portfolio/assets/css/steller.css
200      GET     7013l    22369w   222911c http://dev.pov.htb/portfolio/assets/vendors/bootstrap/bootstrap.bundle.js
200      GET    10598l    42768w   280364c http://dev.pov.htb/portfolio/assets/vendors/jquery/jquery-3.4.1.js
200      GET        0l        0w    21371c http://dev.pov.htb/portfolio/default.aspx
200      GET      106l      271w     4691c http://dev.pov.htb/portfolio/contact.aspx
Scanning: http://dev.pov.htb/
Scanning: http://dev.pov.htb/portfolio/
```

Also, a very interessting thing to note comes when checking the source code for the page.

<p align="center">
  <a href="/assets/images/pov/Captura6.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura6.PNG" width="700">
  </a>
</p>

The `Download CV` link is calling JavaScript `__doPostBack('download', '')`, and the most interesting, the headers `"__VIEWSTATEGENERATOR"` and `"__EVENTVALIDATION"` invoked when using the download function. A quick search in google reveals that this headers are part of the ASP.NET WebForms, meaning this site is running ASP.NET WebForms. I had a bit of trouble trying to discover traffic with BurpSuite when downloading the CV, it won't show any POST request, so, from now on, I'll use solely the intercept function.

<p align="center">
  <a href="/assets/images/pov/Captura7.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura7.PNG" width="700">
  </a>
</p>

## Initial foothold


