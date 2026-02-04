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

Feroxbuster shows two .aspx pages, `"default"` and `"contact"`.

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

<p align="center">
  <a href="/assets/images/pov/Captura9.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura9.PNG" width="700">
  </a>
</p>

default.aspx is just the main index page, and contact.aspx shows a contact form that I never really got to tinker with. Digging any deeper didn’t reveal anything new.

That said, inspecting the page’s source code revealed something much more interesting.

<p align="center">
  <a href="/assets/images/pov/Captura7.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura7.PNG" width="700">
  </a>
</p>

The Download CV link triggers the JavaScript function __doPostBack('download', ''). What really stands out here are the __VIEWSTATEGENERATOR and __EVENTVALIDATION fields involved in the request. A quick search shows that these are part of the ASP.NET WebForms framework, confirming that the application is running on WebForms.

While trying to capture the download with Burp Suite, no POST request was showing up, which made traffic analysis a bit tricky. Because of that, I decided to rely exclusively on Burp’s intercept mode moving forward.

### Initial foothold

Reviewing the traffic from BurpSuite, we can see the already mentioned ASP.NET WebForms headers.

<p align="center">
  <a href="/assets/images/pov/Captura8.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura8.PNG" width="700">
  </a>
</p>

To understand the plan ahead, I'll explain what is ASP.NET WebForms and how does it handle states, as well as what these headers mean and do.

ASP.NET Web Forms is an older ASP.NET framework that handles user interactions using server-side events rather than direct, clearly defined HTTP endpoints. It keeps track of page state through mechanisms such as ViewState and EventValidation, which are exchanged between the client and the server on each interaction.

As a visual learner myself, I find it easier to understand this behavior by looking at the flow rather than just reading about it. The chart below represents how information and state are passed back and forth between the client and the server in an ASP.NET Web Forms application.

<p align="center">
  <a href="/assets/images/pov/Captura10.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura10.PNG" width="700">
  </a>
</p>

From an attack point of view, anything the client can influence and that later gets processed by the server is always worth looking at. In this case, the state-related fields used by Web Forms stand out, since they play a direct role in how the server decides what logic to execute.

It’s also worth keeping in mind that actions in ASP.NET Web Forms don’t generate the kind of clean, obvious POST requests you might expect. Instead, everything is handled through generic postbacks to the same page, with the server figuring out what to do based on the submitted state data.

