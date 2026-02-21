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

Perfect, now we just have to log out and in again. Once again, we will be using the shortcut for this. With the windows key + x, we can open the "Quick Link Manu"

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
  <a href="/assets/images/VulnEscape/Captura16.png" class="glightbox">
    <img src="/assets/images/VulnEscape/Captura16.png" width="700">
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

Upon research, I discovered that the Kiosk User can be set up as "Assigned Access (Single-App Mode)" or "Multi-App".

> *Assigned Access (Single-App Mode): This is the most restrictive method, ideal for public-facing devices. It runs a single Universal Windows Platform (UWP) app or Microsoft Edge in full-screen, rendering the Windows shell, taskbar, and desktop completely inaccessible.*

> *Multi-App Kiosk Mode: This mode allows administrators to define a whitelist of specific applications, such as a browser, a specific document viewer, and a calculator, while blocking all others.*

Because we can access the system settings and the control panel, as well as Microsoft Edge, it's safe to assume this is a Multi-App mode. Reading it's definition tells us that it works based on a whitelist of permitted applications.

Knowing this, I'll be bypassing a whitelist. My first attempt will be to rename de executable to something that is inside the whitelist, for example msedge.exe, the executable of Micrososft Edge.

We'll right click and choose "Save link as" on our previously downloaded cmd.exe.

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
