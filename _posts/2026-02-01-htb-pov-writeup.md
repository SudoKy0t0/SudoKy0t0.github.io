---
layout: posts
title: "HTB — Pov Writeup"
date: 2026-01-23
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

The initial scan shows only one port open, udp scan didn't show anything interesting.

### Port 80

<p align="center">
  <a href="/assets/images/pov/Captura.PNG" class="glightbox">
    <img src="/assets/images/pov/Captura.PNG" width="700">
  </a>
</p>
