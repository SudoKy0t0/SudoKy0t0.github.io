---
layout: posts
title: "HTB — Facts Writeup"
date: 2026-02-02
tags: [htb, writeup, linux, web]
categories: [ctf]
---

## Overview

- **Machine:** Facts
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

Facts is a beginner-friendly machine that emphasizes the importance of thorough enumeration. The attack path is short and straightforward, with simple, well-defined steps. It serves as an excellent introduction for newcomers learning how to identify and chain basic findings effectively.

As this machine is currently active, a full write-up cannot be provided. The complete write-up will be published once the machine has been retired, however, if you wish to discuss it, feel free to contact!

<p align="center">
  <a href="/assets/images/facts/Captura1.PNG.jpg" class="glightbox">
    <img src="/assets/images/facts/Captura1.PNG.jpg" width="700">
  </a>
</p>

---

## Initial Enumeration

### Nmap scan

```bash
┌──(kali㉿kali)-[~/hackthebox/facts]
└─$ sudo nmap -p- -sVC 10.129.67.248
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-03 06:40 EST
Nmap scan report for 10.129.67.248
Host is up (0.031s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  http    Golang net/http server
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://10.129.67.248:9001
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 303
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 1890B9BCD650F23B
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 03 Feb 2026 11:41:14 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>1890B9BCD650F23B</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 1890B9B93D75AC68
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 03 Feb 2026 11:40:58 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>1890B9B93D75AC68</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Tue, 03 Feb 2026 11:40:58 GMT
|_    Content-Length: 0
```
