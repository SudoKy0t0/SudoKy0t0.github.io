---
layout: default
title: "HTB — Admirer Writeup"
date: 2026-01-23
tags: [htb, writeup, linux, web]
categories: [ctf]
---

## Overview

- **Machine:** Admirer
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

Admirer is an easy machine on HackTheBox that shows the importance of basic directory fuzzing and file enumeration, as well as core understanding of the configuration in sudo and the interaction between linux and python.
---

## Enumeration

Nmap Scan:

![Nmap scan results][/assets/imgages/admirer/Captura.PNG]

Nmap reveals a few interesting ports, starting with port 21, ftp, where anonymous access is not allowed, so that is as far as we can go there.
Next stop, port 80, clicking around doesn’t reveal anything interesting and the contact form seems to not be implemented yet. Running feroxbuster in the background while I play around with the page
