---
layout: posts
title: "HTB — Overwatch Writeup"
date: 2026-02-13
tags: [htb, writeup, windows, web]
categories: [ctf]
---

## Overview

- **Machine:** Overwatch
- **Platform:** Hack The Box
- **OS:** Windows
- **Difficulty:** Medium

Overwatch is a very smooth medium machine, one of my favourites so far. Anonymous SMB access exposes a .NET application requiring light reverse engineering. SQL misconfigurations influence the early attack path, leading to the eventual exploitation of a SOAP-based WCF service.

The full writeup will be published once the machine is retired, in the meanwhile, feel free to contact!

<p align="center">
  <a href="/assets/images/overwatch/captura1.png" class="glightbox">
    <img src="/assets/images/overwatch/captura1.png" width="700">
  </a>
</p>

---
