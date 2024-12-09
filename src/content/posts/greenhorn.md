---
title: greenhorn
published: 2024-10-09
description: "this the greenhorn HTB machine's writeup"
tags: [HTB, Machines]
category: 'Machines'
image: ../../assets/greenhorn/greenhorn.jpg
draft: false 
lang: 'en'
---

# Introduction

So this is a writeup of an easy machine i did in HackTheBox 

## Enumeration

### nmap scan

As always we start our scanning with an nmap :
```shell
sudo nmap -sC -sV  -oA GreenHorn 10.10.11.25
```

the result of the scan is this :
```
# Nmap 7.92 scan initiated Thu Jul 25 15:20:15 2024 as: nmap -sC -sV -oA GreenHorn 10.10.11.25
Nmap scan report for 10.10.11.25
Host is up (0.43s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)

```
we see port 22 and 80 open, so lets visit the website at port 80
![](src/assets/greenhorn/GreenHorn_image_1.png)


but we are getting this error when visiting the website at address 10.10.11.25 so lets add the hostname `greenhorn.htb` to `/etc/passwd`
![](src/assets/greenhorn/GreenHorn_image_2.png)

## Exploitation

visiting the `greenhorn.htb` site now we will see this page
![](src/assets/greenhorn/GreenHorn_image_3.png)

clicking at the admin href at the bottom of the page will redirect us to the `/login.php` page where we can see that the website is using pluck version 4.7.18
![](src/assets/greenhorn/GreenHorn_image_4.png)

and with a quick google search we can find a public PoC : 

::github{repo="Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC"}

after following the steps in the github repository we get a shell

![](src/assets/greenhorn/GreenHorn_image_5.png)

but we are `www-data` user so we will need to escalate our privileges 


## First Privileges escalation
first lets get a more stable shell by executing the following commands
`script /dev/null -qc /bin/bash`
then `(ctr+Z)` and then `stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;`

reading the `login.php` we see that the application takes a hashed password in `data/settings/pass.php` and compared against the hashed user input password and if it matches then gives access. the hashed password in `data/settings/pass.php` is `d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163` stored in variable `$ww`. running crackstation on this gives us tha password `iloveyou1`

![](src/assets/greenhorn/GreenHorn_image_6.png)

so what can we do with this password ?

listing the `/home` folder we find two folders `git` and `junior` so probably `junior` is our target user, so lets try to log in as `junior` with the found password
![](src/assets/greenhorn/GreenHorn_image_7.png)

Indeed now we are the `junior` user and we can get the `user.txt` flag

## Second Privilege escalation (root)

first, lets stabilize our shell more by using ssh
- *In Attacker Box*: run `ssh-keygen` and copy the public key `.pub`
- *in the target box*: 
	- `mkdir .ssh`
	- `echo <coppied public key> > .ssh/authorized_keys`
	- `chmod 600 .ssh/authorized_keys`
	- `chmod 7000 .ssh`
- *in the Attacker Box*: run `ssh -i key junior@greenhorn.htb`

in the `junior` home directory there is .pdf file named `Using OpenVAS.pdf` downloading it using `scp` (ssh cp) : `scp -i key junior@greenhorn.htb:"/home/junior/Using OpenVAS.pdf" .`

![](src/assets/greenhorn/GreenHorn_image_8.png)

we see there is a blured image containing the root password, so i right-clicked on it and saved it and used a tool called `Depix` to unblur it : 

::github{repo="spipm/Depix"}

```bash
python3 depix.py \                                                  
    -p ../image4.png \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
```

the output is saved in output.png
![](src/assets/greenhorn/GreenHorn_image_9.png)

`side from side The other side side from side The other side`

trying this as root password did not work, so i removed the spaces `sidefromsidetheothersidesidefromsidetheotherside`

AND booom we got root

![](src/assets/greenhorn/GreenHorn_image_10.png)

now we can get the `root.txt` flag

