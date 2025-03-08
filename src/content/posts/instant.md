---
title: instant
published: 2024-12-17
description: 'Instant HTB machine writeup'
image: '../../assets/instant/image.png'
tags: [HTB, AD, Machines]
category: 'HTB'
draft: false 
lang: ''
---


# Enumeration
as always we start with an nmap

```bash
nmap -sC -sV -Pn -oA Instant 10.10.11.37

Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)

```
after setting the domain name in the `/etc/hosts` we can visit the website `http://instant.htb`
![](src/assets/instant/Instant_image_1.png)

we download the APK and open it using jadx-ui to analyze it

# Analyzing the APK

we start with opening the `AndroidManifest.xml` file first
![](src/assets/instant/Instant_image_2.png)

we notice that the package name is `col.instantlabs.instant` if we go to the corresponding folder of that package we find some classes
![](src/assets/instant/Instant_image_3.png)

the most interesting one is the `AdminActivities` where we can see a JWT there that is used on the `mywallet1` subdomain

next, we do some search if there is any other subdomains, using the text search feature of jadx, make sure to select all the `search definition` so that jadx will search in resource files too
![](src/assets/instant/Instant_image_4.png)

we find 2 other subdomains, lets add them to our `/etc/hosts`, and navigate to them

# swagger-ui subdomain
visiting this subdomain we see it shows us a lot of api endpoints but first we need to authorize ourselves suing the JWT token we found earlier
![](src/assets/instant/Instant_image_5.png)

we see two interesting endpoints:
![](src/assets/instant/Instant_image_6.png)

the read endpoint might be vulnerable to LFI, lets call the view logs to see where logs are beeing read from 
```bash
{ "Files": [ "1.log" ], "Path": "/home/shirohige/logs/", "Status": 201 }
```

now lets try to exploit LFI in the read endpoint:

![](src/assets/instant/Instant_image_7.png)

it works so now lets try to read some sensitive data like ssh keys (`../.ssh/id_rsa`)

![](src/assets/instant/Instant_image_8.png)

we can use this to get a shell as the `shirohige` use and get the flag
```bash
ssh -i private_key shirohige@instant.htb
```

# Priv escalation

## part 1

in the `~/projects/mywallet/Instant-Api/mywallet/instance` we find an sqlite database if we read we find some hashed passwords of pkdf2 format one of them is for `shirohige`, to crack it with hashcat we need to rewrite the hashes to: `pbkdf2_sha256$600000$YnRgjnim$yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=`

```bash
hashcat -m 10000 shirohige_hash rockyou.txt
```
the password is `estrella`

trying  to use this to login to the shirohige account in the machine failed

## part 2

executing linpease.sh we find an interesting folder `/opt/backups/Solar-PuTTY` that have a `sessions-backup.dat` after googling a bit i found this repo to decrypt the `session` :
https://github.com/VoidSec/SolarPuttyDecrypt

but we first need a password so lets try the password we cracked earlier
```powershell
 .\SolarPuttyDecrypt.exe C:\Users\vboxuser\Downloads\sessions-backup.dat estrella
```

```powershell
...
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  ...
```

login as root and enter the flag
```bash
su
```

then read the root.txt


