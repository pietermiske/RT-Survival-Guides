# __Active Directory domain reconnaissance__
>Author: Pieter Miske
---
### __Domain mapping & enumeration:__
#### _General domain information gathering:_
- Quick dump of users, groups, computers, trusts and policy via LDAP \([LDAPDomaindump](https://github.com/dirkjanm/ldapdomaindump)\): `python ldapdomaindump.py <FQDN or IP DC> -u <domain>\\<username> -p <password> -o <dir to dump .htlm, .json, .grep files>`
- List DC’s, domain policy, domain/forest name \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): `Domaininfo`
- Check domain password policy \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)\): `Get-DomainPolicyData | select -ExpandProperty SystemAccess`
- Check if AD CS is enrolled:
	- Via IX509PolicyServerListManager COM object ([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): `adcs_enum_com2`
	- Via Win32 functions (CS-Situational-Awareness-BOF): `adcs_enum`
- List Organization Units \(OUs\) \([SharpView](https://github.com/tevora-threat/SharpView)\): `Get-DomainOU -Properties Name | sort -Property Name`

#### _Start Bloodhound GUI:_
- 1\. (optional) Configure neo4j database:
	- 1\. Start the neo4j console: `neo4j console`
	- 2\. Browse to [http://localhost:7474](http://localhost:7474) and login with username “neo4j” and password “neo4j”
	- 3\. Change your password and close the browser
- 2\. Make sure the neo4j console is running: `neo4j console`
- 3\. Start bloodhound GUI \([Bloodhound](https://github.com/BloodHoundAD/BloodHound)\): `./BloodHound --sandbox`
- 4\. Drag and drop bloodhound\.zip or all \.JSON files in the bloodhound interface \(check below for ingestors\)\.
- 5\. Add [custom queries](https://github.com/ShutdownRepo/Exegol/blob/master/sources/bloodhound/customqueries.json) to bloodhound GUI \(add the customqueries\.json file to the ‘~/\.config/bloodhound/’ folder\)\. 

#### _Collect Bloodhound data via ingestors:_
>Make sure that you use an up\-to\-date ingestor that is compatible with the BloodHound GUI you use. 
- C\# ingestor \([SharpHound\.exe](https://github.com/BloodHoundAD/SharpHound)\): `SharpHound.exe -c all -d <FQDN> --outputdirectory c:\users\public\documents\ --zipfilename <filename> (--encryptzip) (--stealth) (--ldapusername <username> --ldappassword <password> --domaincontroller <target DC IP>)`
- PowerShell ingestor \([SharpHound\.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)\): `Invoke-Bloodhound -CollectionMethod All -NoSaveCache -OutputDirectory c:\users\public\documents\ (-ZipFilename <filename>) (-EncryptZip) (-DisableKerberosSigning)`
- Python ingestor \([Bloodhound.py](https://github.com/fox-it/BloodHound.py)\):
	- 1\. \(optional\) If DNS is not configured, modify "/etc/resolv\.conf" so it is possible to query the target DC:
		- 1\. In "/etc/resolv\.conf" add the following variables \(under the original ones\):
            ```
            nameserver <ip target DC> 
            search <FQDM \(e\.g\. hidro\.local\)>
            ```
		- 2\. in "/etc/hosts" delete any lines pointing to the target DC ip
	- 2\. Gather data:
		- If DC is within reach: `bloodhound.py -u <user> -p '<pass>' -d <FQDN> -ns <target DC ip> -dc <FQDN target DC> -c all (-w1) (--dns-timeout 30)`
		- Via proxychains: `proxychains4 bloodhound.py -u <user> -p '<pass>' -d <FQDN> -ns <target DC ip> -c all --dns-tcp`
- Snapshot ingestor \([ADExplorerSnapshot](https://github.com/c3c/ADExplorerSnapshot.py)\):
	- 1\. Create snapshot of AD from attacker Windows system:
		- 1\. From the Sysinternals suite open ‘ADExplorer64\.exe’ and enter credentials to login to the target DC \(can be any valid user account\)
		- 2\. Create a snapshot of the AD: in the ADExplorer GUI, click on 'File' > 'Create Snapshot\.\.' 
	- 2\. Create Bloodhound compatible json files: Extract the data as \.json files from the \.dat snapshot file: `python3 ADExplorerSnapshot.py </path to .dit file>`


---
### __Identify domain computers & system and service information:__
#### _Identify host via passive network traffic analysis:_
- Listen for network traffic to identify IP ranges or specific systems:
	- WireShark
	- TCPdump:  `tcpdump -i <interface (e.g. eth0)> (-vvvASs) (| grep <search ip>)`
- Store incoming packets in file\.pcap: `tcpdump -i <interface (e.g. eth0)> (<port>) -w file.pcap `

#### _Identify computers via AD information:_
- Via Active Directory Integrated DNS \(ADIDNS\) \([Standin](https://github.com/FuzzySecurity/StandIn)\): `StandIn.exe --dns (--forest)`
- List all the domain controllers within the current domain \(Standin)\): `StandIn.exe --dc`
- List all computer accounts in the domain \([SharpView](https://github.com/tevora-threat/SharpView)\) | \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)\): `Get-DomainComputer (|Out-File -encoding ascii hosts.txt)`
- List all computer accounts (and sometimes service accounts) \([Windapsearch](https://github.com/ropnop/go-windapsearch/releases)\): `./windapsearch-linux-amd64 -d <target DC ip> (-u <usename>@<FQDN>) (-p "<password>") -m computers`
- List computers in specific OU \(SharpView\): `Get-DomainComputer -SearchBase "LDAP://OU=<OU name>,DC=domain,DC=com"`
- Gather remote system version info via API:\([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): `Smbinfo <ip>`

#### _Internal host discovery:_
>These are all very noisy.
- Host discovery via open port through proxychains \(change the specified port for something that most likely is open on Windows or Linux based systems\): `proxychains4 nmap -sTV -p <port> --open <target ip range>`
- Ping based host discovery in subnet \(optional to only output IP/FQDN of live hosts\): `nmap -sn 10.0.0.0/24 -n (|grep for |cut -d " " -f 5)`	
- Identify hosts within multiple subnet: `netdiscover -r <10.0.0.0/8 | 172.16.0.0/16 | 192.168.0.0/16>`

#### _Identify new hosts via SNMP MIB:_
The SNMP Management Information Base \(MIB\) is a database containing information usually related to network management\. If you can reach the interface \(udp 161\) and it is used by a firewall, it may be possible to dump local IP adresses and identify new hosts\. *
- 1\. Scan for the default community string \([onesextyone](https://github.com/trailofbits/onesixtyone)\): `onesixtyone -c /usr/share/Seclists/Discovery/SNMP/common-snmp-community-strings.txt <target ip or range>`
- 2\. Gather information from the MIB database \(MIB value for TCP local ports: ): 
	- Dump TCP data \(recommended\): `snmpwalk -c <community string> -v<version (e.g. 2c)> <target ip> 1.3.6.1.2.1.6.13.1.3`
	- Dump all data: `snmpwalk -c <community string> -v<version (e.g. 2c)> <target ip> | tee snmp-mib.txt`

#### _Internal service and version scanning:_
>Do not scan the whole subnets in a short amount of time as network monitoring can easely detect it\.  
- ([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): `probe <IP or FQDN target system> <single port>`
- Cobalt Strike: `portscan <target ip> <port,port> none 1024`
- PoshC2: `portscan "<target ip>" "<port>,<port>" 1 100`
- Stealthy nmap scan \(can take some serieus time if scanning all ports\):
	- 1\. Create list of IP targets \([Prips](https://github.com/honzahommer/prips.sh)\): `./prips.sh <start ip> <end ip> > hosts.txt`
	- 2\. Scan range \(make sure nmap supports the ‘\-\-win’ option or leave it out\): `Nmap --reason -Pn -n -T2 --scan-delay 12 (--win 1023) -sTV --version-intensity --max-retries 0 --randomize hosts <-p 22,445 | -p0-> -oA scan-results -v --open -iL hosts.txt (--script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36")`

#### _Search for internal web apps:_
Internal web apps (e.g. SharePoint, Confluence) are an incredible source of information (e.g. usernames and passwords) and can sometimes be leveraged to get a foothold on the web server due some RCE vulnerability. 
- 1\. Create a list of all IP addresses of live hosts in the network and save it as "urls\.txt"\. 
- 2\. Take screenshots of websites, provide some server header info and identify default credentials if known \([EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)\): `EyeWitness.exe -f C:\<path to>\urls.txt`



---
### __Identify domain users, groups and remote sessions:__
#### _Identify domain users & user account information:_
- List all user accounts in the domain 
	- \([SharpView](https://github.com/tevora-threat/SharpView)\) | \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)\): `Get-DomainUser (|Out-File -encoding ascii users.txt)`
	- \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): `domainenum`
- Dump all domain users and email addresses \([Windapsearch](https://github.com/ropnop/go-windapsearch/releases)\): `./windapsearch-linux-amd64 -d <target DC ip> (-u <usename>@<FQDN>) (-p "<password>") -m users (--full) (--attrs cn,displayName,userAccountControl,mail,memberOf,homeDirectory,description)`
- List users with high privileges \(if the ‘userAccountControl’ attribute has the value ‘512’ or ‘66048’ the account is enabled\) \(Windapsearch\): `./windapsearch-linux-amd64 -d <target DC ip> (-u <usename>@<FQDN>) (-p "<password>") -m privileged-users --attrs cn,displayName,userAccountControl,mail,memberOf,homeDirectory,description`
- Enumerate local system users \(only possible if you can read the IPC$ share\) \([impacket](https://github.com/SecureAuthCorp/impacket)\): `python3 lookupsid.py .\/<username>@<target ip>`
- Check accounts that do not have to follow the password policy rules and may have an empty or weak password set \(doesn’t have to be but could be\) \([Standin](https://github.com/FuzzySecurity/StandIn)\): `StandIn.exe --passnotreq` 
- List all accounts with mail box via Exchange Global Address List \(GAL\) \([MailSniper](https://github.com/dafthack/MailSniper)\): `Get-GlobalAddressList -ExchHostname <FQDN exchange server> -UserName <domain>\<username> -Password <password> -OutFile C:\users\public\documents\email-addresses.txt`
- Obtain specific user information via Exchange server:
    - 1\. Request the Exchange server for all available tables \(e\.g\. Users, Folders\) \([impacket](https://github.com/SecureAuthCorp/impacket)\): `python3 exchanger.py <domain>/<username(:<password>)@<FQDN exchange server> nspi list-tables (-hashes :<NTLM>)`
    - 2\. Dump the data from a specific table \(impacket\): `python3 exchanger.py <domain>/<username(:<password>)@<FQDN exchange server> nspi dump-tables -guid <the Guid string from the table listing> (-hashes :<NTLM>)`
    - 3 Retrieve specific user AD information based on dumped GUID \(impacket\): `python3 exchanger.py <domain>/<username(:<password>)@<FQDN exchange server> nspi guid-known -guid <target user Guid> -lookup-type FULL (-hashes :<NTLM>)`

#### _Identify domain groups and its members:_
- List all groups in the domain:
	- \([SharpView](https://github.com/tevora-threat/SharpView)\): `Get-DomainGroup`
	- \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): `netGroupList`
- List members of a specific domain group:
	- \([Standin](https://github.com/FuzzySecurity/StandIn)\): `Standin.exe --group "Domain Admins"`
	- \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): netGroupListMembers “<groupname>”
- Enumerate the computers in the domain where a specific domain user/group is a member of a specific local group through GPO correlation \(specify either user or group\) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)\): `Get-DomainGPOUserLocalGroupMapping (-Identity <username>) (-LocalGroup <local group name>) | select ObjectName, GPODisplayName, ContainerName, ComputerName`
- List all groups and list its members \([Windapsearch](https://github.com/ropnop/go-windapsearch/releases)\): `./windapsearch-linux-amd64 -d <target DC ip> (-u <usename>@<FQDN>) (-p "<password>") -m groups --attrs member`

#### _Gather remote session information:_
- Query all computers and check which user is logged in or specify a specific user \(SharpView\): `Find-DomainUserLocation (-UserIdentity "<username>")`
- Identify on which system\(s\) domain admins are currently logged in \(PowerView\): `Find-DomainUserLocation -UserGroupIdentity "Domain Admins"`
- Returns user session information of the current or remote machine \(where CName is the source IP\) \(SharpView\): `Get-NetSession -ComputerName <IP or FQDN target system>`
- Identify systems you have local admin access to \(SharpView\): `Find-LocalAdminAccess`


