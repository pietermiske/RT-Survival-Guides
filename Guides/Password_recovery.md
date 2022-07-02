# __Password recovery techniques:__
>Author: Pieter Miske
---
### __Password recovery preperations:__
##### _Password wordlists:_
- [PasswordList](https://github.com/Cyb3r4rch3r/PasswordList)
- [Crackstation](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm) 

##### _Create custom wordlist:_
- Targeted wordlist:
	- 1\. Make small password list of key words associated with the target organisation and common words\. 
	- 2\. Generate costum wordlist with variations based on the words: `hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule <name list with basic words> > output.txt`
- Keyboard walk wordlist generator (e.g. ‘qwerty’, ‘1q2w3e4r’ and ‘6yHnMjU7’): based on the target region, select the correct keyboard layout \([kwprocessor](https://github.com/hashcat/kwprocessor)\): `kwp64.exe basechars\full.base keymaps\en-us.keymap routes\2-to-10-max-3-direction-changes.route -o keywalk.txt`

##### _Create custom rule set:_
- 1\. Create empty file with the extention ‘\.rule’ 
- 2\. Add custom rules to the file and place them under each other:
	- Append character: $x \(e\.g\. $2$0$2$1\)
	- Capatilize the first letter and lower the rest: c
	- Uppercase all letters: u
	- Duplicate entire word \(Welkom01Welkom01\): d

##### _Create custom mask file:_
- 1\. Create empty file with the extention ‘\.hcmask’
- 2\. Add custom mask to file \(modify below example masks if needed\):
	- Add one number or special character to word with length 5 to 9:
        ```
        ?d?s, ?u?l?l?l?l?1
        ?d?s, ?u?l?l?l?l?l?1
        ?d?s, ?u?l?l?l?l?l?l?1
        ?d?s, ?u?l?l?l?l?l?l?l?1
        ?d?s, ?u?l?l?l?l?l?l?l?l?l?1
        ```
    - Start with specific word with additional numbers/special characters \(change word that fits target\):
        ```
        ?d?s, Password?1
        ?d?s, Password?1?1
        ?d?s, Password?1?1?1
        ?d?s, Password?1?1?1?1
        ```
	- All combinations for word length 7 to 9
        ```
        ?l?u?d?s, ?1?1?1?1?1?1?1
        ?l?u?d?s, ?1?1?1?1?1?1?1?1
        ?l?u?d?s, ?1?1?1?1?1?1?1?1?1
        ```

##### _Modify excisting wordlist:_
- Modify wordlist  to specific password length: `grep '\w\{7,20\}' </path/to/wordfile> > newfile.txt`
- Create wordlist with specific password length and characteristics: `grep '[a-zA-Z0-9]\{7\}' </path/to/wordfile>` 

##### _Prepare large hash file for cracking:_
- Create hash list from NTLM hash dump:
	- Filter usernames \(and domain name if available\) from impacket’s secretsdump: `cat hashdump.txt| cut -d ":" -f1 | grep '^[a-zA-Z]' | uniq | tee users.txt`
	- Filter NT hashes from impacket’s secretsdump: `cat hashdump.txt| cut -d ":" -f4 | uniq |tee nthashes.txt`
- Filter specific information from column based textfile \(alter $? to change column\): `cat <file> | awk ‘{print $2}’ | awk -F\@ ‘{print$1}’`
- Change all uppercase to lowercase: `cat <file> | tr '[:upper:]' '[:lower:]'`
- Delete all spaces and new lines from a file: `cat <file> | tr -d "\n" | tr -d " "`


---
### __Password recovery techniques:__
##### _Cracking techniques:_
- Identify hashtype and select hash type code:
	- Hash type identification tool: `hashid <hash string>`
	- Via [hashcat website](ohttps://hashcat.net/wiki/doku.php?id=example_hashes) 
	- Locally via hashcat: `hashcat --example-hashes | grep <name hash>`
- Wordlist based hash cracking \(use ‘—username’ if hash format in file is ‘user:hash’\): `hashcat (--username) -m <hash type code> <file or code to crask> <wordlist> (--force)`
- Wordlist \+ Rule based hash cracking: `hashcat -a 0 -m <hash type code> <file or code to crask>  <wordlist> -r file.rule`
- Mask based hash cracking: 
	- Use custom mask file: `hashcat -m <hash type code> <hash file> -a 3 maskfile.hcmask`
	- Password length of 9 chars starting with uppercase and ending with small custom charset: `hashcat -m <hash type code> <hash file> -a 3 -1 ?d?s ?u?l?l?l?l?l?l?l?1` 
	- Complete custom charset: `hashcat -m <hash type code> <hash file> -a 3 -1 "?l?u?d?s" "<add ?1 per char to specify word length>"`
- Wordlist \+ mask based hash cracking \(for wordlist \+ mask use ‘\-a 6’ for mask \+ wordlist use ‘\-a 7’\): `hashcat -m <hash type code> <hash file> -a 6 <wordlist> <mask (e.g. ?d?d?d?d)>` 

##### _Extract and crack hashes from secured files:_
- Office documents: 
	- 1: Extract hash from \.docx document: `python office2john.py dummy.docx > hash.txt`
	- 2: Crack hash: `john -wordlist=/<wordlist (e.g. rockyou.txt)> hash.txt`
	- 3: Show cracked password: `john --show hash.txt`
- ZIP files:
	- 1: Extract hash from \.zip file: `zip2john file.zip > hash.txt`
	- 2: Crack hash: `john -wordlist=/<wordlist (e.g. rockyou.txt)> hash.txt` 
	- 3: Show cracked password: `john -show hash.txt`
- RAR files:
	- 1: Extract hash from \.zip file: `rar2john file.rar > hash.txt` 
	- 2: Crack hash: `john -wordlist=/<wordlist (e.g. rockyou.txt)> (--format=rar) hash.txt`
	- 3: Show cracked password: `john -show hash.txt`
- \- KeePass \.kdb file:
	- 1\. Extract hash from KeePass \.kdb file: `keepass2john <Keepass Database>.kdb > keepasshash`
	- 2\. Recover password: `hashcat -m 13400 keepasshash <wordlist>`
- Ansible vault:
	- 1\. Copy from the identified playbook \(\.yaml file\) or other file type, the encrypted content \(looks something like: $ANSIBLE\_VAULT;1\.1;AES256\.\.\.\) without deleting any new lines and save it as vault\_mod
	- 2\. Extract the hash from the vault\_mod file: `/usr/share/john/ansible2john.py vault_mod`
	- 3\. Save the output in a new file called “vault\_hash” without the filename at the beginning of the string\. 
	- 4\. Recover the vault password: `hashcat -m 16900 vault_hash --session=<username> <wordlist>`
	- 5\. Upload the “vault\_mod” file back to the target system which has the installed ansible program
	- 6\. Use the recovered password to dycrypt the actual vault and recover the secrets it holds \(enter the recovered password in the previous step\): `cat vault_mod | ansible-vault decrypt`
