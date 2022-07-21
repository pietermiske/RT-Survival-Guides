# __External reconnaissance & OSINT gathering__
>Author: Pieter Miske
---
### __Identify domains and externaly exposed services associated with the target organisation:__
#### _Identify root and subdomain domains:_
>Be aware that some identified domain names/IP addresses are not externally accessible but are used internally within the target organisations' network\. 
- Identify domains based on the specified domain whois record \([Amass](https://github.com/OWASP/Amass)\): `./amass intel -d <domain name> -whois`
- Identify root domains based on ASN's:
	- 1\. Identify ASN of the target company \(this doesn't always work for each company\) (Amass): `./amass intel -org "<name company (e.g. Tesla)>"`
	- 2\. Request root domains based on the ASN (Amass): `./amass intel -active -asn <asn number>`
- Scan every root domain for existing subdomains (Amass): ./amass enum -active -d <target domain or ip> (-ipv4)`
- Brute force subdomains (use the ‘\-\-hw’ option to filter out the correct results based on their "Word" value) \([wfuzz](https://github.com/xmendez/wfuzz)\): `wfuzz -u http://<target ip or domain> -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.<target ip or domain>' (--hw <12>)`
- Use Google Dorks to find subdomain names:
    - Search for subdomains and exclude already known ones: site:\*\.domain\.com \-www
    - Search for keyword that is part of the targets domain name \(e\.g\. login\): site:<domain name> inurl:<keyword>

#### _OSINT service enumeration:_
- Use [Shodan](https://www.shodan.io/) to check what services are available on the target host


---
### __Identify employee names, functions and email addresses:__
#### _Gathering publicly available employee names, e-mail addresses and username conventions:_
- Identify target company email addresses of potential employees via: [https://hunter\.io](https://hunter.io)
- Check for email addresses based on earlier breaches: [https://www\.dehashed\.com/](https://www.dehashed.com/)
- LinkedIn enumeration tool that uses search engine scraping to collect valid employee names from a target organization \([CrossLinked](https://github.com/m8r0wn/CrossLinked)\): `python3 crosslinked.py -f '<first>.<last>@domain.com' <company_name>`
- [Search engine](https://intelx.io) that searches in places such as the darknet, document sharing platforms, whois data, public data leaks and others. 

#### _Identify valid usernames via exposed Exchange server:_
- 1\. Enumerate the NetBIOS name and FQDN of the target \([MailSniper\.ps1](https://github.com/dafthack/MailSniper)\): `Invoke-DomainHarvestOWA -ExchHostname <IP Exchange server>`
- 2\. Use a timing attack to identify valid usernames \([MailSniper\.ps1](https://github.com/dafthack/MailSniper)\): `Invoke-UsernameHarvestOWA -ExchHostname <IP target Exchange server> -Domain <domain> -UserList .\usernames.txt -OutFile valid-users.txt`

---
### __Search for secrets and metadata in publicly available documents associated with the target organisation:__
- Find files and metadata information by quering a specified domain name and a variety of file extensions \(pdf, doc, docx, etc\),downloading the file, and enumerate for metadata using Exiftool (due to Google's built in rate limiting, queries may end up timed out if too many are made in a short amount of time) \([MSDorkDump](https://github.com/dievus/msdorkdump)\): `python3 msdorkdump.py <domain>`
- Manually search for documents combining the following Google Dork queries:
    - Search specific site and lists all the results: site:[www\.google\.com](http://www.google.com)
    - Search within a particular date range: filetype:pdf & \(before:2000\-01\-01 after:2001\-01\-01\)
    - Search for a keyword that is used on the targets webpage: site:<domain name> intext:<keyword>
    - Search for a keyword that is used as a title on the targets webpage: site:<domain name> intitle:<keyword>
    - Searches for a particular filetype \(e\.g\. doc, pdf, txt, ppt, xml\): filetype:"pdf"
    - Searches for external links to pages: link:"keyword"
    - Locate specific numbers in your searches: numrange:321\-325


