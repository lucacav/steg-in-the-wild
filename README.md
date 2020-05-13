# steg-in-the-wild
A list of attacks and malware using steganography or information hiding

<!--- Newer First --->
## Image Attacks

* [Attack at the Tupperware website with credit card skimmer](https://blog.malwarebytes.com/hacking-2/2020/03/criminals-hack-tupperware-website-with-credit-card-skimmer/): PNG file containing a malicious JavaScript (see [here](https://blog.malwarebytes.com/threat-analysis/2019/12/new-evasion-techniques-found-in-web-skimmers/) for similar techniques from the Magecart Group)
* [MyKings Botnet hiding malicious data exchanges](https://www.sophos.com/en-us/medialibrary/pdfs/technical-papers/sophoslabs-uncut-mykings-report.pdf): malware payload is hidden in images (e.g, a JPG containing the SQL brute forcer)
* [Titanium](https://securelist.com/titanium-the-platinum-group-strikes-again/94961/): a PNG file is used to exchange commands for a backdoor (another thechnique used by Platinum is [here](#text-attacks))
* [LokiBot](https://securitynews.sonicwall.com/xmlpost/loki-bot-started-using-image-steganography-and-multi-layered-protection/): data appended to a BMP is extracted to create an encrypted DLL
* [LokiBot - Variant](https://blog.trendmicro.com/trendlabs-security-intelligence/lokibot-gains-new-persistence-mechanism-uses-steganography-to-hide-its-tracks/): encrypted binary is embedded in a JPG
* [IcedID Trojan propagates via image steganography](https://blog.malwarebytes.com/threat-analysis/2019/12/new-version-of-icedid-trojan-uses-steganographic-payloads/amp/): the payload of the trojan is embedded in a PNG image
* [ScarCruft Malware](https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/): multi-stage loading is implemented by embedding part of the payload in an image
* [PHP scripts in EXIF data of JPG](https://threatpost.com/rare-steganography-hack-can-compromise-fully-patched-websites/146701/): PHP webshells hidden in EXIF headers of JPGs to upload malware on a website
* [Okrum and Ketrican](https://www.welivesecurity.com/wp-content/uploads/2019/07/ESET_Okrum_and_Ketrican.pdf): the Stage 1 loader containing the backdoor is embedded in a valid PNG
* [Stegoware-3PC](https://www.scmagazine.com/home/security-news/malware/stegoware-3pc-marks-new-high-in-adware-sophistication/): malware can redirect iOS 12 devices to a phishing site by injecting data in PNG images
* [Turla](https://www.bleepingcomputer.com/news/security/turla-backdoor-deployed-in-attacks-against-worldwide-targets/): it uses backdoors placed in ad-hoc PDF and JPF mail attachments (main target was Microsoft Exchange)
* [OceantLotus](https://gbhackers.com/oceanlotus-apt-hackers-group-steganography/): malware loaded and extensions are embedded in PNG (by using LSB steganography)
* [Cardinal RAT](https://gbhackers.com/oceanlotus-apt-hackers-group-steganography/): it uses various obfuscation techniques, the first one is a .NET executable embedding a BMP containing a DLL
* [Powload](https://gbhackers.com/oceanlotus-apt-hackers-group-steganography/): it embeds malicious code in images via the [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage) technique. 
* [VeryMal](https://www.theregister.co.uk/2019/01/24/mac_steganography_malware/): malware is injected in JPG (mainly targeting macOS and iOS)
* [Ursnif](https://securityaffairs.co/wordpress/80342/hacking/steganography-obfuscate-pdf.html): malicious code is injected in images embedded in PDF files
* [On the use of steganographic Twitter memes](https://blog.trendmicro.com/trendlabs-security-intelligence/cybercriminals-use-malicious-memes-that-communicate-with-malware/): Trojan.MSIL.BERBOMTHUM.AA embeds in memes a /print command and sends screenshots of infected machines to a C&C server (the URL is hard-coded on pastebin.com)
* [Cutwail botnet spam campaign to deliver the Bebloh banking Trojan](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/spam-campaign-targets-japan-uses-steganography-to-deliver-the-bebloh-banking-trojan?): a PowerShell script to retrieve the malware payload [Ursnif](#https://securityaffairs.co/wordpress/80342/hacking/steganography-obfuscate-pdf.html) is embedded in a PNG
* [Games on Google Play contain Android.RemoveCode.127.origin](https://news.drweb.com/show/?lng=en&i=11685&c=5): the 呀呀云 SDK contained trojan-like functions for covertly retrieving malicious code from a C&C server embedded in images
* [Daserf Backdoor](https://blog.trendmicro.com/trendlabs-security-intelligence/redbaldknight-bronze-butler-daserf-backdoor-now-using-steganography/): C&C communications and 2nd stage backdoors happen via embedding data in images
* [SyncCrypt](https://www.bleepingcomputer.com/news/security/synccrypt-ransomware-hides-inside-jpg-files-appends-kk-extension/): a ZIP is embedded in an image containing the components of the ransomware 
* [AdGholas Malvertising Campaigns](https://www.proofpoint.com/us/threat-insight/post/massive-adgholas-malvertising-campaigns-use-steganography-and-file-whitelisting-to-hide-in-plain-sight): data is embedded in various images (the [Astrum/Stegano](https://blog.trendmicro.com/exploit-kit-attacks-on-the-rise-as-astrum-emerges/) exploit kit is used)
* [StegBaus](https://unit42.paloaltonetworks.com/unit42-stegbaus-because-sometimes-xor-just-isnt-enough/): the loader uses multiple PNG embedded in .NET resources
* [Gatak/Stegoloader](https://www.secureworks.com/research/stegoloader-a-stealthy-information-stealer): malicious code is hidden in PNG (Gatak has been widely used to infect users visiting keygen websistes)
* [PowerDuke spear phishing campaign post 2016 US elections](https://www.secureworks.com/research/stegoloader-a-stealthy-information-stealer): components of a backdoor were hidden in PNG files 
* [Android/Twitoor](https://www.bleepingcomputer.com/news/security/candc-servers-too-risky-android-botnet-goes-with-twitter-instead/): encrypted commands are retrieved from a Twitter account acting as the C&C
* [TSPY_GATAK.GTK](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_gatak.gtk): additional code and a list of URLs are retrieved via images
* [Zberp](https://securityintelligence.com/new-zberp-trojan-discovered-zeus-zbot-carberp/): data is hidden in a JPG image. This is a variant of [Zeus/Zbot](https://blog.malwarebytes.com/threat-analysis/2014/02/hiding-in-plain-sight-a-story-about-a-sneaky-banking-trojan/)

## Audio Attacks

* [XMRig Monero CPU Miner](https://threatvector.cylance.com/en_us/home/malicious-payloads-hiding-beneath-the-wav.html):  malware loader is obfuscated in different parts of a WAV file (e.g., econded in least significative bits)

## Network Attacks

* [Okrum and Ketrican](https://www.welivesecurity.com/wp-content/uploads/2019/07/ESET_Okrum_and_Ketrican.pdf): C&C communications are hidden in HTTP traffic, i.e., in Set-Cookie and Cookie headers of HTTP requests
* [DarkHydrus](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling): it uses DNS tunneling to transfer information, which is a technique observed in the past also in Morto and Feederbot malware
* [Steganography in contemporary cyberattacks](https://securelist.com/steganography-in-contemporary-cyberattacks/79276/): a general review including Backdoor.Win32.Denis which hidden data in a DNS tunnel for communicating with C&C
* [ChChes](https://attack.mitre.org/software/S0144/): the malware uses Cookie headers of HTTP for C&C communications
* [NanoLocker](https://www.bleepingcomputer.com/news/security/nanolocker-ransomware-can-be-decrypted-if-caught-early/): the ransomware hide data in ICMP packets
* [FAKEM RAT](https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-fakem-rat.pdf): C&C communications are camouflaged in Yahoo! Messenger and MSN Messenger as well as HTTP (**strictly not network steganography!**)

## Text Attacks

* [Astaroth](https://blog.talosintelligence.com/2020/05/astaroth-analysis.html): the description of YouTube channels hides the URL of command and control servers. 
* [Platinum APT](https://securelist.com/platinum-is-back/91135/): C&C data is hidden in the order of HTML attributes and its encryption key in spaces among HTML tags
