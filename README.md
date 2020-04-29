# steg-in-the-wild
A list of attacks and malware using steganography or information hiding

## Image Attacks

* [Attack at the Tupperware website with credit card skimmer](https://blog.malwarebytes.com/hacking-2/2020/03/criminals-hack-tupperware-website-with-credit-card-skimmer/): PNG file containing a malicious JavaScript 
* [MyKings Botnet hiding malicious data exchanges](https://www.sophos.com/en-us/medialibrary/pdfs/technical-papers/sophoslabs-uncut-mykings-report.pdf):malware payload is hidden in images (e.g, a JPG containing the SQL brute forcer)
* [LokiBot](https://securitynews.sonicwall.com/xmlpost/loki-bot-started-using-image-steganography-and-multi-layered-protection/): data appended to a BMP is extracted to create an encrypted DLL
* [IcedID Trojan propagates via image steganography](https://blog.malwarebytes.com/threat-analysis/2019/12/new-version-of-icedid-trojan-uses-steganographic-payloads/amp/): the payload of the trojan is embedded in a PNG image

## Audio Attacks

* [XMRig Monero CPU Miner](https://threatvector.cylance.com/en_us/home/malicious-payloads-hiding-beneath-the-wav.html):  malware loader is obfuscated in different parts of a WAV file (e.g., econded in least significative bits)


