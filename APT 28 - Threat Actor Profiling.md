
# Bulletin Metadata

DATE: November 20th 2025 

CONFIDENCE: 1 - Confirmed 

TLP: CLEAR

Threat Actor: APT28 (FANCY BEAR)

Location: Russia

Victim Location: Global, USA, EU 

Sectors: PA, Regulatory Agencies, Critical Infrastructure, Citizens

Motivation: Politics, Retaliation

# Threat Actor

APT28, also known as “Fancy Bear”, is a threat group associated with Russia’s General Staff Main Intelligence Directorate (GRU), specifically with the 85th Main Special Service Center (GTsSS) military unit 26165. This group has been active since at least 2004. 

The extensive operations conducted against Public Administration, Regulatory Agencies and Critical Infrastructure, reflect the strategic and geopolitical interests of the Russian government. In earlier stages, the Actor, has been associated with operations against Russian Citizens, who were considered as regime dissidents.

The actor’s operations are typically highly coordinated, leveraging spear-phishing, credential harvesting, and custom malware tools to achieve long-term objectives.

This Actor has demonstrated capabilities to compromise IT networks; develop mechanisms to maintain long-term, persistent access to IT networks; exfiltrate sensitive data from IT and operational technology (OT) networks; and disrupt critical industrial control systems (ICS)/OT functions by deploying destructive malware. 

Some of their most relevant attack campaigns and targets include:

| Year | Targets                                                                                                                                                        |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2014 | “US nuclear facility”                                                                                                                                          |
| 2015 | “Deutscher Bundestag”                                                                                                                                          |
| 2016 | “Hillary Clinton Campaign”, “Democratic National Committee”/“Democratic Congressional Campaign Committee”, “World Anti-Doping Agency”, “US Anti-Doping Agency” |
| 2018 | “Organization for the Prohibition of Chemical Weapons”                                                                                                         |

# Historical campaigns 

## APT28 Attack on “US Nuclear Facility”

Between 2014 and 2015 a US nuclear-related facility was the target of a cyber-espionage attack. The intrusion was conducted through Spear-Phishing emails designed to harvest credentials and gain unauthorized access to internal systems. 

According to US federal indictments, the actor conducted reconnaissance, collected internal documents, and exfiltrated data associated with the facility’s operations. The case was included in US charges against GRU officers. Detailed technical indicators are not publicly available.

## APT28 Attack on “Deutscher Bundestag”

Between April and May 2015, the German federal parliament was the target of a major cyber-attack; the attackers managed to steal a significant amount of data, and affect the email accounts of several MPs, including Chancellor Angela Merkel. 

The attack was carried out through malware delivered by using Spear-Phishing emails, in which the actor posed as Officials from the United Nations. Consequently, the Parliamentary IT systems were down for several days, and the whole “Bundestag” IT infrastructure had to be rebuilt. Sanctions, Travel ban, Asset Freeze and Arrests were imposed on individuals and bodies related to the attack. Among them we find the name of a GRU member “Dmitri Badin”, strengthening the connection with Russian’s military intelligence services.

## APT28 Attack on “Hillary Clinton Campaign”

Between March and May 2016, the Hillary Clinton US presidential campaign was the target of a cyber-espionage operation. The attack was carried out through Spear-Phishing emails, containing shortened links, leading to a fraudulent Google Account login page.

The Accounts owners held a wide range of responsibilities within the campaign. This Operation enabled the theft of sensitive communications and internal information, contributing to wider compromises affecting the “Democratic National Committee”, “Democratic Congressional Campaign Committee” during the same period, and subsequent data leaks. 

## APT28 Attack on “Democratic National Committee”/ “Democratic Congressional Campaign Committee”

Between March and June 2016, the Democratic National Committee was the target of a cyber-espionage campaign. The attack was carried out through Spear-Phishing emails, leading to fraudulent Google and Microsoft Account login page. After gaining access to internal email accounts, and network resources, the actor deployed malware tools allowing persistence, lateral movement and data exfiltration of sensitive communications and strategic documents. 

The compromise was sustained over several months, and some of the stole information was later publicly disclosed, causing repercussions.

## APT28 Attack on “World Anti-Doping Agency”

Between August and September 2016, the World Anti-Doping Agency was targeted by a cyber-espionage and information-leak operation. The attack was carried out trough Spear-Phishing emails and password-spraying methods, granting the actor unauthorized access to the “Anti-Doping Administration and Management System”.

The attackers had access to medical records, testing data and Therapeutic Use Exemption documentation belonging to numerous high-profile international athletes. The stolen data was later leaked on public websites, with an attempt to frame the operation as “whistleblowing”. The targeting closely followed public sanctions imposed on Russian athletes, after the exposure of the state-sponsored doping program, indicating a retaliatory and political motive behind the intrusion.

## APT28 Attack on “US Anti-Doping Agency” 

Between August and October 2016, the US Anti-Doping Agency was targeted by a cyber-espionage and information-leak operation. The attack was carried out through Spear-Phishing emails and credential-harvesting techniques designed to obtain access to Agency staff accounts and systems. The attackers accessed internal platforms containing athlete information, testing records and Therapeutic Use Exemption documents. 

The stolen data was leaked through public websites, mirroring parallel disclosures targeting the World Anti-Doping Agency after international sanctions were imposed on Russian athletes, linking them to a state-sponsored doping program.

## APT28 Attack on “Organization for the Prohibition of Chemical Weapons”

Between March and April 2018, the Organization for the Prohibition of Chemical Weapons was victim of a cyber-espionage campaign. The attack was carried through Spear-Phishing emails leading to credential-harvesting pages, aimed at the Organization’s personnel. The actor gained access and conducted reconnaissance within the Organization’s networks, attempted to access internal communications, documentation and investigations reports related to chemical weapons inspections. Technical indicators were not fully publicly disclosed. The attack coincided with the investigations into chemical weapon use in Syria, once again highlighting the geopolitical motivation of the actor. 

# Attacker’s TTPs

The following table summarizes the known TTPs utilized by the Threat Actor:

| Tactic                                  | Technique | Sub-Technique     |
| --------------------------------------- | --------- | ----------------- |
| Archive Collected Data                  | T1560     | - .001            |
| Brute Force                             | T1110     | - .003            |
| Command and Scripting Interpreter       | T1059     | - .001 <br>- .003 |
| Compromise Infrastructure               | T1584     | - N/A             |
| Data Staged                             | T1074     | - .001            |
| Deobfuscate/Decode Files or Information | T1140     | - N/A             |
| Disk Wipe                               | T1561     | - .001            |
| Exfiltration Over Web Service           | T1567     | - N/A             |
| OS Credential Dumping                   | T1003     | - .003            |
| System Network Configuration Discovery  | T1016     | - .002            |
| Wi-Fi Networks                          | T1669     | - N/A             |

# Attacker’s Malwares

Here we have a list with some of the most used malware/malicious tools for the Actor, covering general description, usual delivery/deployment methods and capabilities.

## Jaguar Tooth

Jaguar Tooth is a non-persistent malware targeting Cisco IOS routers running firmware “C5350-ISM, Version 12.3(6)”. Its main functions comprehend data collection, data exfiltration and unauthenticated backdoor access.

It is deployed and executed via exploitation of the SNMP vulnerability CVE-2017-6742.

The malware modifies Cisco IOS authentication routines, granting access to local accounts without checking the provided password. The malware also creates a new process called “Service Policy Lock” that automatically collects information such as the running configuration, firmware version, routing tables, network interfaces and other connected routers, exfiltrating it over TFTP.

## Drovorub

Drovorub is a Linux malware toolset consisting of a kernel module rootkit, a file transfer and port forwarding tool, and a Command-and-Control Server. Its main functions comprehend direct communication with C2 infrastructure, file download and upload, arbitrary command execution as “root” and port forwarding of network traffic to other hosts on the network.

It is unclear exactly how Drovorub is initially delivered, unconfirmed reports indicate it may be distributed via previously compromised websites.

Drovorub components appear to be installed in sequence, with the rootkit first creating system hooks in order to hide all its associated processes, files sockets and Netfilter components. The Host component gets installed only if the rootkit is successful, it then connects to a C2 Server to download additional items before awaiting further commands.

## CHOPSTICK (X-AGENT)

CHOPSTICK (Also known as X-AGENT) is a second-stage modular remote access trojan, capable of running on Windows, IOS and Unix-based operating systems. Its main functions include data collection, data exfiltration, keylogging and Remote Command Execution. More recent version use SSL/TLS to encrypt communications.

It is usually delivered through Spear-Phishing attacks, based on emails containing Microsoft Word documents with macro-based droppers, or weaponized documents exploiting known vulnerabilities. 

CHOPSTICK components appear to be installed in sequence, with core backdoor deployed first. Once the backdoor successfully connects to its C2 Server, it retrieves all the modules needed to exert its intended malicious functionalities. This approach aims at reducing the footprint during initial execution.

## Zebrocy

Zebrocy is a Windows based Trojan written in many languages including Delphi, C#, Visual C++, VB.net and Golang. Its main functions include system reconnaissance, data collection, backdoor access and secondary payloads deployment.

The primary deployment mechanism for Zebrocy has been Spear-Phishing emails, containing malicious attachments such as weaponized documents, archives or executables.

Zebrocy components appear to be installed in sequence, with a Windows registry being added in the first place to achieve persistence. It then gathers information on the victim system and sends it to the C2 Server via POST request. If the target is deemed of interest the C2 responds with “AutoIt” downloader, for a second reconnaissance phase, during which the tool is capable of detecting sandbox and virtual environments. The actual backdoor (Delphi) then gets finally installed. The multi-stage approach aims at reducing detection during early phases of the intrusion.
# APT28 “Nearest Neighbor Campaign” in-depth analysis  

From February 2022 to November 2024, the actor conducted an attack campaign against organizations and individuals with expertise on Ukraine. Notably this campaign started just ahead of the Russian invasion of Ukraine.  
APT28 primarily leveraged living-off-the-land techniques during this campaign, while at the same time exploited a zero-day vulnerability known as CVE-[2022-38028](tel:2022-38028). 

The campaign leveraged Wi-Fi networks in close proximity to the intended target in order to gain initial access to the victim environment: by chain-attacking multiple organizations, nearby the final target, APT28 discovered dual-homed systems, that implemented multiple network interfaces, with both wired and wireless network access capabilities, to enable Wi-Fi and use compromised credentials to connect to the victim network.  

The attack campaign was unveiled by “Volexity”, a cyber security firm, that was providing its services to the victim organization, henceforth referred as “Organization A”:  

“*Volexity made a discovery that led to one of the most fascinating and complex incident investigations Volexity had ever worked*”  

The investigations began with an alert, from a custom detection signature, developed to look for files being written to and executed out of the root of the “C:ProgramData” directory, indicating the compromission of a Server on Organization A’s network.  

During the analysis, the attack vector was recognized as “novel” and not previously encountered. At the end of the investigation the attack would be tied to APT28 (Fancy Bear), determining the active targeting of “Organization A” to collect data from individuals and projects involving Ukraine. The Actor was able to breach “Organization A” by connecting to their enterprise Wi-Fi network.  

In order to obtain validate credentials to authenticate over Organization A’s Wi-Fi network, the Actor attacked a victim’s public-facing service, through password spraying techniques. The public-facing Service itself was secured through MFA, while the Wi-Fi network only required a user’s valid domain username and password to authenticate. 

The strategy involved the compromission of multiple other organizations.  
The actor exploited a second compromised Organization, henceforth referred ad “Organization B”, and lateral movement inside of its network, to find systems that were dual-homed.  

The threat actor accessed a vulnerable system under Organization B’s network and exploited its Wi-Fi adapter to connect to the Organization’s A’s network.

During the investigations, the following activities were found to be occured:

- A file named "C:ProgramDataservtask.bat" had been written and executed;
- A file named "servtask.bat" had invoked the command-line registry utility and Powershell to run the following commands:
  
	- `reg save hklmsam C:ProgramDatasam.save`
	- `reg save hklmsecurity C:ProgramDatasecurity.save`
	- `reg save hklmsystem C:ProgramDatasystem.save`
	- `Powershell -c “Get-ChildItem C:ProgramDatasam.save, C:ProgramDatasecurity.save, C:ProgramDatasystem.save ^| Compress-Archive -DestinationPath C:ProgramDataout.zip”`

Sensitive registry hives were being exported and compressed into a ZIP file.

The investigations proceded, focussing on the EDR event history, and the collection of the affected system's RAM and key disk artifacts.

From the EDR logs the following activities were found to have occured just before the registry interactions mentioned above:

- A login with an unprivileged user account on the server occurred over RDP.
- A file named `DefragmentSrv.zip` appeared on the system under that user’s directory and was unarchived using the GUI version of WinRAR present on the system.
- Two files, `DefragmentSrv.exe` and `DefragmentSrv.bat`, were also written and executed; that chain ultimately led to the writing and execution of `servtask.bat`.
- A file named `wayzgoose52.dll` was also written to a fake directory located at `C:ProgramDataAdobev3.80.15456`.

During the memory collection, the system was shut down, resulting in the loss of volatile data, useful for the analysis.

Moreover the Attacker promptly removed all the files and folders identified during the investigations.

In addition the Attacker run "`Cipher.exe`", a native Microsoft utility, to cover their tracks.

From there the attacker laid low for a while. An IP address was found to have connected to the victim server, but it was no longer online, and its purpose wasn't clear.  

When the attacker returned the investigations were able to track its IP address, and associate it with Organization A's Enterprise Wi-Fi network, and highlight the usage of one of the domain controllers on the network as a DHCP server.

By examining the DHCP logs, there was no record of the IP addresses tied to the attacker.

By investigating a wireless controller, used to manage Organization's A wireless network and all related infrastructure, the attacker's IP was found and tied to an authenticated domain user and a MAC address.

Such user and MAC address were tied back to authentication events present into Organization A's RADIUS logs, happening during the initial breach. The same MAC address was found to be related to additional authentication events, under a different username, going back to late January 2022. This account had its password changed due to expiration, locking the attacker out, who was able to come back in early February 2022 with the account observed from the wireless controller.

This new information lead the investigations to examine logs of a system providing Internet-facing webservices with authentication functionalities. 

The service was protected with MFA, but could be used to verify valid credentials.

Upon examining those logs it was found that during January/February, password-spray attacks had been carried out against the service, and three different accounts were successfully compromised by the attacker: 2 of them were the accounts already found to be exploited, the third one was not used yet.

The attacker was connecting to the network via wireless credentials they had brute-forced from an Internet-facing service.

Still it wasn't clear where the attacker was physically located.

By further analysis of data available from the wireless controller, the attacker was seen to be connecting to the same access points, in a conference room at the far end of the building, near windows along the street. 

This was the first evidence that the:

“_call was not coming from inside the building._”

The compromised account credentials were reset, but the attacker still had working ones.

By improving the logging and network visibility, the investigations were able to capture all activity involving Wi-Fi connections. 

When the attacker regained access to the Organization's A Enterprise Wi-Fi, its machine had sent out NetBIOS Name Service (NBNS) queries, revealing its computer name and the joined active directory domain. 

The AD domain was related to Organization B, located "_right across the street_".

In coordination with Organization B, the investigations uncovered how the attacker was operating, finding the system that had connected to Organization A's Wi-Fi.

The incriminated Organization B's system, was dual-homed and had been breached after the attacker used privileged credentials to connect to it via RDP, from another system within the same network.

The attacker used a PowerShell script to examine the available networks within range of its wireless interface, and from there connected to Organization's A Wi-Fi.

Here we can find a redacted copy of the C# code embedded in the custom PowerShell script: https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs

Additional analysis of systems at Organization B revealed the intruder had two modes of access to their network:

- A VPN connection's credentials, with no MFA;
- Wi-Fi connections coming from a nearby Organization (henceforth referred as "Organization C")

Organization C was identified, based on MAC addresses and SSID information. Organization C opted not to provide access to key data required to take the investigations further.

Mitigation and Remediation steps were followed cutting out the attacker's access to Organization A's Enterprise Wi-Fi.

One month later, another alert was triggered, indicating suspect activity in the Organization A's network.

By investigating the activity, the same threat actor was found to have managed to return to the network by proxying through multiple internal systems.

By walking back the systems, it origin was found to be a system on Organization A's Guest Wi-Fi network.

The Guest Wi-Fi network was supposed to be completely isolated from the corporate wired network. But instead there was one system that was accessible from both networks.

Using stolen credentials, the attacker was able to pivot back into the corporate wired network, through this single system.

To achieve this pivot the attacker used the Windows "netsh" utility to set up a series of port-forwards:

```
cmd.exe /C netsh advfirewall firewall add rule name="Remote Event Log Management SMB" dir=in action=allow protocol=tcp localport=12345 > C:WindowsTempMSI28122Ac.LOG 2>&1

cmd.exe /C netsh interface portproxy add v4tov4 listenaddress=172.33.xx.xx listenport=12345 connectaddress=172.20.xx.xx connectport=445 > C:WindowsTempMSI2cBfA24.LOG 2>&1
```

The source system connected on the Guest Wi-Fi network, was determined once again through network and log analysis from Organization A's wireless controller.

This time the attacker was connecting from "Organization C", who had been contacted once again, to take new remediation steps to resolve this new intrusion.

Since this final activity related to the Guest Wi-Fi network, there has been no observed activity tied to an attacker leveraging the "Nearest Neighbor Attack".

## Use of Cipher.exe

The attacker removed files they created using "Cipher.exe", Its usage is described in the Microsoft documentation.

The following command was used to overwrite deleted data in a particular folder:

```
cmd.exe /c cipher /W:C
```

*"Type `cipher /w:<directory>`, and then press ENTER, where `<directory>` is any folder in the volume that you want to clean. For example, the `cipher /w:C` command causes all deallocated space on drive C to be overwritten. If `<directory>` is a mount point or points to a folder on another volume, all deallocated space on that volume will be cleaned."*

## Dumping Ntds.dit via VSSAdmin

Another observed tactic was the attempt to steal the AD database by creating a volume shadow copy.

This procedure is publicly well documented (https://netwrix.com/en/resources/blog/extracting-password-hashes-from-the-ntds-dit-file/) and consists of the following key components:

- Create a volume shadow copy, e.g., the following:

	`vssadmin create shadow /for C: /quiet`

- Retrieve a copy of the `ntds.dit` file and the SYSTEM registry hive from the volume shadow copy:

	`copy \?GLOBALROOTDeviceHarddiskVolumeShadowCopy1WindowsNTDSNTDS.dit [dest]`

	`copy \?GLOBALROOTDeviceHarddiskVolumeShadowCopy1WindowsSystem32configSYSTEM [dest]`

 - Download the copied files. To download the files (which were fairly large) the attacker compressed them using a PowerShell command:

	`powershell -c "& { Add-Type -Assembly 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory($path1', '$path2');}" > C:WindowsTempb2rMBPL.tmp 2>&1`

## Staging Data for Exfiltration

The majority of the data from this incident was copied back to the attacker’s system connected to the Wi-Fi. 

However, in a few cases, Volexity observed the attacker staging data in directories on a public-facing webserver. These files were then exfiltrated via external downloads.

# Attribution

Initially, Volexity was not able to attribute this intrusion to a known threat actor, but once it was able to determine who and what was being targeted internally, it immediately suspected that this was the activity of a Russian threat actor.

Then, in April 2024, Microsoft published research on "Forest Blizzard", which Volexity tracks as "GruesomeLarch", detailing a post-compromise tool named GooseEgg that the threat actor had used.

This tool was leveraged in the zero-day exploitation of CVE-2022-38028, a privilege escalation vulnerability in the Microsoft Windows Print Spooler service.

In their report, Microsoft detailed several key file names, folder paths, and commands used by the framework, notably the following:

- `Servtask.bat`
- `Wayzgoose52.dll`
- `DefragmentSrv.exe`
- `C:ProgramData[var]v%u.%02u.%04u`

These exact file names and paths were observed in the incident investigated by Volexity.

Microsoft’s report also showed what commands were in the `servtask.bat` file, which were identical to what Volexity had seen where registry hives had been saved and compressed into a file named `out.zip` from the initial intrusion activity.

Microsoft’s post stated that GooseEgg had been in use since “_at least June 2020 and possibly as early as April 2019._” Volexity can confirm this tool was definitively used in February 2022. 

Exploitation of CVE-2022-38028 also provides an explanation as to how the initial victim system was likely compromised.

Based on the use of this tool, which Microsoft indicates is unique to this threat actor, Volexity assesses with high confidence that the activity described in this post can be attributed to APT28.



# Detection&Mitigation

To generally prevent or detect attacks similar to those discussed in this report, its recommended to:

- Monitor and alert on anomalous use of the `netsh` and `Cipher.exe` utilities within your environment.
- Create custom detection rules to look for files executing from various non-standard locations, such as the root of `C:ProgramData`.
- Detect and identify exfiltration of data from Internet-facing services run in your environment.
- Create separate networking environments for Wi-Fi and Ethernet-wired networks, particularly where Ethernet-based networks allow for access to sensitive resources.
- Consider hardening access requirements for Wi-Fi networks, such as applying MFA requirements for authentication or certificate-based solutions.
- Monitor network traffic between devices to identify files being transferred via SMB that contain commonly exfiltrated data (credential data, `ntds.dit`, registry hives, etc.).



# references

- - [https://attack.mitre.org/groups/G0007/](https://attack.mitre.org/groups/G0007/ "https://attack.mitre.org/groups/G0007/")
    
- [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108 "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-108")
    
- [https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a")
    
- [https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a")
    
- https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/russia/publications
    
- https://www.gov.uk/government/news/uk-enforces-new-sanctions-against-russia-for-cyber-attack-on-german-parliament
    
- [https://attack.mitre.org/software/S0502/](https://attack.mitre.org/software/S0502/ "https://attack.mitre.org/software/S0502/")
    
- [https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/jaguar-tooth/NCSC-MAR-Jaguar-Tooth.pdf](https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/jaguar-tooth/NCSC-MAR-Jaguar-Tooth.pdf "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/jaguar-tooth/NCSC-MAR-Jaguar-Tooth.pdf")
    
- [https://www.cisa.gov/news-events/alerts/2020/08/13/joint-nsa-and-fbi-cybersecurity-advisory-discloses-russian-malware-drovorub](https://www.cisa.gov/news-events/alerts/2020/08/13/joint-nsa-and-fbi-cybersecurity-advisory-discloses-russian-malware-drovorub "https://www.cisa.gov/news-events/alerts/2020/08/13/joint-nsa-and-fbi-cybersecurity-advisory-discloses-russian-malware-drovorub")
    
- [https://web-assets.esetstatic.com/wls/2016/10/eset-sednit-part-2.pdf](https://web-assets.esetstatic.com/wls/2016/10/eset-sednit-part-2.pdf "https://web-assets.esetstatic.com/wls/2016/10/eset-sednit-part-2.pdf")
    
- [https://www.swp-berlin.org/10.18449/2021RP11/](https://www.swp-berlin.org/10.18449/2021RP11/ "https://www.swp-berlin.org/10.18449/2021RP11/")
    
- [https://www.consilium.europa.eu/en/press/press-releases/2020/10/22/malicious-cyber-attacks-eu-sanctions-two-individuals-and-one-body-over-2015-bundestag-hack/](https://www.consilium.europa.eu/en/press/press-releases/2020/10/22/malicious-cyber-attacks-eu-sanctions-two-individuals-and-one-body-over-2015-bundestag-hack/ "https://www.consilium.europa.eu/en/press/press-releases/2020/10/22/malicious-cyber-attacks-eu-sanctions-two-individuals-and-one-body-over-2015-bundestag-hack/")
    
- [https://www.auswaertiges-amt.de/en/newsroom/news/hacker-attack-bundestag-2345580](https://www.auswaertiges-amt.de/en/newsroom/news/hacker-attack-bundestag-2345580 "https://www.auswaertiges-amt.de/en/newsroom/news/hacker-attack-bundestag-2345580")
    
- [https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign](https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign "https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign")
    
- [https://eurepoc.eu/wp-content/uploads/2023/07/APT28-EN.pdf](https://eurepoc.eu/wp-content/uploads/2023/07/APT28-EN.pdf "https://eurepoc.eu/wp-content/uploads/2023/07/APT28-EN.pdf")
    
- [https://www.justice.gov/archives/opa/pr/us-charges-russian-gru-officers-international-hacking-and-related-influence-and](https://www.justice.gov/archives/opa/pr/us-charges-russian-gru-officers-international-hacking-and-related-influence-and "https://www.justice.gov/archives/opa/pr/us-charges-russian-gru-officers-international-hacking-and-related-influence-and")
    
- [https://www.nucnet.org/news/us-indicts-russians-in-hacking-of-nuclear-company-westinghouse](https://www.nucnet.org/news/us-indicts-russians-in-hacking-of-nuclear-company-westinghouse "https://www.nucnet.org/news/us-indicts-russians-in-hacking-of-nuclear-company-westinghouse")
    
- [https://www.wada-ama.org/en/news/wada-confirms-attack-russian-cyber-espionage-group](https://www.wada-ama.org/en/news/wada-confirms-attack-russian-cyber-espionage-group "https://www.wada-ama.org/en/news/wada-confirms-attack-russian-cyber-espionage-group")
    
- [https://www.wada-ama.org/en/news/cyber-security-update-wadas-incident-response](https://www.wada-ama.org/en/news/cyber-security-update-wadas-incident-response "https://www.wada-ama.org/en/news/cyber-security-update-wadas-incident-response")
    
- [https://www.fbi.gov/wanted/cyber/gru-hacking-to-undermine-anti-doping-efforts](https://www.fbi.gov/wanted/cyber/gru-hacking-to-undermine-anti-doping-efforts "https://www.fbi.gov/wanted/cyber/gru-hacking-to-undermine-anti-doping-efforts")
    
- [https://services.google.com/fh/files/misc/apt28-at-the-center-of-the-storm.pdf](https://services.google.com/fh/files/misc/apt28-at-the-center-of-the-storm.pdf "https://services.google.com/fh/files/misc/apt28-at-the-center-of-the-storm.pdf")
    
- [https://www.gov.uk/government/news/uk-exposes-russian-cyber-attacks](https://www.gov.uk/government/news/uk-exposes-russian-cyber-attacks "https://www.gov.uk/government/news/uk-exposes-russian-cyber-attacks")
    
- [https://nvd.nist.gov/vuln/detail/cve-2017-6742](https://nvd.nist.gov/vuln/detail/cve-2017-6742 "https://nvd.nist.gov/vuln/detail/cve-2017-6742")
    
- [https://www.cisa.gov/sites/default/files/2023-04/apt28-exploits-known-vulnerability-to-carry-out-reconnaissance-and-deploy-malware-on-cisco-routers-uk.pdf](https://www.cisa.gov/sites/default/files/2023-04/apt28-exploits-known-vulnerability-to-carry-out-reconnaissance-and-deploy-malware-on-cisco-routers-uk.pdf "https://www.cisa.gov/sites/default/files/2023-04/apt28-exploits-known-vulnerability-to-carry-out-reconnaissance-and-deploy-malware-on-cisco-routers-uk.pdf")
    
- [https://media.defense.gov/2020/aug/13/2002476465/-1/-1/0/CSA_drovorub_russian_gru_malware_aug_2020.pdf](https://media.defense.gov/2020/aug/13/2002476465/-1/-1/0/CSA_drovorub_russian_gru_malware_aug_2020.pdf "https://media.defense.gov/2020/aug/13/2002476465/-1/-1/0/CSA_drovorub_russian_gru_malware_aug_2020.pdf")
    
- [https://digital.nhs.uk/cyber-alerts/2020/cc-3598](https://digital.nhs.uk/cyber-alerts/2020/cc-3598 "https://digital.nhs.uk/cyber-alerts/2020/cc-3598")
    
- [https://www.ncsc.gov.uk/files/NCSC_APT28.pdf](https://www.ncsc.gov.uk/files/NCSC_APT28.pdf "https://www.ncsc.gov.uk/files/NCSC_APT28.pdf")
    
- [https://nvd.nist.gov/vuln/detail/cve-2014-1761](https://nvd.nist.gov/vuln/detail/cve-2014-1761 "https://nvd.nist.gov/vuln/detail/cve-2014-1761")
    
- [https://nvd.nist.gov/vuln/detail/cve-2015-1641](https://nvd.nist.gov/vuln/detail/cve-2015-1641 "https://nvd.nist.gov/vuln/detail/cve-2015-1641")
    
- [https://nvd.nist.gov/vuln/detail/cve-2017-0199](https://nvd.nist.gov/vuln/detail/cve-2017-0199 "https://nvd.nist.gov/vuln/detail/cve-2017-0199")
    
- [https://www.cisa.gov/news-events/analysis-reports/ar20-303b](https://www.cisa.gov/news-events/analysis-reports/ar20-303b "https://www.cisa.gov/news-events/analysis-reports/ar20-303b")
    
- [https://unit42.paloaltonetworks.com/sofacy-creates-new-go-variant-of-zebrocy-tool/](https://unit42.paloaltonetworks.com/sofacy-creates-new-go-variant-of-zebrocy-tool/ "https://unit42.paloaltonetworks.com/sofacy-creates-new-go-variant-of-zebrocy-tool/")
    
- [https://unit42.paloaltonetworks.com/dear-joohn-sofacy-groups-global-campaign/](https://unit42.paloaltonetworks.com/dear-joohn-sofacy-groups-global-campaign/ "https://unit42.paloaltonetworks.com/dear-joohn-sofacy-groups-global-campaign/")
    
- [https://www.securityweek.com/researchers-dissect-tool-used-infamous-russian-hacker-group](https://www.securityweek.com/researchers-dissect-tool-used-infamous-russian-hacker-group "https://www.securityweek.com/researchers-dissect-tool-used-infamous-russian-hacker-group")
    
- [https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/ "https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/")
    
- [https://attack.mitre.org/campaigns/C0051/](https://attack.mitre.org/campaigns/C0051/ "https://attack.mitre.org/campaigns/C0051/")
    
- [https://nvd.nist.gov/vuln/detail/cve-2022-38028](https://nvd.nist.gov/vuln/detail/cve-2022-38028 "https://nvd.nist.gov/vuln/detail/cve-2022-38028")
    
- https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/
    
- https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs
    
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/use-cipher-to-overwrite-deleted-data
    
- https://netwrix.com/en/resources/blog/extracting-password-hashes-from-the-ntds-dit-file/
    
- https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/
    
- https://learn.microsoft.com/en-us/mem/intune/protect/certificates-configure
    
- https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/
    
- https://nvd.nist.gov/vuln/detail/CVE-2022-38028
    
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/use-cipher-to-overwrite-deleted-data
  
  


