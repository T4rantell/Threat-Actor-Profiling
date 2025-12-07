
# Bulletin Metadata 

DATE: November 24th 2025 

CONFIDENCE: 1 - Confirmed 

TLP: CLEAR

Threat Actor: APT29 (COZY BEAR)

Location: Russia

Victim Location: Global, USA, EU 

Sectors: Governmental, Diplomatic, Think-tank, Healthcare, Pharmaceutical, Energy

Motivation: Politics, Retaliation

# Threat Actor

APT29, also known as "Cozy Bear", is a threat group associated with Russia's Foreign Intelligence Service (SVR). This group has been active since at least 2008.

Their activity is predominantly focused on intelligence collection rather than disruption.

The intelligence collection operations conducted against governmental organizations, political groups, think tanks and various individuals involved in defense, reflect the strategic and geopolitical interests of the Russian government. 
 
The actor’s operations are typically highly covert, leveraging spear-phishing, credential harvesting, and living-off-the-land techniques to evade detection. APT29 leverages custom malware families as well as modular backdoors to achieve persistance.
 
This Actor has demonstrated capabilities to mantain operational secrecy, to abuse legitimate cloud services, and to conduct supply-chain attacks to access high-value targets.

Some of their most relevant attack campaigns and targets include:

| Year      | Targets                                                                                          |
| --------- | ------------------------------------------------------------------------------------------------ |
| 2014      | "White House"/"State Department"                                                                 |
| 2015-2016 | "Democratic National Committee"                                                                  |
| 2017      | "Norwegian Police Security Service"                                                              |
| 2019      | Multiple European and US: "Ministry of Foreign Affairs"                                          |
| 2020      | Supply chain SolarWinds ("StellarParticle"), multiple organizations involved in COVID-19 vaccine |
# Historical Campaigns 

## APT29 attack on "White House"/"State Department"

Sometime before October 2014, the White House and State Department were the targets of a cyber-espionage attack. The precise time frame of the breach is unknown. It's still unclear what vector the attackers used to access these networks. Officials did not disclose the precise number/sensitivity of the stolen data. The Actor gained access to unclassified but sensitive information, including President Obama's emails and his schedule. According to unnamed government sources, the intrusion was routed through computer around the world. Consequently the White House and the State Department partially shut down their email systems, forcing officials involved in the Iranian nuclear negotiations to communicate through personal email accounts. Government investigators from the FBI, U.S. Secret Service, and the U.S. intelligence community believed the Actor was working for the Russian government. At the same time private cybersecurity firms have attributed the attack to APT29. The Obama administration refused to reveal its conclusions about who was responsible for the intrusion. 

## APT29 attack on "Democratic National Committee"

From July 2015, the Democratic National Committee (DNC) was the target of a cyber-espionage operation. The Actor managed to operate within DNC systems for almost a year. The attack was carried through a malware dropper delivered through Spear-Phishing emails. Once inside the network the Actor focussed on persistence and lateral movement. Over many months APT29 monitored and exfiltrated sensitive communications and documents. Starting from June 22nd, 2016, Wikileaks released different batches of emails, causing politcal fallout and undermining public trust in the party.

During a short period of time there was a second group present in the DNC Servers, APT28 (Fancy Bear): the groups appeared to be unaware of each other, both independently stealing the same credentials. The Actor's (APT29) breach was only uncovered when the presence of APT28 inside the network was discovered.

## APT29 attack on "Norwegian Police Security Service"

In January 2017, the Norwegian Police Security Service (PST) and several other Norwegian government entities were targeted, among others, during APT29's "Operation Ghost".

Public OSINT sources report that the operation primarily involved spear-phishing emails directed at Norwegian government officials, including employees from PST, the Ministry of Defence, the Ministry of Foreign Affairs, a national radiation authority, and a political party.

The precise timeframe of the campaign is uncertain, and the exact vector used by the attackers remains publicly undisclosed.

## APT29 attack on Multiple European and US: "Ministry of Foreign Affairs"

Sometime before October 2019, the Actor resumed its cyber‑espionage operations against diplomatic networks, targeting the Ministries of Foreign Affairs of at least three European countries, as well as the embassy in Washington, D.C., of an EU member state. The intrusion was uncovered by researchers at ESET, who named it "Operation Ghost".

The Operation likely began as early as 2013, the initial vector used to access these networks has not been publicly disclosed. 

The Actor gained access to sensitive communications, diplomatic documents, and internal policy information. The intrusion involved previously undocumented malware variants, such as PolyglotDuke, RegDuke, and FatDuke, which were designed for stealthy persistence and data exfiltration, using covert channels and steganography techniques.

Specific operational responses have not been publicly detailed.

# Attacker’s Malwares

Here we have a list with some of the most used malwares for theActor, covering general description, usual delivery/deployment methods and capabilities.

## CozyCar (CozyDuke) 

CozyCar is a modular second-stage backdoor used in long-term espionage operations. Its main functions include command execution, system reconnaissance, file exfiltration, credential harvesting, and deployment of additional payloads.

It's been tipically spread via Spear-Phishing attacks, containing malicious attachments or links leading the victims to download ZIP files.

CozyCar components appear to be installed in a multi-stage sequence, with a Windows registry, or scheduled tasks being added in the first place to achieve persistence. The malware is able to identifiy and avoid security products on the system. It enstablish an encrypted connection to its C2 infrastructure, from here it retrieves additional modules, such as keylogging, file enumeration, screen capture, credential dumping tools, depending on the use case. This approach minimizes detection during early execution.

## SeaDuke

SeaDuke is simple cross-platform backdoor written in Python, designed to work on both Windows and Linux. Its main functions are C2 communication, command execution, file upload and download, system commands execution and Python code evaluation.

The only known infection vector is via an existing CozyDuke infection, wherein it gets downloaded and executed. For APT29 it's a first in Linux platforms exploitation malwares. It relies on a shared code framework and a single loader.

When the malware initially runs, it will determine the victim's Operating System. The malware is then able to obtain persistance via PowerShell, via the "Run" Registry key or a ".lnk" file stored in the Startup directory. From here it begins to make RC4 encrypted network requests, usually over HTTP/S, to an attacker Server that mimics an HTML page; it will respond with b64-encoded JSON data, containing the commands to be executed. If the decryption does not produce proper JSON data, SeaDuke will discard it and enter a sleep cycle. Multiple layers of obfuscation are set in place to avoid early detection.
## MiniDuke

MiniDuke is a toolset consisting of multiple downloader and backdoor components, some of which are written in Assembly, and a secondary JScript component. Its main functions include C2 communications, data collection, payload encryption and decryption, persistance, file upload and download, code execution.

It's been typically delivered and deployed through malicious document files and exploitation of known vulnerabilities such as: CVE-2013-0640 and CVE-2014-1761.

The malware installation usually begins with a shellcode exploiting one of the CVE mentioned above, checking for the presence of security software. Once MiniDukes receives control it will confirm that is run for the first time, and then proceeds to complete its deployment. It gathers information about the system and uses it to encrypt its configuration, making it impossible to analyze it on a different computer. It then creates an hidden ".lnk" file in the "Startup" directory to obtain persistance. From here it will try to obtain the address of a C2 Server via Twitter, looking for encoded data embedded in specific profiles or images, to which it will send various system information along with a request to download a payload. Obfuscation along with System information based encryption makes it hard to analayze it. 

## CosmicDuke

CosmicDuke is a multi-component malware, compiled using a custom framework called "BotGenStudio". Its main functions include C2 communications, reconnaissance, persistance, code execution, and data harvesting and exfiltration.

Its typically delivered and deployed through Spear-Phishing attacks based on malicious documents attachments, or the exploitation of known vulnerabilities such as: CVE-2010-0232 or CVE-2010-4398. 

CosmicDuke firstly performs checks to detect virtual machines or analysis environment. It then decrypts its configuration using system-specific information. CosmicDuke collects the same information along with running processes and stored credentials. It will try to spoof popular applications file information, icons and even file size to run undisturbed in the background.  It tries to establish persistance trough Registry keys or scheduled tasks. From here it starts a series of harvesting routines to enumerate file, log keystrokes and take screenshots. This data get encrypted before being transmitted to its C2 architecture, through small chunks of data over encrypted communication channels, disguising the traffic using padding. The malware remains active in the background waiting for the actor to send new instructions. The layers of obfuscation, system-specific encryption, and low-profile exfiltration makes it hard to detect.

# APT29 "StellarParticle" in-depth analysis  

From August 2019 to January 2021, the actor conducted a sophisticated supply chain cyber operation, against SolarWinds' Orion product, discovered in mid-December 2020. The US government assessed that approximately 18,000 public and private customers of were infected, but only a much smaller number of victims were compromised by follow-on APT29 activity on their systems.

The actor used customized malware to inject malicious code into the Orion software build process, later distributed through a normal software update. APT29 leveraged Password Spraying attacks, Token theft, API abuse, Spear-Phishing and other supply chain attacks to compromise user accounts and exploit their associated access. Among the victims of this campaign we can find governments, consulting, technology, telecomunications and other organizations in North America, Europe, Asia and the Middle East such as: Homeland Security, State, Commerce and Treasury, FireEye, Microsoft, Intel, Cisco and Deloitte.

The breadth of the hack is unprecedented and one of the largest of its kind ever recorded. Since the hack exposed the inner workings of Orion users, the hackers could potentially gain access to the data and networks of their customers and partners as well.

The breach was first detected by the affected cybersecurity company "FireEye", that confirmed their malware infection when they saw it spread into its customer's systems. FireEye was able to identify the backdoor used to gain access to its systems and named it "SUNBURST". 

The attackers managed the intrusion through multiple servers based in the United States, and mimicked legitimate network traffic. By doing this they were able to cirumvent threat detection techniques employed by both SolarWinds and its affected customers.

To avoid detection the Actor prefers to maintain a light malware footprint, preferring legitimate credentials and remote access to reach into a victim's environment.

Notably in its post-compromise tactics the Actor:

- Used Hostnames matching the victim environment;
- Used IP Addresses located in the victmin country;
- Used temporary File Replacement and Temporary Task modification;
- Achieved Lateral Movement by using different Credentials.

Suspected nation-state hackers based in China, exploited SolarWinds during the same period of time, targeting the "National Finance Center", a US Department of Agriculture payroll agency, using a different malware identified as "Supernova".

The hack has become a catalyst for rapid and broad change in the cybersecurity industry, causing many companies and government agencies to began a process of devising new methods to react to these types of attacks. Notably the U.S. Cybersecurity and Infrastructure Security Agency issued guidance on software supply chain compromise mitigations, with specific tactical recommendations for identification and removal of exploited components.

In June 2023, the U.S. Securities and Exchange Commision (SEC) sent SolarWinds a Wells notice at the end of their investigation, informing their intent to recommend civil enforcement action, alleging that SolarWinds broke federal security laws in public statements and internal controls.

In October 2023 the SEC sued SolarWinds and CISO Timothy Brown, stating the company concealed its cybersecurity vulnerabilities before it was attacked. This is the first time the SEC has sued the victim of a cyberattack.

## SUNBURST Backdoor

The backdoor, identified by FireEye, was contained into a digitally-signed component of the Orion software framework: "SolarWinds.Orion.Core.BusinessLayer.dll".

After an initial dormant period of up to two weeks, it retrieves and executes commands, with the ability to transfer files, execute files, profile the system, reboot the machine and disable system services.

The malware masqueraded its traffic as the "Orion Improvement Program" protocol (OIP), storing reconnaissance results within legitimate plugin configuration files.

The backdoor uses multiple obfuscated blocklists to identify forensic and anti-virus tools running on the system.

Multiple trojanized updates were digitally signed from March 2020 till May 2020, and posted on the SolarWinds updates website.

The update package "CORE-2019.4.5220.20574-SolarWinds-Core-v2019.4.5220-Hotfix5.msp" contains the DLL described in this report.

The update file is a standard Windows Installer Patch, that uses compressed resources, including the "SolarWinds.Orion.Core.BusinessLayer.dll".

Once installed, the malicious DLL, will be loaded by the legitimate "SolarWinds.BusinessLayerHost.exe"/"SolarWinds.BusinessLayerHostx64.exe", depending on the system configuration.

The class "SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer" implements an HTTP-based backdoor. Code within the logically unrelated routine "SolarWinds.Orion.Core.BusinessLayer.BackgroundInventory.InventoryManager.RefreshInternal" invokes the backdoor code when the Inventory Manager plugin is loaded.

On execution of the malicious "SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Initialize" method the sample verifies that its lower case process name hashes to the value "17291806236368054941". This hash value is calculated as the standard FNV-1A 64-bit hash with an additional XOR by "6605813339339102567" after computing the FNV-1A.

The sample only executes if the filesystem write time of the assembly is at least 12 to 14 days prior to the current time. Once the threshold is met, the sample creates the named pipe "583da945-62af-10e8-4902-a8f205c72b2e" to verify that only one instance is running before reading "SolarWinds.Orion.Core.BusinessLayer.dll.config" from disk and retrieving the XML field "appSettings".

The "appSettings" fields gets repurposed as a persistent configuration, to continue with its execution the key "ReportWatcherRetry" must be any value other than 3.

The malware checks that the machine is domain joined, and retrieves the domain name. A "userID" is generated by computing the MD5 of a network interface MAC Address, that is up and not a loopback device, togheter with the domain name and the registry value "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid". The "userID" is then encoded through a custom XOR scheme.

The "ReportWatcherPostpone" key of "appSettings" is then read from "SolarWinds.Orion.Core.BusinessLayer.dll.config" to retrieve the initial, legitimate value. This will be used later to read out bit packs flags, injected into this field, and differentiate them from the initial value.

The sample then invokes the "Update" method which is the core event loop of the sample.

Process name, service name, and driver path listings are obtained, and each value is hashed via the FNV-1a + XOR algorithm and checked against hardcoded blocklists: these routines are scanning for analysis tools and antivirus engine components.

The blocklisted services are stopped by setting their "HKLM\SYSTEM\CurrentControlSet\services\<service_name>\Start registry" entries to value 4 (disabled). The list of stopped services is then bit-packed into the "ReportWatcherPostpone" key of the "appSettings".

If any service was transitioned to "disabled" the "Update" method exits and retries later. The sample retrieves a driver listing via the WMI query:

	Select * From Win32_SystemDriver

If any blocklisted driver is seen the "Update" method exits and retries.

If all blocklist tests pass, the sample tries to resolve "api.solarwinds.com" to test the network for connectivity.

If all blocklist and connectivity checks pass, the malware will attempt to resolve a subdomain of "avsvmcloud[.]com", by using a Domain Generation Algorithm. It will receive a CNAME record pointing to a C2 domain. 

Once a domain has been successfully retrieved, the sample will spawn a new thread of execution invoking the method "HttpHelper.Initialize which is responsible" for all C2 communications and dispatching.

The malware uses HTTP GET or HTTP POST requests. If the sample is attempting to send outbound data the "content-type" header will be set to "application/octet-stream" otherwise to "application/json". 

A JSON payload is present for all POST and PUT requests and contains the keys:

- “userId”
- “sessionId”
- “steps”.
 
The “steps” field contains a list of objects with the following keys:

- “Timestamp”
- “Index”
- “EventType”, hardcoded to the value “Orion”
- “EventName”, hardcoded to “EventManager”
- “DurationMs”
- “Succeeded”
- “Message”, Base64 encoded separately

 Malware responses to send to the server are DEFLATE compressed and single-byte-XOR encoded, then split among the “Message” fields in the “steps” array.
 
Not all objects in the “steps” array contribute to the malware message: the integer in the “Timestamp” field must have the 0x2 bit set to indicate that the contents of the “Message” field are used in the malware message. 

Step objects whose bit 0x2 is clear in the Timestamp field contain random data and are discarded when assembling the malware response.

The C2 traffic is designed to mimic normal SolarWinds API communications.

Multiple SUNBURST samples have been recovered, delivering different payloads. In at least one instance the attackers deployed a novel memory-only dropper therefore named "TEARDROP", to deploy Cobalt Strike BEACON.

A malicious tool, name "SUNSPOT" was deployed into the build environment to inject this Backdoor into the Orion platform without arousing any suspicion. In addition several safeguards were added to "SUNSPOT" to avoid the Orion builds from failing, and raising errors, potentially alerting developers of the adversary’s presence.
## SUNSPOT Implant

SUNSPOT is an implant that injected the SUNBURST backdoor into the SolarWinds Orion software update framework. A lot of effort was invested to ensure the code was properly inserted and remained undetected, prioritizing operational security, to avoid revealing the Actor presence in the build environment to SolarWinds developers. The Actor maintened persistence by creating a scheduled task set to execute when the host boots.

It's still unclear how the Actor managed to initially deploy this malware inside the SolarWinds build environment. Theories include credential theft, abuse of Orion test systems, exploitation of Orion build servers, or lateral movement after earlier footholds but none are confirmed.

When SUNSPOT gets executed, it ensures that only one instance is running, by using a mutual exclusion (mutex) synchronization primitive.

It then creates an RC4 encrypted log file under "C:\Windows\Temp\vmware-vmdmp.log", throughout execution SUNSPOT will log errors to this file, along with other deployment information. 

This log entries begin with the number of seconds elapsed since the first log line, and if they're referring to an occurred error, they contain a step number associated with a specific malware action:

| **Step In Log File** | **Meaning**                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| START                | Logged after the initialization has completed successfully                                                                     |
| Step1                | Original file cannot be restored after tampering with the build process                                                        |
| Step2                | Could not decrypt one of the targeted source code file’s path (relative to the solution directory)                             |
| Step3                | Could not create the file path for the targeted source code file                                                               |
| Step4                | Could not get the size of the original source code file                                                                        |
| Step5                | Computation of the MD5 hash of the original source file failed                                                                 |
| Step6                | There was a mismatch between the expected target original source code file MD5 hash and the expected value                     |
| Step7                | Could not successfully decrypt the backdoored source code                                                                      |
| Step8                | Computation of the MD5 hash of the backdoored source code failed                                                               |
| Step9                | There was a mismatch between the expected backdoored source code data MD5 hash and the expected value                          |
| Step10               | Could not create backup of the original source code file                                                                       |
| Step11               | Could not write the backdoored source code to disk (in the .tmp file)                                                          |
| Step12               | Could not copy the temporary file with the backdoored source code (with the .tmp extension) to the path of the original source |
| Step14               | Could not read the MsBuild.exe process memory to resolve its command-line arguments                                            |
| Step15               | The returned PEB address for the remote process is zero                                                                        |
| Step16               | Calling NtQueryInformationProcess failed                                                                                       |
| Step17               | Could not create a handle to the MsBuild.exe process with SYNCHRONIZE access                                                   |
| Step18               | Could not successfully wait for the MsBuild.exe process termination                                                            |
| Step19               | Obtention of the address of the NtQueryInformationProcess function failed                                                      |
| Step20               | Modification of the process security token to obtain SeDebugPrivileges failed                                                  |
| Step21               | The number of currently running tampering threads exceeded 256, and SUNSPOT cannot track more threads                          |
| Step22               | Unable to get a list of running processes                                                                                      |
| Step23               | There was an error when enumerating the running processes list                                                                 |
| Step30               | Could not decrypt the solution name core.sln                                                                                   |

The malware then grants itself debugging privileges by modifying its security token to add "SeDebugPrivilege". This is a prerequisite to the remainder of the malware execution, which involves reading other processes memory.

SUNSPOT then starts to monitor running processes for instances of "MsBuild.exe", a part of Microsoft Visual Studio development tools.

When it finds one, It will spawn a new thread to determine if the Orion software is being built and, if so, hijack the build operation to inject SUNBURST. The monitoring loop executes every second, allowing SUNSPOT to modify the target source code before it has been read by the compiler.

The malware checks for the presence of a second mutex, if it is found the backdoor interprets it as a s signal to quit, after the completion of its running threads: this functionality was likely intended to be used to discreetly stop the malware, instead of killing the process risking detection. 

The malware extracts the command-line arguments for each running "MsBuild.exe" process from the virtual memory, looking for the directory path of the Orion software Visual Studio solution:

 - A call to "NtQueryInformationProcess" allows the adversary to obtain a pointer to the remote process’s "Process Environment Block" (PEB), which contains a pointer to a "\_RTL\_USER\_PROCESS\_PARAMETERS" structure. 
 - By reading its content is possible to obtain the full command line passed to the "MsBuild.exe".

Once SUNSPOT has found a "MsBuild.exe" using the Orion file path, it replaces a source code file "InventoryManager.cs" in the solution directory, with a malicious variant to inject SUNBURST while Orion is being built. 

Before the substitution occurs, there's a hash verification check, to ensure the injected code is compatible and didn't get corrupted.

The original source file is copied with a ".bk" extension to back up the original content. The backdoored source is written to the same filename, but with a ".tmp" extension, and then moved using "MoveFileEx".

After these steps, the source file backdoored with SUNBURST will then be compiled as part of the standard process. 

SUNSPOT appends an entry in the log file ("vmware-vmdmp.log") with the date and time of the backdoor attempt and waits for the "MsBuild.exe" process to exit before restoring the original source code and deleting the temporary "InventoryManager.bk" file.

If the Orion solution build is successful, it is backdoored with SUNBURST.

## TEARDROP

TEARDROP is a memory only dropper, it runs as a service, spawns a thread and reads from the file "gracious_truth.jpg", which likely has a fake JPG header. It then checks for "HKU\SOFTWARE\Microsoft\CTF" existance, decodes an embedded payload using a custom XOR algorithm, and manually loads into memory an embedded payload using a custom PE-like format. It's believed that this was used to execute a customized Cobalt Strike BEACON.

# TTPs (Mitre ATT&CK)

## Techniques Used

| **ID**    | **Description**                  |
| --------- | -------------------------------- |
| T1012     | Query Registry                   |
| T1027     | Obfuscated Files or Information  |
| T1057     | Process Discovery                |
| T1071.004 | Application Layer Protocol: DNS  |
| T1083     | File and Directory Discovery     |
| T1195.002 | Compromise Software Supply Chain |
| T1518.001 | Security Software Discovery      |
| T1543.003 | Windows Service                  |
| T1553.002 | Code Signing                     |
| T1568.002 | Domain Generation Algorithms     |
| T1569.002 | Service Execution                |
| T1584     | Compromise Infrastructure        |


# Yara rules

## SUNBURST

```
import "pe"

rule APT_Backdoor_MSIL_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}
rule APT_Backdoor_MSIL_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}
rule APT_Backdoor_MSIL_SUNBURST_3
{
    meta:
        author = "FireEye"
        description = "This rule is looking for certain portions of the SUNBURST backdoor that deal with C2 communications. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $sb1 = { 05 14 51 1? 0A 04 28 [2] 00 06 0? [0-16] 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F [1-32] 03 0? 05 28 [2] 00 06 0? [0-32] 03 [0-16] 59 45 06 }
        $sb2 = { FE 16 [2] 00 01 6F [2] 00 0A 1? 8D [2] 00 01 [0-32] 1? 1? 7B 9? [0-16] 1? 1? 7D 9? [0-16] 6F [2] 00 0A 28 [2] 00 0A 28 [2] 00 0A [0-32] 02 7B [2] 00 04 1? 6F [2] 00 0A [2-32] 02 7B [2] 00 04 20 [4] 6F [2] 00 0A [0-32] 13 ?? 11 ?? 11 ?? 6E 58 13 ?? 11 ?? 11 ?? 9? 1? [0-32] 60 13 ?? 0? 11 ?? 28 [4] 11 ?? 11 ?? 9? 28 [4] 28 [4-32] 9? 58 [0-32] 6? 5F 13 ?? 02 7B [2] 00 04 1? ?? 1? ?? 6F [2] 00 0A 8D [2] 00 01 }
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_MSIL_SUNBURST_4
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific methods used by the SUNBURST backdoor. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
        $ss5 = "\x00ExecuteEngine\x00"
        $ss6 = "\x00ParseServiceResponse\x00"
        $ss7 = "\x00RunTask\x00"
        $ss8 = "\x00CreateUploadRequest\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}
rule APT_Dropper_Win64_TEARDROP_2
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
```

## SUNSPOT

```
rule CrowdStrike_SUNSPOT_01 : artifact stellarparticle sunspot {`    `meta:           copyright = "(c) 2021 CrowdStrike Inc."           description = "Detects RC4 and AES key encryption material in SUNSPOT"`        `version = "202101081448"           last_modified = "2021-01-08"           actor = "StellarParticle"           malware_family = "SUNSPOT"`    `strings:`        `$key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}           $iv  = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}`    `condition:           all of them and filesize < 32MB``   }``   rule CrowdStrike_SUNSPOT_02 : artifact stellarparticle sunspot   {`    `meta:           copyright = "(c) 2021 CrowdStrike Inc."           description = "Detects mutex names in SUNSPOT"           version = "202101081448"           last_modified = "2021-01-08"           actor = "StellarParticle"           malware_family = "SUNSPOT"`    `strings:           $mutex_01 = "{12d61a41-4b74-7610-a4d8-3028d2f56395}" wide ascii           $mutex_02 = "{56331e4d-76a3-0390-a7ee-567adf5836b7}" wide ascii`    `condition:           any of them and filesize < 10MB``   }``rule CrowdStrike_SUNSPOT_03 : artifact logging stellarparticle sunspot` `   {`    `meta:           copyright = "(c) 2021 CrowdStrike Inc."           description = "Detects log format lines in SUNSPOT"           version = "202101081443"           last_modified = "2021-01-08"           actor = "StellarParticle"           malware_family = "SUNSPOT"`    `strings:           $s01 = "[ERROR] ***Step1('%ls','%ls') fails with error %#x***\x0A" ascii           $s02 = "[ERROR] Step2 fails\x0A" ascii           $s03 = "[ERROR] Step3 fails\x0A" ascii           $s04 = "[ERROR] Step4('%ls') fails\x0A" ascii           $s05 = "[ERROR] Step5('%ls') fails\x0A" ascii           $s06 = "[ERROR] Step6('%ls') fails\x0A" ascii           $s07 = "[ERROR] Step7 fails\x0A" ascii           $s08 = "[ERROR] Step8 fails\x0A" ascii           $s09 = "[ERROR] Step9('%ls') fails\x0A" ascii           $s10 = "[ERROR] Step10('%ls','%ls') fails with error %#x\x0A" ascii           $s11 = "[ERROR] Step11('%ls') fails\x0A" ascii           $s12 = "[ERROR] Step12('%ls','%ls') fails with error %#x\x0A" ascii           $s13 = "[ERROR] Step30 fails\x0A" ascii           $s14 = "[ERROR] Step14 fails with error %#x\x0A" ascii           $s15 = "[ERROR] Step15 fails\x0A" ascii           $s16 = "[ERROR] Step16 fails\x0A" ascii           $s17 = "[%d] Step17 fails with error %#x\x0A" ascii           $s18 = "[%d] Step18 fails with error %#x\x0A" ascii           $s19 = "[ERROR] Step19 fails with error %#x\x0A" ascii           $s20 = "[ERROR] Step20 fails\x0A" ascii           $s21 = "[ERROR] Step21(%d,%s,%d) fails\x0A" ascii           $s22 = "[ERROR] Step22 fails with error %#x\x0A" ascii           $s23 = "[ERROR] Step23 fails with error %#x\x0A" ascii           $s24 = "[%d] Solution directory: %ls\x0A" ascii           $s25 = "[%d] %04d-%02d-%02d %02d:%02d:%02d:%03d %ls\x0A" ascii           $s26 = "[%d] + '%s' " ascii`    `condition:           2 of them and filesize < 10MB   }
```

# References 

- https://attack.mitre.org/groups/G0016/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a
- https://www.hivepro.com/wp-content/uploads/2024/07/TA2024255.pdf
- https://mac.kaspersky.es/enterprise-security/mitre/apt29
- https://blogs.vmware.com/security/2020/03/the-dukes-of-moscow.html
- https://attack.mitre.org/software/S0046/
- https://attack.mitre.org/software/S0559
- https://attack.mitre.org/software/S0560
- https://attack.mitre.org/software/S0562/
- https://media.defense.gov/2020/Jul/16/2002457639/-1/-1/0/NCSC_APT29_ADVISORY-QUAD-OFFICIAL-20200709-1810.PDF
- https://blackpointcyber.com/wp-content/uploads/2024/06/Threat-Profile-APT29_Blackpoint-Adversary-Pursuit-Group-APG_2024.pdf
- https://securelist.com/the-cozyduke-apt/69731/
- https://blog-assets.f-secure.com/wp-content/uploads/2020/03/18122307/F-Secure_Dukes_Whitepaper.pdf
- https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/
- https://archive.f-secure.com/weblog/archives/00002822.html
- https://www.welivesecurity.com/2014/05/20/miniduke-still-duking
- https://static.crysys.hu/publications/files/technical-reports/miniduke_indicators_public.pdf
- https://nvd.nist.gov/vuln/detail/CVE-2013-0640
- https://nvd.nist.gov/vuln/detail/CVE-2014-1761
- https://securelist.com/miniduke-is-back-nemesis-gemina-and-the-botgen-studio/64107/
- https://nvd.nist.gov/vuln/detail/CVE-2010-4398
- https://nvd.nist.gov/vuln/detail/CVE-2010-0232
- https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
- https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
- https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
- https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
- https://www.rand.org/content/dam/rand/pubs/research_reports/RRA1100/RRA1190-1/RAND_RRA1190-1.pdf
- https://asamborski.github.io/cs558_s17_blog/2017/02/24/dnc.html
- https://www.matisoftlabs.com/case-studies/apt29
- https://cyberlaw.ccdcoe.org/wiki/APT-29_cyber_operations_against_government_agencies_of_Norway_and_the_Netherlands_%282016-2017%29
- https://cyberlaw.ccdcoe.org/wiki/APT-29_cyber_operations_against_government_agencies_of_Norway_and_the_Netherlands_%282016-2017%29
- https://web-assets.esetstatic.com/wls/2019/10/ESET_Operation_Ghost_Dukes.pdf
- https://apt.etda.or.th/img/Threat_Group_Cards_v2.0.pdf
- https://www.welivesecurity.com/2019/10/17/operation-ghost-dukes-never-left/
- https://www.securityweek.com/russian-hackers-silently-hit-government-targets-years/
- https://www.eset.com/au/about/newsroom/press-releases1/press-releases/operation-ghost-the-dnc-hacking-group-dukes-still-attacks-government-targets-eset-discovers-4/
- https://www.darkreading.com/threat-intelligence/cozy-bear-emerges-from-hibernation-to-hack-eu-ministries
