# Goal
Detect when a SIP provider key has been modified in the Windows registry. This is likely an attempt to bypass code-signing enforcement policies or an attempt to execute code in the address space of all newly created user-mode processes. 

# Categorization
These attempts are categorized as: 
* [Process Injection / Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001)
* [Other sub-techniques of Subvert Trust Controls / SIP and Trust Provider Hijacking](https://attack.mitre.org/techniques/T1443/003).

# Strategy Abstract
The strategy will function as follows: 

* Monitor registry changes in keys:
  * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllGetSignedDataMsg{SIP_GUID}\Dll`
   * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllGetSignedDataMsg{SIP_GUID}\FuncName`
   * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllVerifyIndirectData{SIP_GUID}\Dll`
   * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllVerifyIndirectData{SIP_GUID}\FuncName`
  * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\Providers\Trust\FinalPolicy{trust provider GUID}\Dll`
  * `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\Providers\Trust\FinalPolicy{trust provider GUID}\Function`. 
* Calculate the hash of the file specified in the newly updated `Dll` key.
* Compare the hash to a list of valid SIP providers seen throughout the business.
* Alert on any discrepancies between known SIP provider hashes and current file hash.

# Technical Context
An attacker with administrator privileges can modify the machine registry, forcing Windows to load an arbitrary DLL into all newly created processes (system-wide). Because Windows is responsible for loading the DLL at runtime, this method of code injection will often go overlooked by most security solutions which detect anomalies based on behavioral analytics.

Additionally, the replacement DLL may circumvent code-signing validation and execution prevention policies by returning TRUE via the exported function specified in `HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType0\CryptSIPDllGetSignedDataMsg{SIP_GUID}\FuncName`. Since the process of validating signed binaries on the machine is no longer trustable, a list of valid SIP provider file hashes must be gathered throughout the organization and compared against the new provider to ensure its validity.

# Blind Spots and Assumptions
This strategy relies on the following assumptions: 

* Endpoint tooling is running and functioning correctly on the system.
* Registry changes in Windows are being recorded.
* Logs from endpoint tooling are reported to the server.
* Endpoint tooling is correctly forwarding logs to SIEM.
* SIEM is successfully indexing endpoint tooling logs. 
* A hash can be calculated from the newly updated SIP DLL

A blind spot will occur if any of the assumptions are violated. For instance, the following would trip the alert: 
* A malicious SIP provider already exists in the organization and compromises the baseline.
* Endpoint tooling is modified to not collect registry events or report to the server.

# False Positives
There are several instances where false positives will occur: 

* A valid SIP provider change is performed during a scheduled Windows update and the new provider hash has not yet been seen in the organization.
* The baseline did not include the provider hash.

# Priority
The priority is set to high under all conditions.

# Validation
Validation can occur for this ADS by performing the following execution on a Windows host as Administrator:

```
Set-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}' -Name 'Dll' -value 'C:\Windows\system32\sampledll.dll'
``` 

# Response
In the event that this alert fires, the following response procedures are recommended:

* Compare the new SIP DLL against the baseline entries. 
* Obtain the SIP DLL and validate the signature on a fresh Windows install.
* Look at the execution behavior of the process that modified the registry. 
  * Has it made any unusual network connections?
  * Has it spawned any child processes?
  * Has it made any suspicious file modifications?
If the binary is not trustworthy, or cannot be traced to a legitimate installed application, treat it as a potential compromise and escalate to a security incident.

# Additional Resources
* [Sigthief](https://github.com/secretsquirrel/SigThief)
