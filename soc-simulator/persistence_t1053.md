# Simulator SOC - Persistence : T1053

This report documents the investigation of multiple alerts from a SOC Simulator of TryHackMe.
The only two alerts come from scheduled tasks.

The objective of this report is to document the analyst’s investigation process, evidence correlation, and incident response decisions.

---

This is the first alert that we receive :

```log
Description: This alert fires when Windows Security logs the creation of a scheduled task on THM-Luke. Analysts must review the task definition, payload path, and registering account to decide whether it matches an approved baseline or represents suspicious persistence. Account_Domain: THM-LUKE Account_Name: Administrator ClientProcessId: 4328 ComputerName: THM-Luke Error_Code: - EventCode: 4698 EventType: 0 FQDN: 0 Keywords: Audit Success LogName: Security Logon_ID: 0xB61EF Message: A scheduled task was created. Subject: Security ID: S-1-5-21-1927039393-948638853-243650942-500 Account Name: Administrator Account Domain: THM-LUKE Logon ID: 0xB61EF Task Information: Task Name: \IT-WeeklyDiskCleanup Task Content: <?xml version="1.0" encoding="UTF-16"?><Task version="1.3"><RegistrationInfo><Description>Weekly disk cleanup - IT Operations maintenance. CR-2024-1234</Description><URI>\IT-WeeklyDiskCleanup</URI></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2025-11-10T14:00:00Z</StartBoundary><Enabled>true</Enabled><ScheduleByWeek><DaysOfWeek><Sunday/></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger></Triggers><Principals><Principal id="Author"><UserId>THM-LUKE\Administrator</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT72H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context="Author"><Exec><Command>cleanmgr.exe</Command><Arguments>/sagerun:65535</Arguments></Exec></Actions></Task> Other Information: ProcessCreationTime: 5910974510923867 ClientProcessId: 4328 ParentProcessId: 876 FQDN: 0 OpCode: Info RecordNumber: 43961 Security_ID: S-1-5-21-1927039393-948638853-243650942-500 SourceName: Microsoft Windows security auditing. Subject_Account_Domain: THM-LUKE Subject_Account_Name: Administrator Subject_Logon_ID: 0xB61EF Subject_Security_ID: S-1-5-21-1927039393-948638853-243650942-500 TaskCategory: Other Object Access Events Task_Name: \IT-WeeklyDiskCleanup Type: Information _time: 2025-11-04T10:56:37.000+0000 action: created category: Other Object Access Events change_type: scheduled task dest: THM-Luke event_id: 43961 host: THM-LUKE index: corp object: \IT-WeeklyDiskCleanup object_category: scheduled task product: Windows result: A scheduled task was created session_id: 0xB61EF severity: informational signature: A scheduled task was created signature_id: 4698 source: WinEventLog:Security status: success user: Administrator vendor: Microsoft vendor_product: Microsoft Windows
```

The first step is to analyse it

#### Event details :

| Signature id : 4698 |
Event type : 0 |
Logname : Security |
Source Name : Microsoft Windows security auditing |
Keywords : Audit Success |
TaskCategory : Other Object Access Events |
OpCode : Info |
Type : Information |

#### Host Information :

| ComputerName : THM-Luke |
FQDN : 0 |
Domain : THM-LUKE |

#### Account Information :

| Account_Name : Administrator |
Account_Domain : THM-LUKE |
Security_ID : S-1-5-21-1927039393-948638853-243650942-500 |
Logon_ID : 0xB61EF |

#### Process Information :

| ClientProcessId : 4328 |
ParentProcessId : 876 |
ProcessCreationTime : 5910974510923867 |

#### Task Information :

| Task Name : \IT-WeeklyDiskCleanup |
Description : Weekly disk cleanup - IT Operations maintenance. CR-2024-1234 |
Trigger : Weekly (Sunday) |
User Id : THM-LUKE\Administrator |
Command : cleanmgr.exe |

#### Timestamp :

| Event Time: 2025-11-04 10:56:37 UTC |

It seems to be a legitimate scheduled task. The command cleanmgr.exe is a real tool of Microsoft and nothing is suspicious.

---

This is the second alert that we receive :

```log
Description: This alert fires when Windows Security logs the creation of a scheduled task on THM-Luke. Analysts must review the task definition, payload path, and registering account to decide whether it matches an approved baseline or represents suspicious persistence. Account_Domain: THM-LUKE Account_Name: luke.s ClientProcessId: 4328 ComputerName: THM-Luke Error_Code: - EventCode: 4698 EventType: 0 FQDN: 0 Keywords: Audit Success LogName: Security Logon_ID: 0x20D5BE Message: A scheduled task was created. Subject: Security ID: S-1-5-21-1927039393-948638853-243650942-1001 Account Name: luke.s Account Domain: THM-LUKE Logon ID: 0x20D5BE Task Information: Task Name: \UpgradeRAMExtreme Task Content: <?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>Upgrade RAM Extreme startup task.</Description><URI>\UpgradeRAMExtreme</URI></RegistrationInfo><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT72H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context="Author"><Exec><Command>C:\Users\luke.s\AppData\Local\Temp\272b5c05-78da-492b-afcb-8a17ce1f3333_UpgradeRAMExtreme.zip.333\UpgradeRAMExtreme.exe</Command></Exec></Actions></Task> Other Information: ProcessCreationTime: 5910974510923867 ClientProcessId: 4328 ParentProcessId: 876 FQDN: 0 OpCode: Info ParentProcessId: 876 ProcessCreationTime: 5910974510923867 RecordNumber: 44053 Security_ID: S-1-5-21-1927039393-948638853-243650942-1001 SourceName: Microsoft Windows security auditing. Subject_Account_Domain: THM-LUKE Subject_Account_Name: luke.s Subject_Logon_ID: 0x20D5BE Subject_Security_ID: S-1-5-21-1927039393-948638853-243650942-1001 TaskCategory: Other Object Access Events TaskContent: <?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>Upgrade RAM Extreme startup task.</Description><URI>\UpgradeRAMExtreme</URI></RegistrationInfo><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT72H</ExecutionTimeLimit><Priority>7</Priority></Settings><Actions Context="Author"><Exec><Command>C:\Users\luke.s\AppData\Local\Temp\272b5c05-78da-492b-afcb-8a17ce1f3333_UpgradeRAMExtreme.zip.333\UpgradeRAMExtreme.exe</Command></Exec></Actions></Task> Task_Content: <?xml version="1.0" encoding="UTF-16"?> Task_Name: \UpgradeRAMExtreme Type: Information _raw: 11/04/2025 10:58:35 AM LogName=Security EventCode=4698 EventType=0 ComputerName=THM-Luke SourceName=Microsoft Windows security auditing. Type=Information RecordNumber=44053 Keywords=Audit Success TaskCategory=Other Object Access Events OpCode=Info Message=A scheduled task was created. Subject: Security ID: S-1-5-21-1927039393-948638853-243650942-1001 Account Name: luke.s Account Domain: THM-LUKE Logon ID: 0x20D5BE Task Information: Task Name: \UpgradeRAMExtreme Task Content: <?xml version="1.0" encoding="UTF-16"?><Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">...</Task> _time: 2025-11-04T10:58:35.000+0000 action: created app: win:unknown body: A scheduled task was created category: Other Object Access Events change_type: scheduled task dest: THM-Luke dest_nt_domain: THM-LUKE dest_nt_host: THM-Luke dvc: THM-Luke dvc_nt_host: THM-LUKE event_id: 44053 eventtype: endpoint_services_processeswindows_event_signaturewindows_security_changewindows_ta_datawineventlog_securitywineventlog_windowswinsec host: THM-LUKE id: 44053 index: corp member_dn: luke.s member_id: S-1-5-21-1927039393-948638853-243650942-1001 name: A scheduled task was created object: \UpgradeRAMExtreme object_attrs: <?xml version="1.0" encoding="UTF-16"?><Task version="1.3"...></Task> object_category: scheduled task product: Windows result: A scheduled task was created session_id: 0x20D5BE severity: informational severity_id: 0 signature: A scheduled task was created signature_id: 4698 source: WinEventLog:Security sourcetype: WinEventLog src_nt_domain: S-1-5-21-1927039393-948638853-243650942-1001 src_subject_security_id: S-1-5-21-1927039393-948638853-243650942-1001 status: success subject: A scheduled task was created ta_windows_action: failure tag: changeossecuritytrack_event_signatureswindows tag::eventtype: changeossecuritytrack_event_signatureswindows user: luke.s user_name: luke.s vendor: Microsoft vendor_product: Microsoft Windows timestamp: 02/16/2026 16:57:51.135 datasource: WinEventLog:Security
``` 
If we analyse it, we've got this : 

#### Event details :

| Signature id : 4698 |
Event type : 0 |
Logname : Security |
Source Name : Microsoft Windows security auditing |
Keywords : Audit Success |
TaskCategory : Other Object Access Events |
OpCode : Info |
Type : Information |

#### Host Information :

| ComputerName : THM-Luke |
FQDN : 0 |
Domain : THM-LUKE |

#### Account Information :

| Account_Name : Administrator |
Account_Domain : THM-LUKE |
Security_ID : S-1-5-21-1927039393-948638853-243650942-1001 |
Logon_ID : 0x20D5BE |

#### Process Information :

| ClientProcessId : 4328 |
ParentProcessId : 876 |
ProcessCreationTime : 5910974510923867 |

#### Task Information :

| Task Name : \UpgradeRAMExtreme |
Description : Upgrade RAM Extreme startup task. |
Trigger : System Startup (BootTrigger) |
User Id : S-1-5-18 --> NT AUTHORITY\SYSTEM |
Command : C:\Users\luke.s\AppData\Local\Temp\272b5c05-78da-492b-afcb-8a17ce1f3333_UpgradeRAMExtreme.zip.333\UpgradeRAMExtreme.exe |

#### Timestamp :

| Event Time: 02/16/2026 16:57:51.135 UTC |

Multiple things seems suspicious with this alert.

- The first thing is the name : UpgradeRAMExtreme.
The "Extreme" is not necessary and not pro, and no approved/known baseline reference observed for this task name in the provided context.

- The second thing is the directory "Temp". If it was really a legitimate task, it will be not in this directory.

- The third thing is the abnormal extension ".zip.333".
It is not a standart file extension for windows and it suggests obfuscation or staging artifact.

Due to the proof we've got, the next step is to report this alert.

---

#### Time of activity : 

02/16/2026 16:57:51.135 UTC

#### List of Affected Entities : 

- ComputerName : THM-Luke
- User: luke.s
- Process: BootTrigger
- Script: UpgradeRAMExtreme.exe

#### Reason for classifying as True Positive : 

- Execution context: S-1-5-18 (NT AUTHORITY\SYSTEM) with Highest Available privileges
- Payload path in the user directory temporary
- Abnormal .zip.333 staging pattern

#### Reason for escalating the Alert : 

- The trigger is a BootTrigger, this establishes a startup persistence.

#### Recommended Remediation Actions :

- Isolate host THM-Luke from the network
- Remove the scheduled task : schtasks /delete /tn "\UpgradeRAMExtreme" /f
- Delete or quarantine the payload : C:\Users\luke.s\AppData\Local\Temp\272b5c05-78da-492b-afcb-8a17ce1f3333_UpgradeRAMExtreme.zip.333\UpgradeRAMExtreme.exe
- Collect hashes (SHA256/MD5) of UpgradeRAMExtreme.exe and submit to malware analysis / reputation checks
- Identify the process that created the task using the PID fields : ClientProcessId: 4328, ParentProcessId: 876
- Reset credentials for user luke.s

#### - List of Attack Indicators :

- Scheduled task : UpgradeRAMExtreme
- Malicious path : C:\Users\luke.s\AppData\Local\Temp\272b5c05-78da-492b-afcb-8a17ce1f3333_UpgradeRAMExtreme.zip.333\UpgradeRAMExtreme.exe

---

This activity represents a persistence via scheduled tasks. It lanched a payload with high privileges and it's not normal because of the administrative privilege luke.s has.
Finally the host is declared compromise until proven otherwise.
