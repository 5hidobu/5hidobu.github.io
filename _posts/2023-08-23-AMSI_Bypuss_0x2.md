# AMSI_bypuss_0x2
This technique permit to force AmsiInitFailed via a null AmsiContext pointer invoking AmsiOpenSession. How can we detect this kind of technique? keep reading.

---

As covered in the other blogpost (https://5hidobu.github.io/2023-04-23-AMSI_Bypuss_0x1/) there are several methods to impair defenses by bypassing AMSI. Introduced with Windows 10, AMSI stands for "Antimalware Scan Interface”, an API that enables to sending content to vendor endpoint security agent, each command or script that it is run in a Powershell session e.g. is fetched by AMSI and sent to installed antivirus software for inspection.
When an application attempts to submit content to be scanned by a vendor agent, the application loads amsi.dll and calls its functions in order to establish an AMSI session, the content to bescanned is then submitted and checked.
This technique exploits error generation to perform AMSI bypass.

![image](https://github.com/user-attachments/assets/65c58023-ee91-477a-a813-7eb01429e8d2)

Leaving aside the process by which AMSI performs checks, if in a low priv Powershell session we want to run cmdlet ( e.g InvokeExpression), before being executed, AMSI checks the command and if it does not match security parameters, the command is not executed returning an error.
Among the known techniques to bypass in memory this process is to force an error condition on opening the AMSI session, so any cmdlet can be run without AMSI blocks. This can be done by force AMSI initialization via the AmsiInitFailed value resulting in no scan being initialized for the current process/session and so block malicious command execution, but Microsoft has developed a signature for this technique to prevent its exploitation, so it can no longer be used to bypass AMSI.

In this blogpost we cover an alternative method to force that error, this bypass allocates memory for " amsiContext " by forcing to "null" the value of AmsiOpenSenssion by returning an error (AmsiInitFailed automaticly setted).


```
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)[Ref].Assembly.GetType(“System.Management.Automation.AmsiUtils”).GetField(“amsiSession”,”NonPublic,Static”).SetValue($null, $null);[Ref].Assembly.GetType(“System.Management.Automation.AmsiUtils”).GetField(“amsiContext”,”NonPublic,Static”).SetValue($null, [IntPtr]$mem)
```

When Powershell attempts to submit content to be scanned by a vendor agent that refers to as an AMSI provider, it loads amsi.dll and calls its AmsiOpenSession function in order to establish an AMSI session. If we can get AmsiOpenSenssion to be invoked with an “amsiContext” pointer wich does not contains a 4 bytes value of AMSI at offset 0x00, an error will be returned from the function of 0x80070057, or “ E_INVALIDARG ”. When the error is returned to Powershell session, amsiInitFailied will be set. As evident from the test performed after the bypass, AMSI does not
intervene as in the previous test.


![image](https://github.com/user-attachments/assets/edddbf5a-e2d7-480c-b08d-ac9cc14aba1d)


## Quick in-depth look

![image](https://github.com/user-attachments/assets/463526fc-397e-40ac-8eb8-952ab882ed27)

Decompiling amsi.dll and looking for AmsiOpenSession function we can observe that if “amsiContext” pointer does not contains a 4 bytes value of AMSI (ISMA), an error will be returned from the function of 0x80070057, or “E_INVALIDARG ”. 

![image](https://github.com/user-attachments/assets/c4a1ded8-7793-4019-9ae3-946229fef25c)

Just to repeat and clarify the context: amsi.dll is loaded in a Powreshell Session, if the AmsiContext pointer is not "AMSI", this value passed to the next function AmsiOpenSession generate an error "E_INVALIDARG".


![image](https://github.com/user-attachments/assets/f9dfe6a1-3942-464d-aa6d-17163ab2cc1f)


## Let's take a look from **Blue Team** perspective.


![image](https://github.com/user-attachments/assets/a3035704-ef37-40f7-bd2b-04661f579708)


From a Blue Team perspective, also here with this technique we can observe the EID 4104 (Powershell Operational Log). 
With the evidences about the command executed in the Powershell session it can be possible write a precise detection rule in order to detect technique execution attempt.


![image](https://github.com/user-attachments/assets/80963121-128e-418e-84df-b9e5d60931f0)


This log is enabled by default, if not, to enable script block logging, go to the Windows PowerShell GPO settings and set Turn on PowerShell Script Block Logging to enabled. Alternately, you can set the following registry value: "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1" ([https://docs.splunk.com/Documentation/UBA/5.1.0.1/GetDataIn/AddPowerShell#:~:text=To%20enable%20script%20block%20logging,Script%20Block%20Logging%20to%20enabled.&text=In%20addition%2C%20turn%20on%20command%20line%20process%20auditing](https://docs.splunk.com/Documentation/UBA/5.1.0.1/GetDataIn/AddPowerShell#:~:text=To%20enable%20script%20block%20logging,Script%20Block%20Logging%20to%20enabled.&text=In%20addition%2C%20turn%20on%20command%20line%20process%20auditing).)

---

Some pseudo code for SIEMs

```
PowerShellOperational 
| where EventID == "4104" 
| where parse_json(Parameters)[1].Log == "GetField(“amsiSession”,”NonPublic,Static”).SetValue($null, $null" 
| where parse_json(Parameters)[2].Log == "GetField(“amsiContext”,”NonPublic,Static”).SetValue($null,"
```

---

This repo is intended as an overview of AMSI bypass and technique detection. There are several ways to do AMSI bypass.

---

Credits: @MDsec, @S3cur3Th1sSh1t and @maorkor





