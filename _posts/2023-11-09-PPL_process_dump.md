---
layout: post
title: PPL process dump
subtitle: What is it a PP/PPL process, how can we bypass it and how can we detect related bypass attempt pattern? keep reading.
---

>

## PPL Process 101

![image](https://github.com/user-attachments/assets/31abe4ca-9b00-442f-8c00-5750b4922932)

On Windows Vista and Server2008, to protect media content and comply with DRM (Digital Rights Management) requirements, was introduced Protected Processes (PP). Microsoft developed this mechanism so media player could read a Blu-ray e.g. while preventing from copying its content. In practice, a Protected Process can be accessed by an unprotected process only with very limited privileges.

A few years later, starting with Windows 8.1 / Server 2012 R2, Microsoft introduced the concept of Protected Process Light. PPL is actually an extension of the previous Protected Process model, User-mode code cannot penetrate these processes by injecting threads, however, the PPLmodel adds an additional dimension to the quality of being protected: attribute values such as Type and Signer, which in turn results in certain PPLs being more, or less, protected than other PPLs.

![image](https://github.com/user-attachments/assets/f1fc42fc-bba5-431f-852d-0dc2a71c5809)

The protection level of a process was added to the EPROCESS kernel structure.

![image](https://github.com/user-attachments/assets/d3506617-780b-425d-9c97-e87d4a1909fc)

Protected Process Light (PPL) ensures that the operating system only loads trusted services and processes by enforcing them to have a valid internal or external signature that meets the Windows requirements. 

![image](https://github.com/user-attachments/assets/b98d4bb7-6aba-4636-8dc2-9fa99966c601)

According to the process protection levels hierarchy, a process with no protection, or lower protection, has limited privileges to a protected process, or one with a higher level of protection.

As mentioned on the book "**Windows Internals, Part 1**" below indicated valid protection values for processes:

![image](https://github.com/user-attachments/assets/7ee36c64-3362-4c56-87cf-342f31dd3423)

" *there are several signers defined, from high to low power. WinSystem is the highest-priority signer and used for the System process and minimal processes such as the Memory Compression process. For user-mode processes, WinTCB (Windows Trusted Computer Base) is the highest-priority signer and leveraged to protect critical processes that the kernel has intimate knowledge of and might reduce its security boundary toward. When interpreting the power of a process, keep in mind that first, protected processes always trump PPLs, and that next, higher-value signer processes have access to lower ones, but not vice versa.* "

And again, in the book it is also show the table with Signers and Levels that shows the signer levels (higher values denote the signer is more powerful) and some examples of their usage. 

![image](https://github.com/user-attachments/assets/cf40ddda-4572-45a1-a0ad-67eeea49c28d)

The signer type establishes a sort of hierarchy between PP(L)s. Here are the basic rules that apply to PP(L)s:
- A PP can open a PP or a PPL with full access if its signer type is greater or equal.
- A PPL can open a PPL with full access if its signer type is greater or equal.
- A PPL cannot open a PP with full access, regardless of its signer type.

For example, when LSA Protection is enabled, `lsass.exe` is executed as a PPL, and you will observe the following protection level with [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer): `PsProtectedSignerLsa-Light`. 

![image](https://github.com/user-attachments/assets/bc035c7f-568b-4dcf-aec6-ba185156747b)

If you want to access its memory you will need to call `OpenProcess` and specify the `PROCESS_VM_READ` access flag. If the calling process is not protected, this call will immediately fail with an `Access is Denied` error, regardless of the user’s privileges.
By default `lsass.exe` process is not run as a protected process:

![image](https://github.com/user-attachments/assets/2cc7d82d-ffea-4cc7-b7f2-710515d41f3f)

If we want to protect it we must set the key as shows below:

![image](https://github.com/user-attachments/assets/25f3fd77-fe95-4081-9e5e-451ba77fb36c)

---
## bypass PPL

![image](https://github.com/user-attachments/assets/f833e0aa-d764-466e-bbf5-75ea82efa941)

Limiting these access rights reliably allows the kernel to sandbox a protected process from user-mode access. On the other hand, because a protected process is indicated by a flag in the EPROCESS structure, a user can still load a kernel-mode driver that modifies this flag.

There are specific access rights that are not allowed from an unprotected source process to a protected target process, such as the `PROCESS_ALL_ACCESS`. Using a signed driver, it is possible to reset PPL process value in order to have full access that confers all possible access rights for a process object.

![image](https://github.com/user-attachments/assets/08fa4dd6-e7a6-4ae8-881b-1f479bf1d8bb)

Using known BYOVD (Bring Your Own Vulnerable Driver) attack technique: from MITRE ATT&CK https://attack.mitre.org/techniques/T1068/
"*Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD). Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via Ingress Tool Transfer or Lateral Tool Transfer.*"

During some years, tools like `PPLDump` or `PPLKiller` could be used to bypass this protection, but in the last months, Microsoft patched the technique exploited by this vulnerability. 
There is a way to abuse some features in existing drivers to get a handle to protected process and to perform operations with that handle. Perform tests with `PROCEXP152.sys` driver of Process Explorer, a known Sysinternal suite tool, with which it is possible to open a handle to a processes with access rights set to `PROCESS_ALL_ACCESS`. 

<p align=center><img src="https://github.com/user-attachments/assets/0272c3d9-f905-4d1c-b876-69ebf8789781" /></p>

Using `PPLBlade` tool developed by **tastypepperoni** (https://github.com/tastypepperoni/PPLBlade), which load `PROCEXP152.sys` as BYOVD technique, we can dump `lsass.exe` process even if it has PPL set as its protection level.
`PPLBlade` can be used also for other purposes, but with the flag `--mode` it is possible to choose wich operation can be used, e.g. adding `dothatlsassthing` exploit the PROCEXP152 driver in order to dump `lsass.exe` protected process.

<p align=center><img src="https://github.com/user-attachments/assets/ca38e088-c219-4d32-9970-722ae52ea23b" /></p>

This tool was also tested endpoints secured with EDR agents, at the time of writing of the post, 2023 fall, Defender is **unable** to detect this technique, some EDRs instead yes.

![image](https://github.com/user-attachments/assets/83873c5d-1f8b-45b1-a4b4-452a26c920f9)


---

## Let's take a look from a BlueTeam point of view!

![image](https://github.com/user-attachments/assets/a2ad5c44-8d5a-4a0f-b373-7f8f67ef82c5)

Detection can be made on evidences of **NewProcessCreated** (or `EID 4688`) where the process is runned with the attempt to dump `lsass.exe` process.

![image](https://github.com/user-attachments/assets/6a24a927-7691-43d5-999e-1300cb031d84)

In addition the process execution must be correlated with evidences of a new service installed in the system when the driver is loaded (`EID 7045`).

![image](https://github.com/user-attachments/assets/098c7319-30f5-4b92-97fb-2cbc59ba4be1)


---

### In the wild

This kind of technique is also used to bybass EDRs, as we saw recently with Terminator thunderstorm. `Terminator` is another tool distributed from a threat actor using the pseudonym “**Spyboy**” that use BYOVD technique to disable EDR. 

<p align=center><img src="https://github.com/user-attachments/assets/132c7468-cb5e-455d-9408-809046d7a309" /></p>

This tool was also observed to be used by **BlackCat** Ransomware Group during their infection chain.

