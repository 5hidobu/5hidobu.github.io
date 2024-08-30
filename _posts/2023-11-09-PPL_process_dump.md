What is it a PP/PPL process, how can we bypass it and how can we detect related bypass attempt pattern? keep reading.

---

## PPL Process 101

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/a8b9e08a-ddd0-4acd-93d1-5025fcbaf134)

On Windows Vista and Server2008, to protect media content and comply with DRM (Digital Rights Management) requirements, was introduced Protected Processes (PP). Microsoft developed this mechanism so media player could read a Blu-ray e.g. while preventing from copying its content. In practice, a Protected Process can be accessed by an unprotected process only with very limited privileges.

A few years later, starting with Windows 8.1 / Server 2012 R2, Microsoft introduced the concept of Protected Process Light. PPL is actually an extension of the previous Protected Process model, User-mode code cannot penetrate these processes by injecting threads, however, the PPLmodel adds an additional dimension to the quality of being protected: attribute values such as Type and Signer, which in turn results in certain PPLs being more, or less, protected than other PPLs.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/2444ab75-c924-48a7-a233-ea9e25fc8945)

The protection level of a process was added to the EPROCESS kernel structure.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/9fac35d8-3b05-4130-a279-ce7a2dea1034)

Protected Process Light (PPL) ensures that the operating system only loads trusted services and processes by enforcing them to have a valid internal or external signature that meets the Windows requirements. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/d831d69b-61a7-4b7f-b20f-39fd599133a6)

According to the process protection levels hierarchy, a process with no protection, or lower protection, has limited privileges to a protected process, or one with a higher level of protection.

As mentioned on the book "**Windows Internals, Part 1**" below indicated valid protection values for processes:

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/4ff8778a-fa22-456a-af30-c4f4b4440641)

" *there are several signers defined, from high to low power. WinSystem is the highest-priority signer and used for the System process and minimal processes such as the Memory Compression process. For user-mode processes, WinTCB (Windows Trusted Computer Base) is the highest-priority signer and leveraged to protect critical processes that the kernel has intimate knowledge of and might reduce its security boundary toward. When interpreting the power of a process, keep in mind that first, protected processes always trump PPLs, and that next, higher-value signer processes have access to lower ones, but not vice versa.* "

And again, in the book it is also show the table with Signers and Levels that shows the signer levels (higher values denote the signer is more powerful) and some examples of their usage. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/c38379e6-ef70-4df0-9ccf-b7948d8bf089)

The signer type establishes a sort of hierarchy between PP(L)s. Here are the basic rules that apply to PP(L)s:
- A PP can open a PP or a PPL with full access if its signer type is greater or equal.
- A PPL can open a PPL with full access if its signer type is greater or equal.
- A PPL cannot open a PP with full access, regardless of its signer type.

For example, when LSA Protection is enabled, `lsass.exe` is executed as a PPL, and you will observe the following protection level with [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer): `PsProtectedSignerLsa-Light`. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/51909cd1-6d89-493e-b41c-97b7faee430b)

If you want to access its memory you will need to call `OpenProcess` and specify the `PROCESS_VM_READ` access flag. If the calling process is not protected, this call will immediately fail with an `Access is Denied` error, regardless of the user’s privileges.
By default `lsass.exe` process is not run as a protected process:

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/5a9966d3-2517-42cb-9c6a-2091fc5edbac)

If we want to protect it we must set the key as shows below:

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/0a90c89d-ba68-4355-aa3f-c1b4b2c036b3)

---
## bypass PPL

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/8ee93ead-1d6e-4bf7-aeee-e4890e3388f0)

Limiting these access rights reliably allows the kernel to sandbox a protected process from user-mode access. On the other hand, because a protected process is indicated by a flag in the EPROCESS structure, a user can still load a kernel-mode driver that modifies this flag.

There are specific access rights that are not allowed from an unprotected source process to a protected target process, such as the `PROCESS_ALL_ACCESS`. Using a signed driver, it is possible to reset PPL process value in order to have full access that confers all possible access rights for a process object.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/1145c573-6064-43aa-a6e4-dbdb726c6350)

Using known BYOVD (Bring Your Own Vulnerable Driver) attack technique: from MITRE ATT&CK https://attack.mitre.org/techniques/T1068/
"*Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD). Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via Ingress Tool Transfer or Lateral Tool Transfer.*"

During some years, tools like `PPLDump` or `PPLKiller` could be used to bypass this protection, but in the last months, Microsoft patched the technique exploited by this vulnerability. 
There is a way to abuse some features in existing drivers to get a handle to protected process and to perform operations with that handle. Perform tests with `PROCEXP152.sys` driver of Process Explorer, a known Sysinternal suite tool, with which it is possible to open a handle to a processes with access rights set to `PROCESS_ALL_ACCESS`. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/4f6ac37e-621e-4d4a-9635-90efb086e70e)

Using `PPLBlade` tool developed by **tastypepperoni** (https://github.com/tastypepperoni/PPLBlade), which load `PROCEXP152.sys` as BYOVD technique, we can dump `lsass.exe` process even if it has PPL set as its protection level.
`PPLBlade` can be used also for other purposes, but with the flag `--mode` it is possible to choose wich operation can be used, e.g. adding `dothatlsassthing` exploit the PROCEXP152 driver in order to dump `lsass.exe` protected process.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/92e90d84-e084-4d0e-b2ae-675f3c0de723)

This tool was also tested endpoints secured with EDR agents, at the time of writing of the post, 2023 fall, Defender is **unable** to detect this technique, some EDRs instead yes.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/e78b7522-94e6-466d-9c95-42b8f69226ba)


---

## Let's take a look from a BlueTeam point of view!

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/06bc8759-5367-4abe-872b-0a90981f61ef)

Detection can be made on evidences of **NewProcessCreated** (or `EID 4688`) where the process is runned with the attempt to dump `lsass.exe` process.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/fac14b27-7c9f-4958-954c-4ecb4ccb51b4)

In addition the process execution must be correlated with evidences of a new service installed in the system when the driver is loaded (`EID 7045`).

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/33e51667-b3e3-407f-af0f-5c1b341f4852)


---

### In the wild

This kind of technique is also used to bybass EDRs, as we saw recently with Terminator thunderstorm. `Terminator` is another tool distributed from a threat actor using the pseudonym “**Spyboy**” that use BYOVD technique to disable EDR. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/89583f25-8079-455f-bd9e-c6396f1ac344)

This tool was also observed to be used by **BlackCat** Ransomware Group during their infection chain.

