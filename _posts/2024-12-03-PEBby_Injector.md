---
layout: post
title: PEBby Injector
subtitle: How malware can retrieve base address of loaded modules in order to resolve specific functions.
---

>

![image](https://github.com/user-attachments/assets/142c3348-734f-432d-a0fb-549b723548fd)

> **TL:DR** Are you too lazy to read the blogpost? At the bottom of the page you will find a podcast-like to listen to! but watch cause it's not so accurate and does not follow everything in the post.

---

# Injector 101
Let's talk about malware, *yess*. But not a generic malware, an Injector!
This is the second in a series of three posts related to a work teamed up with [@zer0phat](https://x.com/zer0phat) dedicated to an handmade injector.
Let's begin with a bit of theory about the type of malware developed and analyzed.

> **TL:DR** Injector malware refers to a category of malicious software designed to insert harmful code into legitimate running processes to do malicious things on infected host.

![image](https://github.com/user-attachments/assets/b65e5829-ed2d-4a12-a66b-5a95b1f352af)

Malware injectors are a specific subset of malware that focus on stealthy code injection into legitimate processes for various malicious purposes, contrasting with other types of malware that may operate differently or have distinct objectives. 
### Different technique to do injection:
Listed below some of the most common and known techniques to perform injection:
1. **PE/Code Injection**: This technique allows attackers to execute PE/arbitrary code by injecting it into a running application.
2. **DLL Injection**: This technique involves inserting a dynamic-link library (DLL) into the address space of another process. Once injected, the DLL can execute code within the context of that process.
3. **Process Hollowing**: This method creates a new process in a suspended state and replaces its memory with malicious code. The legitimate process is then resumed, executing the injected code while appearing normal to the operating system. 
4. **Reflective DLL Injection**: A more advanced form of DLL injection where the DLL is loaded directly from memory rather than from disk, making it harder to detect.

There are other techniques, maybe also too stealthy and powerfull, but its not the post to talk about that, and internet is full of info related to. This blog post is intended as an in-depth look at the technique by which the malware retrieves the information needed to load modules already loaded into memory. *Let's start.*

---

# Know history and the ASLR
The malware needs to collect information about the modules loaded in memory to succeed.
Nowadays it is *a little bit* more complicated than the older days. Why? Because the ASLR. 
**Address Space Layout Randomization** (ASLR) is a security technique used in operating systems to randomize the memory addresses used by system and application processes. This is a security feature the MS implement after Win8 because core processes tended to be loaded into predictlable memory locatoin upon system startup, yes because prior to ASLR, the memory locations of files and applications were either known or easily determined and some exploit targetting memory location known to be assocaited with paticular processes. ASLR randomized the memory location used by system file and other programs making much harder, *but not impossible ;)* for an attacker to guess the right location of a needed process.

<p align=center><img src="https://github.com/user-attachments/assets/dce80ff1-c736-4aef-8502-7e48b72ae05e" /></p>

> **TL:DR** A malware cannot simply make a call to a function since it has no idea where it is in memory. It has to retrieve the address.

Not-so TL:DR :		
To interact with its runtime environment, malware must execute various API calls. Some of these functions may already be loaded into the memory of the compromised application, while others might reside in DLLs that the malware needs to load itself. To achieve this, malwares typically uses the `LoadLibrary` function to load a DLL, and then it calls `GetProcAddress` to find the specific function within that DLL. Both `LoadLibrary` and `GetProcAddress` are located in `kernel32.dll`, which is usually pre-loaded in the memory space of the exploited application. Consequently, malware often inspects the application's memory to locate `kernel32.dll`, enabling it to examine its export table for essential functions like `LoadLibrary` and `GetProcAddress`.
Malware must then compute the address in memory, in the past these addresses were hardcoded, then Windows implemented ASLR as a security countermeasure, *but as we all know, the countermeasure to the countermeasure is around the corner*. As we saw in the 1st episode on the @zer0phat blog [post](https://t.co/SooOEnOlZC) one technique might be to snapshot the process and parse the modules loaded into memory to do the retrieve of the information needed to proceed with the technique, using first `CreateToolhelp32Snapshot` and then the `Process32First` and `Process32Next` functions, respectively, to enumerate the processes. 
There is an even more juicy and stealthy way to do this, by parsing the `PEB`. 
Or rather, by walking through the `PEB`.

---

# Let's take a (PEB-)walk

#### first of all, what is it the PEB?
The **Process Environment Block (PEB)** is contained in objects called EPROCESS structures in the Windows operating system, is a crucial data structure that holds important information about a running process. 

<p align=left><img src="https://github.com/user-attachments/assets/b527c99b-9dae-4dc3-b8e7-b5c674d8dbd1"/></p>

It is primarily utilized by the operating system to manage process-related data and is essential for both system operations and security analysis.
#### What happens when a process is created?
When a new process is created in an operating system, several critical steps are involved, primarily managed by the kernel. This process creation involves loading the program into memory, allocating resources, and initializing various structures, including the Process Environment Block (PEB), that serves as a central repository for information that user-mode applications can access without needing to switch back to kernel mode frequently, thus improving efficiency in process management. So, let's breaking process creation in 3 major steps useful to us talking about this technique.

1. **Kernel Initialization**: The kernel first creates a representation of the process in kernel space using structures like EPROCESS and KPROCESS. These structures track various attributes of the process and its execution context.
2. **User Space Creation**: The PEB is then created in user space. It contains vital information about the process, including pointers to loaded modules and parameters for execution. Specifically, it includes fields such as:
	- `Ldr`: A pointer to a structure that holds information about loaded modules;
	- `ProcessParameters`: A pointer to a structure containing command-line parameters and other settings relevant to the process;
3. **Loading DLLs**: During its creation, the PEB also loads essential dynamic link libraries (DLLs), such as `Ntdll.dll` and `Kernel32.dll`, which provide fundamental services needed by user-mode applications.

![image](https://github.com/user-attachments/assets/e4fd4127-a7a6-4df7-a9b2-99784b8b1c30)

From "the Art of Memory Forensics", representation of how PEB points to the modules loaded in memory.

![image](https://github.com/user-attachments/assets/84b59f3b-e88c-4610-afab-094981b8f6c9)

Simply attaching a process to a debugger and using "!peb" command we can show all the information in it. We can spot `Ldr` structure where there are loaded modules.


#### So, do you see the point?
When the structure is created, there is information inside that is needed by the process to locate the structure that holds the information about the loaded modules. As described in @zer0phat's first blog post, he retrieve needed information calling functions such as `CreateToolhelp32Snapshot`, `Process32First` and `Process32Next` but we now know that we can achieve the same goal via `PEB`, *in a more juicy way*.
Ok, now we know what we want to find, we need to know the **how** and most importantly the **where**.



---

# WHERE: what are segment registers

Thanks to Raymond Chen, author of "The Old New Thing" bible.

<p align=left><img src="https://github.com/user-attachments/assets/ebe93ed0-d307-459c-843a-3c573d4dabb8" width="450" height="490" /></p>

Segment registers are special-purpose registers that help the CPU access memory efficiently by dividing it into different segments. Each segment can hold a specific type of data or code, which enhances the organization and management of memory. 

![image](https://github.com/user-attachments/assets/fad332cf-b1bb-48a7-aa43-707ee6f3d04d)


The first four segments have architectural meaning, but without specifying every purpose of each segment registers, the are two bonus segment registers that aren’t architecturally significant, and we can use them for anything, the ones we are interested in are `fs` and `gs`. 
Windows uses the `fs` segment register to access a small block of memory that is associated with each thread, known as the Thread Environment Block, or `TEB`.
To access memory relative to a specific segment register, you prefix the segment register and a colon to the memory reference.

 `MOV     eax, fs:[0]        ; eax = memory at offset 0 in segment fs`

Indicated below some of the offsets using the segment `fs`: 
1.  `FS:[0]` Points to the Current Structured Exception Handling (SEH) frame. This is used for managing exceptions in the current thread.
   > Malware also exploit this offset to do some powerfull misdirection technique as a self-defense approach to make it harder for analyst to understand the flow of the specimen's execution. Maybe I'll write something related to this technique in the future ;)
2. `FS:[18]` Contains the address of the TEB itself. This is crucial as it allows access to other thread-specific information.
3. `FS:[20]` Holds the Process ID (PID) of the current thread's process. This is useful for identifying which process is currently executing.
4. `FS:[24]` Contains the Thread ID (TID) of the current thread, allowing for thread-specific operations.
5. `FS:[30]` **This offset points to the PEB.** The PEB contains vital information about the process, such as loaded modules and process parameters. *And now we have the "where"!*

<p align=center><img src="https://github.com/user-attachments/assets/d9bf4c12-427a-4df5-a4b6-dba0b2e70792" /></p>

From Cucci's "Evasive Malware" masterpiece, a table that represent corresponding x86/x64 offsets.

---

# HOW: with a couple of lowest level code instructions!

Here’s a simple example of how we might use inline assembly to access these structures:

```cpp
#include <stdio.h> 
#include <Windows.h> 

int main() { 
	PVOID peb; 
	
	\_asm { 
		mov eax, fs:[0x30]        // Get address of PEB 
		mov peb, eax              // Store in peb variable 
	} 
	
	printf("PEB Address: %p\n", peb); 
	return 0; 
}
```

In this example, `fs:[0x30]` retrieves the address of the `PEB`, which can then be used to access various fields within it. Once we have accessed the `PEB` using `FS:[0x30]`, we can further explore various fields within it, such as:

- `PEB_LDR_DATA` Structure: At offset `0x0C` in the PEB, this structure contains information about loaded modules.

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

- `InLoadOrderModuleList`: This linked list can be accessed to enumerate all modules loaded into the process.

```cpp
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

![image](https://github.com/user-attachments/assets/77d34fcd-1121-4da1-9c3e-07e3964dc4d0)

> Another interesting PEB_struct data that malware try to retrieve is also the `BeingDebugged` value, aimed to act as a countermeasure, if it set to "Yes" resulting that the process (the malware) is actually debugged, killing itself or misdirect execution flow to something that a not-skilled analyst or a not so controlled environment can intercept as suspicious and proceed to don't analyze further the specimen. (spot it in WinDbg image right above!)

# Static analysis of the walk

Let's feed our friendly red dragon with this new specimen.

![image](https://github.com/user-attachments/assets/da4c8faa-8b29-4659-8c63-48819f6252a5)

Focusing on what we want to see related to the PEB, we must highlight this FUNction.
> It is a x64 sample, so segment and offset are different from examples in the previous chapter (refer to Cucci's table).
> e.g. `fs:[0x30]` became `gs:[0x60]` and `EAX` register is `RAX`

Let's split the instructions that we see in the code snippet below:

![image](https://github.com/user-attachments/assets/788f132d-0f16-4c3a-b46a-123c1e929893)

1- **Initialization**: These instructions clear the registers RAX and RCX by performing an exclusive OR operation with themselves. This is a common way to set registers to zero.

`XOR RAX, RAX 
XOR RCX, RCX`

2- **Retrieve PEB Address**: This instruction loads the address of the PEB into the RAX register. In a 64-bit Windows environment, the PEB address can be accessed using the GS segment register with a specific offset, typically 0x60 for 64-bit systems, that points to the PEB within the Thread Environment Block (TEB). 

`MOV RAX, qword ptr GS:[0x60]`

3- **Ldr data strc**: After obtaining the PEB address, this line accesses the `Ldr` field of the PEB structure by adding an offset of 0x18 to the PEB address. The `Ldr` field points to the PEB Loader Data structure, which contains information about loaded modules.

`MOV RAX, qword ptr [RAX + 0x18]`

4- **InLoadOrderModuleList**: This instruction adds 0x10 to RAX, which now points to the `InLoadOrderModuleList` within the PEB Loader Data structure. This linked list contains information about all loaded modules in the process.

`ADD RAX, 0x10`


After this, based on the below attached code snippet, skipping most of the instructions, we can see which module the code is try to reach. 
To do so it use the `LEA` (Load Effective Address) instruction that calculates the address of the string `s_KERNELBASE.dll_180004000` and stores it in the `RDI` register. 

![image](https://github.com/user-attachments/assets/88ef9931-2a92-4412-8d47-b98219264b87)

This suggests to us that this code may be dealing with Windows API functions in KERNELBASE.dll that it is a core Windows library that provides various system services. *Maybe it wants to call some of its function to perform injection? .. I think so ;)* 

![image](https://github.com/user-attachments/assets/a68dec67-f391-4b2d-99f6-a567d5e6a6f8)

The `FS`/`GS` segment register provides a powerful mechanism for accessing thread-specific data and process information in Windows environments. By utilizing specific offsets, malware developers can efficiently manage and retrieve critical information about both threads and processes.

Accessing the PEB directly through assembly is often used in low-level programming contexts such as by malware developer or system-level programming because it allows for efficient retrieval of process-related information without relying on higher-level APIs. The method shown in the code is typical for retrieving such critical system information directly from memory in a more stealthy and efficient manner.

In the context of malware, accessing the `PEB_LDR_DATA` structure enables the extraction of base addresses for loaded modules, which can be used to resolve specific functions within those modules, even in the presence of security features like ASLR.

# AI-Podcast - hear me out!
### generated for fun with AI
<iframe width="100%" height="300" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/2020203861&color=%23ff5500&auto_play=false&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true&visual=true"></iframe><div style="font-size: 10px; color: #cccccc;line-break: anywhere;word-break: normal;overflow: hidden;white-space: nowrap;text-overflow: ellipsis; font-family: Interstate,Lucida Grande,Lucida Sans Unicode,Lucida Sans,Garuda,Verdana,Tahoma,sans-serif;font-weight: 100;"><a href="https://soundcloud.com/5hidobu" title="5hidobu" target="_blank" style="color: #cccccc; text-decoration: none;">5hidobu</a> · <a href="https://soundcloud.com/5hidobu/pebby-injector" title="PEBby Injector" target="_blank" style="color: #cccccc; text-decoration: none;">PEBby Injector</a></div>












