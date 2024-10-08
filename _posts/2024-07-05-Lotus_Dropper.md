---
layout: post
title: Lotus Blossom Dropper
subtitle: Code analysis of a dropper developed and deployed during espionage campaigns by Chinese nexus threat group Lotus Blossom. 
---

>


# Dropper Analysis

![image](https://github.com/user-attachments/assets/e39d9827-23f7-4aff-80b7-e166224b8dff)

The specimen is recognized as malware developed and deployed during espionage campaigns by Chinese nexus threat group Lotus Blossom. 

 ![image](https://github.com/user-attachments/assets/ab74bde4-d02c-41d1-b751-2a99d7860da8)
  
Lotus Blossom is a cybercriminal group identified as responsible for a persistent cyber espionage campaign targeting government and military organizations in Southeast Asia. This group employs spear phishing tactics, often utilizing malicious documents to install custom Trojan backdoors named Elise and Emissary, indicating a likely state-sponsored affiliation due to the nature and persistence of their attacks.

---
## Dropper 101
first of all: 

- **What is it a dropper?**
Dropper malware is a type of malicious software specifically designed to deliver and execute additional malware on a victim's system. Acting as a carrier, **it encapsulates other malicious components**, such as Trojans or ransomware, and ensures their installation while often evading detection by security measures. 

- **Why implement a dropper?**
Implementing a dropper is a strategic choice for cybercriminals seeking to deliver malware effectively while evading detection. The key reasons for implementing a dropper could be: **bypassing security measures**, are designed to circumvent antivirus signatures and other security protocols, making it easier for malicious payloads to be installed without immediate detection; **multi-payload delivery**, a dropper can contain multiple types of malware, this versatility enhances the effectiveness of their attacks; other key reason could be obfuscation, persistence and, last but not least, the user interaction which can be achieved through social engineering techniques, such as phishing attacks. This reliance on user actions increases the likelihood of successful malware installation

---
## Lotus Blossom Dropper(s)
Lotus Blossom employs a sophisticated dropper to disseminate malware, primarily targeting government and military organizations in Southeast Asia. 
Kind of Lotus Blossom developed droppers exploits the Microsoft Office vulnerability CVE-2012-0158, often delivered through spear phishing emails containing malicious Word document attachments. This kind of sample is described [here](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/research/unit42-operation-lotus-blossom).
The sample under analysis is not related to those that exploited the Office CVE, but represents the well-known characteristics used by a dropper to continue in the infection chain. Probably a version developed for a campaign without the CVE exploit feature.

<p align=center><img src="https://github.com/user-attachments/assets/198e388e-36fc-4aa1-9113-30a54c73e008" /></p>

---
## Dropper 102
Droppers (**the simple ones**) often utilize the following Windows API calls to load and execute embedded malware:
#### FindResource
The **FindResource** function is used to locate a resource with the specified type and name in the specified module. It returns a handle to the resource's information block. This handle is then passed to **LoadResource** to obtain a handle to the actual resource data.

```cpp
HRSRC FindResourceW(
  [in, optional] HMODULE hModule,
  [in]           LPCWSTR lpName,
  [in]           LPCWSTR lpType
);
```

#### LoadResource
The **LoadResource** function retrieves a handle that can be used to obtain a pointer to the first byte of the specified resource in memory. It takes the module handle and the resource handle returned by **FindResource** as input parameters.

```cpp
HGLOBAL LoadResource(
  [in, optional] HMODULE hModule,
  [in]           HRSRC   hResInfo
);
```

#### LockResource
The **LockResource** function obtains a pointer to the first byte of the loaded resource. It takes the handle returned by **LoadResource** as input and returns a pointer to the resource data.

```cpp
LPVOID LockResource(
  [in] HGLOBAL hResData
);
```

**By calling these functions in succession, a dropper can locate, load, and execute malicious code embedded as a resource within the executable.** The FindResource and LoadResource functions retrieve a handle to the resource data, while LockResource provides a direct pointer to the resource bytes in memory, allowing the dropper to execute the embedded malware payload

---

# Let's start to observe the specimen

As we can see, magic bytes 4D 5A indicate that its an executable binary.

![image](https://github.com/user-attachments/assets/23c9f420-979b-4041-8141-0c9cece14141)

in particular, its a dll:

![image](https://github.com/user-attachments/assets/6786379a-79f8-4308-abf7-ab530b5672f9)

as we saw before, a kind (the simple one) of a dropper it can locate, load and lock a resource that it is embedded inside of itself. 
We can see the resources and locate the binary ("ASDASDSADASD..") that will be loaded and "dropped by the dropper".

![image](https://github.com/user-attachments/assets/3f71e96b-900b-46e7-a127-947c7c5152d2)

right here we can dump the content and don't proceed with further code analysis, but you are here to see the code analysis, so.. lets just call our faithful neighbourhood NSA dragon and have him disassembled:

![image](https://github.com/user-attachments/assets/cd3be696-ef6e-4613-a349-77dc832c53ae)

Ghidrino.jpg

---

# Code Analysis - fasten your seat belts
not because it is very complicated, but because all the instructions are described (perhaps even too much) to clarify the assembly.
Also sorry for the scribbled screenshots, hope it'll helps.

ok - lets start:
### 1 - FindResource

![image](https://github.com/user-attachments/assets/e74a669a-2abc-4479-a703-d8ee16a3c4c5)

Looking for the MS docs, the first argument is the handle to the module that contain the resource.
The second argument is the name of the resource (0x66 = 102 in decimal) and it is the name of the binary seen in PEstudio, that one that can be dumped without blowing our mind with the code analysis.
The third parameter is the type and also here we have the evidences in PEstudio

![image](https://github.com/user-attachments/assets/eeded756-695f-4878-9eee-230c5fe93e63)

![image](https://github.com/user-attachments/assets/9c970783-fdab-45d0-976a-dbc5090c16d2)

the return value is a handle to the specified resource's information block.

![image](https://github.com/user-attachments/assets/680cc68e-8d9f-4500-87eb-fa99909635f8)

if its not '0' jump to the next instruction

![image](https://github.com/user-attachments/assets/4e5b3aa8-eb7e-44a6-9279-74bebbe4201a)



### 2 - LoadResource

the next instruction its a CALL to the function "SizeOfResource" - the return value is the number of bytes in the resource.
the first parameter its the handle to the module (which is the FindResourceW return value)

![image](https://github.com/user-attachments/assets/4972897b-d24c-4aec-b3b7-8ddf6b460828)

next instruction is the CALL to LoadLibraryA in order to load kernel32.dll into memory.
return value in EAX is CMPared and if it is non zero the control flow will be passed to the next instruction that it is the GetProcAddress which the return value is the address of the exported function - the first parameter is the return value of the LoadLibraryA stored in EAX, but the next arguments is the function that we want to know the address to point to, in our case is "LoadResource" that its used to have an handle that can be used as a pointer to the first byte of the specs resource in memory.
next, conditional jump, if the EAX is not 0, skip the Error handler and pass the control flow to the next function "FreeLibrary":

![image](https://github.com/user-attachments/assets/109309f6-c220-4086-a552-d4d34e42b651)

the parameter passed to the functoin FreeLibrary is the handle of the module previously loaded.

![image](https://github.com/user-attachments/assets/0306dc88-a9cd-439e-9610-1eb10adb2df4)



### 3 - LockResource

here something tricky, at the offsets 100018f8, 100018fb there is a tricky (fuc\*ing) instruction where it is called to a pointer (that it is the address of the module loaded previously and retrieved with GetProcAddress), that store the pointer into EAX and then (next instruction) MOV the content into another ptr, then use this value to push into the stack the parameter HGLOBAL (that its an handle to the resource to be accessed) for the LockResource API CALL. 
based on MS docs, "If the loaded resource is available, the return value is a pointer to the first byte of the resource; otherwise, it is **NULL**."
https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource
so CMP to 0 and conditional jump JNZ is taken to pass the control flow to the next instruction:

![image](https://github.com/user-attachments/assets/824594b9-b067-4ce0-933d-3e3e46c78c33)



### 4 - Write on the disk what the Dropper want to drop

so, at this point we have a pointer to the first byte of the resource.
Next instruction is CreateFileA, all parameters are PUSHed into the stack before the CALL. 
Based on MS docs "If the function succeeds, the return value is an open handle to the specified file, device, named pipe, or mail slot." 

![image](https://github.com/user-attachments/assets/79fa3dbc-cd0a-4f57-a147-be1886526ee8)

looking for the args passed to the FUN CreateFileA
the second args "dwDesiredAccess" is the requested access to the file or device, and the value passed is GENERIC_WRITE that means "Write access".

![image](https://github.com/user-attachments/assets/27e52c44-7f02-48a5-990e-04c756b6a81a)

next, control flow will be passed to the next instruction that its the WriteFile API call, as first parameter is setted the return value of the CreateFileA API CALL that its the handle to the file to be written. as per MS docs "The _hFile_ parameter must have been created with the write access." and we got it.
at the end, If the function succeeds, the return value is nonzero (**TRUE**).
and FUN epilogue with POP EBP and RET to return to the caller.

![image](https://github.com/user-attachments/assets/9f0530f2-c520-434f-8732-ab35653aa8e5)

further stager is dropped on disk

![image](https://github.com/user-attachments/assets/d188128f-a76b-42d2-86b0-626961961071)

---

### EasterEgg - CreateMutex

Another important (and juicy) FUN must be highlighted, "CreateMutexA", "CreateMutexA is used to create a new mutex object. Mutexs are often used by malware to prevent the reinfection of a system with the same or different malware variant." (https://malapi.io/winapi/CreateMutexA)

![image](https://github.com/user-attachments/assets/cd0edefa-922e-4e01-9cf9-f957cb793486)

parameters LPCSTR, based on MS docs, "The name of the mutex object.". In this case is "MICROSOFT_LOADER_MUTEX".

Malware often calls the CreateMutex API to ensure that only one instance of the malware is running on the system at a time. By creating a named mutex with a predetermined hard-coded name, the malware can check if another instance is already running, otherwise could be killed itself. in summary CreateMutex API is a common tool used by malware to ensure single instance execution, maintain persistence, evade detection, and coordinate botnet activities.

---

## Dropper 103

Droppers employ various advanced techniques to evade detection and successfully deliver their malicious payloads.
Some kind of droppers split the infection process into multiple stages, each delivered by a different file or script. This makes it harder to analyze the entire infection chain at once. 

**Raspberry Robin**, first classified as a worm because of its spreading infection method via USB drives and WSF files, can indeed be classified as a kind of downloader/dropper.
<p align=center><img src="https://github.com/user-attachments/assets/8785106f-4172-4caf-b196-6124e8f32383" /></p>
@LambdaMamba RaspberryRobin Malwaremon 

Once it infects a system, Raspberry Robin is designed to install and execute additional malware after initial infection. The payload delvery is one of the most interesting phase to observe, the malware is designed to drop various payloads based on its environment. For instance, it can drop fake payloads when it detects analysis tools, thereby evading detection while still delivering its malicious functionality. The purpose of the fake payload dropped by Raspberry Robin is to mislead security researchers and evade detection when the malware is running in sandboxes or being debugged, making it more difficult to detect and understand the full extent of the malware's capabilities. 

This is an advanced evasion technique used by dropper and I hope to cover it in another post in order to share this huge and "must to be highlighted" (dropper) technique.


---

![image](https://github.com/user-attachments/assets/a63de05a-3a80-4d02-89f8-de069b376233)
...ok mum
