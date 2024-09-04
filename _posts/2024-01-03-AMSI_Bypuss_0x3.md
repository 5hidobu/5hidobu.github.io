---
layout: post
title: AMSI bypuss 0x3
subtitle: This technique permit to achieve another AMSI bypass via hardware breakpoints. How can we detect this kind of technique? keep reading.
---

>





# AMSI_bypuss_0x3

Everything begin when a freak guy named CCob develop **SharpBlock**, tool that operates by implementing a debugger that listens for DLL load events and prevents the DLL entry point from executing in order to stealth kicking in the ass EDRs.
Below a clear image of that guy, aka EthicalChaos.

<img align="right" width="50" src="https://github.com/user-attachments/assets/d0d06848-2ca5-49c2-9a75-3e31298ca1bc">

All the information present here are a summary of the great EthicalChaos research performed to find the best way to bypass AMSI and run SharpBlock without problems.
If you want to deep dive on the research and how SharpBlock works (highly recommended, it's a masterpiece) click on the link below:
(`https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/`)

This post intends to gather ideas from the research done by CCob and with graphical evidence and tests explain the technique to bypass AMSI.
Far be it from me to think that I copy others' research ;) 5haring is caring, remember!

Brief preamble needed: the hierarchy of calls to the amsi.dll load

![image](https://github.com/user-attachments/assets/5ab19132-7aa3-4892-8ebe-2ad7c486a752)

`https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiinitialize`

With the method to bypass AMSI by setting a null AmsiContext pointer to the AmsiOpenSession, the session was not "opened," but the AmsiInitialize call was there.
Why not patching memory like AmsiScanBuffer() or AmsiInitFailed()? Cause it will can be detected form tools like AMSIDetection and/or those functions must be called before patching it.

The goal of this bypass is to change the current instruction pointer back to the caller of AmsiInitialize and update the return value with 0x8007002 to indicate that AMSI is currently disabled, how? with hardware breakpoints!

![image](https://github.com/user-attachments/assets/1cfe441c-7f6c-4875-9e23-3874ad6abd5e)

Below an overview of the state of relevant registers when AmsiInitialize breakpoint is hit:

![image](https://github.com/user-attachments/assets/e4e21d86-c166-4b89-9c89-c3a9893679dd)

So leaving out all the details of why and how EthicalChaos came to this conclusion, 3 points are required to make this bypass:

- The first is to update the current instruction pointer to the caller. This is achieved by reading the memory address where RSP is currently pointing to, since on the first instruction of a function this will be the return address.
- The second is to set the RAX register to our return value of 0x8007002
- And the third is to increment our stack pointer so that it points to the same location as if the RET instruction was actually executed.

**SharpBlocks implementions of DisableAMSI:**

![image](https://github.com/user-attachments/assets/a0d5e120-6801-49a6-bb34-5547740dce96)

"The Context64 class used within the code above is a light wrapper around the native API’s GetThreadContext and SetThreadContext, which essentially enable applications to query and change the current state of a thread and its registers.  The thread that called AmsiInitialize is now in a state indicating AMSI has been disabled and no context was created."

Below the structure that its used to enable EnaableBreakpoints:

~~~cpp
public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                   break;
               case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
               case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                   break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }
            //Set bits 16-31 as 0, which sets
            //DR0-DR3 HBP's for execute HBP
            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            //Set DRx HBP as enabled for local mode
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;
            // Now copy the changed ctx into the original struct
            Marshal.StructureToPtr(ctx, pCtx, true);
}
~~~

`https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file#Using-Hardware-Breakpoints`

Intercepting the call and change the return address of the amsiInitialize before the open of the session, we can bypass the AMSI and no change is detected from AMSIDetection.

![image](https://github.com/user-attachments/assets/9d98e811-f6ba-4a6f-a18f-21eca1d18d59)

![image](https://github.com/user-attachments/assets/f636cf80-edfb-4dad-9e82-394ca506c4b1)


---
## Debug Registers, Hardware Breakpoints, Malwares anti-debug technique

![image](https://github.com/user-attachments/assets/25390c9e-bc0c-4404-b1d3-448df2e39caa)

But, hardware breakpoints are used also in an other smart way, **by malwares**.

"On the x86 architecture, a **debug register** is a register used by a processor for program debugging. There are six debug registers, named **DR0**...**DR7**, with DR4 and DR5 as obsolete synonyms for DR6 and DR7." [wiki_debug_register](https://en.wikipedia.org/wiki/X86_debug_register).

![image](https://github.com/user-attachments/assets/0f125dee-5cc4-4bb3-b55a-cee496f56b8f)

**Malwares with anti-debug checks** verify the contents of the first four debug registers to see if the hardware breakpoints has been set.

From the [al-khaser](https://github.com/LordNoteworthy/al-khaser) project, below the anti-debug hardwarebreakpoints cpp code:

~~~cpp
#include "pch.h"
#include "HardwareBreakpoints.h"
/*
Hardware breakpoints are a technology implemented by Intel in their processor architecture,
and are controlled by the use of special registers known as Dr0-Dr7.
Dr0 through Dr3 are 32 bit registers that hold the address of the breakpoint .
*/
BOOL HardwareBreakpoints()
{
	BOOL bResult = FALSE;
	// This structure is key to the function and is the 
	// medium for detection and removal
	PCONTEXT ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
	if (ctx) {
		SecureZeroMeory(ctx, sizeof(CONTEXT));
		// The CONTEXT structure is an in/out parameter therefore we have
		// to set the flags so Get/SetThreadContext knows what to set or get.
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		// Get the registers
		if (GetThreadContext(GetCurrentThread(), ctx)) {
			// Now we can check for hardware breakpoints, its not 
			// necessary to check Dr6 and Dr7, however feel free to
			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
				bResult = TRUE;
		}
		VirtualFree(ctx, 0, MEM_RELEASE);
	}
	return bResult;
}
~~~


---
 as always..
## Let’s take a look from **Blue Team** perspective.

![image](https://github.com/user-attachments/assets/c7bdd6d9-cf95-43ea-9ae9-913af050caff)

From a Blue Team perspective, also here with this technique we can observe the EID 4104 (Powershell Operational Log). With the evidences about the command executed in the Powershell session it can be possible write a precise detection rule in order to detect technique execution attempt.

![image](https://github.com/user-attachments/assets/b384c79b-dab1-490a-8c9b-8db5824e2efd)

This log is enabled by default, if not, to enable script block logging, go to the Windows PowerShell GPO settings and set Turn on PowerShell Script Block Logging to enabled. Alternately, you can set the following registry value: “HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1” ([docs.splunk](https://docs.splunk.com/Documentation/UBA/5.1.0.1/GetDataIn/AddPowerShell#:~:text=To%20enable%20script%20block%20logging,Script%20Block%20Logging%20to%20enabled.&text=In%20addition%2C%20turn%20on%20command%20line%20process%20auditing).)

---

Some pseudo code for SIEMs

~~~
SecurityEvent
| where EventID == 4104
| where AdditionalInfo contains "WinAPI.CONTEXT64" and AdditionalInfo contains "ctx.Dr0" and AdditionalInfo contains "ctx.Dr1" and AdditionalInfo contains "ctx.Dr2" and AdditionalInfo contains "ctx.Dr3"
~~~

---

This repo is intended as an overview of AMSI bypass and technique detection. There are several ways to do AMSI bypass.

---

Credits: @CCob




