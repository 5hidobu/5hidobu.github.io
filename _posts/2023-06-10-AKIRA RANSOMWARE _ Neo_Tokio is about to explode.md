# THE AKIRA RANSOMWARE

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/99314be0-c8de-499d-a000-3f01950f397a)

Recently it was observed a new emerging ransomware named Akira. It is believed that the ransomware group started their campaign in late March of 2023 and within a short time period they already infected more than 16 organisations worldwide. The ransomware group also have their own retro styled TOR website where they publicly expose stolen data if the victim doesn’t pay the ransom. They also have a chat feature on their website to let the victims communicate with them using the unique ID from the ransom note.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/1e56b709-dd7d-47ac-8234-3610a16d23b1)

Below Akira TOR domain address:
[hxxps://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad[.]onion]

------

This post it's based on below SHA256 sample.
SHA256: 2084AB8F92A86A37A35879378610949E21EA7B5030313655BB82FE6C67772B0D

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/99d91ba9-cef8-406e-9ddf-655598771408)

at the time of the analysis there was no previous detections from public resources.

------

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/9d1884aa-c347-440d-a435-ba4782d0ac05)

Compile data stamp, that correspond to 22 days before detonation detected in a compromised infrastracture

------

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/27a543f2-3897-49e6-99b6-310021381e6e)

Bin sections.

------

### Commands:
during the pre-execution we can find evidences about flags that the artifacts permit to select to specify some values and perform actions. 

`--encryption_path` > destination to be encrypted;
`--share_file` > wich share file;
`--encryption_percent` > iteration percentage of encryption power;

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/d37071fd-c2b8-4a2f-991d-d5e57ec02f9a)

right before the encryption blob, the sample remove shadow copy via powershell

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/c1e30a3a-856a-456f-b242-657a2b8e98bd)

------
### Strings Selection:
in the meantime, the sample compare strings (that correspond to files extension) to understand wich encrypt and wich not (`.dll` `.exe` `.sys` `.msi`), in order to don't interrupt the correct execution of the encryption process.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/82d0041c-8f52-44c7-ab72-6c5f9d008aee)

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/b07edcc1-a80c-4391-8b8f-d9a47846950d)

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/fe710ade-dffb-4cc8-ad7a-4070c847db8d)

------
### Ransomware Extension:
encrypted files are now stored with additional extension `.akira`

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/5c54099f-db29-423a-8171-5753a98f0ef9)

------
### Ransom Note:
each folder with an encrypted file will have fn.txt that is the malicious actor comunication file with the indication to speech about the ransom

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/e7ebb020-0674-49f3-b487-615af3b84b01)

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/f1ac4b86-8c0e-416c-a730-7a12a63dbe85)

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/7208ed3c-c4d8-49dd-954b-6d5aca7917b1)

------

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/0c37e506-7274-49c2-86bd-08fbd9edea90)

Sample activities can be splitted in two distinct phases: "Setup", the first step wich are sets and initialized checks and values to proceed with the second step that correspond to the "Execution" to perform actions and impacts.

------

## STEP 1 - initilizing CSP (cryptographic service provider):

load CSP library that implement crptography-related API.
A cryptographic service provider (CSP) contains implementations of cryptographic standards and algorithms. At a minimum, a CSP consists of a dynamic-link library (DLL) that implements the functions in CryptoSPI (a system program interface). Most CSPs contain the implementation of all of their own functions.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/7495de50-2972-4d98-8f41-9ff8e4e4ae49)

The `CryptAcquireContextW` function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). This returned handle is used in calls to `CryptoAPI` functions that use the selected CSP.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/146bc172-9fd1-401b-b98e-f0f814084dfc)

`szProvider` can tell us more informations about the algorithm that can be used for the encryption process.
The malware uses the “Microsoft Enhanced RSA and AES Cryptographic Provider” (MS_ENH_RSA_AES_PROV) to create keys and to encrypt data with the RSA (CALG_RSA_KEYX) and AES (CALG_AES_256) algorithms.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/2f101daf-0757-4b68-8625-a054f30df0ba)

------

## STEP 2 - preparing the key
some malware authors hash the key, Akira ones add in the sample in plaintext

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/69462db3-a7fb-478a-abd3-f2ee9972d501)

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/dfdccfd7-a5ff-4914-9c09-531880d53f22)

the use of the `CryptGenRanom` function that fills a buffer with random bytes of encryption is also observed.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/959d4f92-37a9-4c30-8510-300f474aa877)


------

## STEP 3 - Process Killing
The ransomware is also capable of killing process which are registered resources with the windows restart manager, to encrypt the files used by them uninterruptedly, to achieve this it does the following:
First it calls `wtsenumerateprocesses` to find all the running processes and retrieve the PIDs which will then be compared with the list of Whitelisted process names and stores the PIDs of the whitelisted process.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/546c5471-15eb-4908-a397-06bc02eba7f6)

Each file will be passed to a function which will start a restart manager session and register those files to restart manager, where `RmGetList` will be called which will return the list of process and services information that are using the file.

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/14a4ae59-5e35-4c34-83f3-0d8d996dc500)

`RmGetList()` -> Gets a list of all applications and services that are currently using resources that have been registered with the Restart Manager session;
`RmEndSession() `;
`GetCurrentProcess()`;
`GetProcessId()`;
`RmShutdown()` -> Initiates the shutdown of applications;


It then compares the PID of the current process and the whitelisted processes with the PID of the Process obtained from ‘RmGetList’, if there is a match found it will end the restart manager session, otherwise, it will forcefully shut down all registered processes that are using the file by calling ‘RmShutdown’ .

------

## STEP 4 - encrypting the data
the keys are ready, the malware use CryptEncrypt to encrypt the data. 
With this API call we can understand exactly the start of the encryption blob. 

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/e6e9bc2d-7d89-4285-a6f4-8bf5bfdea1aa)

------

A decryptor was recently developed by Avast researchers for this ransomware sample:

![image](https://github.com/5hidobu/5hidobu.github.io/assets/65976929/a4f8cade-69d8-416e-8b32-8dc4afacb62d)

Therefore, a second version of the ransomware used by Threat Actors was observed.















