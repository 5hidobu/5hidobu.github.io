---
layout: post
title: Akira Ransomware - NEO Tokyo is about to explode
subtitle: Brief analysis of the first version of the ransomware specimen used to ransom companies around the globe by the group named Akira.
---

>



# THE AKIRA RANSOMWARE

![image](https://github.com/user-attachments/assets/846cc351-9b1f-4903-a27b-6d01dc715308)

Recently it was observed a new emerging ransomware named Akira. It is believed that the ransomware group started their campaign in late March of 2023 and within a short time period they already infected more than 16 organisations worldwide. The ransomware group also have their own retro styled TOR website where they publicly expose stolen data if the victim doesn’t pay the ransom. They also have a chat feature on their website to let the victims communicate with them using the unique ID from the ransom note.

![image](https://github.com/user-attachments/assets/2c26f796-c2e8-4138-9cb2-6f23e2ca2eab)

Below Akira TOR domain address:
[hxxps://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad[.]onion]

------

This post it's based on below SHA256 sample.
SHA256: 2084AB8F92A86A37A35879378610949E21EA7B5030313655BB82FE6C67772B0D

![image](https://github.com/user-attachments/assets/7fd2c5c5-0d3f-43d9-a474-588ff5ee8a3d)

at the time of the analysis there was no previous detections from public resources.

------

![image](https://github.com/user-attachments/assets/59c27fbb-882b-42ff-9a5d-642c2ca8548c)

Compile data stamp, that correspond to 22 days before detonation detected in a compromised infrastracture

------

![image](https://github.com/user-attachments/assets/807ed619-3317-4649-9e79-ceef951808de)

Bin sections.

------

### Commands:
during the pre-execution we can find evidences about flags that the artifacts permit to select to specify some values and perform actions. 

`--encryption_path` > destination to be encrypted;
`--share_file` > wich share file;
`--encryption_percent` > iteration percentage of encryption power;

![image](https://github.com/user-attachments/assets/70bd39b6-2c6b-426c-8799-38a6f6476933)

right before the encryption blob, the sample remove shadow copy via powershell.

------
### Strings Selection:
in the meantime, the sample compare strings (that correspond to files extension) to understand wich encrypt and wich not (`.dll` `.exe` `.sys` `.msi`), in order to don't interrupt the correct execution of the encryption process.

![image](https://github.com/user-attachments/assets/b848496c-53bf-4d53-a4d2-fe9920418306)

~~~
| .4dd   | .ade | .cdb        | .dbf | .dp1  | .exb   | .fp5  | .idb   | .kexis | .mpd    | .ns4  | .pdb  | .rsd      | .sqlite   | .udb  | .xdb    | .hjt | .vmdk   | .bin  | .accdb | .arc | .cpd        | .dbc | .dlis | .epim  | .fp4  | .itdb  | .maf   | .mwb    | .nv2  | .pan  | .rpd      | .sql      | .v12  | .abcddb | .kdb | .vmsn   | .vmrs | .4dl   | .adp | .cma        | .dbt | .dsk  | .fdb   | .fpt  | .ihx   | .lwx   | .mud    | .nyf  | .pnz  | .sbf      | .sqlitedb | .usr  | .xmlff  | .icr | .vmem   | .avhd | .accde | .alf | .dad        | .dbs | .dqy  | .fcd   | .fp7  | .jet   | .mar   | .ndf    | .nwdb | .pdm  | .sas7bdat | .sqlite3  | .vpd  | .abx    | .maw | .nvram  | .avdx | .accdc | .ora | .dacpac     | .dbx | .dtsx | .fmp   | .gdb  | .itw   | .maq   | .myd    | .oqy  | .qvd  | .sdb      | .temx     | .vis  | .abs    | .lut | .vmsd   | .vhdx | .accdt | .btr | .daschema   | .dbv | .dsn  | .fic   | .frm  | .kdb   | .mav   | .nrmlib | .odb  | .qry  | .scx      | .tps      | .wdb  | .adn    | .mdt | .raw    | .iso  | .accdr | .ask | .dadiagrams | .dct | .eco  | .fmpsl | .gwi  | .jtx   | .mas   | .nnt    | .owc  | .rctd | .sdf      | .tmd      | .vvv  | .accdw  | .mdn | .vmx    | .vmcx | .adb   | .cat | .db-shm     | .dcb | .dxl  | .fmp12 | .grdb | .kexic | .mdf   | .ns3    | .orx  | .rbf  | .sdc      | .trm      | .wrk  | .fm5    | .vhd | .subvol |       | .accft | .bdf | .db3        | .ddl | .edb  | .fp3   | .his  | .kexi  | .mdb   | .ns2    | .p97  | .rodx | .spq      | .trc      | .wmdb | .db2    | .vdi | .qcow2  |  .adf   | .ckp | .db-wal     | .dcx | .ecx  | .fol   | .hdb  | .lgc   | .mrg   | .nsf    | .p96  | .rod  | .sis      | .udl      | .xld  | .icg    | .pvm | .vsv  
~~~

![image](https://github.com/user-attachments/assets/b250e15f-1dee-45b2-a6c8-f7e5bc34af8e)

------
### Ransomware Extension:
encrypted files are now stored with additional extension `.akira`

![image](https://github.com/user-attachments/assets/830d2e46-b875-4936-9e8d-3e4273b391a9)

------
### Ransom Note:
each folder with an encrypted file will have fn.txt that is the malicious actor comunication file with the indication to speech about the ransom

![image](https://github.com/user-attachments/assets/10bcb6b9-2a3d-4e7c-b5c8-80c88572cbfa)

![image](https://github.com/user-attachments/assets/32bfcf93-342e-4f53-b069-d4e509b98adb)

------

## Malware execution phases

![image](https://github.com/user-attachments/assets/82a08816-9742-4d42-8f95-aeb840ee31aa)

Specimen activities can be splitted in two distinct phases: "Setup", the first step wich are sets and initialized checks and values to proceed with the second step that correspond to the "Execution" to perform actions and impacts.

------

## STEP 1 - initilizing CSP (cryptographic service provider):

load CSP library that implement crptography-related API.
A cryptographic service provider (CSP) contains implementations of cryptographic standards and algorithms. At a minimum, a CSP consists of a dynamic-link library (DLL) that implements the functions in CryptoSPI (a system program interface). Most CSPs contain the implementation of all of their own functions.

![image](https://github.com/user-attachments/assets/130cf9b1-91d1-40a4-96c7-f98af77a5248)

The `CryptAcquireContextW` function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). This returned handle is used in calls to `CryptoAPI` functions that use the selected CSP.

![image](https://github.com/user-attachments/assets/1e869b27-cc00-4c80-8a99-3f06238f4260)

`szProvider` can tell us more informations about the algorithm that can be used for the encryption process.
The malware uses the “Microsoft Enhanced RSA and AES Cryptographic Provider” (MS_ENH_RSA_AES_PROV) to create keys and to encrypt data with the RSA (CALG_RSA_KEYX) and AES (CALG_AES_256) algorithms.

------

## STEP 2 - preparing the key
some malware authors hash the key, Akira ones add in the sample in plaintext

![image](https://github.com/user-attachments/assets/7372175d-8a9b-4354-95c4-bd2c01355835)

![image](https://github.com/user-attachments/assets/74e84f78-e149-4af2-8155-c3bd871d2387)

the use of the `CryptGenRanom` function that fills a buffer with random bytes of encryption is also observed.

![image](https://github.com/user-attachments/assets/3dcf0d3b-6982-48da-9c74-fd17d78130a0)


------

## STEP 3 - Process Killing
The ransomware is also capable of killing process which are registered resources with the windows restart manager, to encrypt the files used by them uninterruptedly, to achieve this it does the following:
First it calls `wtsenumerateprocesses` to find all the running processes and retrieve the PIDs which will then be compared with the list of Whitelisted process names and stores the PIDs of the whitelisted process.

![image](https://github.com/user-attachments/assets/a1528dff-5540-4431-9d1c-db1368dda468)

Each file will be passed to a function which will start a restart manager session and register those files to restart manager, where `RmGetList` will be called which will return the list of process and services information that are using the file.

![image](https://github.com/user-attachments/assets/58d9cd48-f459-4969-8b10-61359383113b)

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

![image](https://github.com/user-attachments/assets/56789de9-6f73-4244-a2a0-b1e18e3283be)

------

A decryptor was recently developed by Avast researchers for this ransomware sample:

![image](https://github.com/user-attachments/assets/67fd33d8-22d8-4f31-970f-acfe02f6c4ed)

Therefore, a second enhanced version of the ransomware used by Threat Actors was observed.















