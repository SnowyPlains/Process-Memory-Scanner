# Cross-Process Memory Layout Scanner
#### Description: A native Windows diagnostic and security analysis utility written in pure C that enumerates and inspects the virtual address space of a target running process. Built using Win32 memory management APIs (VirtualQueryEx, OpenProcess, IsWow64Process2), this tool categorizes memory regions by state, type, protection flags, and heuristic security context.
#### Date: 12 October 2026

## Features:
- **Robust Argument Parsing:** Validates target Process IDs (PIDs) using strtol, checking for malformed inputs, string overflows (ERANGE), and negative numbers.
- **Dual-Architecture Target Support:** Automatically detects whether a target application runs as a 32-bit or 64-bit process using IsWow64Process2.
- **Virtual Address Space Traversal:** Iterates through the entire user-mode address boundary (0x0 up to 0x7FFFFFFF for 32-bit or 0x00007FFFFFFFFFFF for 64-bit) via VirtualQueryEx.
- **Protection Mask & State Decoding:** Decodes complex bitmask protection flags and memory states into readable string tables.
- **Heuristic Region Fingerprinting:** Resolves disk file mappings for DLLs and executables using K32GetMappedFileNameA, identifies thread stack guards, and pinpoints private heap roots.
- **Defensive Threat Flagging:** Automatically tracks executable and full-access memory pages, raising alerts for suspicious RWX regions often leveraged by code injection or payload execution.

## Compilation & Usage:
**Prerequisites:**  
Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
gcc -Wall -Wextra -lpsapi -O3 main.c -o ProcMemScanner

*ProcMemScanner is the name of the program, you can name it anything you want

**Execution Examples:**  
- **General Syntax:** .\ProcMemScanner.exe \<pid\>
- **Example:** .\ProcMemScanner.exe 7828

## Sample Output:
```
================================================================================
                          Cross-Process Memory Scanner                     
================================================================================

Target PID: 7828 (Valid)
Target Process Architecture: 64-bit

Scanning the Virtual Address Space..

Base Address         End Address          Size (KB)  State        Type         Protection                     Details
---------------------------------------------------------------------------------------------------------------------------------------
0x000000007FFE0000   0x000000007FFE1000   4          MEM_COMMIT   MEM_PRIVATE  PAGE_READONLY                 [Private Allocation Root / Heap]
0x000000007FFE2000   0x000000007FFE3000   4          MEM_COMMIT   MEM_PRIVATE  PAGE_READONLY                 [Private Allocation Root / Heap]
0x000000B3C8600000   0x000000B3C8678000   480        MEM_RESERVE  MEM_PRIVATE  N/A                           [Reserved Address Space]
0x000000B3C8678000   0x000000B3C867B000   12         MEM_COMMIT   MEM_PRIVATE  PAGE_READWRITE                [Private Data]
0x000000B3C867B000   0x000000B3C8800000   1556       MEM_RESERVE  MEM_PRIVATE  N/A                           [Reserved Address Space]
0x000000B3C8800000   0x000000B3C89F8000   2016       MEM_RESERVE  MEM_PRIVATE  N/A                           [Reserved Address Space]
0x000000B3C89F8000   0x000000B3C89FB000   12         MEM_COMMIT   MEM_PRIVATE  PAGE_READWRITE | PAGE_GUARD   [Thread Stack Guard]
0x000000B3C89FB000   0x000000B3C8A00000   20         MEM_COMMIT   MEM_PRIVATE  PAGE_READWRITE                [Private Data]
0x0000027D332F0000   0x0000027D332F1000   4          MEM_COMMIT   MEM_MAPPED   PAGE_READWRITE                [MEM_MAPPED]
0x0000027D332F1000   0x0000027D332F2000   4          MEM_RESERVE  MEM_MAPPED   N/A                           [Reserved Address Space]
0x0000027D33300000   0x0000027D33310000   64         MEM_COMMIT   MEM_MAPPED   PAGE_READWRITE                [MEM_MAPPED]
0x0000027D33310000   0x0000027D3333A000   168        MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D33340000   0x0000027D33344000   16         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D33350000   0x0000027D33351000   4          MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D33360000   0x0000027D33362000   8          MEM_COMMIT   MEM_PRIVATE  PAGE_READWRITE                [Private Allocation Root / Heap]
0x0000027D33370000   0x0000027D33381000   68         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [Mapped File: C_1252.NLS]
0x0000027D33390000   0x0000027D333A1000   68         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [Mapped File: C_437.NLS]
0x0000027D333B0000   0x0000027D333B3000   12         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [Mapped File: l_intl.nls]
0x0000027D333C0000   0x0000027D333CE000   56         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D333D0000   0x0000027D333DE000   56         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D333E0000   0x0000027D333E2000   8          MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
0x0000027D333F0000   0x0000027D333FC000   48         MEM_COMMIT   MEM_MAPPED   PAGE_READONLY                 [MEM_MAPPED]
...

Memory Scan Summary:
--------------------

Total Regions Scanned: 111
Total Committed Memory: 9.6992 MB
- Image Memory: 7.9844
- Private Memory: 0.1641
- Mapped Memory: 1.5508
Total Reserved Memory: 4135.6133 MB

Executable Regions: 9
Full Access Regions (RWX): 0
```

## Engineering Journal and Implementation Process:
This section documents a summary of the implementation process:

### Phase 1: Argument Parsing and Robust PID Validation
First, I made sure that the amount of arguments was correct. If argc < 2 or argc > 2, the program exits with an error message.

Next, I made sure that the argument provided was indeed a number using strtol. The function takes 3 arguments: the provided argument, endPtr of type char* used to store any characters written after the number, and the base of conversion. If the provided number is too large and overflows the long type, the ERANGE error is set to the errno variable.

After this, I added 4 checks to validate the PID:
- endPtr == argv[1] (Tests if the whole provided argument was a string).
- *endPtr != '\0' (Tests if the argument contains trailing characters after the number).
- errno == ERANGE (Tests for overflow).
- pid < 0 (Checks if the number is negative).

### Phase 2: Handle Acquisition & Process Query Privileges
Next, I used OpenProcess to get a handle to the target process. Remembering from earlier memory concepts that I need PROCESS_QUERY_INFORMATION rights to query virtual memory via VirtualQueryEx, I set up the handle acquisition:
```c
HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
if (processHandle == NULL) {
    printf("(Invalid)\n\nExiting..\n");
    return -1;
}
```

### Phase 3: Navigating Architecture Detection Gotchas
Initially, I thought about opening the program as a file and parsing its PE headers like in Project 4, but that would overly complicate inspecting a running process. Researching how to get the architecture of a running process led me to IsWow64Process2 (I found IsWow64Process mentioned in a StackOverflow thread, and in MS Docs, IsWow64Process2 was mentioned to be recommended over the first version).

However, I hit two roadblocks:
- **Compilation Error:** The compiler complained IsWow64Process2 didn't exist. I fixed this after I found that I should explicitly define _WIN32_WINNT to Windows 10 (0x0A00) before including <windows.h>.
- **Crash on Execution:** Leaving pointer variables uninitialized or assigning them NULL caused access violations because IsWow64Process2 writes directly to pre-allocated variables passed by address (&), rather than initializing pointers for you.

Fixing these allowed me to set up architecture checking properly:
```c
#define _WIN32_WINNT 0x0A00

USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
BOOL result = IsWow64Process2(processHandle, &processMachine, &nativeMachine);
```

While testing, I realized that processMachine only returns a valid value if the process is running through a 64-bit emulator (WOW64). Since I was running native 64-bit programs on a 64-bit machine, processMachine returned IMAGE_FILE_MACHINE_UNKNOWN. To solve this, I fell back to nativeMachine if processMachine was unknown:
```c
USHORT targetMachine = processMachine;
if (targetMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
    targetMachine = nativeMachine;
}
```

### Phase 4: Virtual Address Space Enumeration Loop
To traverse virtual memory, I needed VirtualQueryEx and a loop bounds check. Instead of writing separate loops for 32-bit and 64-bit targets, I unified the logic using a virtualSizeMax limit:
```c
MEMORY_BASIC_INFORMATION mbi;
size_t queryResult;
uintptr_t memoryAddress = 0x0;
unsigned long long virtualSizeMax;
if (is32) {
    virtualSizeMax = 0x7FFFFFFF;
} else if (is64) {
    virtualSizeMax = 0x00007FFFFFFFFFFF;
}

while ((queryResult = VirtualQueryEx(processHandle, (LPCVOID)memoryAddress, &mbi, sizeof(mbi))) != 0 && memoryAddress <= virtualSizeMax) {
    if (mbi.State == MEM_FREE) {
        memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        continue;
    }

    // ...
    
    memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

    // ...
}
```

### Phase 5: Decoding States, Types, and Protection Flags
To translate raw DWORD values into readable strings, I created helper functions (GetState, GetType). For protection flags, multiple bit flags can be active simultaneously. For example: "PAGE_READWRITE | PAGE_GUARD". So I iterated through a ProtectTable flag map using bitwise AND operators (&).

### Phase 6: Deriving Region Details
Adding a "Details" column was the most challenging part of the project. With Gemini's guidance, I implemented GetRegionDetails using K32GetMappedFileNameA to extract clean DLL filenames from backing file paths, while utilizing structural heuristics (PAGE_GUARD for thread stacks and AllocationBase == BaseAddress for private heap roots).

### Phase 7: Bug Fixes
- **Counter Increment Bug:** In PrintProtect, checking multiple execute flags inside the flag table loop caused executeRegions to increment multiple times per region. Moving the execute and full access checks outside the loop resolved this.
- **Compiler Warnings:** Passing an empty string literal "" to snprintf triggered a -Wformat-zero-length warning. Changing it to `detailsString[0] = '\0';` eliminated the warning instantly.
- **Column Alignment:** Refactored PrintProtect into GetProtect to return a formatted string buffer rather than streaming directly to stdout, allowing fixed-width column formatting.

## References:
1) [strtol](https://cplusplus.com/reference/cstdlib/strtol/)
2) [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
3) [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
4) [IsWow64Process - Stack Overflow](https://stackoverflow.com/questions/14160757/how-do-i-detect-the-architecture-of-a-process-on-windows)
5) [IsWow64Process](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process)
6) [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)
7) [Image File Machine Constants](https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants)
8) [Memory Basic Information](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information)