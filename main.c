#define _WIN32_WINNT 0x0A00

#include <stdio.h>
#include <windows.h>
#include <wow64apiset.h>
#include <psapi.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct FlagMap {
    DWORD flag;
    const char* name;
};

const struct FlagMap ProtectTable[] = {
    { PAGE_EXECUTE, "PAGE_EXECUTE" },
    { PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ" },
    { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" },
    { PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY" },
    { PAGE_NOACCESS, "PAGE_NOACCESS" },
    { PAGE_READONLY, "PAGE_READONLY" },
    { PAGE_READWRITE, "PAGE_READWRITE" },
    { PAGE_WRITECOPY, "PAGE_WRITECOPY" },
    { PAGE_TARGETS_INVALID, "PAGE_TARGETS_INVALID" },
    { PAGE_TARGETS_NO_UPDATE, "PAGE_TARGETS_NO_UPDATE" },
    { PAGE_GUARD, "PAGE_GUARD" },
    { PAGE_NOCACHE, "PAGE_NOCACHE" },
    { PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE" }
};

void GetState(char* stateString, int sizeOfStateString, DWORD state);
void GetType(char* typeString, int sizeOfTypeString, DWORD type);
void GetProtect(DWORD protect, DWORD state, unsigned long long* executeRegions, unsigned long long* fullAccessRegions, BOOL* isRWX, char* protectString, size_t protectStringSize);
void GetRegionDetails(HANDLE processHandle, MEMORY_BASIC_INFORMATION* mbi, char* detailsString, size_t maxLen);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Please provide the PID of the running process!\n");

        return -1;
    }

    if (argc > 2) {
        printf("Too Many Arguments! The program expects a PID to a running process\n");

        return -1;
    }

    char *endPtr;
    errno = 0;

    long pid = strtol(argv[1], &endPtr, 10);

    if (endPtr == argv[1]) {
        printf("PID is not a string, please provide a PID as a number\n");

        return -1;
    }

    if (*endPtr != '\0') {
        printf("PID is a full number! Some characters were found with the provided PID\n");

        return -1;
    }

    if (errno == ERANGE) {
        printf("The provided number is too large!\n");

        return -1;
    }

    if (pid < 0) {
        printf("PID is not a negative number!\n");

        return -1;
    }

    printf("\n================================================================================\n");
    printf("                          Cross-Process Memory Scanner                     \n");
    printf("================================================================================\n");

    printf("\nTarget PID: %ld ", pid);
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (processHandle == NULL) {
        printf("(Invalid)\n\nExiting..\n");

        return -1;
    }

    printf("(Valid)\n");

    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL result = IsWow64Process2(processHandle, &processMachine, &nativeMachine);

    if (!result) {
        printf("IsWow64Process 2 Failed - Error: %lu\n", GetLastError());

        return -1;
    }

    printf("Target Process Architecture: ");
    BOOL is64 = FALSE;
    BOOL is32 = FALSE;
    
    USHORT targetMachine = processMachine;
    if (targetMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
        targetMachine = nativeMachine;
    }

    if (targetMachine == IMAGE_FILE_MACHINE_I386) {
        printf("32-bit\n");
        is64 = FALSE;
        is32 = TRUE;
    } else if (targetMachine == IMAGE_FILE_MACHINE_AMD64) {
        printf("64-bit\n");
        is64 = TRUE;
        is32 = FALSE;
    } else {
        printf("Unknown\n\nExiting...\n");

        return -1;
    }

    printf("\nScanning the Virtual Address Space..\n\n");    

    MEMORY_BASIC_INFORMATION mbi;
    size_t queryResult;
    uintptr_t memoryAddress = 0x0;
    unsigned long long virtualSizeMax;
    if (is32) {
        virtualSizeMax = 0x7FFFFFFF;
    } else if (is64) {
        virtualSizeMax = 0x00007FFFFFFFFFFF;
    }

    printf("%-20s %-20s %-10s %-12s %-12s %-30s %-s\n", "Base Address", "End Address", "Size (KB)", "State", "Type", "Protection", "Details");
    printf("---------------------------------------------------------------------------------------------------------------------------------------\n");

    unsigned int regionsScanned = 0;
    unsigned long long committedMemorySize = 0;
    unsigned long long committedImageSize = 0;
    unsigned long long committedPrivateSize = 0;
    unsigned long long committedMappedSize = 0;
    unsigned long long reservedMemorySize = 0;

    unsigned long long executeRegions = 0;
    unsigned long long fullAccessRegions = 0;
    while ((queryResult = VirtualQueryEx(processHandle, (LPCVOID)memoryAddress, &mbi, sizeof(mbi))) != 0 && memoryAddress <= virtualSizeMax) {
        regionsScanned++;
        
        if (mbi.State == MEM_FREE) {
            memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            
            continue;
        }

        if (mbi.State == MEM_COMMIT) {
            committedMemorySize += mbi.RegionSize;

            if (mbi.Type == MEM_IMAGE) {
                committedImageSize += mbi.RegionSize;
            } else if (mbi.Type == MEM_PRIVATE) {
                committedPrivateSize += mbi.RegionSize;
            } else if (mbi.Type == MEM_MAPPED) {
                committedMappedSize += mbi.RegionSize;
            }
        }

        if (mbi.State == MEM_RESERVE) {
            reservedMemorySize += mbi.RegionSize;
        }
        
        size_t regionSizeKB = mbi.RegionSize / 1024;
        char state[20];
        GetState(state, sizeof(state), mbi.State);

        char type[20];
        GetType(type, sizeof(type), mbi.Type);

        char protectString[128];
        BOOL isRWX = FALSE;
        GetProtect(mbi.Protect, mbi.State, &executeRegions, &fullAccessRegions, &isRWX, protectString, sizeof(protectString));

        char details[128];
        GetRegionDetails(processHandle, &mbi, details, sizeof(details));

        memoryAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        printf("0x%016llX   0x%016llX   %-10llu %-12s %-12s %-30s", (unsigned long long)mbi.BaseAddress, memoryAddress, regionSizeKB, state, type, protectString);
        
        if (isRWX) {
            printf("RWX ALERT!!");
        }

        printf("%s\n", details);
    }
    printf("---------------------------------------------------------------------------------------------------------------------------------------\n\n");

    printf("Memory Scan Summary:\n");
    printf("--------------------\n\n");

    printf("Total Regions Scanned: %u\n", regionsScanned);

    long double committedMemorySizeMB = ((long double)committedMemorySize / 1024) / 1024;
    long double committedImageSizeMB = ((long double)committedImageSize / 1024) / 1024;
    long double committedPrivateSizeMB = ((long double)committedPrivateSize / 1024) / 1024;
    long double committedMappedSizeMB = ((long double)committedMappedSize / 1024) / 1024;
    long double reservedMemorySizeMB = ((long double)reservedMemorySize / 1024) / 1024;
    printf("Total Committed Memory: %.4Lf MB\n", committedMemorySizeMB);
    printf("- Image Memory: %.4Lf\n", committedImageSizeMB);
    printf("- Private Memory: %.4Lf\n", committedPrivateSizeMB);
    printf("- Mapped Memory: %.4Lf\n", committedMappedSizeMB);
    printf("Total Reserved Memory: %.4Lf MB\n\n", reservedMemorySizeMB);

    printf("Executable Regions: %llu\n", executeRegions);
    printf("Full Access Regions (RWX): %llu\n", fullAccessRegions);
    CloseHandle(processHandle);
    
    return 0;
}

void GetState(char* stateString, int sizeOfStateString, DWORD state) {
    if (state == MEM_COMMIT) {
        strcpy_s(stateString, sizeOfStateString, "MEM_COMMIT");
    } else if (state == MEM_RESERVE) {
        strcpy_s(stateString, sizeOfStateString, "MEM_RESERVE");
    } else if (state == MEM_FREE) {
        strcpy_s(stateString, sizeOfStateString, "MEM_FREE");
    }
}

void GetType(char* typeString, int sizeOfTypeString, DWORD type) {
    if (type == MEM_IMAGE) {
        strcpy_s(typeString, sizeOfTypeString, "MEM_IMAGE");
    } else if (type == MEM_MAPPED) {
        strcpy_s(typeString, sizeOfTypeString, "MEM_MAPPED");
    } else if (type == MEM_PRIVATE) {
        strcpy_s(typeString, sizeOfTypeString, "MEM_PRIVATE");
    }
}

void GetProtect(DWORD protect, DWORD state, unsigned long long* executeRegions, unsigned long long* fullAccessRegions, BOOL* isRWX, char* protectString, size_t protectStringSize) {
    if (state == MEM_RESERVE) {
        snprintf(protectString, protectStringSize, "N/A");

        return;
    }
    
    if (protect == 0) {
        snprintf(protectString, protectStringSize, "PAGE_NOACCESS");

        return;
    }

    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE)) {
        (*executeRegions)++;
    }

    if (protect & PAGE_EXECUTE_READWRITE) {
        (*fullAccessRegions)++;
        (*isRWX) = TRUE;
    }

    protectString[0] = '\0';
    BOOL isFirst = TRUE;
    int protectTableSize = 13;
    
    for (int i = 0; i < protectTableSize; i++) {
        if ((protect & ProtectTable[i].flag) == ProtectTable[i].flag) {
            char temp[64];

            if (!isFirst) {
                snprintf(temp, sizeof(temp), " | %s", ProtectTable[i].name);
            } else {
                snprintf(temp, sizeof(temp), "%s", ProtectTable[i].name);
                isFirst = FALSE;
            }

            strncat_s(protectString, protectStringSize, temp, _TRUNCATE);
        }
    }
}

void GetRegionDetails(HANDLE processHandle, MEMORY_BASIC_INFORMATION* mbi, char* detailsString, size_t maxLen) {
    detailsString[0] = '\0';

    if (mbi->State == MEM_RESERVE){
        snprintf(detailsString, maxLen, "[Reserved Address Space]");

        return;
    }

    if (mbi->Type == MEM_IMAGE) {
        char filePath[MAX_PATH] = {0};

        if (K32GetMappedFileNameA(processHandle, mbi->BaseAddress, filePath, sizeof(filePath))) {
            char* fileName = strrchr(filePath, '\\');

            if (fileName) {
                fileName++;
            } else {
                fileName = filePath;
            }

            snprintf(detailsString, maxLen, "[Module: %s]", fileName);
        } else {
            snprintf(detailsString, maxLen, "[MEM_IMAGE]");
        }
    } else if (mbi->Type == MEM_PRIVATE) {
        if (mbi->Protect & PAGE_GUARD) {
            snprintf(detailsString, maxLen, "[Thread Stack Guard]");
        } else if (mbi->AllocationBase == mbi->BaseAddress) {
            snprintf(detailsString, maxLen, "[Private Allocation Root / Heap]");
        } else {
            snprintf(detailsString, maxLen, "[Private Data]");
        }
    } else if (mbi->Type == MEM_MAPPED) {
        char filePath[MAX_PATH] = {0};

        if (K32GetMappedFileNameA(processHandle, mbi->BaseAddress, filePath, sizeof(filePath))) {
            char* fileName = strrchr(filePath, '\\');

            if (fileName) {
                fileName++;
            } else {
                fileName = filePath;
            }

            snprintf(detailsString, maxLen, "[Mapped File: %s]", fileName);
        } else {
            snprintf(detailsString, maxLen, "[MEM_MAPPED]");
        }
    }
}