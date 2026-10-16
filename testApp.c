#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    (void)argv;
    
    if (argc > 1) {
        printf("Too Many Arguments! This program doesn't expect any arguments!\n");

        return -1;
    }

    DWORD pid = GetCurrentProcessId();
    printf("Process's PID: %lu\n", pid);

    getchar();

    return 0;
}