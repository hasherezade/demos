#pragma once
#include <psapi.h>

bool is_searched_process( DWORD processID, LPWSTR searchedName)
{
    WCHAR szProcessName[MAX_PATH];

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if (hProcess == NULL) return false;

    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName( hProcess, hMod, szProcessName, MAX_PATH );
        if (wcsstr(szProcessName, searchedName) != NULL) {
            printf( "%S  (PID: %u)\n", szProcessName, processID );
            CloseHandle(hProcess);
            return true;   
        }
    }
    CloseHandle(hProcess);
    return false;
}

HANDLE find_running_process(LPWSTR searchedName)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return NULL;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);
    // Print the name and process identifier for each process.

    for ( i = 0; i < cProcesses; i++ ) {
        if( aProcesses[i] != 0 ) {
            if (is_searched_process(aProcesses[i], searchedName)) {
                HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
                return hProcess;
            }
        }
    }
    return NULL;
}