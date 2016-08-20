#pragma once

#include <Windows.h>
#include "ntddk.h"

//undocumented functions from ntdll.dll
//
//don't forget to load functions before use:
//load_ntdll_functions();

NTSTATUS (NTAPI *NtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ ULONG ApcReserved OPTIONAL
);

NTSTATUS (NTAPI *ZwSetInformationThread) (
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _In_ PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength
);

NTSTATUS (NTAPI *ZwCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle, 
    _In_ ACCESS_MASK DesiredAccess, 
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, 
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ ULONG_PTR ZeroBits, 
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize, 
    _In_opt_ PVOID AttributeList 
);

NTSTATUS (NTAPI *ZwQueryInformationProcess) (
  HANDLE  ProcessHandle,
  PROCESSINFOCLASS  ProcessInformationClass,
  PVOID  ProcessInformation,
  ULONG  ProcessInformationLength,
  PULONG  ReturnLength  OPTIONAL
);

NTSTATUS (NTAPI  *RtlCreateUserThread) (
  _In_ HANDLE ProcessHandle,
  _In_ PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
  _In_ BOOLEAN CreateSuspended,
  _In_ ULONG StackZeroBits,
  _In_ _Out_ PULONG StackReserved,
  _In_ _Out_ PULONG StackCommit,
  _In_ PVOID StartAddress,
  _In_ PVOID StartParameter OPTIONAL,
  _Out_ PHANDLE ThreadHandle,
  _Out_ PCLIENT_ID ClientID
  );

BOOL load_ntdll_functions()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (hNtdll == NULL) return FALSE;

    NtQueueApcThread = (NTSTATUS (NTAPI *)(HANDLE, PVOID, PVOID, PVOID, ULONG)) GetProcAddress(hNtdll,"NtQueueApcThread");
    if (NtQueueApcThread == NULL) return FALSE;
    
    ZwSetInformationThread = (NTSTATUS (NTAPI *)(HANDLE, THREADINFOCLASS, PVOID, ULONG)) GetProcAddress(hNtdll,"ZwSetInformationThread");
    if (ZwSetInformationThread == NULL) return FALSE;

    ZwCreateThreadEx = (NTSTATUS (NTAPI *) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID)) GetProcAddress(hNtdll,"ZwCreateThreadEx");
    if (ZwCreateThreadEx == NULL) return FALSE;

    RtlCreateUserThread = (NTSTATUS (NTAPI *) (HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN,ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PCLIENT_ID)) GetProcAddress(hNtdll,"RtlCreateUserThread");
    if (RtlCreateUserThread == NULL) return FALSE;

    ZwQueryInformationProcess = (NTSTATUS (NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)) GetProcAddress(hNtdll,"ZwQueryInformationProcess");
    if (ZwQueryInformationProcess == NULL) return FALSE;
    return TRUE;
}
