// Driver_Process.h - Updated for Comodo Blocking
#pragma once

#include <ntddk.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                 (0x0001)  
#define PROCESS_CREATE_THREAD             (0x0002)  
#define PROCESS_SET_SESSIONID             (0x0004)  
#define PROCESS_VM_OPERATION              (0x0008)  
#define PROCESS_VM_READ                   (0x0010)  
#define PROCESS_VM_WRITE                  (0x0020)  
#define PROCESS_DUP_HANDLE                (0x0040)  
#define PROCESS_CREATE_PROCESS            (0x0080)  
#define PROCESS_SET_QUOTA                 (0x0100)  
#define PROCESS_SET_INFORMATION           (0x0200)  
#define PROCESS_QUERY_INFORMATION         (0x0400)  
#define PROCESS_SUSPEND_RESUME            (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION   (0x2000)
#endif

#define THREAD_TERMINATE           0x0001
#define THREAD_SUSPEND_RESUME      0x0002
#define THREAD_GET_CONTEXT         0x0008
#define THREAD_SET_CONTEXT         0x0010
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_SET_INFORMATION     0x0020
#define THREAD_QUERY_INFORMATION   0x0040
#define THREAD_SET_THREAD_TOKEN    0x0080
#define THREAD_IMPERSONATE         0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200

#define PID_LIST_TAG 'diPP'
#define SAFE_PROCESS_ACCESS (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define SAFE_THREAD_ACCESS (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)

typedef struct _PROTECTED_PID_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
} PROTECTED_PID_ENTRY, * PPROTECTED_PID_ENTRY;

NTSTATUS ProcessDriverEntry();
NTSTATUS ProcessDriverUnload();
NTSTATUS ProtectProcess();

VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

BOOLEAN IsComodoProcessByPath(
    PEPROCESS Process
);

BOOLEAN IsComodoProcessByPid(
    HANDLE ProcessId
);

BOOLEAN IsSystemProcess(
    PEPROCESS Process
);

BOOLEAN UnicodeStringEndsWithInsensitive(
    PUNICODE_STRING Source,
    PCWSTR Pattern
);
