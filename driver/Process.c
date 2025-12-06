// Process.c - Aggressive Comodo Process Blocking for Sandbox Testing
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver_Process.h"

LIST_ENTRY g_ComodoTargetPidsList;
KSPIN_LOCK g_ComodoTargetPidsLock;
PVOID g_ObRegistrationHandle = NULL;

NTSTATUS ProcessDriverEntry() {
    NTSTATUS status = ProtectProcess();
    if (NT_SUCCESS(status)) {
        DbgPrint("[Comodo-Blocker] Process blocking initialized successfully\r\n");
    }
    else {
        DbgPrint("[Comodo-Blocker] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

NTSTATUS ProtectProcess(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("ProtectProcess: wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    InitializeListHead(&g_ComodoTargetPidsList);
    KeInitializeSpinLock(&g_ComodoTargetPidsLock);

    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Comodo-Blocker] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        return status;
    }

    g_OpReg = (POB_OPERATION_REGISTRATION)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(OB_OPERATION_REGISTRATION) * 2, 'gOpR');
    if (!g_OpReg) {
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION) * 2);

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(OB_CALLBACK_REGISTRATION), 'gObR');
    if (!g_ObReg) {
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        g_OpReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_ObReg, sizeof(OB_CALLBACK_REGISTRATION));

    g_OpReg[0].ObjectType = PsProcessType;
    g_OpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[0].PreOperation = preCall;
    g_OpReg[0].PostOperation = NULL;

    g_OpReg[1].ObjectType = PsThreadType;
    g_OpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[1].PreOperation = threadPreCall;
    g_OpReg[1].PostOperation = NULL;

    g_ObReg->Version = ObGetFilterVersion();
    g_ObReg->OperationRegistrationCount = 2;
    g_ObReg->OperationRegistration = g_OpReg;
    g_ObReg->RegistrationContext = NULL;
    RtlInitUnicodeString(&g_ObReg->Altitude, L"321000");

    status = ObRegisterCallbacks(g_ObReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Comodo-Blocker] ObRegisterCallbacks failed: 0x%X\n", status);
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        ExFreePoolWithTag(g_ObReg, 'gObR');
        g_OpReg = NULL;
        g_ObReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return status;
    }

    DbgPrint("[Comodo-Blocker] ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
}

VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo) {
        if (IsComodoProcessByPath(Process)) {
            PPROTECTED_PID_ENTRY pNewEntry = ExAllocatePoolWithTag(
                NonPagedPool, sizeof(PROTECTED_PID_ENTRY), PID_LIST_TAG
            );

            if (pNewEntry) {
                pNewEntry->ProcessId = ProcessId;

                KLOCK_QUEUE_HANDLE lockHandle;
                KeAcquireInStackQueuedSpinLock(&g_ComodoTargetPidsLock, &lockHandle);
                InsertTailList(&g_ComodoTargetPidsList, &pNewEntry->ListEntry);
                KeReleaseInStackQueuedSpinLock(&lockHandle);

                DbgPrint("[Comodo-Blocker] *** COMODO PROCESS DETECTED ***: PID %llu - BLOCKING ALL ACCESS\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
            }
        }
    }
    else {
        KLOCK_QUEUE_HANDLE lockHandle;
        KeAcquireInStackQueuedSpinLock(&g_ComodoTargetPidsLock, &lockHandle);

        PLIST_ENTRY pCurrent = g_ComodoTargetPidsList.Flink;
        while (pCurrent != &g_ComodoTargetPidsList) {
            PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
            if (pEntry->ProcessId == ProcessId) {
                RemoveEntryList(&pEntry->ListEntry);
                ExFreePoolWithTag(pEntry, PID_LIST_TAG);
                DbgPrint("[Comodo-Blocker] Comodo process terminated: PID %llu\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
                break;
            }
            pCurrent = pCurrent->Flink;
        }

        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
}

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProc);

    // Check if target is a Comodo process
    BOOLEAN targetIsComodo = IsComodoProcessByPid(targetPid);

    if (!targetIsComodo)
        return OB_PREOP_SUCCESS;

    // AGGRESSIVELY strip ALL access to Comodo processes
    HANDLE callerPid = PsGetProcessId(currentProc);

    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        ACCESS_MASK original = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

        // Strip EVERYTHING - give ZERO access (not even synchronize)
        pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

        DbgPrint("[COMODO-BLOCKER] *** DENIED ALL PROCESS ACCESS *** Target PID: %p, Caller PID: %p, Original: 0x%X, New: 0x0\r\n",
            targetPid, callerPid, original);
    }
    else {
        ACCESS_MASK original = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

        DbgPrint("[COMODO-BLOCKER] *** DENIED ALL DUPLICATE PROCESS ACCESS *** Target PID: %p, Caller PID: %p, Original: 0x%X, New: 0x0\r\n",
            targetPid, callerPid, original);
    }

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(currentProc);

    PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
    PEPROCESS targetProc = PsGetThreadProcess(targetThread);

    if (!targetProc)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId(targetProc);

    BOOLEAN targetIsComodo = IsComodoProcessByPid(targetPid);

    if (!targetIsComodo)
        return OB_PREOP_SUCCESS;

    // AGGRESSIVELY strip ALL thread access
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        ACCESS_MASK original = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

        // Strip EVERYTHING from threads - ZERO access
        pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

        DbgPrint("[COMODO-BLOCKER] *** DENIED ALL THREAD ACCESS *** Target PID: %p, Caller PID: %p, Original: 0x%X, New: 0x0\r\n",
            targetPid, callerPid, original);
    }
    else {
        ACCESS_MASK original = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

        DbgPrint("[COMODO-BLOCKER] *** DENIED ALL DUPLICATE THREAD ACCESS *** Target PID: %p, Caller PID: %p, Original: 0x%X, New: 0x0\r\n",
            targetPid, callerPid, original);
    }

    return OB_PREOP_SUCCESS;
}

BOOLEAN IsComodoProcessByPid(HANDLE ProcessId) {
    BOOLEAN isComodo = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ComodoTargetPidsLock, &lockHandle);

    PLIST_ENTRY pCurrent = g_ComodoTargetPidsList.Flink;
    while (pCurrent != &g_ComodoTargetPidsList) {
        PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
        if (pEntry->ProcessId == ProcessId) {
            isComodo = TRUE;
            break;
        }
        pCurrent = pCurrent->Flink;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return isComodo;
}

BOOLEAN IsComodoProcessByPath(PEPROCESS Process) {
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer) {
        if (pImageName) ExFreePool(pImageName);
        return FALSE;
    }

    // Comodo process patterns to aggressively block
    static const PCWSTR patterns[] = {
        // Main Comodo processes
        L"\\Comodo\\COMODO Internet Security\\cistray.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdagent.exe",
        L"\\Comodo\\COMODO Internet Security\\cavwp.exe",
        L"\\Comodo\\COMODO Internet Security\\cis.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdvirth.exe",
        L"\\Comodo\\COMODO Internet Security\\ciscvc.exe",
        L"\\Comodo\\COMODO Internet Security\\cfpconfg.exe",
        L"\\Comodo\\COMODO Internet Security\\cfpchecker.exe",
        L"\\Comodo\\COMODO Internet Security\\cfpsbx.exe",
        L"\\Comodo\\COMODO Internet Security\\cis_tray_icon.exe",

        // CRITICAL: Comodo Sandbox/Virtualization processes
        L"\\Comodo\\COMODO Internet Security\\virtkiosk.exe",
        L"\\Comodo\\COMODO Internet Security\\virtkiosk32.exe",
        L"\\Comodo\\COMODO Internet Security\\virtkiosk64.exe",
        L"\\VTRoot\\",  // Any process running in virtual root

        // Comodo updaters and services
        L"\\Comodo\\COMODO Internet Security\\cistray.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdagent.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(patterns); ++i) {
        if (UnicodeStringEndsWithInsensitive(pImageName, patterns[i])) {
            result = TRUE;
            break;
        }
    }

    ExFreePool(pImageName);
    return result;
}

BOOLEAN IsSystemProcess(PEPROCESS Process) {
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer) {
        if (pImageName) ExFreePool(pImageName);
        return FALSE;
    }

    static const PCWSTR systemProcesses[] = {
        L"\\Windows\\System32\\csrss.exe",
        L"\\Windows\\System32\\services.exe",
        L"\\Windows\\System32\\svchost.exe",
        L"\\Windows\\System32\\lsass.exe",
        L"\\Windows\\System32\\smss.exe",
        L"\\Windows\\System32\\wininit.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(systemProcesses); ++i) {
        if (UnicodeStringEndsWithInsensitive(pImageName, systemProcesses[i])) {
            result = TRUE;
            break;
        }
    }

    ExFreePool(pImageName);
    return result;
}

BOOLEAN UnicodeStringEndsWithInsensitive(PUNICODE_STRING Source, PCWSTR Pattern) {
    if (!Source || !Source->Buffer || !Pattern) return FALSE;

    UNICODE_STRING patternString;
    RtlInitUnicodeString(&patternString, Pattern);

    if (Source->Length < patternString.Length) return FALSE;

    UNICODE_STRING sourceSuffix;
    sourceSuffix.Length = patternString.Length;
    sourceSuffix.MaximumLength = patternString.Length;
    sourceSuffix.Buffer = (PWCH)((PCHAR)Source->Buffer + Source->Length - patternString.Length);

    return (RtlCompareUnicodeString(&sourceSuffix, &patternString, TRUE) == 0);
}
