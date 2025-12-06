// File.c - Aggressive Comodo Blocking for Sandbox Testing
#include "Driver_File.h"

// globals
PVOID g_CallBackHandle = NULL;

// forward declarations
NTSTATUS ProtectFileByObRegisterCallbacks(VOID);
VOID EnableObType(POBJECT_TYPE ObjectType);
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

// entry/unload
NTSTATUS FileDriverEntry()
{
    NTSTATUS status = ProtectFileByObRegisterCallbacks();
    if (NT_SUCCESS(status)) {
        DbgPrint("[Comodo-Blocker] File blocking initialized\n");
    }
    else {
        DbgPrint("[Comodo-Blocker] ProtectFileByObRegisterCallbacks failed: 0x%X\n", status);
    }
    return status;
}

VOID EnableObType(POBJECT_TYPE ObjectType)
{
    if (!ObjectType) {
        DbgPrint("[Comodo-Blocker] EnableObType: NULL ObjectType\n");
        return;
    }

    __try {
        POBJECT_TYPE_TEMP pTemp = (POBJECT_TYPE_TEMP)ObjectType;

        if (pTemp->Name.Buffer == NULL && pTemp->DefaultObject == NULL) {
            DbgPrint("[Comodo-Blocker] EnableObType: object type fields appear NULL (continuing with caution)\n");
        }

        pTemp->TypeInfo.SupportsObjectCallbacks = 1;

        DbgPrint("[Comodo-Blocker] EnableObType: Set SupportsObjectCallbacks=1 for object type at %p\n", ObjectType);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Comodo-Blocker] EnableObType: exception while attempting to set SupportsObjectCallbacks\n");
    }
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION callBackReg;
    OB_OPERATION_REGISTRATION operationReg;
    NTSTATUS status;

    EnableObType(*IoFileObjectType);

    RtlZeroMemory(&callBackReg, sizeof(callBackReg));
    RtlZeroMemory(&operationReg, sizeof(operationReg));

    callBackReg.Version = ObGetFilterVersion();
    callBackReg.OperationRegistrationCount = 1;
    callBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callBackReg.Altitude, L"321000");

    operationReg.ObjectType = IoFileObjectType;
    operationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)PreCallBack;
    operationReg.PostOperation = NULL;

    callBackReg.OperationRegistration = &operationReg;

    status = ObRegisterCallbacks(&callBackReg, &g_CallBackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Comodo-Blocker] ObRegisterCallbacks failed: 0x%X\n", status);
    }
    else {
        DbgPrint("[Comodo-Blocker] ObRegisterCallbacks succeeded\n");
    }

    return status;
}

BOOLEAN GetFileDosName(PFILE_OBJECT FileObject, POBJECT_NAME_INFORMATION* OutNameInfo)
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st;

    if (!FileObject || !OutNameInfo) return FALSE;

    st = IoQueryFileDosDeviceName(FileObject, &nameInfo);
    if (!NT_SUCCESS(st) || !nameInfo || !nameInfo->Name.Buffer || nameInfo->Name.Length == 0) {
        if (nameInfo) ExFreePool(nameInfo);
        *OutNameInfo = NULL;
        return FALSE;
    }

    *OutNameInfo = nameInfo;
    return TRUE;
}

OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *IoFileObjectType) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PFILE_OBJECT fileObj = (PFILE_OBJECT)OperationInformation->Object;
    if (!fileObj) return OB_PREOP_SUCCESS;

    POBJECT_NAME_INFORMATION nameInfo = NULL;
    if (!GetFileDosName(fileObj, &nameInfo)) {
        return OB_PREOP_SUCCESS;
    }

    UNICODE_STRING fileName = nameInfo->Name;
    BOOLEAN isComodoTarget = FALSE;

    // Comodo components to aggressively block access to
    static const PCWSTR comodoPatterns[] = {
        // Main Comodo executables
        L"\\Comodo\\COMODO Internet Security\\cistray.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdagent.exe",
        L"\\Comodo\\COMODO Internet Security\\cavwp.exe",
        L"\\Comodo\\COMODO Internet Security\\cis.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdvirth.exe",
        L"\\Comodo\\COMODO Internet Security\\ciscvc.exe",
        L"\\Comodo\\COMODO Internet Security\\cfpconfg.exe",
        L"\\Comodo\\COMODO Internet Security\\CSUIAd.dll",
        L"\\Comodo\\COMODO Internet Security\\guardiand.dll",
        L"\\Comodo\\COMODO Internet Security\\cfpchecker.dll",

        // Comodo Sandbox/Virtualization components - CRITICAL TO BLOCK
        L"\\Comodo\\COMODO Internet Security\\virtkiosk.exe",
        L"\\Comodo\\COMODO Internet Security\\cavwp.exe",
        L"\\Comodo\\COMODO Internet Security\\cmdvirth.exe",
        L"\\Comodo\\COMODO Internet Security\\cfpsbx.exe",
        L"\\VTRoot\\",  // Virtual root for sandboxed applications

        // Comodo drivers
        L"\\drivers\\cmdguard.sys",
        L"\\drivers\\cmderd.sys",
        L"\\drivers\\inspect.sys",
        L"\\drivers\\cmdhlp.sys",
        L"\\drivers\\hooksys.sys",
        L"\\drivers\\cmdvirth.sys",

        // Guard DLLs
        L"\\Windows\\System32\\guard64.dll",
        L"\\Windows\\SysWOW64\\guard32.dll",

        // Comodo data directories
        L"\\ProgramData\\Comodo\\",
        L"\\Program Files\\Comodo\\",
        L"\\Program Files (x86)\\Comodo\\"
    };

    for (ULONG i = 0; i < ARRAYSIZE(comodoPatterns); ++i) {
        if (wcsstr(fileName.Buffer, comodoPatterns[i]) != NULL) {
            isComodoTarget = TRUE;
            break;
        }
    }

    if (isComodoTarget) {
        ACCESS_MASK desiredAccess = 0;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        // AGGRESSIVELY strip ALL access rights except minimal read
        if (desiredAccess != 0) {
            HANDLE currentPid = PsGetCurrentProcessId();

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                // Strip EVERYTHING including read/write/execute/delete
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[COMODO-BLOCKER] *** DENIED ALL ACCESS *** to: %wZ from PID: %p (Original: 0x%X)\n",
                    &fileName, currentPid, desiredAccess);
            }
            else {
                // Strip duplicate handle access too
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[COMODO-BLOCKER] *** DENIED DUPLICATE ACCESS *** to: %wZ from PID: %p (Original: 0x%X)\n",
                    &fileName, currentPid, desiredAccess);
            }
        }
    }

    if (nameInfo) {
        ExFreePool(nameInfo);
    }

    return OB_PREOP_SUCCESS;
}
