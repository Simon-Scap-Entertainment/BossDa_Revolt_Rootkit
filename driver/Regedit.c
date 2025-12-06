// Regedit.c - Aggressive Comodo Registry Blocking for Sandbox Testing
#include "Driver_Regedit.h"

LARGE_INTEGER Cookie;

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern);

NTSTATUS RegeditDriverEntry()
{
    NTSTATUS status = CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Comodo-Blocker] Registry blocking initialized successfully\r\n");
    }
    else
    {
        DbgPrint("[Comodo-Blocker] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

    pRegistryPath->Length = 0;

    if (!pRegistryObject || !MmIsAddressValid(pRegistryObject))
        return FALSE;

    NTSTATUS Status;
    ULONG ReturnLen = 0;
    POBJECT_NAME_INFORMATION NameInfo = NULL;

    Status = ObQueryNameString(pRegistryObject, NULL, 0, &ReturnLen);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || ReturnLen == 0)
        return FALSE;

    NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLen, REG_TAG);
    if (!NameInfo)
        return FALSE;

    RtlZeroMemory(NameInfo, ReturnLen);

    Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
    if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    if (NameInfo->Name.Length > pRegistryPath->MaximumLength)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);

    ExFreePoolWithTag(NameInfo, REG_TAG);
    return TRUE;
}

BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || Source->Length == 0 || !Pattern)
        return FALSE;

    UNICODE_STRING srcUp = { 0 }, patUp = { 0 };
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, Pattern);

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, Source, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &pat, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcChars = srcUp.Length / sizeof(WCHAR);
    ULONG patChars = patUp.Length / sizeof(WCHAR);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patChars * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
    RegPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REG_TAG);
    if (!RegPath.Buffer)
        return Status;

    RegPath.Length = 0;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    __try
    {
        switch (NotifyClass)
        {
        case RegNtPreDeleteValueKey:
        {
            PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }

                    // Block ALL Comodo registry operations
                    if (UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_SERVICE) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_GUARD) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_INSPECT) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_HOOKS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_APP) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_VIRT))
                    {
                        DbgPrint("[COMODO-BLOCKER] *** BLOCKED DELETE_VALUE ***: %wZ\r\n", &RegPath);
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreDeleteKey:
        {
            PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_SERVICE) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_GUARD) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_INSPECT) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_HOOKS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_APP) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_VIRT))
                    {
                        DbgPrint("[COMODO-BLOCKER] *** BLOCKED DELETE_KEY ***: %wZ\r\n", &RegPath);
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreSetValueKey:
        {
            PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }

                    if (UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_SERVICE) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_GUARD) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_INSPECT) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_HOOKS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_APP) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_VIRT))
                    {
                        DbgPrint("[COMODO-BLOCKER] *** BLOCKED SET_VALUE ***: %wZ\r\n", &RegPath);
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreRenameKey:
        {
            PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->NewName && pInfo->NewName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->NewName);
                    }

                    if (UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_SERVICE) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_GUARD) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_INSPECT) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_HOOKS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_APP) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_VIRT))
                    {
                        DbgPrint("[COMODO-BLOCKER] *** BLOCKED RENAME_KEY ***: %wZ\r\n", &RegPath);
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreOpenKey:
        case RegNtPreOpenKeyEx:
        {
            // Optionally block even OPENING Comodo keys (very aggressive)
            PREG_OPEN_KEY_INFORMATION pInfo = (PREG_OPEN_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->CompleteName && pInfo->CompleteName->Length > 0)
            {
                if (UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_SERVICE) ||
                    UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_GUARD) ||
                    UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_INSPECT) ||
                    UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_HOOKS) ||
                    UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_APP) ||
                    UnicodeContainsInsensitive(pInfo->CompleteName, REG_BLOCK_COMODO_VIRT))
                {
                    DbgPrint("[COMODO-BLOCKER] *** BLOCKED OPEN_KEY ***: %wZ\r\n", pInfo->CompleteName);
                    Status = STATUS_ACCESS_DENIED;
                }
            }
            break;
        }

        case RegNtPreQueryKey:
        {
            // Block even query operations
            PREG_QUERY_KEY_INFORMATION pInfo = (PREG_QUERY_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_SERVICE) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_GUARD) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_INSPECT) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_HOOKS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_APP) ||
                        UnicodeContainsInsensitive(&RegPath, REG_BLOCK_COMODO_VIRT))
                    {
                        DbgPrint("[COMODO-BLOCKER] *** BLOCKED QUERY_KEY ***: %wZ\r\n", &RegPath);
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Comodo-Blocker] Exception in callback: 0x%X\r\n", GetExceptionCode());
        Status = STATUS_SUCCESS;
    }

    ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}
