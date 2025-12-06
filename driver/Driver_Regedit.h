// ============================================
// Driver_Regedit.h - Updated for Comodo Blocking
// ============================================

#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

#define REG_TAG 'gkER'

// Comodo registry paths to block
#define REG_BLOCK_COMODO_SERVICE L"\\Services\\cmdAgent"
#define REG_BLOCK_COMODO_GUARD L"\\Services\\cmdGuard"
#define REG_BLOCK_COMODO_INSPECT L"\\Services\\inspect"
#define REG_BLOCK_COMODO_HOOKS L"\\Services\\cmdHlp"
#define REG_BLOCK_COMODO_APP L"\\SOFTWARE\\Comodo\\Firewall"
#define REG_BLOCK_COMODO_VIRT L"\\Services\\cmdvirth"  // Comodo virtualization service

NTSTATUS RegeditDriverEntry();
NTSTATUS RegeditUnloadDriver();

NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(
    _In_ PUNICODE_STRING Source,
    _In_ PCWSTR Pattern
);
