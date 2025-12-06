#ifndef CXX_FILEPROTECTX64_H
#define CXX_FILEPROTECTX64_H
#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <devioctl.h>
#include <ntstrsafe.h>   // RtlStringCb* functions
#include <wdm.h>         // kernel-mode APIs

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

char dosPath[MAX_PATH];

/* Custom object type initializer with anonymous union/struct so that
   TypeInfo.SupportsObjectCallbacks is directly accessible (as in your code). */
typedef struct _CXX_OBJECT_TYPE_INITIALIZER
{
    USHORT Length;
    union
    {
        UCHAR ObjectTypeFlags;
        struct /* anonymous - allows direct access to SupportsObjectCallbacks */
        {
            UCHAR CaseInsensitive : 1;
            UCHAR UnnamedObjectsOnly : 1;
            UCHAR UseDefaultObject : 1;
            UCHAR SecurityRequired : 1;
            UCHAR MaintainHandleCount : 1;
            UCHAR MaintainTypeList : 1;
            UCHAR SupportsObjectCallbacks : 1;
            UCHAR ReservedFlags : 1;
        };
    }; /* end union */
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG RetainAccess;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;
} CXX_OBJECT_TYPE_INITIALIZER, * PCXX_OBJECT_TYPE_INITIALIZER;

/* Temporary object-type-like structure for your usage */
typedef struct _CXX_OBJECT_TYPE_TEMP
{
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    UCHAR _PADDING0[3];
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    UCHAR _PADDING1[4];
    CXX_OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONG64 TypeLock;
    ULONG Key;
    UCHAR _PADDING2[4];
    LIST_ENTRY CallbackList;
} CXX_OBJECT_TYPE_TEMP, * PCXX_OBJECT_TYPE_TEMP;

/* --- Backwards-compatible aliases --- */
/* These make your existing code (which expects OBJECT_TYPE_TEMP / POBJECT_TYPE_TEMP)
   continue to compile. */
typedef CXX_OBJECT_TYPE_INITIALIZER OBJECT_TYPE_INITIALIZER;
typedef PCXX_OBJECT_TYPE_INITIALIZER POBJECT_TYPE_INITIALIZER;
typedef CXX_OBJECT_TYPE_TEMP OBJECT_TYPE_TEMP;
typedef PCXX_OBJECT_TYPE_TEMP POBJECT_TYPE_TEMP;

/* Callback prototype — keep using kernel-provided types */
OB_PREOP_CALLBACK_STATUS
PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

/* Initialization helper */
NTSTATUS ProtectFileByObRegisterCallbacks(VOID);

#endif /* CXX_FILEPROTECTX64_H */
