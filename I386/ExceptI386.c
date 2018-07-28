/*
*
* Copyright (c) 2015-2017 by blindtiger ( blindtiger@foxmail.com )
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License")); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
* for the specific language governing rights and limitations under the
* License.
*
* The Initial Developer of the Original e is blindtiger.
*
*/

#include <OsDefs.h>

#include <cc.h>

#include "Except.h"
#include "Jump.h"
#include "Reload.h"
#include "Testis.h"

static PFUNCTION_TABLE InvertedFunctionTable;
static PFUNCTION_TABLE UserInvertedFunctionTable;
static PFUNCTION_TABLE_SPECIAL UserSpecialInvertedFunctionTable;

BOOLEAN
(NTAPI * NtosRtlDispatchException)(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
    );

NTSTATUS
NTAPI
ProtectPages(
    __inout PVOID BaseAddress,
    __inout SIZE_T RegionSize,
    __in ULONG NewProtect,
    __out PULONG OldProtect
);

EXCEPTION_DISPOSITION
NTAPI
ExecuteHandlerForException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PVOID EstablisherFrame,
    __inout PCONTEXT ContextRecord,
    __inout PVOID DispatcherContext,
    __in PEXCEPTION_ROUTINE ExceptionRoutine
);

BOOLEAN
NTAPI
DispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
);

NTSTATUS
NTAPI
InitializeExcept(
    VOID
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID ImageBase = NULL;
    PCHAR NtosRtlRaiseException = NULL;

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        NtosRtlRaiseException = GetProcedureAddress(
            ImageBase,
            "RtlRaiseException",
            0);

        if (NULL != NtosRtlRaiseException) {
            NtosRtlDispatchException = (PVOID)((NtosRtlRaiseException + 0x2d) +
                *(PLONG)(NtosRtlRaiseException +
                    0x2d) + sizeof(LONG));

            if (NULL != NtosRtlDispatchException) {
                Status = SetHotPatchRoutine(
                    (PVOID *)&NtosRtlDispatchException,
                    DispatchException);
            }
        }
    }

    return Status;
}

PVOID
NTAPI
LookupFunctionTable(
    __in PVOID ControlPc,
    __out PVOID * ImageBase,
    __out PULONG SizeOfTable
)
{
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = CONTAINING_RECORD(
            InvertedFunctionTable->TableEntry,
            FUNCTION_TABLE,
            TableEntry);

        CurrentSize = InvertedFunctionTable->CurrentSize;

        for (Index = 0;
            Index < CurrentSize;
            Index += 1) {
            if (PtrToUlong(ControlPc) >= FunctionTableEntry[Index].ImageBase &&
                PtrToUlong(ControlPc) < FunctionTableEntry[Index].ImageBase +
                FunctionTableEntry[Index].SizeOfImage) {
                *ImageBase = UlongToPtr(FunctionTableEntry[Index].ImageBase);
                *SizeOfTable = FunctionTableEntry[Index].SizeOfTable;

                FunctionTable = ULongToPtr(
                    DecodeSystemPointer(FunctionTableEntry[Index].FunctionTable));

                /*
#ifndef VMP
                DbgPrint(
                    "Soul - Testis - lookup function table < %p >\n",
                    ControlPc);
#endif // !VMP
                */

                break;
            }
        }
    }

    return FunctionTable;
}

BOOLEAN
NTAPI
DispatchException(
    __in PEXCEPTION_RECORD ExceptionRecord,
    __in PCONTEXT ContextRecord
)
{
    BOOLEAN Completion = FALSE;
    DISPATCHER_CONTEXT DispatcherContext = { 0 };
    EXCEPTION_DISPOSITION Disposition = { 0 };
    PEXCEPTION_REGISTRATION_RECORD RegistrationPointer = NULL;
    PEXCEPTION_REGISTRATION_RECORD NestedRegistration = NULL;
    ULONG HighAddress = 0;
    ULONG HighLimit = 0;
    ULONG LowLimit = 0;
    EXCEPTION_RECORD RaiseExceptionRecord = { 0 };
    ULONG Index = 0;
    ULONG TestAddress = 0;
    PKPRCB Prcb = NULL;
    ULONG DpcStack = 0;
    PVOID FunctionTable = NULL;
    PVOID ImageBase = NULL;
    ULONG SizeOfTable = 0;

    IoGetStackLimits(&LowLimit, &HighLimit);

    RegistrationPointer = KeGetPcr()->NtTib.ExceptionList;

    FunctionTable = LookupFunctionTable(
        ExceptionRecord->ExceptionAddress,
        &ImageBase,
        &SizeOfTable);

    if (NULL == FunctionTable) {
        Completion = NtosRtlDispatchException(ExceptionRecord, ContextRecord);
        goto DispatchExit;
    }

    NestedRegistration = 0;

    while (RegistrationPointer != EXCEPTION_CHAIN_END) {
        HighAddress = PtrToUlong(RegistrationPointer) + sizeof(EXCEPTION_REGISTRATION_RECORD);

        if ((PtrToUlong(RegistrationPointer) < LowLimit) ||
            (HighAddress > HighLimit) ||
            ((PtrToUlong(RegistrationPointer) & 0x3) != 0)) {
            TestAddress = PtrToUlong(RegistrationPointer);

            if (((TestAddress & 0x3) == 0) &&
                KeGetCurrentIrql() >= DISPATCH_LEVEL) {

                Prcb = KeGetCurrentPrcb();
                DpcStack = PtrToUlong(Prcb->DpcStack);

                if ((Prcb->DpcRoutineActive) &&
                    (HighAddress <= DpcStack) &&
                    (TestAddress >= DpcStack - KERNEL_STACK_SIZE)) {
                    HighLimit = DpcStack;
                    LowLimit = DpcStack - KERNEL_STACK_SIZE;
                    continue;
                }
            }

            ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            goto DispatchExit;
        }

        Disposition = ExecuteHandlerForException(
            ExceptionRecord,
            RegistrationPointer,
            ContextRecord,
            &DispatcherContext,
            RegistrationPointer->Handler);

        if (NestedRegistration == RegistrationPointer) {
            ExceptionRecord->ExceptionFlags &= ~EXCEPTION_NESTED_CALL;
            NestedRegistration = 0;
        }

        switch (Disposition) {
        case ExceptionContinueExecution: {
            if ((ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) {
                RaiseExceptionRecord.ExceptionCode = STATUS_NONCONTINUABLE_EXCEPTION;
                RaiseExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
                RaiseExceptionRecord.ExceptionRecord = ExceptionRecord;
                RaiseExceptionRecord.NumberParameters = 0;

                RtlRaiseException(&RaiseExceptionRecord);
            }
            else {
                Completion = TRUE;
                goto DispatchExit;
            }
        }

        case ExceptionContinueSearch: {
            if (ExceptionRecord->ExceptionFlags & EXCEPTION_STACK_INVALID) {
                goto DispatchExit;
            }

            break;
        }

        case ExceptionNestedException: {
            ExceptionRecord->ExceptionFlags |= EXCEPTION_NESTED_CALL;
            if (DispatcherContext.RegistrationPointer > NestedRegistration) {
                NestedRegistration = DispatcherContext.RegistrationPointer;
            }

            break;
        }

        default: {
            RaiseExceptionRecord.ExceptionCode = STATUS_INVALID_DISPOSITION;
            RaiseExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
            RaiseExceptionRecord.ExceptionRecord = ExceptionRecord;
            RaiseExceptionRecord.NumberParameters = 0;

            RtlRaiseException(&RaiseExceptionRecord);

            break;
        }
        }

        RegistrationPointer = RegistrationPointer->Next;
    }

DispatchExit:
    return Completion;
}

VOID
NTAPI
SearchUserInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PSTR SectionName = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PFUNCTION_TABLE_ENTRY32 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    if (FALSE == PsIsSystemProcess(IoGetCurrentProcess())) {
        ImageBase = GetImageHandle("ntdll.dll");

        if (NULL != ImageBase) {
            NtHeaders = RtlImageNtHeader(ImageBase);

            if (FALSE != MmIsAddressValid(NtHeaders)) {
                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                FunctionTableEntry = ExAllocatePool(
                    NonPagedPool,
                    sizeof(FUNCTION_TABLE_ENTRY32));

                if (NULL != FunctionTableEntry) {
                    CaptureImageExceptionValues(
                        ImageBase,
                        &FunctionTable,
                        &SizeOfTable);

                    FunctionTableEntry->FunctionTable = PtrToUlong(FunctionTable);
                    FunctionTableEntry->ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry->SizeOfImage = FetchSizeOfImage(ImageBase);
                    FunctionTableEntry->SizeOfTable = SizeOfTable;

                    for (Index = 0;
                        Index < NtHeaders->FileHeader.NumberOfSections;
                        Index++) {
                        SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                        SizeToLock = NtSection[Index].SizeOfRawData;

                        if (SizeToLock < NtSection[Index].Misc.VirtualSize) {
                            SizeToLock = NtSection[Index].Misc.VirtualSize;
                        }

                        if (FALSE != MmIsAddressValid(SectionBase)) {
                            if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                                NtSection[Index].Characteristics,
                                IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                                for (Offset = 0;
                                    Offset < AlignedToSize(
                                        SizeToLock,
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY32);
                                    Offset += sizeof(PVOID)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            UserInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE,
                                                TableEntry);

                                            if (UserInvertedFunctionTable->MaximumSize == MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (UserInvertedFunctionTable->Overflow == TRUE ||
                                                    UserInvertedFunctionTable->Overflow == FALSE)) {
                                                break;
                                            }

                                            FoundFunctionTableEntry--;
                                        } while (TRUE);

                                        goto exit;
                                    }
                                }
                            }
                        }
                    }

                exit:
                    ExFreePool(FunctionTableEntry);
                }
            }
        }
    }
}

VOID
NTAPI
SearchUserSpecialInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    PSTR SectionName = NULL;
    PCHAR SectionBase = NULL;
    ULONG SizeToLock = 0;
    USHORT Index = 0;
    SIZE_T Offset = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PFUNCTION_TABLE_ENTRY32 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    if (FALSE == PsIsSystemProcess(IoGetCurrentProcess())) {
        ImageBase = GetImageHandle("ntdll.dll");

        if (NULL != ImageBase) {
            NtHeaders = RtlImageNtHeader(ImageBase);

            if (FALSE != MmIsAddressValid(NtHeaders)) {
                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                FunctionTableEntry = ExAllocatePool(
                    NonPagedPool,
                    sizeof(FUNCTION_TABLE_ENTRY32));

                if (NULL != FunctionTableEntry) {
                    CaptureImageExceptionValues(
                        ImageBase,
                        &FunctionTable,
                        &SizeOfTable);

                    FunctionTableEntry->FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                    FunctionTableEntry->ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry->SizeOfImage = FetchSizeOfImage(ImageBase);
                    FunctionTableEntry->SizeOfTable = SizeOfTable;

                    for (Index = 0;
                        Index < NtHeaders->FileHeader.NumberOfSections;
                        Index++) {
                        SectionBase = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;

                        SizeToLock = NtSection[Index].SizeOfRawData;

                        if (SizeToLock < NtSection[Index].Misc.VirtualSize) {
                            SizeToLock = NtSection[Index].Misc.VirtualSize;
                        }

                        if (FALSE != MmIsAddressValid(SectionBase)) {
                            if (IMAGE_SCN_CNT_INITIALIZED_DATA == FlagOn(
                                NtSection[Index].Characteristics,
                                IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                                for (Offset = 0;
                                    Offset < AlignedToSize(
                                        SizeToLock,
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY32);
                                    Offset += sizeof(PVOID)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            UserSpecialInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE_SPECIAL,
                                                TableEntry);

                                            if (UserSpecialInvertedFunctionTable->MaximumSize == MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (UserSpecialInvertedFunctionTable->Overflow == TRUE ||
                                                    UserSpecialInvertedFunctionTable->Overflow == FALSE)) {
                                                break;
                                            }

                                            FoundFunctionTableEntry--;
                                        } while (TRUE);

                                        goto exit;
                                    }
                                }
                            }
                        }
                    }

                exit:
                    ExFreePool(FunctionTableEntry);
                }
            }
        }
    }
}

VOID
NTAPI
InsertInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;

    if (NULL == InvertedFunctionTable) {
        InvertedFunctionTable = ExAllocatePool(
            NonPagedPool,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE);

        if (NULL != InvertedFunctionTable) {
            RtlZeroMemory(
                InvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE);

            InvertedFunctionTable->MaximumSize = MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE;

            InitializeExcept();
        }
    }

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = CONTAINING_RECORD(
            InvertedFunctionTable->TableEntry,
            FUNCTION_TABLE,
            TableEntry);

        CurrentSize = InvertedFunctionTable->CurrentSize;

        if (CurrentSize != InvertedFunctionTable->MaximumSize) {
            if (0 != CurrentSize) {
                for (;
                    Index < CurrentSize;
                    Index++) {
                    if (PtrToUlong(ImageBase) < FunctionTableEntry[Index].ImageBase) {
                        RtlMoveMemory(
                            &FunctionTableEntry[Index + 1],
                            &FunctionTableEntry[Index],
                            (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY32));

                        break;
                    }
                }
            }

            CaptureImageExceptionValues(
                ImageBase,
                &FunctionTable,
                &SizeOfTable);

            if (LongToPtr(-1) != FunctionTable &&
                -1 != SizeOfTable) {
                FunctionTableEntry[Index].ImageBase = PtrToUlong(ImageBase);
                FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                FunctionTableEntry[Index].FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                InvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - insert inverted function table < %04d >\n",
                    Index);
#endif // !VMP
            }
        }
        else {
            InvertedFunctionTable->Overflow = TRUE;
        }
    }
}

VOID
NTAPI
RemoveInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = CONTAINING_RECORD(
            InvertedFunctionTable->TableEntry,
            FUNCTION_TABLE,
            TableEntry);

        CurrentSize = InvertedFunctionTable->CurrentSize;

        for (Index = 0;
            Index < CurrentSize;
            Index += 1) {
            if (PtrToUlong(ImageBase) == FunctionTableEntry[Index].ImageBase) {
                RtlMoveMemory(
                    &FunctionTableEntry[Index],
                    &FunctionTableEntry[Index + 1],
                    (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY32));

                InvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - remote inverted function table < %04d >\n",
                    Index);
#endif // !VMP

                break;
            }
        }
    }
}

VOID
NTAPI
InsertUserInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == UserInvertedFunctionTable) {
        SearchUserInvertedFunctionTable();
    }

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != UserInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if (PtrToUlong(ImageBase) < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY32));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                if (LongToPtr(-1) != FunctionTable &&
                    -1 != SizeOfTable) {
                    FunctionTableEntry[Index].ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                    FunctionTableEntry[Index].FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                    FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                    UserInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert user inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                UserInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectPages(
                UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveUserInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if (PtrToUlong(ImageBase) == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY32));

                    UserInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remote user inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectPages(
                UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
InsertUserSpecialInvertedFunctionTable(
    __in PVOID ImageBase,
    __in ULONG SizeOfImage
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG SizeOfTable = 0;
    ULONG Index = 0;
    PVOID FunctionTable = NULL;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == UserSpecialInvertedFunctionTable) {
        SearchUserSpecialInvertedFunctionTable();
    }

    if (NULL != UserSpecialInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * UserSpecialInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != UserSpecialInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if (PtrToUlong(ImageBase) < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY32));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                if (LongToPtr(-1) != FunctionTable &&
                    -1 != SizeOfTable) {
                    FunctionTableEntry[Index].ImageBase = PtrToUlong(ImageBase);
                    FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                    FunctionTableEntry[Index].FunctionTable = EncodeSystemPointer(PtrToUlong(FunctionTable));
                    FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                    UserSpecialInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                UserSpecialInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectPages(
                UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveUserSpecialInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != UserSpecialInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * UserSpecialInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if (PtrToUlong(ImageBase) == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY32));

                    UserSpecialInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remote user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectPages(
                UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}
