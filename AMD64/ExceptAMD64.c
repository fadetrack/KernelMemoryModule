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
#include "Reload.h"
#include "Testis.h"

static PFUNCTION_TABLE InvertedFunctionTable;
static PFUNCTION_TABLE UserInvertedFunctionTable;
static PFUNCTION_TABLE Wx86UserInvertedFunctionTable;
static PFUNCTION_TABLE_SPECIAL Wx86UserSpecialInvertedFunctionTable;

NTSTATUS
NTAPI
ProtectPages(
    __inout PVOID BaseAddress,
    __inout SIZE_T RegionSize,
    __in ULONG NewProtect,
    __out PULONG OldProtect
);

VOID
NTAPI
SearchInvertedFunctionTable(
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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PFUNCTION_TABLE_ENTRY64 FoundFunctionTableEntry = NULL;
    PVOID FunctionTable = NULL;
    ULONG SizeOfTable = 0;

    ImageBase = GetImageHandle("ntoskrnl.exe");

    if (NULL != ImageBase) {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (FALSE != MmIsAddressValid(NtHeaders)) {
            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            FunctionTableEntry = ExAllocatePool(
                NonPagedPool,
                sizeof(FUNCTION_TABLE_ENTRY64));

            if (NULL != FunctionTableEntry) {
                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry->FunctionTable = (ULONG64)FunctionTable;
                FunctionTableEntry->ImageBase = (ULONG64)ImageBase;
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
                                    NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY64);
                                Offset += sizeof(PVOID)) {
                                FoundFunctionTableEntry = SectionBase + Offset;

                                if (sizeof(FUNCTION_TABLE_ENTRY64) == RtlCompareMemory(
                                    FoundFunctionTableEntry,
                                    FunctionTableEntry,
                                    sizeof(FUNCTION_TABLE_ENTRY64))) {
                                    do {
                                        InvertedFunctionTable = CONTAINING_RECORD(
                                            FoundFunctionTableEntry,
                                            FUNCTION_TABLE,
                                            TableEntry);

                                        if (InvertedFunctionTable->MaximumSize == MAXIMUM_KERNEL_FUNCTION_TABLE_SIZE &&
                                            (InvertedFunctionTable->Overflow == TRUE ||
                                                InvertedFunctionTable->Overflow == FALSE)) {
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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PFUNCTION_TABLE_ENTRY64 FoundFunctionTableEntry = NULL;
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
                    sizeof(FUNCTION_TABLE_ENTRY64));

                if (NULL != FunctionTableEntry) {
                    CaptureImageExceptionValues(
                        ImageBase,
                        &FunctionTable,
                        &SizeOfTable);

                    FunctionTableEntry->FunctionTable = (ULONG64)FunctionTable;
                    FunctionTableEntry->ImageBase = (ULONG64)ImageBase;
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
                                        NtHeaders->OptionalHeader.SectionAlignment) - sizeof(FUNCTION_TABLE_ENTRY64);
                                    Offset += sizeof(PVOID)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY64) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY64))) {
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
SearchWx86UserInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
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
        ImageBase = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

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
                                    Offset += sizeof(ULONG)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            Wx86UserInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE,
                                                TableEntry);

                                            if (Wx86UserInvertedFunctionTable->MaximumSize == MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (Wx86UserInvertedFunctionTable->Overflow == TRUE ||
                                                    Wx86UserInvertedFunctionTable->Overflow == FALSE)) {
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
SearchWx86UserSpecialInvertedFunctionTable(
    VOID
)
{
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
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
        ImageBase = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

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
                                    Offset += sizeof(ULONG)) {
                                    FoundFunctionTableEntry = SectionBase + Offset;

                                    if (sizeof(FUNCTION_TABLE_ENTRY32) == RtlCompareMemory(
                                        FoundFunctionTableEntry,
                                        FunctionTableEntry,
                                        sizeof(FUNCTION_TABLE_ENTRY32))) {
                                        do {
                                            Wx86UserSpecialInvertedFunctionTable = CONTAINING_RECORD(
                                                FoundFunctionTableEntry,
                                                FUNCTION_TABLE_SPECIAL,
                                                TableEntry);

                                            if (Wx86UserSpecialInvertedFunctionTable->MaximumSize == MAXIMUM_USER_FUNCTION_TABLE_SIZE &&
                                                (Wx86UserSpecialInvertedFunctionTable->Overflow == TRUE ||
                                                    Wx86UserSpecialInvertedFunctionTable->Overflow == FALSE)) {
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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;

    if (NULL == InvertedFunctionTable) {
        SearchInvertedFunctionTable();
    }

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &InvertedFunctionTable->TableEntry;

        CurrentSize = InvertedFunctionTable->CurrentSize;

        ImageHandle = GetImageHandle("ntoskrnl.exe");

        if (NULL != ImageHandle &&
            ImageHandle == (PVOID)FunctionTableEntry[0].ImageBase) {
            Index = 1;
        }

        if (CurrentSize != InvertedFunctionTable->MaximumSize) {
            if (0 != CurrentSize) {
                for (;
                    Index < CurrentSize;
                    Index++) {
                    if ((ULONG64)ImageBase < FunctionTableEntry[Index].ImageBase) {
                        RtlMoveMemory(
                            &FunctionTableEntry[Index + 1],
                            &FunctionTableEntry[Index],
                            (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY64));

                        break;
                    }
                }
            }

            CaptureImageExceptionValues(
                ImageBase,
                &FunctionTable,
                &SizeOfTable);

            FunctionTableEntry[Index].ImageBase = (ULONG64)ImageBase;
            FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
            FunctionTableEntry[Index].FunctionTable = (ULONG64)FunctionTable;
            FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

            InvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
            DbgPrint(
                "Soul - Testis - insert inverted function table < %04d >\n",
                Index);
#endif // !VMP
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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;

    if (NULL != InvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &InvertedFunctionTable->TableEntry;

        CurrentSize = InvertedFunctionTable->CurrentSize;

        for (Index = 0;
            Index < CurrentSize;
            Index += 1) {
            if ((ULONG64)ImageBase == FunctionTableEntry[Index].ImageBase) {
                RtlMoveMemory(
                    &FunctionTableEntry[Index],
                    &FunctionTableEntry[Index + 1],
                    (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY64));

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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    PVOID ImageHandle = NULL;
    ULONG OldProtect = 0;

    if (NULL == UserInvertedFunctionTable) {
        SearchUserInvertedFunctionTable();
    }

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = GetImageHandle("ntdll.dll");

            if (NULL != ImageHandle &&
                ImageHandle == (PVOID)FunctionTableEntry[0].ImageBase) {
                Index = 1;
            }

            if (CurrentSize != UserInvertedFunctionTable->MaximumSize) {
                if (0 != CurrentSize) {
                    for (;
                        Index < CurrentSize;
                        Index++) {
                        if ((ULONG64)ImageBase < FunctionTableEntry[Index].ImageBase) {
                            RtlMoveMemory(
                                &FunctionTableEntry[Index + 1],
                                &FunctionTableEntry[Index],
                                (CurrentSize - Index) * sizeof(FUNCTION_TABLE_ENTRY64));

                            break;
                        }
                    }
                }

                CaptureImageExceptionValues(
                    ImageBase,
                    &FunctionTable,
                    &SizeOfTable);

                FunctionTableEntry[Index].ImageBase = (ULONG64)ImageBase;
                FunctionTableEntry[Index].SizeOfImage = SizeOfImage;
                FunctionTableEntry[Index].FunctionTable = (ULONG64)FunctionTable;
                FunctionTableEntry[Index].SizeOfTable = SizeOfTable;

                UserInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                DbgPrint(
                    "Soul - Testis - insert user inverted function table < %04d >\n",
                    Index);
#endif // !VMP
            }
            else {
                UserInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectPages(
                UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
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
    PFUNCTION_TABLE_ENTRY64 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY64)
            &UserInvertedFunctionTable->TableEntry;

        CurrentSize = UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            for (Index = 0;
                Index < CurrentSize;
                Index += 1) {
                if ((ULONG64)ImageBase == FunctionTableEntry[Index].ImageBase) {
                    RtlMoveMemory(
                        &FunctionTableEntry[Index],
                        &FunctionTableEntry[Index + 1],
                        (CurrentSize - Index - 1) * sizeof(FUNCTION_TABLE_ENTRY64));

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
                sizeof(FUNCTION_TABLE_ENTRY64) * UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
InsertWx86UserInvertedFunctionTable(
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

    if (NULL == Wx86UserInvertedFunctionTable) {
        SearchWx86UserInvertedFunctionTable();
    }

    if (NULL != Wx86UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            Wx86UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != Wx86UserInvertedFunctionTable->MaximumSize) {
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

                    Wx86UserInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert wx86 user inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                Wx86UserInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectPages(
                Wx86UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveWx86UserInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != Wx86UserInvertedFunctionTable) {
        FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            Wx86UserInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
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

                    Wx86UserInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remote wx86 user inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectPages(
                Wx86UserInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
InsertWx86UserSpecialInvertedFunctionTable(
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

    if (NULL == Wx86UserSpecialInvertedFunctionTable) {
        SearchWx86UserSpecialInvertedFunctionTable();
    }

    if (NULL != Wx86UserSpecialInvertedFunctionTable) {
        FunctionTableEntry =
            FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            Wx86UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
            PAGE_READWRITE,
            &OldProtect);

        if (NT_SUCCESS(Status)) {
            ImageHandle = UlongToPtr(Wx86GetImageHandle("ntdll.dll"));

            if (NULL != ImageHandle &&
                ImageHandle == UlongToPtr(FunctionTableEntry[0].ImageBase)) {
                Index = 1;
            }

            if (CurrentSize != Wx86UserSpecialInvertedFunctionTable->MaximumSize) {
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

                    Wx86UserSpecialInvertedFunctionTable->CurrentSize += 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - insert wx86 user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP
                }
            }
            else {
                Wx86UserSpecialInvertedFunctionTable->Overflow = TRUE;
            }

            ProtectPages(
                Wx86UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}

VOID
NTAPI
RemoveWx86UserSpecialInvertedFunctionTable(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG CurrentSize = 0;
    ULONG Index = 0;
    PFUNCTION_TABLE_ENTRY32 FunctionTableEntry = NULL;
    ULONG OldProtect = 0;

    if (NULL != Wx86UserSpecialInvertedFunctionTable) {
        FunctionTableEntry =
            FunctionTableEntry = (PFUNCTION_TABLE_ENTRY32)
            &Wx86UserSpecialInvertedFunctionTable->TableEntry;

        CurrentSize = Wx86UserSpecialInvertedFunctionTable->CurrentSize;

        Status = ProtectPages(
            Wx86UserSpecialInvertedFunctionTable,
            FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
            sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
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

                    Wx86UserSpecialInvertedFunctionTable->CurrentSize -= 1;

#ifndef VMP
                    DbgPrint(
                        "Soul - Testis - remote wx86 user special inverted function table < %04d >\n",
                        Index);
#endif // !VMP

                    break;
                }
            }

            ProtectPages(
                Wx86UserSpecialInvertedFunctionTable,
                FIELD_OFFSET(FUNCTION_TABLE_SPECIAL, TableEntry) +
                sizeof(FUNCTION_TABLE_ENTRY32) * Wx86UserSpecialInvertedFunctionTable->MaximumSize,
                OldProtect,
                &OldProtect);
        }
    }
}
