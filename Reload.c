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
#include <StubsApi.h>

#include <cc.h>

#ifdef _WIN64
#include <wow64t.h>
#endif // _WIN64

#include "Except.h"
#include "Reload.h"
#include "Testis.h"

static PLIST_ENTRY LdrList;

NTSTATUS
NTAPI
ProtectPages(
    __inout PVOID BaseAddress,
    __inout SIZE_T RegionSize,
    __in ULONG NewProtect,
    __out PULONG OldProtect
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Status = StubProtectVirtualMemory(
        ZwCurrentProcess(),
        &BaseAddress,
        &RegionSize,
        NewProtect,
        OldProtect);

    return Status;
}

NTSTATUS
NTAPI
FindEntryForDriver(
    __in PSTR DriverName,
    __out PKLDR_DATA_TABLE_ENTRY * DataTableEntry
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PDRIVER_OBJECT DriverObject = NULL;
    UNICODE_STRING DriverPath = { 0 };
    PKLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;
    PKLDR_DATA_TABLE_ENTRY FoundDataTableEntry = NULL;
    ANSI_STRING AnsiImageFileName = { 0 };
    UNICODE_STRING ImageFileName = { 0 };

    extern POBJECT_TYPE * IoDriverObjectType;

    if (NULL != LdrList) {
        LdrDataTableEntry = CONTAINING_RECORD(
            LdrList,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);

        FoundDataTableEntry = CONTAINING_RECORD(
            LdrDataTableEntry->InLoadOrderLinks.Flink,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);

        RtlInitAnsiString(&AnsiImageFileName, DriverName);

        Status = RtlAnsiStringToUnicodeString(
            &ImageFileName,
            &AnsiImageFileName,
            TRUE);

        if (NT_SUCCESS(Status)) {
            Status = STATUS_NO_MORE_ENTRIES;

            while (FoundDataTableEntry != LdrDataTableEntry) {
                if (FoundDataTableEntry->DllBase) {
                    if (FALSE != RtlEqualUnicodeString(
                        &ImageFileName,
                        &FoundDataTableEntry->BaseDllName,
                        TRUE)) {
                        *DataTableEntry = FoundDataTableEntry;
                        Status = STATUS_SUCCESS;
                        goto exit;
                    }
                }

                FoundDataTableEntry = CONTAINING_RECORD(
                    FoundDataTableEntry->InLoadOrderLinks.Flink,
                    KLDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks);
            }

            RtlFreeUnicodeString(&ImageFileName);
        }
    }

    RtlInitUnicodeString(
        &DriverPath,
        L"\\Driver\\disk");

    Status = ObReferenceObjectByName(
        &DriverPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        FILE_ALL_ACCESS,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        &DriverObject);

    if (NT_SUCCESS(Status)) {
        LdrDataTableEntry = DriverObject->DriverSection;

        if (NULL != LdrDataTableEntry) {
            FoundDataTableEntry = CONTAINING_RECORD(
                LdrDataTableEntry->InLoadOrderLinks.Flink,
                KLDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            RtlInitAnsiString(&AnsiImageFileName, DriverName);

            Status = RtlAnsiStringToUnicodeString(
                &ImageFileName,
                &AnsiImageFileName,
                TRUE);

            if (NT_SUCCESS(Status)) {
                Status = STATUS_NO_MORE_ENTRIES;

                while (FoundDataTableEntry != LdrDataTableEntry) {
                    if (NULL != FoundDataTableEntry->DllBase) {
                        if (FALSE != RtlEqualUnicodeString(
                            &ImageFileName,
                            &FoundDataTableEntry->BaseDllName,
                            TRUE)) {
                            *DataTableEntry = FoundDataTableEntry;
                            Status = STATUS_SUCCESS;

                            break;
                        }
                    }

                    FoundDataTableEntry = CONTAINING_RECORD(
                        FoundDataTableEntry->InLoadOrderLinks.Flink,
                        KLDR_DATA_TABLE_ENTRY,
                        InLoadOrderLinks);
                }

                RtlFreeUnicodeString(&ImageFileName);
            }
        }

        ObDereferenceObject(DriverObject);
    }

exit:
    return Status;
}

NTSTATUS
NTAPI
FindEntryForAddress(
    __in PVOID Address,
    __out PLDR_DATA_TABLE_ENTRY * TableEntry
)
{
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;
    PPEB Peb = NULL;
    PPEB_LDR_DATA Ldr = NULL;
    PLDR_DATA_TABLE_ENTRY DataTableEntry = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;
    PLDR_DATA_TABLE_ENTRY FoundDataTableEntry = NULL;

    if ((ULONG_PTR)Address > *(PULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
        if (NULL != LdrList) {
            LdrDataTableEntry = CONTAINING_RECORD(
                LdrList,
                KLDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                LdrDataTableEntry->InLoadOrderLinks.Flink,
                KLDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            while (FoundDataTableEntry != LdrDataTableEntry) {
                if ((ULONG_PTR)Address >= (ULONG_PTR)FoundDataTableEntry->DllBase &&
                    (ULONG_PTR)Address <= (ULONG_PTR)FoundDataTableEntry->DllBase +
                    FoundDataTableEntry->SizeOfImage) {
                    *TableEntry = FoundDataTableEntry;
                    Status = STATUS_SUCCESS;
                    goto exit;
                }

                FoundDataTableEntry = CONTAINING_RECORD(
                    FoundDataTableEntry->InLoadOrderLinks.Flink,
                    KLDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks);
            }
        }

#define KERNEL_NAME "ntoskrnl.exe"

        Status = FindEntryForDriver(
            KERNEL_NAME,
            &DataTableEntry);

        if (NT_SUCCESS(Status)) {
            Status = STATUS_NO_MORE_ENTRIES;

            LdrDataTableEntry = CONTAINING_RECORD(
                DataTableEntry->InLoadOrderLinks.Blink,
                KLDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                LdrDataTableEntry->InLoadOrderLinks.Flink,
                KLDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            while (FoundDataTableEntry != LdrDataTableEntry) {
                if ((ULONG_PTR)Address >= (ULONG_PTR)FoundDataTableEntry->DllBase &&
                    (ULONG_PTR)Address <= (ULONG_PTR)FoundDataTableEntry->DllBase +
                    FoundDataTableEntry->SizeOfImage) {
                    *TableEntry = FoundDataTableEntry;
                    Status = STATUS_SUCCESS;
                    goto exit;
                }

                FoundDataTableEntry = CONTAINING_RECORD(
                    FoundDataTableEntry->InLoadOrderLinks.Flink,
                    KLDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks);
            }
        }
    }

    Peb = PsGetProcessPeb(IoGetCurrentProcess());

    if (NULL != Peb) {
        Ldr = Peb->Ldr;

        if (NULL != Ldr) {
            LdrDataTableEntry = CONTAINING_RECORD(
                &Ldr->InLoadOrderModuleList,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                LdrDataTableEntry->InLoadOrderLinks.Flink,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            if (NULL == Address) {
                Address = Peb->ImageBaseAddress;
            }

            while (FoundDataTableEntry != LdrDataTableEntry) {
                if ((ULONG_PTR)Address >= (ULONG_PTR)FoundDataTableEntry->DllBase &&
                    (ULONG_PTR)Address <= (ULONG_PTR)FoundDataTableEntry->DllBase +
                    FoundDataTableEntry->SizeOfImage) {
                    *TableEntry = FoundDataTableEntry;
                    Status = STATUS_SUCCESS;
                    goto exit;
                }

                FoundDataTableEntry = CONTAINING_RECORD(
                    FoundDataTableEntry->InLoadOrderLinks.Flink,
                    LDR_DATA_TABLE_ENTRY,
                    InLoadOrderLinks);
            }
        }
    }

exit:
    return Status;
}

PVOID
NTAPI
GetImageHandle(
    __in PSTR ImageName
)
{
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;
    PPEB Peb = NULL;
    PPEB_LDR_DATA Ldr = NULL;
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;
    PLDR_DATA_TABLE_ENTRY FoundDataTableEntry = NULL;
    ANSI_STRING AnsiImageFileName = { 0 };
    UNICODE_STRING ImageFileName = { 0 };
    PVOID ImageBase = 0;

    if (NULL != ImageName) {
        Status = FindEntryForDriver(
            ImageName,
            &LdrDataTableEntry);

        if (Status >= 0) {
            ImageBase = LdrDataTableEntry->DllBase;
            goto exit;
        }
    }

    Peb = PsGetProcessPeb(IoGetCurrentProcess());

    if (NULL != Peb) {
        Ldr = Peb->Ldr;

        if (NULL != Ldr) {
            LdrDataTableEntry = CONTAINING_RECORD(
                &Ldr->InLoadOrderModuleList,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                LdrDataTableEntry->InLoadOrderLinks.Flink,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks);

            if (NULL == ImageName) {
                ImageBase = Peb->ImageBaseAddress;
                goto exit;
            }
            else {
                RtlInitAnsiString(
                    &AnsiImageFileName,
                    ImageName);

                Status = RtlAnsiStringToUnicodeString(
                    &ImageFileName,
                    &AnsiImageFileName,
                    TRUE);

                if (NT_SUCCESS(Status)) {
                    while (FoundDataTableEntry != LdrDataTableEntry) {
                        if (FALSE != RtlEqualUnicodeString(
                            &ImageFileName,
                            &FoundDataTableEntry->BaseDllName,
                            TRUE)) {
                            ImageBase = FoundDataTableEntry->DllBase;
                            break;
                        }

                        FoundDataTableEntry = CONTAINING_RECORD(
                            FoundDataTableEntry->InLoadOrderLinks.Flink,
                            LDR_DATA_TABLE_ENTRY,
                            InLoadOrderLinks);
                    }

                    RtlFreeUnicodeString(&ImageFileName);
                }
            }
        }
    }

exit:
    return ImageBase;
}

PVOID
NTAPI
FetchAddressOfEntryPoint(
    __in PVOID ImageBase
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    ULONG Offset = 0;
    PVOID EntryPoint = NULL;

    __try {
        if (NULL != NtHeaders) {
            if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == NtHeaders->OptionalHeader.Magic) {
                Offset = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.AddressOfEntryPoint;
            }

            if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == NtHeaders->OptionalHeader.Magic) {
                Offset = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.AddressOfEntryPoint;
            }

            if (0 != Offset) {
                EntryPoint = (PCHAR)ImageBase + Offset;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        EntryPoint = NULL;
    }

    return EntryPoint;
}

ULONG
NTAPI
FetchTimeStamp(
    __in PVOID ImageBase
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    ULONG TimeStamp = 0;

    __try {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (NULL != NtHeaders) {
            TimeStamp = NtHeaders->FileHeader.TimeDateStamp;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        TimeStamp = 0;
    }

    return TimeStamp;
}

USHORT
NTAPI
FetchSubsystem(
    __in PVOID ImageBase
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    USHORT Subsystem = 0;

    __try {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (NULL != NtHeaders) {
            if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == NtHeaders->OptionalHeader.Magic) {
                Subsystem = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.Subsystem;
            }

            if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == NtHeaders->OptionalHeader.Magic) {
                Subsystem = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.Subsystem;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Subsystem = 0;
    }

    return Subsystem;
}

ULONG
NTAPI
FetchSizeOfImage(
    __in PVOID ImageBase
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    ULONG SizeOfImage = 0;

    __try {
        NtHeaders = RtlImageNtHeader(ImageBase);

        if (NULL != NtHeaders) {
            if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == NtHeaders->OptionalHeader.Magic) {
                SizeOfImage = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.SizeOfImage;
            }

            if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == NtHeaders->OptionalHeader.Magic) {
                SizeOfImage = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.SizeOfImage;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SizeOfImage = 0;
    }

    return SizeOfImage;
}

PVOID
NTAPI
GetProcedureAddress(
    __in PVOID ImageBase,
    __in_opt PSTR ProcedureName,
    __in_opt ULONG ProcedureNumber
)
{
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    ULONG Size = 0;
    PULONG NameTable = NULL;
    PUSHORT OrdinalTable = NULL;
    PULONG AddressTable = NULL;
    PSTR NameTableName = NULL;
    USHORT HintIndex = 0;
    PVOID ProcedureAddress = NULL;

    ExportDirectory = RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &Size);

    if (NULL != ExportDirectory) {
        NameTable = (PCHAR)ImageBase + ExportDirectory->AddressOfNames;
        OrdinalTable = (PCHAR)ImageBase + ExportDirectory->AddressOfNameOrdinals;
        AddressTable = (PCHAR)ImageBase + ExportDirectory->AddressOfFunctions;

        if (NULL != NameTable &&
            NULL != OrdinalTable &&
            NULL != AddressTable) {
            if (ProcedureNumber >= ExportDirectory->Base &&
                ProcedureNumber < MAXSHORT) {
                ProcedureAddress = (PCHAR)ImageBase +
                    AddressTable[ProcedureNumber - ExportDirectory->Base];
            }
            else {
                for (HintIndex = 0;
                    HintIndex < ExportDirectory->NumberOfNames;
                    HintIndex++) {
                    NameTableName = (PCHAR)ImageBase + NameTable[HintIndex];

                    if (0 == strcmp(
                        ProcedureName,
                        NameTableName)) {
                        ProcedureAddress = (PCHAR)ImageBase +
                            AddressTable[OrdinalTable[HintIndex]];
                    }
                }
            }
        }
    }

    return ProcedureAddress;
}

PULONG_PTR
NTAPI
FindThunk(
    __in PVOID ImageBase,
    __in PSTR ImportName,
    __in_opt PSTR ThunkName,
    __in_opt ULONG ThunkNumber
)
{
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
    ULONG Size = 0;
    PIMAGE_THUNK_DATA OriginalThunk = NULL;
    PIMAGE_THUNK_DATA Thunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;
    USHORT Ordinal = 0;
    PSTR ForwardImageName = NULL;
    ULONG Index = 0;
    PULONG_PTR FoundThunk = NULL;

    ImportDirectory = RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        &Size);

    if (0 != Size) {
        do {
            OriginalThunk = (PCHAR)ImageBase + ImportDirectory->OriginalFirstThunk;
            Thunk = (PCHAR)ImageBase + ImportDirectory->FirstThunk;
            ForwardImageName = (PCHAR)ImageBase + ImportDirectory->Name;

            if (0 == _stricmp(
                ImportName,
                ForwardImageName)) {
                do {
                    if (IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal)) {
                        Ordinal = (USHORT)IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);

                        if (ThunkNumber == Ordinal) {
                            FoundThunk = &Thunk->u1.Function;
                            goto exit;
                        }
                    }
                    else {
                        ImportByName = (PCHAR)ImageBase + OriginalThunk->u1.AddressOfData;

                        if (0 == _stricmp(
                            ImportByName->Name,
                            ThunkName)) {
                            FoundThunk = &Thunk->u1.Function;
                            goto exit;
                        }
                    }

                    OriginalThunk++;
                    Thunk++;
                } while (OriginalThunk->u1.Function);
            }

            ImportDirectory++;
        } while (0 != ImportDirectory->Characteristics);
    }

exit:
    return FoundThunk;
}

VOID
NTAPI
ReplaceThunk(
    __in PVOID ImageBase,
    __in PSTR ImportName,
    __in PREPLACE_THUNK ThunkTable,
    __in_bcount(ThunkTable) ULONG ThunkCount
)
{
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
    ULONG Size = 0;
    PIMAGE_THUNK_DATA OriginalThunk = NULL;
    PIMAGE_THUNK_DATA Thunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;
    USHORT Ordinal = 0;
    PSTR ForwardImageName = NULL;
    ULONG Index = 0;

    ImportDirectory = RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        &Size);

    if (0 != Size) {
        do {
            OriginalThunk = (PCHAR)ImageBase + ImportDirectory->OriginalFirstThunk;
            Thunk = (PCHAR)ImageBase + ImportDirectory->FirstThunk;
            ForwardImageName = (PCHAR)ImageBase + ImportDirectory->Name;

            if (0 == _stricmp(
                ImportName,
                ForwardImageName)) {
                do {
                    if (IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal)) {
                        Ordinal = (USHORT)IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);
                    }
                    else {
                        ImportByName = (PCHAR)ImageBase + OriginalThunk->u1.AddressOfData;

                        for (Index = 0;
                            Index < ThunkCount;
                            Index++) {
                            if (0 == _stricmp(
                                ImportByName->Name,
                                ThunkTable[Index].Name)) {
                                Thunk->u1.Function = (ULONG_PTR)ThunkTable[Index].Function;
                            }
                        }
                    }

                    OriginalThunk++;
                    Thunk++;
                } while (OriginalThunk->u1.Function);
            }

            ImportDirectory++;
        } while (0 != ImportDirectory->Characteristics);
    }
}

VOID
NTAPI
SnapThunk(
    __in PVOID ImageBase
)
{
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
    ULONG Size = 0;
    PIMAGE_THUNK_DATA OriginalThunk = NULL;
    PIMAGE_THUNK_DATA Thunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;
    USHORT Ordinal = 0;
    PSTR ForwardImageName = NULL;
    PSTR ForwardImageBase = NULL;
    PVOID FunctionAddress = NULL;

    ImportDirectory = RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        &Size);

    if (0 != Size) {
        do {
            OriginalThunk = (PCHAR)ImageBase + ImportDirectory->OriginalFirstThunk;
            Thunk = (PCHAR)ImageBase + ImportDirectory->FirstThunk;
            ForwardImageName = (PCHAR)ImageBase + ImportDirectory->Name;
            ForwardImageBase = GetImageHandle(ForwardImageName);

            if (NULL != ForwardImageBase) {
                do {
                    if (IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal)) {
                        Ordinal = (USHORT)IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);

                        FunctionAddress = GetProcedureAddress(
                            ForwardImageBase,
                            NULL,
                            Ordinal);

                        if (NULL != FunctionAddress) {
                            Thunk->u1.Function = (ULONG_PTR)FunctionAddress;
                        }
                        else {
                            DbgPrint(
                                "Soul - Testis - import procedure ordinal@%d not found\n",
                                Ordinal);
                        }
                    }
                    else {
                        ImportByName = (PCHAR)ImageBase + OriginalThunk->u1.AddressOfData;

                        FunctionAddress = GetProcedureAddress(
                            ForwardImageBase,
                            ImportByName->Name,
                            0);

                        if (NULL != FunctionAddress) {
                            Thunk->u1.Function = (ULONG_PTR)FunctionAddress;
                        }
                        else {
                            DbgPrint(
                                "Soul - Testis - import procedure %hs not found\n",
                                ImportByName->Name);
                        }
                    }

                    OriginalThunk++;
                    Thunk++;
                } while (OriginalThunk->u1.Function);
            }
            else {
                DbgPrint(
                    "Soul - Testis - import dll %hs not found\n",
                    ForwardImageName);
            }

            ImportDirectory++;
        } while (0 != ImportDirectory->Characteristics);
    }
}

FORCEINLINE
ULONG
NTAPI
GetRelocCount(
    __in ULONG SizeOfBlock
)
{
    ULONG Count = 0;

    Count = (SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

    return Count;
}

PIMAGE_BASE_RELOCATION
NTAPI
RelocationBlock(
    __in PVOID VA,
    __in ULONG Count,
    __in PUSHORT NextOffset,
    __in LONG_PTR Diff
)
{
    PUSHORT FixupVA = NULL;
    USHORT Offset = 0;
    USHORT Type = 0;

    while (Count--) {
        Offset = *NextOffset & 0xfff;
        FixupVA = (PCHAR)VA + Offset;
        Type = (*NextOffset >> 12) & 0xf;

        switch (Type) {
        case IMAGE_REL_BASED_ABSOLUTE: {
            break;
        }

        case IMAGE_REL_BASED_HIGH: {
            FixupVA[1] += (USHORT)((Diff >> 16) & 0xffff);
            break;
        }

        case IMAGE_REL_BASED_LOW: {
            FixupVA[0] += (USHORT)(Diff & 0xffff);
            break;
        }

        case IMAGE_REL_BASED_HIGHLOW: {
            *(PULONG)FixupVA += (ULONG)Diff;
            break;
        }

        case IMAGE_REL_BASED_HIGHADJ: {
            FixupVA[0] += NextOffset[1] & 0xffff;
            FixupVA[1] += (USHORT)((Diff >> 16) & 0xffff);

            ++NextOffset;
            --Count;
            break;
        }

        case IMAGE_REL_BASED_MIPS_JMPADDR:
        case IMAGE_REL_BASED_SECTION:
        case IMAGE_REL_BASED_REL32:
            // case IMAGE_REL_BASED_VXD_RELATIVE:
            // case IMAGE_REL_BASED_MIPS_JMPADDR16: 

        case IMAGE_REL_BASED_IA64_IMM64: {
            break;
        }

        case IMAGE_REL_BASED_DIR64: {
            *(PULONG_PTR)FixupVA += Diff;
            break;
        }

        default: {
            return NULL;
        }
        }

        ++NextOffset;
    }

    return (PIMAGE_BASE_RELOCATION)NextOffset;
}

VOID
NTAPI
RelocateImage(
    __in PVOID ImageBase,
    __in LONG_PTR Diff
)
{
    PIMAGE_BASE_RELOCATION RelocDirectory = NULL;
    ULONG Size = 0;
    PVOID VA = 0;

    RelocDirectory = RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_BASERELOC,
        &Size);

    if (0 != Size) {
        if (0 != Diff) {
            while (0 != Size) {
                VA = (PCHAR)ImageBase + RelocDirectory->VirtualAddress;
                Size -= RelocDirectory->SizeOfBlock;

                RelocDirectory = RelocationBlock(
                    VA,
                    GetRelocCount(RelocDirectory->SizeOfBlock),
                    (PUSHORT)(RelocDirectory + 1),
                    Diff);
            }
        }
    }
}

PVOID
NTAPI
AllocatePages(
    __in PVOID ViewBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID ImageBase = NULL;
    PHYSICAL_ADDRESS HighestAcceptableAddress = { 0 };
    USHORT Subsystem = 0;
    ULONG SizeOfImage = 0;
    ULONG OldProtect = 0;

    Subsystem = FetchSubsystem(ViewBase);
    SizeOfImage = FetchSizeOfImage(ViewBase);

    if (0 != SizeOfImage) {
        if (IMAGE_SUBSYSTEM_NATIVE == Subsystem) {
            HighestAcceptableAddress.QuadPart = -1;

            ImageBase = MmAllocateContiguousMemory(
                SizeOfImage,
                HighestAcceptableAddress);
        }
        else if (IMAGE_SUBSYSTEM_WINDOWS_GUI == Subsystem ||
            IMAGE_SUBSYSTEM_WINDOWS_CUI == Subsystem) {
            Status = ZwAllocateVirtualMemory(
                ZwCurrentProcess(),
                &ImageBase,
                0,
                &SizeOfImage,
                MEM_COMMIT,
                PAGE_EXECUTE);

            if (NT_SUCCESS(Status)) {
                Status = ProtectPages(
                    ImageBase,
                    SizeOfImage,
                    PAGE_READWRITE,
                    &OldProtect);
            }
        }
        else {
            DbgPrint(
                "Soul - Testis - image type not supported.\n");
        }
    }

    return ImageBase;
}

VOID
NTAPI
UnloadImage(
    __in PVOID ImageBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    USHORT Subsystem = 0;
    SIZE_T RegionSize = 0;

    Subsystem = FetchSubsystem(ImageBase);
    if (IMAGE_SUBSYSTEM_NATIVE == Subsystem) {
        MmFreeContiguousMemory(ImageBase);
    }
    else if (IMAGE_SUBSYSTEM_WINDOWS_GUI == Subsystem ||
        IMAGE_SUBSYSTEM_WINDOWS_CUI == Subsystem) {

        Status = ZwFreeVirtualMemory(
            ZwCurrentProcess(),
            &ImageBase,
            &RegionSize,
            MEM_RELEASE);

        NT_SUCCESS(Status);
    }
}

PVOID
NTAPI
MapImage(
    __in PVOID ViewBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID ImageBase = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    LONG_PTR Diff = 0;
    SIZE_T Index = 0;

    __try {
        NtHeaders = RtlImageNtHeader(ViewBase);

        if (NULL != NtHeaders) {
            ImageBase = AllocatePages(ViewBase);

            if (NULL != ImageBase) {
                RtlZeroMemory(
                    ImageBase,
                    NtHeaders->OptionalHeader.SizeOfImage);

                NtSection = IMAGE_FIRST_SECTION(NtHeaders);

                RtlCopyMemory(
                    ImageBase,
                    ViewBase,
                    NtSection->VirtualAddress);

                for (Index = 0;
                    Index < NtHeaders->FileHeader.NumberOfSections;
                    Index++) {
                    RtlCopyMemory(
                        (PCHAR)ImageBase + NtSection[Index].VirtualAddress,
                        (PCHAR)ViewBase + NtSection[Index].PointerToRawData,
                        NtSection[Index].SizeOfRawData);
                }

                NtHeaders = RtlImageNtHeader(ImageBase);

                Diff = (LONG_PTR)ImageBase - NtHeaders->OptionalHeader.ImageBase;
                NtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)ImageBase;

                RelocateImage(ImageBase, Diff);
                SnapThunk(ImageBase);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ImageBase = NULL;
    }

    return ImageBase;
}

static
ULONG
NTAPI
MakeProtection(
    __in PIMAGE_SECTION_HEADER NtSection
)
{
    ULONG Protection = 0;

    __try {
        if (FlagOn(
            NtSection->Characteristics,
            IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE) {
            Protection = PAGE_READWRITE;
        }
        else {
            if (FlagOn(
                NtSection->Characteristics,
                IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {
                Protection = PAGE_EXECUTE_READ;
            }
            else {
                Protection = PAGE_READONLY;
            }

            if (FlagOn(
                NtSection->Characteristics,
                IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                Protection |= PAGE_NOCACHE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Protection = PAGE_EXECUTE_READWRITE;
    }

    return Protection;
}

VOID
NTAPI
SetImageProtection(
    __in PVOID ImageBase,
    __in BOOLEAN Reset
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    ULONG OldProtection = 0;
    ULONG SizeToLock = 0;
    ULONG SizeOfImage = 0;
    PVOID BaseAddress = NULL;
    SIZE_T RegionSize = 0;
    ULONG Index = 0;

    __try {
        NtHeaders = RtlImageNtHeader(ImageBase);
        SizeOfImage = FetchSizeOfImage(ImageBase);

        if (NULL != NtHeaders) {
            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            BaseAddress = ImageBase;
            RegionSize = NtSection->VirtualAddress;

            ProtectPages(
                BaseAddress,
                RegionSize,
                PAGE_READONLY,
                &OldProtection);

            for (Index = 0;
                Index < NtHeaders->FileHeader.NumberOfSections;
                Index++) {
                if (0 != NtSection[Index].PointerToRawData) {
                    SizeToLock = NtSection[Index].SizeOfRawData;

                    if (SizeToLock < NtSection[Index].Misc.VirtualSize) {
                        SizeToLock = NtSection[Index].Misc.VirtualSize;
                    }

                    BaseAddress = (PCHAR)ImageBase + NtSection[Index].VirtualAddress;
                    RegionSize = SizeToLock;

                    ProtectPages(
                        BaseAddress,
                        RegionSize,
                        FALSE != Reset ?
                        PAGE_EXECUTE_READWRITE :
                        MakeProtection(&NtSection[Index]),
                        &OldProtection);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NOTHING;
    }
}

VOID
NTAPI
LoadImage(
    __in PVOID ViewBase,
    __out_opt PVOID * ImageHandle
)
{
    PVOID ImageBase = NULL;

    ImageBase = MapImage(ViewBase);

    if (NULL != ImageBase) {
        if ((ULONG_PTR)ImageBase <= *(PULONG_PTR)MM_HIGHEST_USER_ADDRESS) {
            SetImageProtection(ImageBase, FALSE);

#ifndef _WIN64
            if (OsBuildNumber < 9200) {
                InsertUserSpecialInvertedFunctionTable(
                    ImageBase,
                    FetchSizeOfImage(ImageBase));
            }
            else {
                InsertUserInvertedFunctionTable(
                    ImageBase,
                    FetchSizeOfImage(ImageBase));
            }
#else
            InsertUserInvertedFunctionTable(
                ImageBase,
                FetchSizeOfImage(ImageBase));
#endif // !_WIN64
        }
        else {
            if (NULL != LdrList) {
                InsertInvertedFunctionTable(
                    ImageBase,
                    FetchSizeOfImage(ImageBase));
            }
        }

        *ImageHandle = ImageBase;
    }
}

PKLDR_DATA_TABLE_ENTRY
NTAPI
InsertDataTableEntry(
    __in PCWSTR ImageName,
    __in PVOID ImageHandle
)
{
    PKLDR_DATA_TABLE_ENTRY DataTableEntry = NULL;

    if (NULL == LdrList) {
        LdrList = ExAllocatePool(
            NonPagedPool,
            sizeof(LIST_ENTRY));

        if (NULL != LdrList) {
            InitializeListHead(LdrList);
        }
    }

    if (NULL != LdrList) {
        DataTableEntry = ExAllocatePool(
            NonPagedPool,
            sizeof(KLDR_DATA_TABLE_ENTRY) +
            MAXIMUM_FILENAME_LENGTH * sizeof(WCHAR) * 2);

        if (NULL != DataTableEntry) {
            RtlZeroMemory(
                DataTableEntry,
                sizeof(KLDR_DATA_TABLE_ENTRY) +
                MAXIMUM_FILENAME_LENGTH * sizeof(WCHAR) * 2);

            DataTableEntry->DllBase = ImageHandle;
            DataTableEntry->SizeOfImage = FetchSizeOfImage(ImageHandle);
            DataTableEntry->EntryPoint = FetchAddressOfEntryPoint(ImageHandle);

            CaptureImageExceptionValues(
                ImageHandle,
                &DataTableEntry->ExceptionTable,
                &DataTableEntry->ExceptionTableSize);

            DataTableEntry->FullDllName.Buffer = DataTableEntry + 1;

            DataTableEntry->FullDllName.MaximumLength = MAXIMUM_FILENAME_LENGTH * sizeof(WCHAR);

            wcscat(
                DataTableEntry->FullDllName.Buffer,
                L"Pfs:\\");

            wcscat(
                DataTableEntry->FullDllName.Buffer,
                ImageName);

            DataTableEntry->FullDllName.Length =
                wcslen(DataTableEntry->FullDllName.Buffer) * sizeof(WCHAR);

            DataTableEntry->BaseDllName.Buffer =
                DataTableEntry->FullDllName.Buffer + MAXIMUM_FILENAME_LENGTH;

            DataTableEntry->BaseDllName.MaximumLength = MAXIMUM_FILENAME_LENGTH * sizeof(WCHAR);

            wcscat(
                DataTableEntry->BaseDllName.Buffer,
                ImageName);

            DataTableEntry->BaseDllName.Length =
                wcslen(DataTableEntry->BaseDllName.Buffer) * sizeof(WCHAR);

            InsertTailList(
                LdrList,
                &DataTableEntry->InLoadOrderLinks);
        }
    }

    return DataTableEntry;
}

#ifdef _WIN64
NTSTATUS
NTAPI
Wx86FindEntryForAddress(
    __in PVOID Address,
    __out PLDR_DATA_TABLE_ENTRY32 * TableEntry
)
{
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;
    PWOW64_PROCESS Wow64Process = NULL;
    PPEB32 Peb = NULL;
    PPEB_LDR_DATA32 Ldr = NULL;
    PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry = NULL;
    PLDR_DATA_TABLE_ENTRY32 FoundDataTableEntry = NULL;

    Wow64Process = PsGetCurrentProcessWow64Process();

    if (NULL != Wow64Process) {
        Peb = (PPEB32)&Wow64Process->Wow64;

        Ldr = ULongToPtr(Peb->Ldr);

        if (NULL != Ldr) {
            LdrDataTableEntry = CONTAINING_RECORD(
                &Ldr->InLoadOrderModuleList,
                LDR_DATA_TABLE_ENTRY32,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                ULongToPtr(LdrDataTableEntry->InLoadOrderLinks.Flink),
                LDR_DATA_TABLE_ENTRY32,
                InLoadOrderLinks);

            if (NULL == Address) {
                Address = ULongToPtr(Peb->ImageBaseAddress);
            }

            while (FoundDataTableEntry != LdrDataTableEntry) {
                if (PtrToUlong(Address) >= FoundDataTableEntry->DllBase &&
                    PtrToUlong(Address) <= FoundDataTableEntry->DllBase +
                    FoundDataTableEntry->SizeOfImage) {
                    *TableEntry = FoundDataTableEntry;
                    Status = STATUS_SUCCESS;
                    goto exit;
                }

                FoundDataTableEntry = CONTAINING_RECORD(
                    ULongToPtr(FoundDataTableEntry->InLoadOrderLinks.Flink),
                    LDR_DATA_TABLE_ENTRY32,
                    InLoadOrderLinks);
            }
        }
    }

exit:
    return Status;
}

ULONG
NTAPI
Wx86GetImageHandle(
    __in PSTR ImageName
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWOW64_PROCESS Wow64Process = NULL;
    PPEB32 Peb = NULL;
    PPEB_LDR_DATA32 Ldr = NULL;
    PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry = NULL;
    PLDR_DATA_TABLE_ENTRY32 FoundDataTableEntry = NULL;
    ANSI_STRING AnsiImageFileName = { 0 };
    UNICODE_STRING ImageFileName = { 0 };
    UNICODE_STRING Wx86ImageFileName = { 0 };
    ULONG ImageBase = 0;

    Wow64Process = PsGetCurrentProcessWow64Process();

    if (NULL != Wow64Process) {
        Peb = (PPEB32)&Wow64Process->Wow64;

        Ldr = ULongToPtr(Peb->Ldr);

        if (NULL != Ldr) {
            LdrDataTableEntry = CONTAINING_RECORD(
                &Ldr->InLoadOrderModuleList,
                LDR_DATA_TABLE_ENTRY32,
                InLoadOrderLinks);

            FoundDataTableEntry = CONTAINING_RECORD(
                ULongToPtr(LdrDataTableEntry->InLoadOrderLinks.Flink),
                LDR_DATA_TABLE_ENTRY32,
                InLoadOrderLinks);

            if (NULL == ImageName) {
                ImageBase = Peb->ImageBaseAddress;
                goto exit;
            }
            else {
                RtlInitAnsiString(
                    &AnsiImageFileName,
                    ImageName);

                Status = RtlAnsiStringToUnicodeString(
                    &ImageFileName,
                    &AnsiImageFileName,
                    TRUE);

                if (NT_SUCCESS(Status)) {
                    while (FoundDataTableEntry != LdrDataTableEntry) {
                        UStr32ToUStr(&Wx86ImageFileName, &FoundDataTableEntry->BaseDllName);

                        if (FALSE != RtlEqualUnicodeString(
                            &ImageFileName,
                            &Wx86ImageFileName,
                            TRUE)) {
                            ImageBase = FoundDataTableEntry->DllBase;
                            RtlFreeUnicodeString(&ImageFileName);
                            goto exit;
                        }

                        FoundDataTableEntry = CONTAINING_RECORD(
                            ULongToPtr(FoundDataTableEntry->InLoadOrderLinks.Flink),
                            LDR_DATA_TABLE_ENTRY32,
                            InLoadOrderLinks);
                    }

                    RtlFreeUnicodeString(&ImageFileName);
                }
            }
        }
    }

exit:
    return ImageBase;
}

ULONG
NTAPI
Wx86GetProcedureAddress(
    __in ULONG ImageHandle,
    __in_opt PSTR ProcedureName,
    __in_opt ULONG ProcedureNumber
)
{
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    ULONG Size = 0;
    PULONG NameTable = NULL;
    PUSHORT OrdinalTable = NULL;
    PULONG AddressTable = NULL;
    PSTR NameTableName = NULL;
    USHORT HintIndex = 0;
    ULONG ProcedureAddress = 0;

    ExportDirectory = RtlImageDirectoryEntryToData(
        ULongToPtr(ImageHandle),
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &Size);

    if (NULL != ExportDirectory) {
        NameTable = (PCHAR)ULongToPtr(ImageHandle) + ExportDirectory->AddressOfNames;
        OrdinalTable = (PCHAR)ULongToPtr(ImageHandle) + ExportDirectory->AddressOfNameOrdinals;
        AddressTable = (PCHAR)ULongToPtr(ImageHandle) + ExportDirectory->AddressOfFunctions;

        if (NULL != NameTable &&
            NULL != OrdinalTable &&
            NULL != AddressTable) {
            if (ProcedureNumber >= ExportDirectory->Base &&
                ProcedureNumber < MAXSHORT) {
                ProcedureAddress = ImageHandle +
                    AddressTable[ProcedureNumber - ExportDirectory->Base];
            }
            else {
                for (HintIndex = 0;
                    HintIndex < ExportDirectory->NumberOfNames;
                    HintIndex++) {
                    NameTableName = (PCHAR)ULongToPtr(ImageHandle) + NameTable[HintIndex];

                    if (0 == strcmp(
                        ProcedureName,
                        NameTableName)) {
                        ProcedureAddress = ImageHandle +
                            AddressTable[OrdinalTable[HintIndex]];
                    }
                }
            }
        }
    }

    return ProcedureAddress;
}

VOID
NTAPI
Wx86SnapThunk(
    __in ULONG ImageHandle
)
{
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = NULL;
    ULONG Size = 0;
    PIMAGE_THUNK_DATA32 OriginalThunk = NULL;
    PIMAGE_THUNK_DATA32 Thunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;
    USHORT Ordinal = 0;
    ULONG ImportDllName = 0;
    ULONG ImportDllHandle = 0;
    ULONG FunctionAddress = 0;

    ImportDirectory = RtlImageDirectoryEntryToData(
        ULongToPtr(ImageHandle),
        TRUE,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        &Size);

    if (0 != Size) {
        do {
            OriginalThunk = (PCHAR)ULongToPtr(ImageHandle) + ImportDirectory->OriginalFirstThunk;
            Thunk = (PCHAR)ULongToPtr(ImageHandle) + ImportDirectory->FirstThunk;
            ImportDllName = ImageHandle + ImportDirectory->Name;

            ImportDllHandle = Wx86GetImageHandle(UlongToPtr(ImportDllName));

            if (0 != ImportDllHandle) {
                do {
                    Ordinal = IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal);

                    if (0 != Ordinal) {
                        FunctionAddress = Wx86GetProcedureAddress(
                            ImportDllHandle,
                            NULL,
                            Ordinal);

                        if (0 != FunctionAddress) {
                            Thunk->u1.Function = FunctionAddress;
                        }
                        else {
                            DbgPrint(
                                "Soul - Testis - import procedure ordinal@%d not found\n",
                                Ordinal);
                        }
                    }
                    else {
                        ImportByName = (PCHAR)ULongToPtr(ImageHandle) + OriginalThunk->u1.AddressOfData;

                        FunctionAddress = Wx86GetProcedureAddress(
                            ImportDllHandle,
                            ImportByName->Name,
                            0);

                        if (0 != FunctionAddress) {
                            Thunk->u1.Function = FunctionAddress;
                        }
                        else {
                            DbgPrint(
                                "Soul - Testis - import procedure %hs not found\n",
                                ImportByName->Name);
                        }
                    }

                    OriginalThunk++;
                    Thunk++;
                } while (OriginalThunk->u1.Function);
            }
            else {
                DbgPrint(
                    "Soul - Testis - import dll %hs not found\n",
                    ImportDllName);
            }

            ImportDirectory++;
        } while (0 != ImportDirectory->Characteristics);
    }
}

PVOID
NTAPI
Wx86MapImage(
    __in PVOID ViewBase
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID ImageBase = 0;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    PIMAGE_SECTION_HEADER NtSection = NULL;
    LONG Diff = 0;
    SIZE_T Index = 0;

    NtHeaders = RtlImageNtHeader(ViewBase);

    if (NULL != NtHeaders) {
        ImageBase = AllocatePages(ViewBase);

        if (NULL != ImageBase &&
            0 == ((ULONG_PTR)ImageBase >> 32)) {
            RtlZeroMemory(
                ImageBase,
                NtHeaders->OptionalHeader.SizeOfImage);

            NtSection = IMAGE_FIRST_SECTION(NtHeaders);

            RtlCopyMemory(
                ImageBase,
                ViewBase,
                NtSection->VirtualAddress);

            for (Index = 0;
                Index < NtHeaders->FileHeader.NumberOfSections;
                Index++) {
                if (0 != NtSection[Index].PointerToRawData) {
                    RtlCopyMemory(
                        (PCHAR)ImageBase + NtSection[Index].VirtualAddress,
                        (PCHAR)ViewBase + NtSection[Index].PointerToRawData,
                        NtSection[Index].SizeOfRawData);
                }
            }

            NtHeaders = RtlImageNtHeader(ImageBase);

            Diff = PtrToLong(ImageBase) - NtHeaders->OptionalHeader.ImageBase;
            NtHeaders->OptionalHeader.ImageBase = PtrToUlong(ImageBase);

            RelocateImage(ImageBase, Diff);
            Wx86SnapThunk(PtrToUlong(ImageBase));
        }
        else {
            UnloadImage(ImageBase);
            ImageBase = NULL;
        }
    }

    return ImageBase;
}

VOID
NTAPI
Wx86LoadImage(
    __in PVOID ViewBase,
    __out PVOID * ImageHandle
)
{
    PVOID ImageBase = NULL;

    ImageBase = Wx86MapImage(ViewBase);

    if (NULL != ImageBase) {
        SetImageProtection(ImageBase, FALSE);

        if (OsBuildNumber < 9200) {
            InsertWx86UserSpecialInvertedFunctionTable(
                ImageBase,
                FetchSizeOfImage(ImageBase));
        }
        else {
            InsertWx86UserInvertedFunctionTable(
                ImageBase,
                FetchSizeOfImage(ImageBase));
        }

        *ImageHandle = ImageBase;
    }
}

#endif // _WIN64
