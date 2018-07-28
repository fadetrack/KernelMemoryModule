/*
*
* Copyright (c) 2015-2017 by blindtiger ( blindtiger@foxmail.com )
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License"); you may not use this file except in compliance with
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

#ifndef _RELOAD_H_
#define _RELOAD_H_

#ifdef __cplusplus
/* Assume C declarations for C++ */
extern "C" {
#endif	/* __cplusplus */

    typedef struct _REPLACE_THUNK {
        PSTR Name;
        USHORT Ordinal;
        PSTR ReplaceName;
        USHORT ReplaceOrdinal;
        PVOID Function;
    } REPLACE_THUNK, *PREPLACE_THUNK;

    NTSTATUS
        NTAPI
        FindEntryForDriver(
            __in PSTR DriverName,
            __out PKLDR_DATA_TABLE_ENTRY * DataTableEntry
        );

    NTSTATUS
        NTAPI
        FindEntryForAddress(
            __in PVOID Address,
            __out PLDR_DATA_TABLE_ENTRY * TableEntry
        );

    PVOID
        NTAPI
        GetImageHandle(
            __in PSTR ImageName
        );

    PVOID
        NTAPI
        FetchAddressOfEntryPoint(
            __in PVOID ImageBase
        );

    ULONG
        NTAPI
        FetchSizeOfImage(
            __in PVOID ImageBase
        );

    PVOID
        NTAPI
        GetProcedureAddress(
            __in PVOID ImageHandle,
            __in_opt PSTR ProcedureName,
            __in_opt ULONG ProcedureNumber
        );

    PULONG_PTR
        NTAPI
        FindThunk(
            __in PVOID ImageBase,
            __in PSTR ImportName,
            __in_opt PSTR ThunkName,
            __in_opt ULONG ThunkNumber
        );

    VOID
        NTAPI
        ReplaceThunk(
            __in PVOID ImageBase,
            __in PSTR ImportName,
            __in PREPLACE_THUNK ThunkTable,
            __in_bcount(ThunkTable) ULONG ThunkCount
        );

    VOID
        NTAPI
        SetImageProtection(
            __in PVOID ImageBase,
            __in BOOLEAN Reset
        );

    VOID
        NTAPI
        UnloadImage(
            __in PVOID ImageBase
        );

    VOID
        NTAPI
        LoadImage(
            __in PVOID ViewBase,
            __out_opt PVOID * ImageHandle
        );

    PKLDR_DATA_TABLE_ENTRY
        NTAPI
        InsertDataTableEntry(
            __in PCWSTR ImageName,
            __in PVOID ImageHandle
        );

#ifdef _WIN64
    NTSTATUS
        NTAPI
        Wx86FindEntryForAddress(
            __in PVOID Address,
            __out PLDR_DATA_TABLE_ENTRY32 * TableEntry
        );

    ULONG
        NTAPI
        Wx86GetImageHandle(
            __in PSTR ImageName
        );

    ULONG
        NTAPI
        Wx86GetProcedureAddress(
            __in ULONG ImageHandle,
            __in_opt PSTR ProcedureName,
            __in_opt ULONG ProcedureNumber
        );

    VOID
        NTAPI
        Wx86LoadImage(
            __in PVOID ViewBase,
            __out PVOID * ImageHandle
        );
#endif // _WIN64

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_RELOAD_H_
