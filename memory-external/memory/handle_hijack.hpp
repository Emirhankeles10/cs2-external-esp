#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>

// NT API makroları
#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ((HANDLE)(LONG_PTR)-1)
#define ProcessHandleType 0x7
#define SystemHandleInformation 16

// NT API tipleri
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// NT API prototipleri
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
);

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Handle hijack namespace
namespace hj {
    inline SYSTEM_HANDLE_INFORMATION* hInfo = nullptr;
    inline HANDLE procHandle = nullptr;
    inline HANDLE hProcess = nullptr;
    inline HANDLE HijackedHandle = nullptr;

    inline OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security) {
        OBJECT_ATTRIBUTES obj{};
        obj.Length = sizeof(OBJECT_ATTRIBUTES);
        obj.ObjectName = name;
        obj.Attributes = attributes;
        obj.RootDirectory = hRoot;
        obj.SecurityDescriptor = security;
        obj.SecurityQualityOfService = nullptr;
        return obj;
    }

    inline bool IsHandleValid(HANDLE handle) {
        return handle && handle != INVALID_HANDLE_VALUE;
    }

    inline HANDLE HijackExistingHandle(DWORD dwTargetProcessId) {
        HMODULE ntdll = GetModuleHandleA("ntdll");
        auto RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        auto NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
        auto NtOpenProcess = (_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");

        BOOLEAN OldPriv;
        RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

        OBJECT_ATTRIBUTES objAttr = InitObjectAttributes(nullptr, 0, nullptr, nullptr);
        CLIENT_ID clientID{};

        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        hInfo = (PSYSTEM_HANDLE_INFORMATION)new BYTE[size];
        ZeroMemory(hInfo, size);

        NTSTATUS NtRet = 0;
        do {
            delete[] hInfo;
            size = static_cast<DWORD>(size * 1.5);
            try { hInfo = (PSYSTEM_HANDLE_INFORMATION)new BYTE[size]; }
            catch (...) { return nullptr; }
            ZeroMemory(hInfo, size);
        } while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, nullptr)) == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(NtRet)) { delete[] hInfo; return nullptr; }

        for (ULONG i = 0; i < hInfo->HandleCount; ++i) {
            static DWORD numHandles;
            GetProcessHandleCount(GetCurrentProcess(), &numHandles);
            if (numHandles > 50) break;

            SYSTEM_HANDLE& sh = hInfo->Handles[i];
            if (!IsHandleValid((HANDLE)sh.Handle)) continue;
            if (sh.ObjectTypeNumber != ProcessHandleType) continue;

            clientID.UniqueProcess = (HANDLE)sh.ProcessId;
            procHandle ? CloseHandle(procHandle) : 0;

            NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &objAttr, &clientID);
            if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet)) continue;

            NtRet = NtDuplicateObject(procHandle, (HANDLE)sh.Handle, NtCurrentProcess, &HijackedHandle,
                                      PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE, 0, 0);
            if (!IsHandleValid(HijackedHandle) || !NT_SUCCESS(NtRet)) continue;

            if (GetProcessId(HijackedHandle) != dwTargetProcessId) {
                CloseHandle(HijackedHandle);
                continue;
            }

            hProcess = HijackedHandle;
            break;
        }

        delete[] hInfo;
        hInfo = nullptr;
        procHandle ? CloseHandle(procHandle) : 0;
        return hProcess;
    }
}
