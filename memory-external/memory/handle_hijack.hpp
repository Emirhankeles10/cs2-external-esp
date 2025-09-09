#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <chrono>

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

    // Rastgele kısa sleep
    inline void SleepRandom(int minMs = 1, int maxMs = 5) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minMs, maxMs);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    inline HANDLE HijackExistingHandle(DWORD dwTargetProcessId) {
        HMODULE ntdll = GetModuleHandleA("ntdll");
        if (!ntdll) return nullptr;

        auto RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        auto NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
        auto NtOpenProcess = (_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");

        if (!RtlAdjustPrivilege || !NtQuerySystemInformation || !NtDuplicateObject || !NtOpenProcess)
            return nullptr;

        BOOLEAN OldPriv = FALSE;
        if (dwTargetProcessId != GetCurrentProcessId()) {
            RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);
        }

        OBJECT_ATTRIBUTES objAttr = InitObjectAttributes(nullptr, 0, nullptr, nullptr);
        CLIENT_ID clientID{};

        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        std::vector<BYTE> buffer(size);

        NTSTATUS NtRet = 0;
        do {
            buffer.resize(static_cast<size_t>(buffer.size() * 1.5));
            ZeroMemory(buffer.data(), buffer.size());
        } while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), static_cast<ULONG>(buffer.size()), nullptr)) == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(NtRet)) {
            if (OldPriv) RtlAdjustPrivilege(SeDebugPriv, FALSE, FALSE, &OldPriv);
            return nullptr;
        }

        PSYSTEM_HANDLE_INFORMATION hInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.data());

        HANDLE HijackedHandle = nullptr;
        for (ULONG i = 0; i < hInfo->HandleCount; ++i) {
            SYSTEM_HANDLE& sh = hInfo->Handles[i];
            if (!IsHandleValid((HANDLE)sh.Handle)) continue;
            if (sh.ObjectTypeNumber != ProcessHandleType) continue;

            clientID.UniqueProcess = (HANDLE)sh.ProcessId;
            HANDLE procHandle = nullptr;

            NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &objAttr, &clientID);
            if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet)) continue;

            HANDLE tempHandle = nullptr;
            NtRet = NtDuplicateObject(procHandle, (HANDLE)sh.Handle, NtCurrentProcess, &tempHandle,
                                      PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE, 0, 0);
            CloseHandle(procHandle);

            if (!IsHandleValid(tempHandle) || !NT_SUCCESS(NtRet)) continue;
            if (GetProcessId(tempHandle) != dwTargetProcessId) {
                CloseHandle(tempHandle);
                continue;
            }

            HijackedHandle = tempHandle;
            break; // Bulduktan sonra döngüden çık

            SleepRandom(); // Döngüde kısa rastgele gecikme
        }

        if (OldPriv) RtlAdjustPrivilege(SeDebugPriv, FALSE, FALSE, &OldPriv);
        return HijackedHandle;
    }
}
