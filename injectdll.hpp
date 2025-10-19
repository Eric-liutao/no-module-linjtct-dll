// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#pragma once

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>

typedef NTSTATUS(WINAPI* LDRGETPROCEDUREADDRESS)(
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT FARPROC* ProcedureAddress
    );

typedef VOID(WINAPI* RTLFREEUNICODESTRING)(
    _Inout_ PUNICODE_STRING UnicodeString
    );

typedef VOID(WINAPI* RTLINITANSISTRING)(
    _Out_ PANSI_STRING DestinationString,
    _In_opt_ PCSZ SourceString
    );

typedef NTSTATUS(WINAPI* RTLANSISTRINGTOUNICODESTRING)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_ PCANSI_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
    );

typedef NTSTATUS(WINAPI* LDRLOADDLL)(
    PWCHAR,
    PULONG,
    PUNICODE_STRING,
    PHANDLE
    );

typedef BOOL(APIENTRY* PROCDLLMAIN)(
    LPVOID,
    DWORD,
    LPVOID
    );

typedef NTSTATUS(WINAPI* NTALLOCATEVIRTUALMEMORY)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

typedef struct _INJECTPARAM
{
    PVOID lpFileData;      // 我们要注射的DLL内容
    DWORD dwDataLength;    // 我们要注射的DLL长度
    DWORD dwTargetPID;     // 我们要注射的进程PID

    // Native API 函数指针
    LDRGETPROCEDUREADDRESS       Func_LdrGetProcedureAddress;
    NTALLOCATEVIRTUALMEMORY      Func_NtAllocateVirtualMemory;
    LDRLOADDLL                   Func_LdrLoadDll;
    RTLINITANSISTRING            Func_RtlInitAnsiString;
    RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING         Func_RtlFreeUnicodeString;
} INJECTPARAM;


class Injectdll
{
	public:
		void RemoteMapLoadDll(HANDLE targectprocess);
}; 

