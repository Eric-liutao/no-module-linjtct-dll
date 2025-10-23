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

typedef BOOL(APIENTRY* DLLMAIN)(
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

typedef INT(WINAPI* MESSAGEBOXA)(
    _In_opt_ HWND    hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT    uType
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

    MESSAGEBOXA                    Func_MessageBoxA;
    DWORD                          dwRemoteStatus; // status code written by remote shellcode (0 = success)
    // Pointers (remote addresses) to ASCII names placed in the remote param block
    char*                         Name_GetProcAddress;
    char*                         Name_LoadLibraryA;
    char*                         Name_VirtualAlloc;
    char*                         Name_VirtualProtect;
    char*                         Name_User32;
    char*                         Name_MessageBoxA;
    // message box strings (ASCII), stored after struct in remote block
    char*                         Str_MsgText;
    char*                         Str_MsgCaption;
    DWORD                         SkipCallDllMain; // if non-zero, remote loader will NOT call DllMain (diagnostic)

} INJECTPARAM;


class Injectdll
{
	public:
		void RemoteMapLoadDll(HANDLE TargetProcess);
}; 

// external binary blob declared in dllbin.h
extern unsigned char DllX64[];

