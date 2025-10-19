// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "injectdll.hpp"
#include "dllbin.h"

void Injectdll::RemoteMapLoadDll(HANDLE targectprocess)
{
	INJECTPARAM InjectParam;
	RtlZeroMemory(&InjectParam, sizeof(InjectParam));

	InjectParam.dwDataLength = sizeof(DllX64);

	HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

	InjectParam.Func_LdrGetProcedureAddress = (LDRGETPROCEDUREADDRESS)GetProcAddress(hNtDll, "LdrGetProcedureAddress");
	InjectParam.Func_NtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
	InjectParam.Func_LdrLoadDll = (LDRLOADDLL)GetProcAddress(hNtDll, "LdrLoadDll");
	InjectParam.Func_RtlInitAnsiString = (RTLINITANSISTRING)GetProcAddress(hNtDll, "RtlInitAnsiString");
	InjectParam.Func_RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)GetProcAddress(hNtDll, "RtlAnsiStringToUnicodeString");
	InjectParam.Func_RtlFreeUnicodeString = (RTLFREEUNICODESTRING)GetProcAddress(hNtDll, "RtlFreeUnicodeString");

	printf("LdrGetProcedureAddress:%p\r\n", InjectParam.Func_LdrGetProcedureAddress);
	printf("NtAllocateVirtualMemory:%p\r\n", InjectParam.Func_NtAllocateVirtualMemory);
	printf("LdrLoadDll:%p\r\n", InjectParam.Func_LdrLoadDll);
	printf("RtlInitAnsiString:%p\r\n", InjectParam.Func_RtlInitAnsiString);
	printf("RtlAnsiStringToUnicodeString:%p\r\n", InjectParam.Func_RtlAnsiStringToUnicodeString);
	printf("RtlFreeUnicodeString:%p\r\n", InjectParam.Func_RtlFreeUnicodeString);

	SIZE_T dwWrited = 0;
	DWORD ShellCodeSize = 0;
	// 申请内存，把Shellcode和DLL数据，和参数复制到目标进程
// 安全起见，大小多加0x100
	PBYTE pStartAddress = (PBYTE)VirtualAllocEx(
		targectprocess,
		0,
		InjectParam.dwDataLength + 0x100 + sizeof(InjectParam)+ShellCodeSize,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	printf("申请的内存空间 StartAddress:%p\r\n", pStartAddress);

	InjectParam.lpFileData = pStartAddress;

	// DLL数据写入到目标
	WriteProcessMemory(
		targectprocess,
		pStartAddress,
		DllX64,
		InjectParam.dwDataLength,
		&dwWrited
	);

	printf("写入DLL内容完毕\r\n");

}