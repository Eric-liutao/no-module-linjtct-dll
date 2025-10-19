// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "injectdll.hpp"
#include "dllbin.h"



ULONG_PTR WINAPI MemoryLoadLibrary(INJECTPARAM* InjectParam)
{
    // 获取注入参数
    LPVOID lpFileData = InjectParam->lpFileData;
    DWORD dwDataLength = InjectParam->dwDataLength;
    
    // 获取Native API函数指针
    LDRGETPROCEDUREADDRESS Func_LdrGetProcedureAddress = InjectParam->Func_LdrGetProcedureAddress;
    NTALLOCATEVIRTUALMEMORY Func_NtAllocateVirtualMemory = InjectParam->Func_NtAllocateVirtualMemory;
    LDRLOADDLL Func_LdrLoadDll = InjectParam->Func_LdrLoadDll;
    RTLINITANSISTRING Func_RtlInitAnsiString = InjectParam->Func_RtlInitAnsiString;
    RTLANSISTRINGTOUNICODESTRING Func_RtlAnsiStringToUnicodeString = InjectParam->Func_RtlAnsiStringToUnicodeString;
    RTLFREEUNICODESTRING Func_RtlFreeUnicodeString = InjectParam->Func_RtlFreeUnicodeString;
    
    // 初始化DLL入口点函数指针
    DLLMAIN Func_DllMain = NULL;
    PVOID pMemoryAddress = NULL;
	do
	{
		ULONG nAlign = 0;
		ULONG ImageSize = 0;
		ULONG HeaderSize = 0;
		// 检查数据长度并解析PE头
		PIMAGE_DOS_HEADER pDosHeader = NULL;
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;

		if (dwDataLength > sizeof(IMAGE_DOS_HEADER))
		{
			pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileData);

			if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}
			//检查长度
			if (dwDataLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
			{
				break;  //DOS头不完整
			}

			pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<PBYTE>(lpFileData) + pDosHeader->e_lfanew
			);

			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				break; //NT头不完整
			}

			if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
			{
				break; //不是DLL文件
			}

			if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
			{
				break; //不是映像文件
			}
			if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
			{
				break; //可选头大小不正确
			}	

			pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
				reinterpret_cast<PBYTE>(pNtHeader) +
				sizeof(IMAGE_NT_HEADERS)
			);

			BOOL bNeedStop = FALSE;
			for(int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if(pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > dwDataLength)
				{
					bNeedStop = TRUE;
					break; //节数据超出文件大小
				}
			}

			if(bNeedStop)
			{
				break;	 //节数据超出文件大小
			}

			nAlign = pNtHeader->OptionalHeader.SectionAlignment; //0x1000
			ImageSize = pNtHeader->OptionalHeader.SizeOfImage; //0x0001F000
			printf("SizeOfHeaders:%d\r\n", pNtHeader->OptionalHeader.SizeOfHeaders);
			//计算头们大小(Dos头+ Coff头+PE头+数据目录表)
			HeaderSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;

			ImageSize = HeaderSize;
			//
			for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				//得到该节的大小
				int VirtualSize = pSectionHeader[i].Misc.VirtualSize;
				int SizeOfRawData = pSectionHeader[i].SizeOfRawData;
				//取较大值	
				if (VirtualSize < SizeOfRawData)
				{
					VirtualSize = SizeOfRawData;
				}

				int SectionSize = (pSectionHeader[i].VirtualAddress + VirtualSize + nAlign - 1) / nAlign * nAlign;
					
				if (ImageSize < SectionSize)
				{
					ImageSize = SectionSize; //取的最后的Section的地址+大小(跑到文件最后的末尾了)
				}

				printf("ImageSize[2]: 0x%X\r\n", ImageSize);

				if (ImageSize == 0)
				{
					break; //文件大小没获取成功
				}

				SIZE_T uSize = ImageSize;
				Func_NtAllocateVirtualMemory((HANDLE) -1, &pMemoryAddress, 0, &uSize, MEM_COMMIT , PAGE_EXECUTE_READWRITE);
				if(pMemoryAddress != NULL)
				{
									// 复制头部
									RtlCopyMemory(pMemoryAddress, lpFileData, HeaderSize);

									// 复制各个节
									for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
									{
										PBYTE pSectionDest = reinterpret_cast<PBYTE>(pMemoryAddress) + pSectionHeader[i].VirtualAddress;
										PBYTE pSectionSrc = reinterpret_cast<PBYTE>(lpFileData) + pSectionHeader[i].PointerToRawData;
										RtlCopyMemory(
											pSectionDest,
											pSectionSrc,
											pSectionHeader[i].SizeOfRawData
										);
									}

									// 获取入口点函数地址
									Func_LdrGetProcedureAddress(
										pMemoryAddress,
										NULL,
										pNtHeader->OptionalHeader.AddressOfEntryPoint,
										reinterpret_cast<FARPROC*>(&Func_DllMain)
									);

									if (Func_DllMain != NULL)
									{
										// 调用DLL入口点函数
										Func_DllMain(
											pMemoryAddress,
											DLL_PROCESS_ATTACH,
											NULL
										);
									}
				}
			}
		}
	} while (false);
	
	return 0;
}





void Injectdll::RemoteMapLoadDll(HANDLE targectprocess)
{

	INJECTPARAM InjectParam;
	RtlZeroMemory(&InjectParam, sizeof(InjectParam));

	//WORD pShellCodeBegin



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