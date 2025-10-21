// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "injectdll.hpp"
#include "dllbin.h"

// extern declaration for binary DLL data defined in dllbin.h
extern unsigned char DllX64[59904];



ULONG_PTR WINAPI MemoryLoadLibrary_Begin(INJECTPARAM* InjectParam)
{
	
    // // 获取注入参数
	// Remote-resolve shellcode (x64):
	// - Resolve kernel32 base via PEB
	// - Parse kernel32 export table to get GetProcAddress
	// - Use GetProcAddress to get LoadLibraryA, VirtualAlloc, VirtualProtect, etc.
	// - Manual-map the DLL pointed to by InjectParam->lpFileData into allocated memory
	// - Perform relocations and import resolution
	// - Call DllMain(DLL_PROCESS_ATTACH)

	// Basic safety checks
	if (!InjectParam)
		return 1;

	// initialize remote status (0 == success)
	InjectParam->dwRemoteStatus = 0;

	// helper macro to set remote status and return from shellcode
#define SET_STATUS_AND_RETURN(code) do { if (InjectParam) InjectParam->dwRemoteStatus = (DWORD)(code); return (ULONG_PTR)(code); } while(0)

	PBYTE lpFileData = (PBYTE)InjectParam->lpFileData;
	DWORD dwDataLength = InjectParam->dwDataLength;

	// Get PEB (x64)
	// Define local PEB/LDR structures to avoid depending on compiler's winternl definitions
	typedef struct _PEB_LDR_DATA_LOCAL {
		ULONG Length;
		BOOLEAN Initialized;
		BYTE Reserved[3];
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA_LOCAL, *PPEB_LDR_DATA_LOCAL;

	typedef struct _LDR_DATA_TABLE_ENTRY_LOCAL {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
	} LDR_DATA_TABLE_ENTRY_LOCAL, *PLDR_DATA_TABLE_ENTRY_LOCAL;

	typedef struct _PEB_LOCAL {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		PPEB_LDR_DATA_LOCAL Ldr;
	} PEB_LOCAL, *PPEB_LOCAL;

	PPEB_LOCAL peb = (PPEB_LOCAL)__readgsqword(0x60);
	if (!peb)
		SET_STATUS_AND_RETURN(2);

	// checkpoint: PEB read
	if (InjectParam) InjectParam->dwRemoteStatus = 20;

	// Note: avoid lambdas or external helper calls here; implement logic inline where needed

	// Walk loader list to find kernel32.dll base
	PVOID kernel32Base = NULL;
	PPEB_LDR_DATA_LOCAL ldr = peb->Ldr;
	if (ldr)
	{
		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		for (PLIST_ENTRY cur = head->Flink; cur != head; cur = cur->Flink)
		{
			PLDR_DATA_TABLE_ENTRY_LOCAL entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_LOCAL, InLoadOrderLinks);
			if (entry && entry->BaseDllName.Buffer)
			{
				if (entry->BaseDllName.Buffer)
				{
					// inline ascii case-insensitive compare for L"kernel32.dll"
					const wchar_t* a = entry->BaseDllName.Buffer;
					const wchar_t* b = L"kernel32.dll";
					int eq = 1;
					while (*a && *b)
					{
						wchar_t ca = *a;
						wchar_t cb = *b;
						if (ca >= L'A' && ca <= L'Z') ca = ca - L'A' + L'a';
						if (cb >= L'A' && cb <= L'Z') cb = cb - L'A' + L'a';
						if (ca != cb) { eq = 0; break; }
						++a; ++b;
					}
					if (eq && *a == 0 && *b == 0)
					{
						kernel32Base = entry->DllBase;
						break;
					}
				}
			}
		}
	}

	if (!kernel32Base)
		SET_STATUS_AND_RETURN(3);

	// checkpoint: kernel32 located
	if (InjectParam) InjectParam->dwRemoteStatus = 21;

	// Helper: find export by name
	auto FindExport = [&](PVOID moduleBase, const char* name)->FARPROC {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PBYTE)moduleBase + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
		IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (expDir.VirtualAddress == 0) return NULL;
		PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + expDir.VirtualAddress);
		DWORD* names = (DWORD*)((PBYTE)moduleBase + exp->AddressOfNames);
		WORD* ords = (WORD*)((PBYTE)moduleBase + exp->AddressOfNameOrdinals);
		DWORD* funcs = (DWORD*)((PBYTE)moduleBase + exp->AddressOfFunctions);
		for (DWORD i = 0; i < exp->NumberOfNames; i++)
		{
			const char* curName = (const char*)((PBYTE)moduleBase + names[i]);
			// compare
			const char* a = curName;
			const char* b = name;
			int eq = 1;
			while (*a && *b) { if (*a != *b) { eq = 0; break; } a++; b++; }
			if (eq && *a == 0 && *b == 0)
			{
				DWORD funcRVA = funcs[ords[i]];
				return (FARPROC)((PBYTE)moduleBase + funcRVA);
			}
		}
		return NULL;
	};

	// Resolve GetProcAddress from kernel32
	FARPROC pGetProc = FindExport(kernel32Base, "GetProcAddress");
	if (!pGetProc)
		SET_STATUS_AND_RETURN(4);

	// checkpoint: GetProcAddress resolved
	if (InjectParam) InjectParam->dwRemoteStatus = 22;

	typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
	tGetProcAddress GetProcAddress_remote = (tGetProcAddress)pGetProc;

	// Use GetProcAddress to get other API addresses
	tGetProcAddress gp = GetProcAddress_remote;
	FARPROC pLoadLibraryA = gp((HMODULE)kernel32Base, "LoadLibraryA");
	FARPROC pVirtualAlloc = gp((HMODULE)kernel32Base, "VirtualAlloc");
	FARPROC pVirtualProtect = gp((HMODULE)kernel32Base, "VirtualProtect");

	if (!pLoadLibraryA || !pVirtualAlloc || !pVirtualProtect)
		SET_STATUS_AND_RETURN(5);

	// checkpoint: core APIs resolved
	if (InjectParam) InjectParam->dwRemoteStatus = 23;

	typedef LPVOID(WINAPI* tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
	typedef BOOL(WINAPI* tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);

	tVirtualAlloc VirtualAlloc_remote = (tVirtualAlloc)pVirtualAlloc;
	tVirtualProtect VirtualProtect_remote = (tVirtualProtect)pVirtualProtect;
	tLoadLibraryA LoadLibraryA_remote = (tLoadLibraryA)pLoadLibraryA;

	// Begin manual mapping of the DLL image present at lpFileData
	if (!lpFileData || dwDataLength < sizeof(IMAGE_DOS_HEADER))
		SET_STATUS_AND_RETURN(6);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileData;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) SET_STATUS_AND_RETURN(7);
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(lpFileData + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) SET_STATUS_AND_RETURN(8);

	SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;

	// Allocate memory in remote (this code runs in remote already) — VirtualAlloc_remote with NULL base
	PBYTE remoteImage = (PBYTE)VirtualAlloc_remote(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteImage) SET_STATUS_AND_RETURN(9);

	// checkpoint: remoteImage allocated
	if (InjectParam) InjectParam->dwRemoteStatus = 24;

	// Copy headers (inline loop to avoid external calls)
	SIZE_T headersSize = pNt->OptionalHeader.SizeOfHeaders;
	{
		unsigned char* d = remoteImage;
		unsigned char* s = (unsigned char*)lpFileData;
		for (SIZE_T i = 0; i < headersSize; ++i) d[i] = s[i];
	}

	// checkpoint: headers copied
	if (InjectParam) InjectParam->dwRemoteStatus = 25;

	// Copy sections
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		PBYTE dest = remoteImage + pSection[i].VirtualAddress;
		PBYTE src = lpFileData + pSection[i].PointerToRawData;
		SIZE_T copySize = pSection[i].SizeOfRawData;
		if (copySize > 0)
		{
			unsigned char* d = dest;
			unsigned char* s = src;
			for (SIZE_T j = 0; j < copySize; ++j) d[j] = s[j];
		}
	}

	// checkpoint: sections copied
	if (InjectParam) InjectParam->dwRemoteStatus = 26;

	// Perform base relocations if necessary
	ULONG_PTR delta = (ULONG_PTR)remoteImage - pNt->OptionalHeader.ImageBase;
	if (delta != 0 && pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)(lpFileData + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		SIZE_T maxRelSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		SIZE_T processed = 0;
		while (processed < maxRelSize && rel->SizeOfBlock)
		{
			DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* list = (WORD*)((PBYTE)rel + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD idx = 0; idx < count; idx++)
			{
				WORD entry = list[idx];
				WORD type = entry >> 12;
				WORD offset = entry & 0x0FFF;
				if (type == IMAGE_REL_BASED_DIR64)
				{
					ULONG_PTR* patch = (ULONG_PTR*)(remoteImage + rel->VirtualAddress + offset);
					*patch = (ULONG_PTR)((ULONG_PTR)*patch + delta);
				}
				// checkpoint: relocations applied
				if (InjectParam) InjectParam->dwRemoteStatus = 27;
			}
			processed += rel->SizeOfBlock;
			rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
		}
	}

	// Resolve imports
	if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileData + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (imp->Name)
		{
			char* dllName = (char*)(lpFileData + imp->Name);
			HMODULE hMod = LoadLibraryA_remote(dllName);
			if (!hMod) { /* failed to load dependency */ SET_STATUS_AND_RETURN(10); }

			// thunk arrays
			PIMAGE_THUNK_DATA64 oft = (PIMAGE_THUNK_DATA64)(lpFileData + imp->OriginalFirstThunk);
			PIMAGE_THUNK_DATA64 ft = (PIMAGE_THUNK_DATA64)(remoteImage + imp->FirstThunk);
			while (oft && oft->u1.AddressOfData)
			{
				FARPROC func = NULL;
				if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					// ordinal
					UINT16 ord = (UINT16)(oft->u1.Ordinal & 0xFFFF);
					func = (FARPROC)gp(hMod, (LPCSTR)(uintptr_t)ord);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(lpFileData + oft->u1.AddressOfData);
					func = gp(hMod, (LPCSTR)ibn->Name);
				}
				// write into FT
				ft->u1.Function = (ULONGLONG)func;
				oft++;
				ft++;
			}
			imp++;
		}
	}

	// checkpoint: imports resolved
	if (InjectParam) InjectParam->dwRemoteStatus = 28;

	// Call entry point
	if (pNt->OptionalHeader.AddressOfEntryPoint)
	{
		DLLMAIN DllEntry = (DLLMAIN)(remoteImage + pNt->OptionalHeader.AddressOfEntryPoint);
		if (DllEntry)
		{
			// checkpoint: about to call DllMain
			if (InjectParam) InjectParam->dwRemoteStatus = 29;
			DllEntry(remoteImage, DLL_PROCESS_ATTACH, NULL);
			// after calling
			if (InjectParam) InjectParam->dwRemoteStatus = 30;
		}
	}

	SET_STATUS_AND_RETURN(0);
#undef SET_STATUS_AND_RETURN
	// 	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	// 	if (dwDataLength > sizeof(IMAGE_DOS_HEADER))
	// 	{
	// 		pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileData);

	// 		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	// 		{
	// 			break;
	// 		}
	// 		//检查长度
	// 		if (dwDataLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
	// 		{
	// 			break;  //DOS头不完整
	// 		}

	// 		pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	// 			reinterpret_cast<PBYTE>(lpFileData) + pDosHeader->e_lfanew
	// 		);

	// 		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	// 		{
	// 			break; //NT头不完整
	// 		}

	// 		if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
	// 		{
	// 			break; //不是DLL文件
	// 		}

	// 		if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
	// 		{
	// 			break; //不是映像文件
	// 		}
	// 		if (pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	// 		{
	// 			break; //可选头大小不正确
	// 		}	

	// 		pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
	// 			reinterpret_cast<PBYTE>(pNtHeader) +
	// 			sizeof(IMAGE_NT_HEADERS)
	// 		);

	// 		BOOL bNeedStop = FALSE;
	// 		for(int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	// 		{
	// 			if(pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > dwDataLength)
	// 			{
	// 				bNeedStop = TRUE;
	// 				break; //节数据超出文件大小
	// 			}
	// 		}

	// 		if(bNeedStop)
	// 		{
	// 			break;	 //节数据超出文件大小
	// 		}

	// 		nAlign = pNtHeader->OptionalHeader.SectionAlignment; //0x1000
	// 		ImageSize = pNtHeader->OptionalHeader.SizeOfImage; //0x0001F000
	// 		printf("SizeOfHeaders:%d\r\n", pNtHeader->OptionalHeader.SizeOfHeaders);
	// 		//计算头们大小(Dos头+ Coff头+PE头+数据目录表)
	// 		HeaderSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;

	// 		ImageSize = HeaderSize;
	// 		//
	// 		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	// 		{
	// 			//得到该节的大小
	// 			int VirtualSize = pSectionHeader[i].Misc.VirtualSize;
	// 			int SizeOfRawData = pSectionHeader[i].SizeOfRawData;
	// 			int MaxSize = (SizeOfRawData > VirtualSize)? SizeOfRawData:VirtualSize;

	// 			int SectionSize = (pSectionHeader[i].VirtualAddress + VirtualSize + nAlign - 1) / nAlign * nAlign;
					
	// 			if(ImageSize < SectionSize)
	// 			{
	// 				ImageSize = SectionSize;
	// 			}


	// 			if (ImageSize == 0)
	// 			{
	// 				break; //文件大小没获取成功
	// 			}

	// 			SIZE_T uSize = ImageSize;
	// 			Func_NtAllocateVirtualMemory((HANDLE) -1, &pMemoryAddress, 0, &uSize, MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	// 			if(pMemoryAddress != NULL)
	// 			{
	// 				Func_MessageBoxA(NULL, NULL, NULL, MB_OK);
	// 				// 这里可以继续实现映像加载的其他步骤，例如拷贝节数据、处理重定位、解析导入表等。
	// 			}
	// 		}
	// 	}
	// } while (false);
	
	return 0;
	
}

void MemoryLoadLibrary_End()
{

}

// Small smoke-test shellcode: sets InjectParam->dwRemoteStatus = 77 and returns
ULONG_PTR WINAPI RemoteSmoke_Begin(INJECTPARAM* InjectParam)
{
	if (!InjectParam) return 1;
	InjectParam->dwRemoteStatus = 77;
	return 0;
}

void RemoteSmoke_End()
{
}



void Injectdll::RemoteMapLoadDll(HANDLE TargetProcess)
{
	SIZE_T dwWrited = 0;
	INJECTPARAM InjectParam;

	RtlZeroMemory(&InjectParam, sizeof(InjectParam));

	DWORD dwFileSize = 59904; // size of DllX64 from dllbin.h

	// temporary: run smoke-test instead of full manual map
	bool useSmoke = true; // set true to run RemoteSmoke_Begin test

	WORD *pShellCodeBegin = (WORD *)(useSmoke ? RemoteSmoke_Begin : MemoryLoadLibrary_Begin);

	DWORD ShellCodeSize = 0;

	// 计算ShellCode大小
	ShellCodeSize = (DWORD)((ULONG_PTR)(useSmoke ? RemoteSmoke_End : MemoryLoadLibrary_End) - (ULONG_PTR)pShellCodeBegin);
	printf("ShellCodeSize:%d\r\n", ShellCodeSize);

	PBYTE pShellCodeBuffer = NULL;
	if (ShellCodeSize)
	{
		pShellCodeBuffer = (PBYTE)malloc(ShellCodeSize);
		RtlZeroMemory(pShellCodeBuffer, ShellCodeSize);
	}

	// If using smoke test, construct a tiny position-independent stub that writes 77 to
	// [RCX + offsetof(INJECTPARAM, dwRemoteStatus)] and returns.
	if (useSmoke)
	{
		// build machine code: mov eax,77; mov [rcx+disp32], eax; xor eax,eax; ret
		SIZE_T statusOffset = offsetof(INJECTPARAM, dwRemoteStatus);
		const int stubSize = 14; // 5 + 6 + 2 +1
		if (pShellCodeBuffer) free(pShellCodeBuffer);
		pShellCodeBuffer = (PBYTE)malloc(stubSize);
		RtlZeroMemory(pShellCodeBuffer, stubSize);
		int idx = 0;
		// mov eax, imm32 (77)
		pShellCodeBuffer[idx++] = 0xB8;
		pShellCodeBuffer[idx++] = 0x4D; // 77
		pShellCodeBuffer[idx++] = 0x00;
		pShellCodeBuffer[idx++] = 0x00;
		pShellCodeBuffer[idx++] = 0x00;
		// mov [rcx + disp32], eax -> 0x89 0x81 <disp32>
		pShellCodeBuffer[idx++] = 0x89;
		pShellCodeBuffer[idx++] = 0x81;
		// write disp32 little-endian
		*(DWORD*)(pShellCodeBuffer + idx) = (DWORD)statusOffset;
		idx += 4;
		// xor eax,eax
		pShellCodeBuffer[idx++] = 0x31;
		pShellCodeBuffer[idx++] = 0xC0;
		// ret
		pShellCodeBuffer[idx++] = 0xC3;
		ShellCodeSize = stubSize;
	}

	// We will NOT pass local function pointers to the remote process. The shellcode
	// running in the remote process must resolve needed APIs itself.
	InjectParam.dwDataLength = dwFileSize;
	InjectParam.dwTargetPID = ::GetProcessId(TargetProcess);

	// Clear function pointers so remote code resolves them locally
	InjectParam.Func_LdrGetProcedureAddress = NULL;
	InjectParam.Func_NtAllocateVirtualMemory = NULL;
	InjectParam.Func_LdrLoadDll = NULL;
	InjectParam.Func_RtlInitAnsiString = NULL;
	InjectParam.Func_RtlAnsiStringToUnicodeString = NULL;
	InjectParam.Func_RtlFreeUnicodeString = NULL;
	InjectParam.Func_MessageBoxA = NULL;

	// 申请三块独立内存：DLL 数据区、Shellcode 区、参数区
	PBYTE pRemoteDllAddr = (PBYTE)VirtualAllocEx(
		TargetProcess,
		NULL,
		dwFileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!pRemoteDllAddr)
	{
		printf("VirtualAllocEx for DLL data failed: %u\n", GetLastError());
		free(pShellCodeBuffer);
		return;
	}

	PBYTE pRemoteShellAddr = (PBYTE)VirtualAllocEx(
		TargetProcess,
		NULL,
		ShellCodeSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteShellAddr)
	{
		printf("VirtualAllocEx for shellcode failed: %u\n", GetLastError());
		VirtualFreeEx(TargetProcess, pRemoteDllAddr, 0, MEM_RELEASE);
		free(pShellCodeBuffer);
		return;
	}

	PBYTE pRemoteParamAddr = (PBYTE)VirtualAllocEx(
		TargetProcess,
		NULL,
		sizeof(InjectParam),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!pRemoteParamAddr)
	{
		printf("VirtualAllocEx for param failed: %u\n", GetLastError());
		VirtualFreeEx(TargetProcess, pRemoteDllAddr, 0, MEM_RELEASE);
		VirtualFreeEx(TargetProcess, pRemoteShellAddr, 0, MEM_RELEASE);
		free(pShellCodeBuffer);
		return;
	}

	printf("Remote DLL addr: %p\n", pRemoteDllAddr);
	printf("Remote shell addr: %p\n", pRemoteShellAddr);
	printf("Remote param addr: %p\n", pRemoteParamAddr);

	// Set remote pointer in InjectParam
	InjectParam.lpFileData = pRemoteDllAddr;
	// initialize remote status field
	InjectParam.dwRemoteStatus = 0;

	// Declare remote thread handle early so goto cleanup_remote doesn't skip its initialization
	HANDLE hRemoteThread = NULL;

	// Cleanup lambda replaces the old goto-based cleanup label
	auto cleanup_remote = [&]() {
		if (hRemoteThread)
		{
			CloseHandle(hRemoteThread);
			hRemoteThread = NULL;
		}
		if (pRemoteDllAddr)
			VirtualFreeEx(TargetProcess, pRemoteDllAddr, 0, MEM_RELEASE);
		if (pRemoteShellAddr)
			VirtualFreeEx(TargetProcess, pRemoteShellAddr, 0, MEM_RELEASE);
		if (pRemoteParamAddr)
			VirtualFreeEx(TargetProcess, pRemoteParamAddr, 0, MEM_RELEASE);
		if (pShellCodeBuffer)
		{
			free(pShellCodeBuffer);
			pShellCodeBuffer = NULL;
		}
	};

	// 写入 DLL 数据 到目标进程 (skip when running smoke test)
	if (!useSmoke)
	{
		if (!WriteProcessMemory(TargetProcess, pRemoteDllAddr, DllX64, dwFileSize, &dwWrited) || dwWrited != dwFileSize)
		{
			printf("WriteProcessMemory DLL failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
			cleanup_remote();
			return;
		}
	}

	// 写入 ShellCode
	if (!WriteProcessMemory(TargetProcess, pRemoteShellAddr, pShellCodeBuffer, ShellCodeSize, &dwWrited) || dwWrited != ShellCodeSize)
	{
		printf("WriteProcessMemory shellcode failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
		cleanup_remote();
		return;
	}

	// 写入参数结构（参数里包含远程 DLL 地址）
	if (!WriteProcessMemory(TargetProcess, pRemoteParamAddr, &InjectParam, sizeof(InjectParam), &dwWrited) || dwWrited != sizeof(InjectParam))
	{
		printf("WriteProcessMemory param failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
		cleanup_remote();
		return;
	}

	// 创建远程线程，传入远程 shellcode 地址 和远程参数地址
	hRemoteThread = CreateRemoteThread(TargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteShellAddr, pRemoteParamAddr, 0, NULL);
	if (!hRemoteThread)
	{
		printf("CreateRemoteThread failed: %u\n", GetLastError());
		cleanup_remote();
		return;
	}

	// 等待远程线程完成（10秒超时），以便获取 shellcode 的返回码用于调试
	DWORD waitRes = WaitForSingleObject(hRemoteThread, 10000); // 10s
	if (waitRes == WAIT_OBJECT_0)
	{
		DWORD exitCode = 0;
		if (GetExitCodeThread(hRemoteThread, &exitCode))
		{
			printf("Remote thread exited with code: %lu\n", (unsigned long)exitCode);
		}
		else
		{
			printf("GetExitCodeThread failed: %u\n", GetLastError());
		}

		// Read back INJECTPARAM from remote to get dwRemoteStatus
		INJECTPARAM remoteParam;
		SIZE_T bytesRead = 0;
		RtlZeroMemory(&remoteParam, sizeof(remoteParam));
		if (ReadProcessMemory(TargetProcess, pRemoteParamAddr, &remoteParam, sizeof(remoteParam), &bytesRead) && bytesRead == sizeof(remoteParam))
		{
			printf("Remote dwRemoteStatus: %lu\n", (unsigned long)remoteParam.dwRemoteStatus);
		}
		else
		{
			printf("ReadProcessMemory for INJECTPARAM failed: %u\n", GetLastError());
		}
	}
	else if (waitRes == WAIT_TIMEOUT)
	{
		printf("WaitForSingleObject timed out waiting for remote thread\n");
	}
	else
	{
		printf("WaitForSingleObject failed: %u\n", GetLastError());
	}

	printf("写入DLL内容完毕\r\n");

	// normal cleanup of local buffer (remote memory stays allocated by design)
	if (pShellCodeBuffer)
	{
		free(pShellCodeBuffer);
		pShellCodeBuffer = NULL;
	}
	return;

}