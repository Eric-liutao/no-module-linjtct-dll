// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "injectdll.hpp"
#include "dllbin.h"





__declspec(safebuffers)
__declspec(noinline)
ULONG_PTR WINAPI MemoryLoadLibrary_Begin(INJECTPARAM* InjectParam)
{
	
	// Manual-map shellcode (x64) high-level steps:
	// 1) Resolve kernel32 base via PEB->Ldr; parse export to get GetProcAddress
	// 2) Resolve LoadLibraryA, VirtualAlloc, VirtualProtect via GetProcAddress
	// 3) Parse PE file in InjectParam->lpFileData: validate DOS/NT headers
	// 4) Allocate image-sized memory; copy headers and sections
	// 5) Apply base relocations (if ImageBase != allocation)
	// 6) Resolve imports: Load dependency DLLs with LoadLibraryA and fill IAT via GetProcAddress
	// 7) Optionally call DllMain(DLL_PROCESS_ATTACH) (guarded by SkipCallDllMain)

	// Basic safety checks
	if (!InjectParam)
		return 1;

	// initialize remote status (0 == success)
	InjectParam->dwRemoteStatus = 0;
	// earliest checkpoint: entered shellcode
	InjectParam->dwRemoteStatus = 19;
	// Respect host-provided SkipCallDllMain (do not override here)

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

	// Prepare to scan exports of loaded modules (no dependency on kernel32 name)
	PVOID kernel32Base = NULL; // optional: module that provides GetProcAddress
	PPEB_LDR_DATA_LOCAL ldr = peb->Ldr;
	if (InjectParam) InjectParam->dwRemoteStatus = 200; // got Ldr

	// Resolve GetProcAddress by scanning all loaded modules' exports and comparing to InjectParam->Name_GetProcAddress
	FARPROC pGetProc = NULL;
	if (!ldr || !InjectParam || !InjectParam->Name_GetProcAddress)
		SET_STATUS_AND_RETURN(4);
	{
		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY cur = head ? head->Flink : NULL;
		int guard2 = 0;
		if (InjectParam) InjectParam->dwRemoteStatus = 220; // start scanning modules for GetProcAddress
		for (; cur && cur != head && guard2 < 1024 && !pGetProc; cur = cur->Flink, ++guard2)
		{
			if (InjectParam) InjectParam->dwRemoteStatus = 221; // have module
			PLDR_DATA_TABLE_ENTRY_LOCAL entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_LOCAL, InLoadOrderLinks);
			PVOID modBase = entry ? entry->DllBase : NULL;
			if (!modBase) continue;
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modBase;
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
			PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PBYTE)modBase + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
			IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (expDir.VirtualAddress == 0) continue;
			PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)modBase + expDir.VirtualAddress);
			DWORD* names = (DWORD*)((PBYTE)modBase + exp->AddressOfNames);
			WORD* ords = (WORD*)((PBYTE)modBase + exp->AddressOfNameOrdinals);
			DWORD* funcs = (DWORD*)((PBYTE)modBase + exp->AddressOfFunctions);
			if (InjectParam) InjectParam->dwRemoteStatus = 222; // scanning names
			for (DWORD i = 0; i < exp->NumberOfNames && !pGetProc; i++)
			{
				const char* curName = (const char*)((PBYTE)modBase + names[i]);
				const char* a = curName;
				const char* b = InjectParam->Name_GetProcAddress;
				int eq = 1;
				while (*a && *b) { if (*a != *b) { eq = 0; break; } a++; b++; }
				if (eq && *a == 0 && *b == 0)
				{
					DWORD funcRVA = funcs[ords[i]];
					pGetProc = (FARPROC)((PBYTE)modBase + funcRVA);
					kernel32Base = modBase; // remember module holding GetProcAddress
					if (InjectParam) InjectParam->dwRemoteStatus = 223; // found GetProcAddress
					break;
				}
			}
		}
	}
	if (!pGetProc)
		SET_STATUS_AND_RETURN(4);
	// checkpoint: GetProcAddress resolved (22)
	if (InjectParam) InjectParam->dwRemoteStatus = 22;

	typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
	tGetProcAddress GetProcAddress_remote = (tGetProcAddress)pGetProc;

	// Use GetProcAddress to get other API addresses
	tGetProcAddress gp = GetProcAddress_remote;
	FARPROC pLoadLibraryA = gp((HMODULE)kernel32Base, InjectParam->Name_LoadLibraryA);
	FARPROC pVirtualAlloc = gp((HMODULE)kernel32Base, InjectParam->Name_VirtualAlloc);
	FARPROC pVirtualProtect = gp((HMODULE)kernel32Base, InjectParam->Name_VirtualProtect);

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
	// bounds: e_lfanew must fit within file buffer
	if ((SIZE_T)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dwDataLength) SET_STATUS_AND_RETURN(13);
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(lpFileData + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) SET_STATUS_AND_RETURN(8);

	SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
	if (imageSize == 0) SET_STATUS_AND_RETURN(16);

	// Ensure section table lies within file buffer
	SIZE_T sectTableEnd = (SIZE_T)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (SIZE_T)pNt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	if (sectTableEnd > dwDataLength) SET_STATUS_AND_RETURN(14);

	// Validate section raw ranges fit inside provided file buffer
	{
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pNt);
		for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i)
		{
			DWORD raw = sec[i].PointerToRawData;
			DWORD rawSize = sec[i].SizeOfRawData;
			if (rawSize && (raw > dwDataLength || raw + rawSize > dwDataLength))
			{
				SET_STATUS_AND_RETURN(12); // section raw out of bounds
			}
		}
	}

	// Allocate memory in remote (this code runs in remote already) — VirtualAlloc_remote with NULL base
	PBYTE remoteImage = (PBYTE)VirtualAlloc_remote(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteImage) SET_STATUS_AND_RETURN(9);

	// checkpoint: remoteImage allocated
	if (InjectParam) InjectParam->dwRemoteStatus = 24;

	// Copy headers (inline loop to avoid external calls)
	SIZE_T headersSize = pNt->OptionalHeader.SizeOfHeaders;
	// clamp to file size and remote image size
	if (headersSize > dwDataLength) headersSize = dwDataLength;
	if (headersSize > imageSize) headersSize = imageSize;
	if (InjectParam) InjectParam->dwRemoteStatus = 241; // start header copy
	__try {
		unsigned char* d = remoteImage;
		unsigned char* s = (unsigned char*)lpFileData;
		for (SIZE_T i = 0; i < headersSize; ++i) d[i] = s[i];
	} __except (1) {
		SET_STATUS_AND_RETURN(90); // exception during header copy
	}

	// checkpoint: headers copied
	if (InjectParam) InjectParam->dwRemoteStatus = 25;

	// Copy sections
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	if (InjectParam) InjectParam->dwRemoteStatus = 261; // start sections copy
	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		DWORD va = pSection[i].VirtualAddress;
		DWORD vsz = pSection[i].Misc.VirtualSize;
		DWORD raw = pSection[i].PointerToRawData;
		DWORD rawSize = pSection[i].SizeOfRawData;
		PBYTE dest = remoteImage + va;
		PBYTE src = lpFileData + raw;
		SIZE_T copySize = rawSize;
		// bounds safety: clamp copy to remaining image space
		if ((SIZE_T)va >= imageSize) copySize = 0;
		else if ((SIZE_T)va + copySize > imageSize) copySize = (SIZE_T)imageSize - va;
		__try {
			if (copySize > 0)
			{
				unsigned char* d = dest;
				unsigned char* s = src;
				for (SIZE_T j = 0; j < copySize; ++j) d[j] = s[j];
			}
		} __except (1) {
			SET_STATUS_AND_RETURN(91); // exception during section copy
		}
		// zero-init the rest of VirtualSize beyond raw data (bss)
		SIZE_T vremain = 0;
		if (vsz > rawSize)
		{
			vremain = (SIZE_T)vsz - rawSize;
			// clamp to image end
			if ((SIZE_T)va + rawSize >= imageSize) vremain = 0;
			else if ((SIZE_T)va + rawSize + vremain > imageSize) vremain = (SIZE_T)imageSize - ((SIZE_T)va + rawSize);
			__try {
				unsigned char* z = remoteImage + va + rawSize;
				for (SIZE_T j = 0; j < vremain; ++j) z[j] = 0;
			} __except (1) {
				SET_STATUS_AND_RETURN(92); // exception during bss zero
			}
		}
	}

	// checkpoint: sections copied
	if (InjectParam) InjectParam->dwRemoteStatus = 26;

	// Helper macro to compute pointers by RVA against the mapped remote image
	#define RVA_REMOTE(ptrBase, rva) ((PBYTE)(ptrBase) + (SIZE_T)(rva))

	// Perform base relocations if necessary (work entirely against remoteImage)
	ULONG_PTR delta = (ULONG_PTR)remoteImage - pNt->OptionalHeader.ImageBase;
	if (delta != 0 && pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		PIMAGE_BASE_RELOCATION rel = (PIMAGE_BASE_RELOCATION)RVA_REMOTE(remoteImage, pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
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
					SIZE_T rva = (SIZE_T)rel->VirtualAddress + offset;
					if (rva + sizeof(ULONG_PTR) <= imageSize)
					{
						ULONG_PTR* patch = (ULONG_PTR*)(RVA_REMOTE(remoteImage, rva));
						*patch = (ULONG_PTR)((ULONG_PTR)*patch + delta);
					}
				}
				// checkpoint: relocations applied
				if (InjectParam) InjectParam->dwRemoteStatus = 27;
			}
			processed += rel->SizeOfBlock;
			rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
		}
	}

	// Resolve imports (work against remoteImage for RVAs)
	if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)RVA_REMOTE(remoteImage, pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (imp->Name)
		{
			char* dllName = (char*)RVA_REMOTE(remoteImage, imp->Name);
			HMODULE hMod = LoadLibraryA_remote(dllName);
			if (!hMod) { /* failed to load dependency */ SET_STATUS_AND_RETURN(10); }

			// Determine thunks; if OriginalFirstThunk is 0, use FirstThunk
			PIMAGE_THUNK_DATA64 oft = (PIMAGE_THUNK_DATA64)(imp->OriginalFirstThunk ? RVA_REMOTE(remoteImage, imp->OriginalFirstThunk) : RVA_REMOTE(remoteImage, imp->FirstThunk));
			PIMAGE_THUNK_DATA64 ft = (PIMAGE_THUNK_DATA64)RVA_REMOTE(remoteImage, imp->FirstThunk);
			while (oft && oft->u1.AddressOfData)
			{
				FARPROC func = NULL;
				if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					UINT16 ord = (UINT16)(oft->u1.Ordinal & 0xFFFF);
					func = (FARPROC)gp(hMod, (LPCSTR)(uintptr_t)ord);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)RVA_REMOTE(remoteImage, oft->u1.AddressOfData);
					func = gp(hMod, (LPCSTR)ibn->Name);
				}
				ft->u1.Function = (ULONGLONG)func;
				oft++;
				ft++;
			}
			imp++;
		}
	}

	// checkpoint: imports resolved
	if (InjectParam) InjectParam->dwRemoteStatus = 28;

	// Note: removed in-shellcode MessageBox to avoid UI popups in target processes

	// Adjust memory protections per-section to be closer to loader behavior (optional, best-effort)
	{
		for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i)
		{
			DWORD scn = pSection[i].Characteristics;
			DWORD newProt = PAGE_NOACCESS;
			BOOL exec = (scn & IMAGE_SCN_MEM_EXECUTE) != 0;
			BOOL read = (scn & IMAGE_SCN_MEM_READ) != 0;
			BOOL write = (scn & IMAGE_SCN_MEM_WRITE) != 0;
			if (exec)
				newProt = write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
			else
				newProt = write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS);
			SIZE_T size = pSection[i].Misc.VirtualSize;
			if (size)
			{
				DWORD oldProt = 0;
				VirtualProtect_remote(remoteImage + pSection[i].VirtualAddress, size, newProt, &oldProt);
			}
		}
	}

	// Call entry point
	if (pNt->OptionalHeader.AddressOfEntryPoint)
	{
		DLLMAIN DllEntry = (DLLMAIN)(remoteImage + pNt->OptionalHeader.AddressOfEntryPoint);
		if (DllEntry)
		{
			// checkpoint: about to call DllMain
			if (InjectParam) InjectParam->dwRemoteStatus = 29;
			// If SkipCallDllMain is set, avoid calling DllMain (diagnostic mode)
			if (!InjectParam || InjectParam->SkipCallDllMain == 0)
			{
				DllEntry(remoteImage, DLL_PROCESS_ATTACH, NULL);
				// after calling
				if (InjectParam) InjectParam->dwRemoteStatus = 30;
			}
			else
			{
				// mark that DllMain was intentionally skipped
				if (InjectParam) InjectParam->dwRemoteStatus = 31;
			}
			// do not overwrite the branch-specific status above
		}
	}

	// Success: preserve last status (e.g., 30 or 31) and return 0
	return 0;
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

	DWORD dwFileSize = (DWORD)sizeof(DllX64); // use actual size from dllbin.h

		// Use the manual-map shellcode (MemoryLoadLibrary_Begin / MemoryLoadLibrary_End)
		WORD *pShellCodeBegin = (WORD *)MemoryLoadLibrary_Begin;

	DWORD ShellCodeSize = 0;

	// 计算ShellCode大小
	ShellCodeSize = (DWORD)((ULONG_PTR)MemoryLoadLibrary_End - (ULONG_PTR)pShellCodeBegin);
	printf("ShellCodeSize:%d\r\n", ShellCodeSize);

	PBYTE pShellCodeBuffer = NULL;
	if (ShellCodeSize)
	{
		pShellCodeBuffer = (PBYTE)malloc(ShellCodeSize);
		RtlZeroMemory(pShellCodeBuffer, ShellCodeSize);
		// Copy the compiled manual-map function bytes into the shellcode buffer.
		// Note: copying compiled function bytes into another process is fragile (RIP-relative refs),
		// but the user requested to always inject MemoryLoadLibrary_Begin.
		RtlCopyMemory(pShellCodeBuffer, (PVOID)pShellCodeBegin, ShellCodeSize);
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

	// Prepare API name strings to embed after the INJECTPARAM in remote memory
	const char* sGetProcAddress = "GetProcAddress";
	const char* sLoadLibraryA   = "LoadLibraryA";
	const char* sVirtualAlloc   = "VirtualAlloc";
	const char* sVirtualProtect = "VirtualProtect";
	// MessageBox-related strings removed
	SIZE_T lenGetProc = (SIZE_T)strlen(sGetProcAddress) + 1;
	SIZE_T lenLoadLib = (SIZE_T)strlen(sLoadLibraryA) + 1;
	SIZE_T lenVirtAlloc = (SIZE_T)strlen(sVirtualAlloc) + 1;
	SIZE_T lenVirtProt = (SIZE_T)strlen(sVirtualProtect) + 1;
	// Removed lengths for user32/MessageBox and message strings
	SIZE_T paramSize = sizeof(InjectParam);
	SIZE_T namesSize = lenGetProc + lenLoadLib + lenVirtAlloc + lenVirtProt;
	SIZE_T totalParamSize = paramSize + namesSize;

	PBYTE pRemoteParamAddr = (PBYTE)VirtualAllocEx(
		TargetProcess,
		NULL,
		totalParamSize,
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
	printf("Param size total: %llu bytes\n", (unsigned long long)totalParamSize);

	// Layout: [INJECTPARAM]["GetProcAddress\0"]["LoadLibraryA\0"]["VirtualAlloc\0"]["VirtualProtect\0"]
	// Compute remote addresses for name strings
	PBYTE namesBase = pRemoteParamAddr + paramSize;
	PBYTE remoteGetProc = namesBase;
	PBYTE remoteLoadLib = remoteGetProc + lenGetProc;
	PBYTE remoteVirtAlloc = remoteLoadLib + lenLoadLib;
	PBYTE remoteVirtProt = remoteVirtAlloc + lenVirtAlloc;
	// No additional pointers for user32/MessageBox or message strings

	// Set remote pointer in InjectParam
	InjectParam.lpFileData = pRemoteDllAddr;
	// initialize remote status field
	InjectParam.dwRemoteStatus = 0;
	// Enable calling DllMain for this run (no popup in shellcode)
	InjectParam.SkipCallDllMain = 0;

	// Fill name pointers (remote addresses)
	InjectParam.Name_GetProcAddress = (char*)remoteGetProc;
	InjectParam.Name_LoadLibraryA   = (char*)remoteLoadLib;
	InjectParam.Name_VirtualAlloc   = (char*)remoteVirtAlloc;
	InjectParam.Name_VirtualProtect = (char*)remoteVirtProt;
	InjectParam.Name_User32         = NULL;
	InjectParam.Name_MessageBoxA    = NULL;
	InjectParam.Str_MsgText         = NULL;
	InjectParam.Str_MsgCaption      = NULL;

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

	// 写入 DLL 数据 到目标进程
	if (!WriteProcessMemory(TargetProcess, pRemoteDllAddr, DllX64, dwFileSize, &dwWrited) || dwWrited != dwFileSize)
	{
		printf("WriteProcessMemory DLL failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
		cleanup_remote();
		return;
	}

	// 写入 ShellCode
	if (!WriteProcessMemory(TargetProcess, pRemoteShellAddr, pShellCodeBuffer, ShellCodeSize, &dwWrited) || dwWrited != ShellCodeSize)
	{
		printf("WriteProcessMemory shellcode failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
		cleanup_remote();
		return;
	}

	// Diagnostic: read back shellcode from remote and compare first/last bytes to ensure integrity
	{
		PBYTE verifyBuf = (PBYTE)malloc(ShellCodeSize);
		SIZE_T bytesRead = 0;
		RtlZeroMemory(verifyBuf, ShellCodeSize);
		if (ReadProcessMemory(TargetProcess, pRemoteShellAddr, verifyBuf, ShellCodeSize, &bytesRead) && bytesRead == ShellCodeSize)
		{
			int mismatch = 0;
			if (ShellCodeSize >= 1 && verifyBuf[0] != pShellCodeBuffer[0]) mismatch = 1;
			if (ShellCodeSize >= 2 && verifyBuf[ShellCodeSize-1] != pShellCodeBuffer[ShellCodeSize-1]) mismatch |= 2;
			if (mismatch)
			{
				printf("Warning: remote shellcode differs from local buffer (mismatch mask=%d).\n", mismatch);
			}
			else
			{
				printf("Remote shellcode write verified (first/last bytes match).\n");
			}
		}
		else
		{
			printf("Warning: ReadProcessMemory verify failed: %u\n", GetLastError());
		}
		free(verifyBuf);
	}

	// 写入参数结构（参数里包含远程 DLL 地址与字符串指针）
	if (!WriteProcessMemory(TargetProcess, pRemoteParamAddr, &InjectParam, sizeof(InjectParam), &dwWrited) || dwWrited != sizeof(InjectParam))
	{
		printf("WriteProcessMemory param failed: %u (written %llu)\n", GetLastError(), (unsigned long long)dwWrited);
		cleanup_remote();
		return;
	}

	// 写入紧随其后的 API 名称字符串块
	SIZE_T wroteNames = 0;
	// Copy names into a single local buffer in the same layout
	SIZE_T localBufSize = namesSize;
	PBYTE localNames = (PBYTE)malloc(localBufSize);
	if (!localNames) { printf("malloc failed for localNames\n"); cleanup_remote(); return; }
	SIZE_T off = 0;
	memcpy(localNames + off, sGetProcAddress, lenGetProc); off += lenGetProc;
	memcpy(localNames + off, sLoadLibraryA,   lenLoadLib);  off += lenLoadLib;
	memcpy(localNames + off, sVirtualAlloc,   lenVirtAlloc);off += lenVirtAlloc;
	memcpy(localNames + off, sVirtualProtect, lenVirtProt); off += lenVirtProt;
	// Only copy the four core API names; user32/MessageBox strings removed
	if (!WriteProcessMemory(TargetProcess, namesBase, localNames, localBufSize, &wroteNames) || wroteNames != localBufSize)
	{
		printf("WriteProcessMemory names failed: %u (written %llu)\n", GetLastError(), (unsigned long long)wroteNames);
		free(localNames);
		cleanup_remote();
		return;
	}
	free(localNames);

	// Ensure remote shellcode page is executable (in case VirtualAllocEx reserved non-exec by policy)
	{
		DWORD oldProt = 0;
		if (!VirtualProtectEx(TargetProcess, pRemoteShellAddr, ShellCodeSize, PAGE_EXECUTE_READ, &oldProt))
		{
			// If VirtualProtectEx fails, print warning but still try CreateRemoteThread
			printf("Warning: VirtualProtectEx failed for shellcode: %u\n", GetLastError());
		}
	}

	// 创建远程线程，传入远程 shellcode 地址 和远程参数地址
	hRemoteThread = CreateRemoteThread(TargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteShellAddr, pRemoteParamAddr, 0, NULL);
	if (!hRemoteThread)
	{
		printf("CreateRemoteThread failed: %u\n", GetLastError());
		cleanup_remote();
		return;
	}

	// 轮询式等待（最多10秒）：边等边读 dwRemoteStatus，避免目标先崩溃导致错过早期状态
	DWORD totalMs = 10000;
	DWORD endTick = GetTickCount() + totalMs;
	DWORD lastStatus = 0xFFFFFFFF;
	for (;;)
	{
		DWORD now = GetTickCount();
		DWORD timeout = (now >= endTick) ? 0 : (endTick - now);
		DWORD slice = (timeout > 50 ? 50 : timeout);
		DWORD wr = WaitForSingleObject(hRemoteThread, slice);

		// 尝试读取 dwRemoteStatus（仅4字节），即使目标稍后会崩溃，也尽量捕获最近进度
		DWORD status = 0; SIZE_T br = 0;
		if (ReadProcessMemory(TargetProcess, (PBYTE)pRemoteParamAddr + offsetof(INJECTPARAM, dwRemoteStatus), &status, sizeof(status), &br) && br == sizeof(status))
		{
			if (status != lastStatus)
			{
				printf("[poll] Remote dwRemoteStatus: %lu\n", (unsigned long)status);
				lastStatus = status;
			}
		}
		else if (GetLastError() == 299)
		{
			// 部分读取，忽略
		}

		if (wr == WAIT_OBJECT_0)
		{
			break;
		}
		if (wr == WAIT_TIMEOUT)
		{
			if (slice == 0) { printf("Wait timed out (10s)\n"); break; }
			continue;
		}
		if (wr == WAIT_FAILED)
		{
			printf("WaitForSingleObject failed: %u\n", GetLastError());
			break;
		}
	}

	// 线程结束后获取返回码
	{
		DWORD exitCode = 0;
		if (GetExitCodeThread(hRemoteThread, &exitCode))
			printf("Remote thread exited with code: %lu\n", (unsigned long)exitCode);
		else
			printf("GetExitCodeThread failed: %u\n", GetLastError());
	}

	// 最后再尝试完整读取参数结构
	{
		INJECTPARAM remoteParam; SIZE_T bytesRead = 0; RtlZeroMemory(&remoteParam, sizeof(remoteParam));
		if (ReadProcessMemory(TargetProcess, pRemoteParamAddr, &remoteParam, sizeof(remoteParam), &bytesRead) && bytesRead == sizeof(remoteParam))
		{
			printf("Remote dwRemoteStatus (final): %lu\n", (unsigned long)remoteParam.dwRemoteStatus);
		}
		else
		{
			DWORD err = GetLastError();
			printf("ReadProcessMemory for INJECTPARAM failed: %u\n", err);
			if (err == 299)
			{
				DWORD status2 = 0; SIZE_T br2 = 0;
				if (ReadProcessMemory(TargetProcess, (PBYTE)pRemoteParamAddr + offsetof(INJECTPARAM, dwRemoteStatus), &status2, sizeof(status2), &br2) && br2 == sizeof(status2))
				{
					printf("Partial read recovered dwRemoteStatus (final): %lu\n", (unsigned long)status2);
				}
			}
		}
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