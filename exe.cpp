// exe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <wchar.h>
#include "injectdll.hpp"

// Get ProcessId By Name (wide-char aware)
std::uint32_t GetProcessId(__in const std::basic_string<wchar_t>& Name)
{
    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    auto ProcessSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32FirstW(ProcessSnapshot, &ProcessEntry))
    {
        do
        {
            if (wcscmp(ProcessEntry.szExeFile, Name.c_str()) == 0)
            {
                CloseHandle(ProcessSnapshot);
                return ProcessEntry.th32ProcessID;
            }
        } while (Process32NextW(ProcessSnapshot, &ProcessEntry));
    }
    CloseHandle(ProcessSnapshot);
    return 0;
}

void AdjustPrivileges()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES priv = { 0 };

    // 提权操作：获取当前进程的访问令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return; // 获取令牌失败，直接返回
    }

    // 设置特权属性
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // 查找并启用调试特权（SE_DEBUG_NAME）
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
    {
        AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
    }

    // 清理资源
    CloseHandle(hToken);
}


int main()
{
    AdjustPrivileges();
    // 假设已经定义了GetProcessId函数和InjectDll类
    auto DwmPID = GetProcessId(L"dwm.exe");
    auto hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        DwmPID
    );

    printf("DwmPID:%d\r\n", DwmPID);

    Injectdll inject_dll;
    inject_dll.RemoteMapLoadDll(hProcess);
    std::cout << "Hello World!\n";

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
