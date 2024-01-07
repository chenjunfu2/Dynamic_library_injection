#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

//二次转发，获取实际行数
#define ERR_PRINT(FUNC_NAME) _ERR_PRINT(FUNC_NAME)
#define _ERR_PRINT(FUNC_NAME) printf("[%s]Fail, GetLastError:%d, Line:%d\n", #FUNC_NAME, GetLastError(), __LINE__)

//获取某个权限
BOOL EnbalePrivileges(HANDLE hProcess, PCWCHAR pszPrivilegesName)
{
	// 打开进程令牌并获取进程令牌句柄
	HANDLE hToken = NULL;
	 BOOL bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (bRet == FALSE)
	{
		ERR_PRINT(OpenProcessToken);
		return FALSE;
	}

	// 获取本地系统的 pszPrivilegesName 特权的LUID值
	LUID luidValue = { 0 };
	bRet = LookupPrivilegeValueW(NULL, pszPrivilegesName, &luidValue);
	if (bRet == FALSE)
	{
		ERR_PRINT(LookupPrivilegeValueW);
		return FALSE;
	}

	// 设置提升权限信息
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 提升进程令牌访问权限
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);
	if (bRet == FALSE)
	{
		ERR_PRINT(AdjustTokenPrivileges);
		return FALSE;
	}

	// 根据错误码判断是否特权都设置成功
	DWORD dwRet = GetLastError();
	if (dwRet == ERROR_SUCCESS)
	{
		return TRUE;
	}
	else if (dwRet == ERROR_NOT_ALL_ASSIGNED)
	{
		ERR_PRINT(AdjustTokenPrivileges);
		return FALSE;
	}

	return FALSE;
}

//通过进程名（带后缀.exe）获取进程ID
BOOL GetProcessIDByPath(PCWCHAR pName, DWORD *pProcessID)
{
	if (pName == NULL || pProcessID == NULL)
	{
		return FALSE;
	}

	//做一个进程快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	//遍历快照找到名称匹配的第一个进程（有多个同名总是选择第一个）
	PROCESSENTRY32W pe = { sizeof(pe) };
	for (BOOL ret = Process32FirstW(hSnapshot, &pe); ret != FALSE; ret = Process32NextW(hSnapshot, &pe))
	{
		if (wcscmp(pe.szExeFile, pName) == 0)
		{
			*pProcessID = pe.th32ProcessID;//传出

			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	CloseHandle(hSnapshot);
	return FALSE;
}


BOOL IsDllLoad(PCWCHAR pDllPath, DWORD dwProcessID, HMODULE *pDllModule)
{
	if (pDllPath == NULL)
	{
		return FALSE;
	}

	//做一个进程内的模块快照
recall:
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_BAD_LENGTH)//MSDN文档说：出现此错误请重复调用直到成功
		{
			Sleep(0);
			goto recall;
		}

		return FALSE;
	}

	//遍历快照找到名称匹配的第一个模块（有多个同名总是选择第一个）
	MODULEENTRY32W md = { sizeof(md) };
	for (BOOL ret = Module32FirstW(hSnapshot, &md); ret != FALSE; ret = Module32NextW(hSnapshot, &md))
	{
		if (wcscmp(md.szExePath, pDllPath) == 0)
		{
			if (pDllModule != NULL)
			{
				*pDllModule = md.hModule;//传出
			}

			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	CloseHandle(hSnapshot);
	return FALSE;
}

int wmain(int argc, wchar_t *argv[])
{
	//通过命令行获取信息，第一个是dll路径，第二个是被注入进程的ID
	if (argc != 3)//3是因为要扣掉第0个自身路径
	{
		ERR_PRINT(arg count);
		printf("Use:\n\t[This EXE] [Dll Path] [Process ID/Name] To Call\n");
		return -1;
	}

	//获取dll路径
	const wchar_t *cpDllPath = argv[1];
	if (cpDllPath[0] == L'\0')
	{
		ERR_PRINT(Dll Path);
		return -1;
	}
	SIZE_T szDllNameSize = (wcslen(cpDllPath) + 1) * sizeof(*cpDllPath);//加1是为了保留末尾0字符

	//获取进程id
	DWORD dwProcessID;
	if (swscanf(argv[2], L"%ld", &dwProcessID) != 1)
	{
		//sscanf失败代表这个有可能是路径
		//通过快照匹配获取进程id
		if (GetProcessIDByPath(argv[2], &dwProcessID) == FALSE)
		{
			ERR_PRINT(Process ID/Name);
			return -1;
		}
	}

	//获得调试权限（提权）
	if (EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME) == FALSE)
	{
		ERR_PRINT(EnbalePrivileges);
		return -1;
	}

	//打开目标进程（请求所有权限，因为本进程具有SE_DEBUG_NAME权限所以此操作必定成功）
	//MSDN：如果调用方已启用 SeDebugPrivilege 特权，则无论安全描述符的内容如何，都会授予请求的访问权限。
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessID);
	if (hTargetProcess == NULL)
	{
		ERR_PRINT(OpenProcess);
		return -1;
	}

	//分配远程进程内存
	LPVOID pProcessMemory = VirtualAllocEx(hTargetProcess, 0, szDllNameSize, MEM_COMMIT, PAGE_READWRITE);
	if (pProcessMemory == NULL)
	{
		ERR_PRINT(VirtualAllocEx);
		return -1;
	}

	//写入dll路径
	SIZE_T szActualWriteSize;
	if (WriteProcessMemory(hTargetProcess, pProcessMemory, (LPVOID)cpDllPath, szDllNameSize, &szActualWriteSize) == FALSE ||
		szActualWriteSize != szDllNameSize)
	{
		ERR_PRINT(WriteProcessMemory);
		return -1;
	}

	//获得ZwCreateThreadEx函数地址
	HMODULE hNtDllMd = LoadLibraryW(L"ntdll.dll");//这里是加载模块，所以后面需要closehandle
	if (hNtDllMd == NULL)
	{
		ERR_PRINT(GetModuleHandleW);
		return -1;
	}

	//先定义一下ZwCreateThreadEx函数指针类型
	typedef DWORD(WINAPI *def_ZwCreateThreadEx)(//x64
		PHANDLE, 
		ACCESS_MASK, 
		LPVOID, 
		HANDLE, 
		LPTHREAD_START_ROUTINE, 
		LPVOID, 
		ULONG, 
		SIZE_T, 
		SIZE_T, 
		SIZE_T, 
		LPVOID);
#define STATUS_SUCCESS 0x0000

	def_ZwCreateThreadEx pZwCreateThreadEx = (def_ZwCreateThreadEx)GetProcAddress(hNtDllMd, "ZwCreateThreadEx");
	if (pZwCreateThreadEx == NULL)
	{
		ERR_PRINT(GetProcAddress);
		return -1;
	}

	//获得LoadLibraryW和FreeLibrary函数地址
	HMODULE hKernel32Md = GetModuleHandleW(L"kernel32.dll");//这里是获取已加载dll的模块句柄，无需closehandle
	if (hKernel32Md == NULL)
	{
		ERR_PRINT(GetModuleHandleW);
		return -1;
	}

	LPVOID pLoadLibraryW = GetProcAddress(hKernel32Md, "LoadLibraryW");
	if (pLoadLibraryW == NULL)
	{
		ERR_PRINT(GetProcAddress);
		return -1;
	}

	LPVOID pFreeLibrary = GetProcAddress(hKernel32Md, "FreeLibrary");
	if (pFreeLibrary == NULL)
	{
		ERR_PRINT(GetProcAddress);
		return -1;
	}

	//启动远程线程加载dll
	HANDLE hTargetThread = NULL;
	DWORD dwStatus = pZwCreateThreadEx(&hTargetThread, PROCESS_ALL_ACCESS, NULL, hTargetProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pProcessMemory, 0, 0, 0, 0, NULL);
	if (hTargetThread == NULL || dwStatus != STATUS_SUCCESS)
	{
		ERR_PRINT(ZwCreateThreadEx);
		return -1;
	}

	//等待函数退出
	WaitForSingleObject(hTargetThread, INFINITE);

	//查看模块是否载入
	HMODULE hTargetDll = NULL;//目标dll在目标进程内的句柄
	if (IsDllLoad(cpDllPath, dwProcessID, &hTargetDll))
	{
		printf("Injection Success.\n");
	}
	else
	{
		printf("Injection Unsuccess.\n");
	}

	//获取线程退出码
	DWORD hTargetThreadExitCode = 0;
	if (GetExitCodeThread(hTargetThread, &hTargetThreadExitCode) == FALSE)
	{
		ERR_PRINT(GetExitCodeThread);
		return -1;
	}

	//关闭远程线程句柄
	CloseHandle(hTargetThread);

	printf("LoadLibrary Thread Exit, Code:%d\n", hTargetThreadExitCode);

	putchar('\n');
	system("pause");//暂停
	putchar('\n');

	//让远程进程卸载dll
	if (hTargetDll != NULL)
	{
		//启动远程线程释放dll
		HANDLE hTargetThread = NULL;
		DWORD dwStatus = pZwCreateThreadEx(&hTargetThread, PROCESS_ALL_ACCESS, NULL, hTargetProcess, (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hTargetDll, 0, 0, 0, 0, NULL);
		if (hTargetThread == NULL || dwStatus != STATUS_SUCCESS)
		{
			ERR_PRINT(ZwCreateThreadEx);
			return -1;
		}

		//等待函数退出
		WaitForSingleObject(hTargetThread, INFINITE);

		//查看模块是否卸载
		if (!IsDllLoad(cpDllPath, dwProcessID, NULL))
		{
			printf("Unload Success.\n");
		}
		else
		{
			printf("Unload Unsuccess.\n");
		}

		//获取线程退出码
		DWORD hTargetThreadExitCode = 0;
		if (GetExitCodeThread(hTargetThread, &hTargetThreadExitCode) == FALSE)
		{
			ERR_PRINT(GetExitCodeThread);
			return -1;
		}

		//关闭远程线程句柄
		CloseHandle(hTargetThread);

		printf("FreeLibrary Thread Exit, Code:%d\n", hTargetThreadExitCode);
	}

	//释放远程进程内存
	if (VirtualFreeEx(hTargetProcess, pProcessMemory, 0, MEM_RELEASE) == FALSE)
	{
		ERR_PRINT(VirtualFreeEx);
		return -1;
	}
	
	//关闭远程进程句柄
	CloseHandle(hTargetProcess);
	//关闭ntdll.dll
	CloseHandle(hNtDllMd);

	//安全退出
	return 0;
}