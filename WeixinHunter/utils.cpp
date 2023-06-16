#include "utils.h"


void ShowError(char* msg) {
	printf("msg:%s\n",msg);
}

BOOL ReadProcessMem(DWORD dwProcessId, PVOID pAddress, PVOID pReadBuf, DWORD dwReadBufferSize)
{
	BOOL bRet = FALSE;
	DWORD dwRet = 0;
	// 根据PID, 打开进程获取进程句柄
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		ShowError("error when OpenProcess");
		return FALSE;
	}
	// 更改页面保护属性
	//DWORD dwOldProtect = 0;
	//bRet = ::VirtualProtectEx(hProcess, pAddress, dwReadBufferSize, PAGE_READWRITE, &dwOldProtect);
	//if (FALSE == bRet)
	//{
	//	ShowError("error when VirtualProtectEx");
	//	return FALSE;
	//}
	// 读取内存数据
	bRet = ::ReadProcessMemory(hProcess, pAddress, pReadBuf, dwReadBufferSize, &dwRet);
	if (FALSE == bRet)
	{
		ShowError("error when ReadProcessMemory");
		return FALSE;
	}
	// 还原页面保护属性
	//bRet = ::VirtualProtectEx(hProcess, pAddress, dwReadBufferSize, dwOldProtect, &dwOldProtect);
	//if (FALSE == bRet)
	//{
	//	ShowError("error when VirtualProtectEx");
	//	return FALSE;
	//}
	// 关闭进程句柄
	::CloseHandle(hProcess);

	return TRUE;
}

DWORD SUNDAY(DWORD PID, unsigned char* lpBaseBuf, unsigned char* pFindData, DWORD nFindDataSize, DWORD nMaxSize)
{
	BYTE* copyBuffer = new BYTE[nMaxSize];
	ReadProcessMem(PID, (PVOID)lpBaseBuf, copyBuffer, nMaxSize);

	size_t temp[256];
	size_t* shift = temp;
	size_t i, patt_size = nFindDataSize, text_size = nMaxSize;

	for (i = 0; i < 256; i++)
		*(shift + i) = patt_size + 1;

	for (i = 0; i < patt_size; i++)
		*(shift + unsigned char(*(pFindData + i))) = patt_size - i;
	size_t limit = text_size - patt_size + 1;
	for (i = 0; i < limit; i += shift[copyBuffer[i + patt_size]])
	{
		if (copyBuffer[i] == *pFindData)
		{
			unsigned char* match_text = copyBuffer + i + 1;
			size_t match_size = 1;
			do
			{
				if (match_size == patt_size)
				{
					delete[] copyBuffer;
					return (DWORD)lpBaseBuf + i;
				}
			} while ((*match_text++) == pFindData[match_size++]);
		}
	}
	delete[] copyBuffer;
	return NULL;
}

BOOL FindModule(DWORD pid, char* sz_Module, DWORD* pBase, DWORD* dwSize)
{
	bool bRet = false;
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 Module;
	BOOL ret;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnapshot)
	{
		Module.dwSize = sizeof(MODULEENTRY32);
		ret = Module32First(hSnapshot, &Module);
		while (ret)
		{
			if (stricmp(Module.szModule, sz_Module) == 0)
			{
				*(DWORD*)pBase = (DWORD)Module.modBaseAddr;
				*(DWORD*)dwSize = Module.modBaseSize;
				bRet = true;
				break;
			}
			ret = Module32Next(hSnapshot, &Module);
		}
		CloseHandle(hSnapshot);
		return bRet;
	}
	else
		return FALSE;
}

BOOL GetModuleInfo(DWORD dwPID, DWORD* pBase, DWORD* dwSize)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return(FALSE);
	}
	do
	{
		if (dwPID == me32.th32ProcessID)
		{
			*(DWORD*)pBase = (DWORD)me32.modBaseAddr;
			*(DWORD*)dwSize = me32.modBaseSize;

			CloseHandle(hModuleSnap);
			return TRUE;
		}
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
	return(FALSE);
}

DWORD GetProcessID(LPCTSTR lpProcessName)
{
	DWORD RetProcessID = 0;
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32* info = new PROCESSENTRY32;
	info->dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(handle, info))
	{
		if (_strcmpi(info->szExeFile, lpProcessName) == 0)
		{
			RetProcessID = info->th32ProcessID;
			return RetProcessID;
		}
		while (Process32Next(handle, info) != FALSE)
		{
			if (lstrcmpi(info->szExeFile, lpProcessName) == 0)
			{
				RetProcessID = info->th32ProcessID;
				return RetProcessID;
			}
		}
	}
	return RetProcessID;
}