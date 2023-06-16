#pragma once

#include <Windows.h>
#include <Winbase.h>
#include <iostream>
#include <Tlhelp32.h>

DWORD SUNDAY(DWORD PID, unsigned char* lpBaseBuf, unsigned char* pFindData, DWORD nFindDataSize, DWORD nMaxSize);
BOOL FindModule(DWORD pid, char* sz_Module, DWORD* pBase, DWORD* dwSize);
BOOL GetModuleInfo(DWORD dwPID, DWORD* pBase, DWORD* dwSize);
BOOL ReadProcessMem(DWORD dwProcessId, PVOID pAddress, PVOID pReadBuf, DWORD dwReadBufferSize);
DWORD GetProcessID(LPCTSTR lpProcessName);