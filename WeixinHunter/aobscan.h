#pragma once
#include <Windows.h>
#include <vector>
#include <Psapi.h>

//#define  X64_SUPPORT 1

namespace AobScan {

	//Sub均16进制代码，以0为结束。支持通配符?, 比如 "2F3C??4D5E",长度必须为2的倍数
	int SundayHex( char* Src, unsigned long dwSrcLen,  char* Sub);
	
	// 参数一：进程ID
	// 参数二：搜索关键字
	// 参数三: 开始搜索位置，为负时从RESERVED_ADDRESS_X32开始搜索
	// 参数四: 搜索结束位置，为负时从SYSTEM_MEMORY_ADDRESS_X32开始停止
	std::vector <DWORD> FindSigX32(DWORD dwPid, const char* Value, ULONG64 Start, ULONG64 End);

#ifdef X64_SUPPORT
	// 支持32位查找64位的线程
	// 参数一：进程ID
	// 参数二：搜索关键字
	// 参数三: 开始搜索位置，为负时从RESERVED_ADDRESS_X64开始搜索
	// 参数四: 搜索结束位置，为负时从SYSTEM_MEMORY_ADDRESS_X64开始停止
	std::vector <ULONG64> FindSigX64(const char* Value, DWORD procID,ULONG64 Start, ULONG64 End);
#endif // X64_SUPPORT
};