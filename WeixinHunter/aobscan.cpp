
#include "aobscan.h"
#include <iostream>
using namespace std;

typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

bool FHexCharValid(char c)
{
	if (c >= '0' && c <= '9' ||
		c >= 'A' && c <= 'F' ||
		c >= 'a' && c <= 'f' ||
		c == '?')
		return true;
	else
		return false;
}

bool FHexDecoder(char* Dec, char* Src)
{
	char HighC, LowC;
	DWORD dwSrcLen = strlen(Src) / 2;
	int i;
	for (i = 0; i < dwSrcLen; i++) {
		HighC = Src[i * 2], LowC = Src[i * 2 + 1];
		if (!FHexCharValid(LowC) || !FHexCharValid(HighC))
			return false;
		HighC -= '0';
		if (HighC > 9) HighC -= 7;
		if (HighC > 0xf) HighC -= 0x20;
		LowC -= '0';
		if (LowC > 9) LowC -= 7;
		if (LowC > 0xf) LowC -= 0x20;
		Dec[i] = (HighC << 4) | LowC;
	}
	return true;
}

namespace AobScan {
	//private: 注意，永远不要手动调用下面的函数
	std::vector <DWORD> FindSigX32(DWORD dwPid, const char* Value, ULONG64 Start = 0, ULONG64 End = 0);
	bool __SundayHexInit__(char* Sub, unsigned long*p, char* HexSub, unsigned long dwSubLen);
	ULONG64 __SundayHex__(char* Src, unsigned long dwSrcLen, char* Sub, DWORD* p, char* HexSub, DWORD dwSubLen);
	ULONG64 __SundayHexV__(char* Src, unsigned long dwSrcLen, char* Sub, DWORD* p, char* HexSub, DWORD dwSubLen, int v);
	std::vector<ULONG64> SundayHexV(char* Src, unsigned long dwSrcLen, char* Sub);
} // namespace AobScan

bool AobScan::__SundayHexInit__(char* Sub, DWORD*p, char* HexSub, unsigned long dwSubLen)
{
	if (!FHexDecoder(HexSub, Sub)) {
		return false;
	}
	ULONG64 i;

	for (i = 0; i < 0x100; i++) {
		p[i] = -1;
	}

	int WildAddr = 0;
	for (i = 0; i < dwSubLen; i++) {
		if (Sub[i * 2] == '?')
			WildAddr = i;
	}

	for (i = WildAddr + 1; i < dwSubLen; i++) {                     //扫描Sub，初始化 P 表
		p[(BYTE)HexSub[i]] = dwSubLen - i;
	}

	for (i = 0; i < 0x100; i++) {
		if (p[i] == -1)
			p[i] = dwSubLen - WildAddr;
	}
	return true;
}

ULONG64 AobScan::__SundayHex__(char* Src, unsigned long dwSrcLen, char* Sub, DWORD* p, char* HexSub, DWORD dwSubLen)
{
	//开始配对字符串
	//j为 Sub位置指标， k为 当前匹配位置
	ULONG64 j, k;
	j = dwSubLen - 1;                                   //初始化位置为 dwSubLen - 1,匹配顺序为从右到左

	bool bContinue = true;
	bool bSuccess;
	while (bContinue) {
		bSuccess = true;
		for (k = 0; k < dwSubLen; k++) {
			if (Sub[(dwSubLen - k - 1) * 2] != '?' && Src[j - k] != HexSub[dwSubLen - k - 1]) {
				bSuccess = false;
				break;
			}
		}
		if (bSuccess)
			bContinue = false;
		else {                                          //移动j指针
			if (j < dwSrcLen - 1)                                                        //防止j+1 >= dwSrcLen造成溢出
				j += p[(BYTE)Src[j + 1]];
			else j++;
		}
		if (j >= dwSrcLen)
			break;
	}
	if (j < dwSrcLen)
		return j - dwSubLen + 1;
	else
		return -1;
}

ULONG64 AobScan::__SundayHexV__(char* Src, unsigned long dwSrcLen, char* Sub, DWORD* p, char* HexSub, DWORD dwSubLen, int v)
{
	//开始配对字符串
	//j为 Sub位置指标， k为 当前匹配位置
	ULONG64 j, k;
	j = dwSubLen - 1 + v;                                   //初始化位置为 dwSubLen - 1,匹配顺序为从右到左

	bool bContinue = true;
	bool bSuccess;
	while (bContinue) {
		bSuccess = true;
		for (k = 0; k < dwSubLen; k++) {
			if (Sub[(dwSubLen - k - 1) * 2] != '?' && Src[j - k] != HexSub[dwSubLen - k - 1]) {
				bSuccess = false;
				break;
			}
		}
		if (bSuccess)
			bContinue = false;
		else {                                          //移动j指针
			if (j < dwSrcLen - 1)                                                        //防止j+1 >= dwSrcLen造成溢出
				j += p[(BYTE)Src[j + 1]];
			else j++;
		}
		if (j >= dwSrcLen)
			break;
	}
	if (j < dwSrcLen)
		return j - dwSubLen + 1;
	else
		return -1;

}
int AobScan::SundayHex(char* Src, unsigned long dwSrcLen, char* Sub)
{
	DWORD dwSubLen = strlen(Sub);
	if (dwSubLen % 2)                    //长度必须为2的倍数
		return -1;
	dwSubLen /= 2;

	char* HexSub = new char[dwSubLen + 1];
	DWORD* p = new DWORD[0x100];        //table P,标志距离
	int i = -1;

	if (AobScan::__SundayHexInit__(Sub, p, HexSub, dwSubLen)) {
		i = AobScan::__SundayHex__(Src, dwSrcLen, Sub, p, HexSub, dwSubLen);
	}

	delete[]p;
	delete[]HexSub;
	return i;
}

vector<ULONG64> AobScan::SundayHexV(char* Src, unsigned long dwSrcLen, char* Sub)
{
	vector<ULONG64> v;
	DWORD dwSubLen = strlen(Sub);

	if (dwSubLen % 2)                    //长度必须为2的倍数
		return v;
	dwSubLen /= 2;

	char* HexSub = new char[dwSubLen + 1];
	DWORD* p = new DWORD[0x100];        //table P,标志距离
	int i = -1;

	if (AobScan::__SundayHexInit__(Sub, p, HexSub, dwSubLen))
	{
		i = AobScan::__SundayHexV__(Src, dwSrcLen, Sub, p, HexSub, dwSubLen, 0);
		while (i != -1)
		{
			v.push_back(i);
			i = AobScan::__SundayHexV__(Src, dwSrcLen, Sub, p, HexSub, dwSubLen, i + dwSubLen);
		}
	}
	delete[]p;
	delete[]HexSub;
	return v;
}

#define  RESERVED_ADDRESS_X32  0x00327000
#define  SYSTEM_MEMORY_ADDRESS_X32 0x70000000
#define  SYSTEM_MEMORY_ADDRESS_X32_MAX 0x7FFFFFFF

// 定义区段上限,一般的区段大小不会超过
#define SECTION_SIZE_X32_MAX  0x0f000000

std::vector <DWORD> AobScan::FindSigX32(DWORD dwPid, const char* Value, ULONG64 Start, ULONG64 End)
{
	std::vector <DWORD> vFindResult;
	if (dwPid == 0)
		return vFindResult;
	if (Start < RESERVED_ADDRESS_X32)
		Start = RESERVED_ADDRESS_X32;
	if (End < 0)
		End = SYSTEM_MEMORY_ADDRESS_X32;
	if (Start >= End)
		return vFindResult;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);

	if (hProcess == NULL)
		return vFindResult;

	DWORD dwSectionSize = 0;
	MEMORY_BASIC_INFORMATION mem_info;
	while (VirtualQueryEx(hProcess, (LPCVOID)Start, &mem_info, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		if (mem_info.Protect != 16 && mem_info.RegionSize != 1 && mem_info.Protect != 512)
		{
			dwSectionSize = (DWORD)mem_info.BaseAddress + mem_info.RegionSize - Start;
			if (dwSectionSize > SECTION_SIZE_X32_MAX)
				break;
			char* buf = new char[dwSectionSize + 1];
			if (buf == NULL)
				break;
			if (ReadProcessMemory(hProcess, (LPCVOID)Start, buf, dwSectionSize, NULL))
			{
				vector<ULONG64>  dwValue = AobScan::SundayHexV(buf, dwSectionSize, (char*)Value);
				for (size_t i = 0; i < dwValue.size(); i++)
				{
					vFindResult.push_back(Start + dwValue[i]);
				}
			}
			delete[]buf;
		}
		if (End == 0)
			break;
		Start += mem_info.RegionSize;
		if (Start > SYSTEM_MEMORY_ADDRESS_X32)
			break;
		if (Start > End)
			break;
	}
	CloseHandle(hProcess);
	return vFindResult;
}

#ifdef X64_SUPPORT
// 支持64位程序
#include "../rewolf-wow64ext/src/wow64ext.h"
#ifdef _DEBUG
#pragma comment(lib,"../Debug/wow64ext.lib")
#else
#pragma comment(lib,"../Release/wow64ext.lib")
#endif // _DEBUG

#define KUSER_SHARED_DATA_ADDRESS_X64  0x07FFE0000
#define  SYSTEM_MEMORY_ADDRESS_X64 0x70000000000
#define  SYSTEM_MEMORY_ADDRESS_X64_MAX 0x7FFFFFFFFFFF
// 定义区段上限,一般的区段大小不会超过
#define SECTION_SIZE_X64_MAX  0x0f000000


// 虚拟地址空间
// https://docs.microsoft.com/zh-cn/windows-hardware/drivers/gettingstarted/virtual-address-spaces

std::vector <ULONG64> AobScan::FindSigX64(const char* Value, DWORD procID, ULONG64 Start, ULONG64 End)
{
	vector <ULONG64> vFindResult;
	if (Start < KUSER_SHARED_DATA_ADDRESS_X64)
		Start = KUSER_SHARED_DATA_ADDRESS_X64;
	if (End < 0)
		End = SYSTEM_MEMORY_ADDRESS_X64;
	if (Start >= End)
		return vFindResult;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (0 == hProcess)
		return vFindResult;

	ULONG64 dwSectionSize = 0;
	MEMORY_BASIC_INFORMATION64 mem_info = { 0 };
	while (VirtualQueryEx64(hProcess, Start, &mem_info, sizeof(mem_info)))
	{
		if (mem_info.Protect != 16 && mem_info.RegionSize != 1 && mem_info.Protect != 512)
		{
			dwSectionSize = (ULONG64)mem_info.BaseAddress + mem_info.RegionSize - Start;
			if (dwSectionSize > SECTION_SIZE_X64_MAX) 
			{
				Start = mem_info.BaseAddress + mem_info.RegionSize;
				if (Start > End)
					break;
				continue;
			}
			char* buf = new char[dwSectionSize + 1];
			memset(buf, 0, dwSectionSize + 1);
			if (buf == NULL)
				break;
			SIZE_T nNumberOfBytesRead = 0;
			if (ReadProcessMemory64(hProcess, Start, buf, dwSectionSize, &nNumberOfBytesRead))
			{
				vector<ULONG64> dwValue = AobScan::SundayHexV(buf, dwSectionSize, (char*)Value);
				for (size_t i = 0; i < dwValue.size(); i++)
				{
					vFindResult.push_back(Start + dwValue[i]);
				}
			}
			delete[] buf;
		}
		if (Start > End)
			break;
		Start += mem_info.RegionSize;
		if (Start > SYSTEM_MEMORY_ADDRESS_X64)
			break;
	}
	CloseHandle(hProcess);
	return vFindResult;
}
#endif // X64_SUPPORT
