#include "injection.h"
#include <stdio.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

BOOL InjByAddingNewSection(LPSTR targetFile, LPSTR dllname, LPSTR newSecName)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	BYTE HeaderBuffer[0x1000];
	BOOL result = FALSE;

	result = CreateProcessA(
		NULL,
		targetFile, // 假定目标文件这一项就是进程创建的commandline
		NULL,
		NULL,
		FALSE,
		//NOTE: 以挂起方式创建进程， 后面用到了ResumeThread
		CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi);
	if (!result)
	{
		printf("[-] 创建进程失败\n");
		return FALSE;
	}
	printf("[*] 已创建进程\n");

	CImage image;

	// 获取基址
	PBYTE imageBase = (PBYTE)FindImageBase(pi.hProcess, targetFile);
	if (imageBase == 0)
	{
		printf("[-] 无法找到进程映像基址\n");
		return FALSE;
	}
	printf("[*] 基地址 = 0x%p\n", imageBase);

	// 读取PE映像头部
	if (!image.AttachToProcess(pi.hProcess, imageBase))
	{
		printf("[*] 读取目标进程内存空间映像头部失败\n");
		return FALSE;
	}
	printf("[*] 读取映像头成功\n");
	DWORD oldIIDsSize = image.m_pImpDataDir->Size;
	DWORD oldIIDsCnt = oldIIDsSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD newIIDsCnt = oldIIDsCnt + 1;
	DWORD newIIDsSize = newIIDsCnt * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	printf("[*] 当前输入表信息：\n\tVA = 0x%p Size = 0x%X\n",
		image.m_pImpDataDir->VirtualAddress,
		oldIIDsSize);

	PIMAGE_SECTION_HEADER pImpSecHeader = image.LocateSectionByRVA(image.m_pImpDataDir->VirtualAddress);
	printf("[*] 输入表所在节: %s\tVA = 0x%X\tPointerToRawData = 0x%X\n",
		pImpSecHeader->Name,
		pImpSecHeader->VirtualAddress,
		pImpSecHeader->PointerToRawData);

	// TODO: 获取导入函数表，计算更准确的thunkDataSize
	char dllExpFunName[] = "Msg"; // NOTE: 偷了懒，其实最好要读取一下dll，读出dll导出表信息。这里暂且假定只有一个导出函数
	DWORD thunkDataSize = sizeof(ULONG_PTR) * 4 + sizeof(WORD) + strlen(dllExpFunName) + 1 + strlen(dllname) + 1;
	// thunkData是直接放在IID数组后面的，这里把新IID数组按ULONG_PTR对齐
	DWORD thunkDataOffsetFromNewIIDsEntry = ALIGN_SIZE_UP(newIIDsSize, sizeof(ULONG_PTR));
	DWORD newSecWriteSize = thunkDataOffsetFromNewIIDsEntry + thunkDataSize;

	// 根据计算出来的大小，给进程内存增加新Section
	PIMAGE_SECTION_HEADER newlyAddedSecHeader = image.AddNewSectionToMemory(newSecName, newSecWriteSize);
	printf("[*] 增加Section成功，Section VA = 0x%X V.Size=0x%X R.Size = 0x%X\n",
		newlyAddedSecHeader->VirtualAddress,
		newlyAddedSecHeader->Misc.VirtualSize,
		newlyAddedSecHeader->SizeOfRawData);

	// 开始构造要填入新Section的IIDs和注入的DLL的Thunk数据
	PBYTE secWriteBuffer = (PBYTE)calloc(1, newSecWriteSize);
	// 把原输入表读入缓冲区
	SIZE_T dwIoCnt;
	ReadProcessMemory(
		pi.hProcess,
		imageBase + image.m_pImpDataDir->VirtualAddress,
		secWriteBuffer,
		oldIIDsSize,
		&dwIoCnt);
	printf("[*] 读取原输入表到缓冲区成功，ReadSize = 0x%X\n", dwIoCnt);

	printf("[*] 开始构造Thunk数据\n");
	// 计算数据填充位置
	PULONG_PTR pOriginFirstThunk = (PULONG_PTR)(secWriteBuffer + thunkDataOffsetFromNewIIDsEntry);
	PULONG_PTR pFirstThunk = pOriginFirstThunk + 2;
	PIMAGE_IMPORT_BY_NAME pImpName = (PIMAGE_IMPORT_BY_NAME)(pFirstThunk + 2);
	PCHAR pDllName = (PCHAR)((PBYTE)pImpName + sizeof(WORD) + strlen(dllExpFunName) + 1);
	// 填充INT项和IAT项
	pOriginFirstThunk[0] = newlyAddedSecHeader->VirtualAddress + MEM_OFFSET(pImpName, secWriteBuffer);
	pFirstThunk[0] = pOriginFirstThunk[0];
	// 填充新IID项
	PIMAGE_IMPORT_DESCRIPTOR newIID = (PIMAGE_IMPORT_DESCRIPTOR)secWriteBuffer + oldIIDsCnt - 1;
	newIID->OriginalFirstThunk = newlyAddedSecHeader->VirtualAddress + MEM_OFFSET(pOriginFirstThunk, secWriteBuffer);
	newIID->FirstThunk = newlyAddedSecHeader->VirtualAddress + MEM_OFFSET(pFirstThunk, secWriteBuffer);
	newIID->Name = newlyAddedSecHeader->VirtualAddress + MEM_OFFSET(pDllName, secWriteBuffer);
	// 填充IMAGE_IMPORT_BY_NAME结构 和 dll名
	strncpy(pDllName, dllname, strlen(dllname));
	pImpName->Hint = 0;
	strncpy(pImpName->Name, dllExpFunName, strlen(dllExpFunName));


	// 更新image保存的pe结构信息，用于之后写回进程内存
	image.m_pImpDataDir->Size = newIIDsSize;
	image.m_pImpDataDir->VirtualAddress = newlyAddedSecHeader->VirtualAddress;

	image.m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	image.m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	printf("[*] PE头更新完毕，准备写入进程\n");

	DWORD oldProtect = 0;
	result = VirtualProtectEx(pi.hProcess, imageBase, image.m_pOptHeader->SizeOfHeaders, PAGE_READWRITE, &oldProtect);
	if (!result)
	{
		printf("[-] 无法修改目标进程内存 0x%p Size = 0x%X的内存属性 [%d]\n", imageBase, image.m_pOptHeader->SizeOfHeaders, GetLastError());
		return FALSE;
	}
	result = WriteProcessMemory(pi.hProcess, imageBase, image.m_HeaderData, image.m_pOptHeader->SizeOfHeaders, &dwIoCnt);
	if (!result)
	{
		printf("[-] 向目标进程内存写入修改头部数据失败\n");
		return FALSE;
	}
	VirtualProtectEx(pi.hProcess, imageBase, image.m_pOptHeader->SizeOfHeaders, oldProtect, &oldProtect);
	printf("[*] 已写入修改后的PE头\n");

	result = WriteProcessMemory(pi.hProcess, imageBase + newlyAddedSecHeader->VirtualAddress, secWriteBuffer, newSecWriteSize, &dwIoCnt);
	if (!result) {
		printf("[-] 向目标进程写入新输入表失败！%d\n", GetLastError());
		return FALSE;
	}
	printf("[*] 已写入新输入表\n");




	ResumeThread(pi.hThread);
	return TRUE;
}

ULONG_PTR FindImageBase(HANDLE hProc, LPSTR lpCommandLine)
{
	ULONG_PTR imgAddressFound = 0;
	BOOL bFoundMemImage = FALSE;
	SYSTEM_INFO sysinfo = { 0 };
	GetSystemInfo(&sysinfo);

	char imageFilePath[MAX_PATH] = { 0 };
	char* fileNameToCheck = strrchr(lpCommandLine, '\\');

	PBYTE pAddress = (PBYTE)sysinfo.lpMinimumApplicationAddress;
	while (pAddress < (PBYTE)sysinfo.lpMaximumApplicationAddress)
	{
		MEMORY_BASIC_INFORMATION mbi;
		ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
		SIZE_T dwSize = VirtualQueryEx(hProc, pAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)); // 获取相同属性内存页的信息
		if (dwSize == 0)
		{
			pAddress += sysinfo.dwPageSize;
			continue;
		}

		switch (mbi.State)
		{
		case MEM_FREE:
		case MEM_RESERVE:
			pAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			break;
		case MEM_COMMIT:
			if (mbi.Type == MEM_IMAGE)
			{
				if (GetMappedFileNameA(hProc, pAddress, imageFilePath, MAX_PATH) != 0)
				{
					if (_stricmp(strrchr(imageFilePath, '\\'), fileNameToCheck) == 0)
					{
						bFoundMemImage = TRUE;
						imgAddressFound = (ULONG_PTR)pAddress;
						break;
					}
				}
			}
			pAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
			break;
		default:
			break;
		}

		if (bFoundMemImage)
		{
			break;
		}
	}
	return imgAddressFound;
}