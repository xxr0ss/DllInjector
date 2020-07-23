#pragma once
#include <Windows.h>

#define PEHEADER_SIZE (0x1000)
/* ~（Alignment - 1)就是用来给尾数清零，比如0x1000 => 0xF000
	Size 加上 (Alignment - 1)后再与一下，最后12bit 成为0x000了
*/
#define ALIGN_SIZE_UP(Size, Alignment) (((ULONG_PTR)(Size) + Alignment - 1) & ~(Alignment - 1))

#define MEM_OFFSET(EndAddr, StartAddr)((ULONG)((ULONG_PTR)EndAddr - (ULONG_PTR)StartAddr))


class CImage 
{
public:
	DWORD m_dwPageSize;
	HANDLE m_hFile;
	HANDLE m_hProc;
	WORD m_SectionCnt;

	PBYTE m_hModule; //TODO: 用于加载IMG的时候保存文件头指针 （好像指向MZ???)
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pNtHeaders;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER m_pOptHeader;
	PIMAGE_DATA_DIRECTORY m_pRelocTable;
	PIMAGE_SECTION_HEADER m_pSecHeader;
	PIMAGE_DATA_DIRECTORY m_pImpDataDir;
	PIMAGE_DATA_DIRECTORY m_pExpDataDir;
    PIMAGE_EXPORT_DIRECTORY m_pExportDir;
	PIMAGE_IMPORT_DESCRIPTOR m_pImportDesp; // 导入的每个DLL项都有一个IID
	IMAGE_DATA_DIRECTORY m_OldImpDir; // 保存原来的导入表，但是注入过程中其实不用

	ULONG_PTR m_dwEntryPoint;
	DWORD m_TotalImageSize;
	ULONG_PTR m_ImageBase;
	BYTE m_HeaderData[0x1000];//保存一份PE头的数据内部使用

	DWORD Rva2Raw(DWORD VirtualAddr);
    DWORD Raw2Rva(DWORD RawAddr);

	DWORD GetTotalImageSize(DWORD Alignment);
	DWORD GetAlignedSize(DWORD theSize, DWORD Alignment);
	ULONG_PTR GetAlignedPointer(ULONG_PTR uPointer, DWORD Alignment); // TODO: 这个干嘛的？
	static DWORD _GetProcAddress(PBYTE pModule, char* szFuncName); // TODO: 干嘛静态？以及这是干嘛的？

    PBYTE LoadImage(HANDLE hFile, BOOL bDoReloc = TRUE,ULONG_PTR RelocBase = 0,BOOL bDoImport = FALSE);
	PBYTE LoadImage(char *szPEPath,BOOL bDoReloc = TRUE,ULONG_PTR RelocBase = 0,BOOL bDoImport = FALSE);

    VOID FreePE();
    VOID InitializePEHeaders(PBYTE pBase);
    VOID ProcessRelocTable(ULONG_PTR RelocBase);
    BOOL ProcessImportTable();
    VOID AttachToMemory(PVOID pMemory);
	BOOL AttachToProcess(HANDLE hProc,PVOID ProcessImageBase);
    BOOL MakeFileHandleWritable();

    DWORD GetSectionPhysialPaddingSize(PIMAGE_SECTION_HEADER pSecHeader); // TODO: 这两个填充尺寸啥区别
	DWORD GetSectionVirtualPaddingSize(PIMAGE_SECTION_HEADER pSecHeader);

    // 定位节区
    PIMAGE_SECTION_HEADER LocateSectionByRawOffset(DWORD dwRawOffset);
	PIMAGE_SECTION_HEADER LocateSectionByRVA(DWORD dwTargetAddr);

    //操作节区
    PIMAGE_SECTION_HEADER AddNewSectionToFile(char *szSectionName,DWORD SectionSize);
	PIMAGE_SECTION_HEADER AddNewSectionToMemory(char *szSectionName,DWORD SectionSize);
    PIMAGE_SECTION_HEADER ExtraLastSectionSizeToFile(DWORD SectionAddSize); // 给文件最后一个节进行拓展

    // error相关
    VOID FormatErrorMsg(char *szPrompt, DWORD ErrCode);
	LPSTR GetErrorMsg(char *szBuf,int BufSize);

    CImage();
    virtual ~CImage(); //TODO: 为啥 virtual？
private:
    BOOL VerifyImage(PVOID pBase);
    BOOL SnapThunk(HMODULE hImpMode,char *szImpModeName,PBYTE ImageBase, PIMAGE_THUNK_DATA NameThunk, PIMAGE_THUNK_DATA AddrThunk);
	VOID Cleanup();
    char m_szErrorMsg[1024];
	char m_szPEPath[MAX_PATH];
};