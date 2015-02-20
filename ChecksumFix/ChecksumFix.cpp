#define WIN32_LEAN_AND_MEAN
#include <WINDOWS.H>
#include <shlwapi.h>

typedef PIMAGE_NT_HEADERS(WINAPI * CheckSumMappedFile_def)(PVOID BaseAddress, DWORD FileLength, PDWORD HeaderSum, PDWORD CheckSum);

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hFile;
	HANDLE hFileMap;
	LPVOID lpBaseAddress;
	DWORD dwSize;
	DWORD dwNewChecksum;
	DWORD dwOldChecksum;
	PIMAGE_DOS_HEADER pimgDosHeaders;
	PIMAGE_NT_HEADERS pimgNtHeaders;
	CheckSumMappedFile_def CheckSumMappedFile;
	int retval = 1;

	if(argc > 1)
	{
		if(PathFileExistsW(argv[1]))
		{
			hFile = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
			if(hFile != INVALID_HANDLE_VALUE)
			{
				hFileMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
				if(hFileMap)
				{
					lpBaseAddress = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
					if(lpBaseAddress)
					{
						pimgDosHeaders = PIMAGE_DOS_HEADER(lpBaseAddress);
						if(pimgDosHeaders->e_magic = IMAGE_DOS_SIGNATURE)
						{
							pimgNtHeaders = PIMAGE_NT_HEADERS(LPVOID(DWORD(lpBaseAddress) + pimgDosHeaders->e_lfanew));
							if (pimgNtHeaders->Signature == IMAGE_NT_SIGNATURE)
							{
								CheckSumMappedFile = CheckSumMappedFile_def(GetProcAddress(LoadLibraryW(TEXT("imagehlp.dll")), "CheckSumMappedFile"));
								if(CheckSumMappedFile)
								{
									CheckSumMappedFile(lpBaseAddress, dwSize, &dwOldChecksum, &dwNewChecksum);
									if(dwOldChecksum != dwNewChecksum)
									{
										pimgNtHeaders->OptionalHeader.CheckSum = dwNewChecksum;
										retval = 0;
									}
								}
							}
						}
						UnmapViewOfFile(lpBaseAddress);
					}
					CloseHandle(hFileMap);
				}
				CloseHandle(hFile);
			}
		}
	}
	return retval;
}
