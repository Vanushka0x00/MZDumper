#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>

enum procType { Exe = 0, Dll = 1, Sys = 2, UnknownFile = 3 };

struct FileInfo {
	uint64_t addr;
	uint64_t size;
	procType PT = procType::UnknownFile;
};




extern DWORD GetProcessIdByName(const wchar_t* processName);

extern uintptr_t GetBaseAddress(DWORD processId);

extern FileInfo GetFileSizeFromMZ(HANDLE procHandle, uint64_t MZ_addr);

extern std::vector<FileInfo> FindAllMZ(HANDLE procHandle, uint64_t start_addr, uint64_t procSize);

extern void DumpAll(std::string& path, std::vector<FileInfo>& files, HANDLE hProcess);
