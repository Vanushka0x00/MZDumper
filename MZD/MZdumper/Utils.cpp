#include "Utils.h"
#include <fstream>
#include <string>
#include <Psapi.h>
#include <iomanip>
#include <sstream>

uintptr_t GetBaseAddress(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Error Create Toolhelp Snapshot: " << GetLastError() << std::endl;
        system("pause");
        return 0;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            if (moduleEntry.th32ProcessID == processId) {
                CloseHandle(hSnapshot);
                return reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
            }
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return -1;
}

FileInfo GetFileSizeFromMZ(HANDLE procHandle, uint64_t MZ_addr) {
    
        IMAGE_DOS_HEADER dosHeader;
        SIZE_T size;
        ReadProcessMemory(procHandle, (LPCVOID)MZ_addr, &dosHeader, sizeof(IMAGE_DOS_HEADER), &size);

        IMAGE_NT_HEADERS ntHeaders;
        ReadProcessMemory(procHandle, (LPCVOID)(MZ_addr + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), &size);

        size_t fileSize = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);

        unsigned char buf[0x500] = { 0 };
        PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
        ReadProcessMemory(procHandle, (LPCVOID)(MZ_addr + dosHeader.e_lfanew), dhead, 0x500, &size);

        PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);

        
        DWORD maxOffset = 0;
        for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
            printf("Section name: %-8s   PhysMem: %x   PhysSize: %x\n", Section->Name, Section->PointerToRawData, Section->SizeOfRawData);
            if (maxOffset < Section->PointerToRawData + Section->SizeOfRawData)
                maxOffset = Section->PointerToRawData + Section->SizeOfRawData;
            Section++;
        }


        FileInfo res = { MZ_addr, maxOffset, procType::UnknownFile };

        WORD characteristics = ntHeaders.FileHeader.Characteristics;
        if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
            if (characteristics & IMAGE_FILE_DLL) {
                std::cout << std::hex << MZ_addr << "(.dll)" << std::endl;
                res.PT = procType::Dll;
            }
            else if (characteristics & IMAGE_FILE_SYSTEM || characteristics & IMAGE_SUBSYSTEM_NATIVE) {
                std::cout << std::hex << MZ_addr << "(.sys)" << std::endl;
                res.PT = procType::Sys;
            }
            else {
                std::cout << std::hex << MZ_addr << " (.exe)" << std::endl;
                res.PT = procType::Exe;
            }
        }
        else {
            std::cout << std::hex << MZ_addr << "Unknown" << std::endl;
            res.PT = procType::UnknownFile;
        }
        std::cout << std::hex << res.addr << " " << res.size << std::endl;
        return res;
    

}


std::vector<FileInfo> FindAllMZ(HANDLE procHandle, uint64_t start_addr, uint64_t procSize) {
    std::cout << "What found:" << std::endl;

    std::vector<FileInfo> res;

    MEMORY_BASIC_INFORMATION mbi;

    SIZE_T numBytes = 0;
    LONGLONG pageStart = 0;

    do
    {
        memset(&mbi, 0, sizeof(mbi));
        numBytes = VirtualQueryEx(procHandle, (LPVOID)pageStart, &mbi, sizeof(mbi));
        if (mbi.State != MEM_FREE)
        {
            
          //  std::cout << std::hex << (LONGLONG)mbi.BaseAddress << " SIZE: " << mbi.RegionSize << std::endl;

            uint64_t addr = (LONGLONG)mbi.BaseAddress;
            while(addr < (LONGLONG)mbi.BaseAddress + mbi.RegionSize){
                if (mbi.RegionSize > 0x1000000)
                    break;
                SIZE_T size;
                short mzFind;
                ReadProcessMemory(procHandle, (LPCVOID)addr, &mzFind, 2, &size);

                if (mzFind == 0x5A4D) {
                    IMAGE_DOS_HEADER dosHeader;
                    SIZE_T size;
                    ReadProcessMemory(procHandle, (LPCVOID)addr, &dosHeader, sizeof(IMAGE_DOS_HEADER), &size);



                    if ((unsigned long)dosHeader.e_lfanew > 1000) {
                        addr += 2;
                        continue;
                    }

                    unsigned char buf[0x500] = { 0 };
                    PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
                    ReadProcessMemory(procHandle, (LPCVOID)(addr), dhead, 0x500, &size);
                    PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
                    if(nthead->FileHeader.NumberOfSections > 20) {
                        addr += 2;
                        continue;
                    }
                    short peFind;
                    ReadProcessMemory(procHandle, (LPCVOID)(addr + dosHeader.e_lfanew), &peFind, 2, &size);
                    if (peFind == 0x4550) {
                        res.push_back(GetFileSizeFromMZ(procHandle, addr));
                    }
                }

                addr++;
            }

        }
        pageStart = (LONGLONG)mbi.BaseAddress + mbi.RegionSize;
        
    } while (numBytes);

    return res;
}

std::string longLongToHex(long long value) {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}

void DumpAll(std::string& path, std::vector<FileInfo>& files, HANDLE hProcess) {
    for (size_t i = 0; i < files.size(); ++i) {
        std::string formats[] = { ".exe", ".dll", ".sys", ".bin" };
        std::string fileName = path + longLongToHex((long long)files[i].addr) + formats[files[i].PT];

        std::ofstream outputFile(fileName, std::ios::binary);
        if (!outputFile.is_open()) {
            std::cerr << "error open file " << fileName << " for write: "  << std::endl;
            continue;
        }

        char* buffer = new char[files[i].size];
        if (!buffer) {
            std::cerr << "Alloc error" << std::endl;
        }

        SIZE_T bytesRead;
        SIZE_T s = files[i].size;
        if (ReadProcessMemory(hProcess, (LPCVOID)files[i].addr, (LPVOID)buffer, s, &bytesRead)) {
            outputFile.write(static_cast<const char*>(buffer), bytesRead);
            std::cout << "File " << fileName << " created." << std::endl;
        }
        else {
            std::cerr << "Cant read process memory: " << std::hex << files[i].addr << std::endl;
        }

        delete[] buffer;
        
        outputFile.close();
    }
    CloseHandle(hProcess);
}