#include <iostream>
#include <Windows.h>
#include <algorithm>
#include <cctype>
#include <locale>
#include <codecvt>
#include <csignal>
#include <cstdlib>
#include <conio.h>

#include "Utils.h"
#include <string>
#include <thread>


bool IsProcessPID(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](unsigned char c) { return std::isdigit(c); });
}

struct DumperSettings {
    std::string dumpFolder = "dumperDir";
    std::string dumperType = "search";
    std::string createFolderForEveryDump = "true";
    std::string dumpModules = "false";
    std::string showAdditionalLogs = "false";
    std::string noLog = "false";
    std::string startSettingsChanger = "true";
} settings;




void main()
{

    std::cout << "========= Settings: =========" << std::endl;
    std::cout << "(1) Dumps folder: " << settings.dumpFolder << std::endl;
    std::cout << "(2) Dumper type: " << settings.dumperType << std::endl;
    std::cout << "(3) Create folder for every dump: " << settings.createFolderForEveryDump << std::endl;
    std::cout << "(4) Dump process modules: " << settings.dumpModules << std::endl;
    std::cout << "(5) Show additional logs: " << settings.showAdditionalLogs << std::endl;
    std::cout << "(6) Disable logs: " << settings.noLog << std::endl;
    std::cout << "(7) Settings changer on start: " << settings.startSettingsChanger << std::endl;
    std::cout << "=============================\n" << std::endl;

    std::cout << "Enter pid or process name:" << std::endl;

    std::string process;
    std::cin >> process;

    DWORD procID = -1;
    
    if (IsProcessPID(process)) {
        if (process.length() > 8) {
            std::cout << "Too big length" << std::endl;
            system("pause");
            return;
        }
        procID = stoi(process);
    }
    else {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        std::wstring wprocess = converter.from_bytes(process);
        if (wprocess.find(L".exe") == std::string::npos) wprocess += L".exe";
        
        procID = GetProcessIdByName(wprocess.c_str());
    }

    if (procID == -1) {
        std::cout << "Process not found" << std::endl;
        system("pause");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, procID);
    if (hProcess == NULL) {
        std::cerr << "Error open process: " << GetLastError() << std::endl;
        system("pause");
        return;
    }

    uint64_t procBase = GetBaseAddress(procID);
    
    std::cout << process << " base address [" << std::hex << procBase << "]" << std::endl;

    FileInfo mainProcSize = GetFileSizeFromMZ(hProcess, procBase);

    std::vector<FileInfo> foundMZs = FindAllMZ(hProcess, procBase, mainProcSize.size);

    std::cout << "Dumped files: " << std::endl;

    std::string path = "C:\\Dumps";
    DumpAll(path, foundMZs, hProcess);

}
