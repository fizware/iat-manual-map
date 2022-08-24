#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <io.h>
#include "injectormain.h"
#include "../Source/Injector_Main.h"
#include "../Tool_Utilities/Tool_Utilities.h"
#include "proc.h"
#include "mem.h"
#include "mmap.h"
#include "rand.h"
#include "seed.h"
#include "servcontrol.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <ostream>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <Winternl.h>
#include <fstream>
#include <future>
#include <filesystem>
#include <tuple>
#include <vector>
#include <memory>
#include <random>
#include <strsafe.h>

#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "urlmon.lib")

char output[50];
char* localPath;
size_t length;

uint32_t xor_key = 0xDEADBEEF;

inline void xor_buf(unsigned char* buf, int len)
{
	int i = 0;
	// Shift the 4 bytes in the key
	unsigned char k1 = xor_key & 0xff;
	unsigned char k2 = (xor_key >> 8) & 0xff;
	unsigned char k3 = (xor_key >> 16) & 0xff;
	unsigned char k4 = (xor_key >> 24) & 0xff;

	for (i = 0; i < len; i++)
	{
		buf[i] ^= k1;
		buf[i] ^= k2;
		buf[i] ^= k3;
		buf[i] ^= k4;
	}

	// Done.

	return;
}

DWORD retrieve_target_pid(void)
{
	return target_pid;
}


HANDLE retrieve_driver_handle(void)
{
	return driver_handle;
}


static BOOL _inject(uint8_t* buf, size_t buf_size, const char* target_lib, const char* target_func, const char* target_mod)
{
	inject_info map;

	map.imports.clear();

	map.type = KERNEL;
	map.target_lib = target_lib;
	map.target_func = target_func;
	map.buf = buf;
	map.buf_size = buf_size;
	map.target_mod = target_mod;

	return inject(&map, TRUE);
}


static BOOL install_cheat(uint8_t* target_lib, uint8_t* target_func, const char* target_proc, std::vector<uint8_t> dll)
{
	BOOL injstatus = FALSE;
	DWORD start_time = 0;
	BOOL timed_out = FALSE;

	std::cout << "Waiting for Proc.\n";

	start_time = GetTickCount();

	while (TRUE)
	{
		target_pid = retrieve_pid_via_name((const char*)target_proc);

		if (target_pid)
		{
			break;
		}

		Sleep(1000);

		if (GetTickCount() - start_time > 60)
		{
			timed_out = TRUE;
			break;
		}
	}

	if (timed_out)
	{
		return 2;
	}
	Beep(500, 600);
	std::cout << "Injecting..\n";
	printf("module -> %d\n", dll.size());
	injstatus = _inject(dll.data(), dll.size(), (const char*)target_lib, (const char*)target_func, (const char*)target_proc);

	return injstatus;
}

static void install_driver(void)
{

	return;
}

LPCSTR DllPath;
DWORD   ProcessId;
HANDLE hProcess;

void clear() {
	COORD topLeft = { 0, 0 };
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen;
	DWORD written;

	GetConsoleScreenBufferInfo(console, &screen);
	FillConsoleOutputCharacterA(
		console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	FillConsoleOutputAttribute(
		console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
		screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	SetConsoleCursorPosition(console, topLeft);
}

using namespace std;

static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int stringLengthh = sizeof(alphanum) - 1;

#include <iostream>
#include <fstream>
#include <filesystem>
#include "../Kdmapper/exports.h"
#include "xor.h"
char genRandomn()
{

	return alphanum[rand() % stringLengthh];
}
void Randomexe()
{
	srand(time(0));
	std::string Str;
	for (unsigned int i = 0; i < 130; ++i)
	{
		Str += genRandomn();

	}

	std::string rename = Str + ".exe";

	char filename[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH);
	if (size)


		std::filesystem::rename(filename, rename);
}

wchar_t* GetCurrentProcessImage() {
	static wchar_t fn[0x10000];
	if (!K32GetModuleFileNameExW(GetCurrentProcess(), (HMODULE)0, fn, sizeof(fn)))
		return (wchar_t*)L"None";
	else
		return fn;
}
bool IsWindowedSS()
{
	
	wchar_t* path = GetCurrentProcessImage();

	HANDLE res = CreateFileW(path, FILE_READ_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (res == INVALID_HANDLE_VALUE)
		return false;
	LARGE_INTEGER size;
	size.LowPart = GetFileSize(res, (LPDWORD)&size.HighPart);
	if (size.QuadPart < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
	{
		CloseHandle(res);
		return false;
	}
	DWORD dwsize;
	if (size.QuadPart < 0x1000)
		dwsize = (DWORD)size.QuadPart;
	else
		dwsize = 0x1000;
	PBYTE file = (PBYTE)malloc(dwsize);
	if (!file)
	{
		CloseHandle(res);
		return false;
	}
	DWORD bytes = 0;
	if (!ReadFile(res, file, dwsize, &bytes, nullptr) && bytes < dwsize)
	{
		CloseHandle(res);
		free(file);
		return false;
	}
	CloseHandle(res);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(file + dos->e_lfanew);
	bool windowed = (nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
	free(file);
	
	return windowed;
}

int loadcheat(std::vector<uint8_t> dll)
{
	
	BOOL status = FALSE;
	uint8_t* tar_dll, * tar_func, * tar_proc;

	if (IsWindowedSS)
	{
		AllocConsole();
		static_cast<VOID>(freopen("CONIN$", "r", stdin));
		static_cast<VOID>(freopen("CONOUT$", "w", stdout));
		static_cast<VOID>(freopen("CONOUT$", "w", stderr));

	}

	if (!check_active_driver())
	{

		install_driver();

		Sleep(5000);

		if (!check_active_driver())
		{
			return EXIT_FAILURE;
		}
	}

	clear_pid_cache();
	tar_dll = _unxor((uint8_t*)"\x49\x47\x50\x4c\x47\x4e\x11\x10\x0c\x46\x4e\x4e\x22", 13); // kernel32.dll
	tar_func = _unxor((uint8_t*)"\x71\x4e\x47\x47\x52\x22", 6); // Sleep

	status = install_cheat(tar_dll, tar_func, ProcName, dll);

	free(tar_dll);
	free(tar_func);

	if (status == 2)
	{
		// [-] Timed out waiting for game launch.
		std::cout << "Timed out waiting for game launch.\n";

	}

	if (status == FALSE)
	{
		// [-] Failed to inject the cheat.
		std::cout << "Failed to inject the cheat.\n";

	}

	if (status == TRUE)
	{
		// [+] Successfully injected the cheat.
		std::cout << "Successfully injected the cheat\n";
	}

	std::cout << " Exiting\n";

	Sleep(100);
	unhook_func();
	
	return TRUE;
	exit(0);
}
std::string ProcChoice;
bool enabledebug;

int main(const int argc, char** argv)
{
	SetConsoleTitle(rand_str(12).c_str());
	HWND console3 = GetConsoleWindow();
	ShowWindow(console3, TRUE); // This hides the console window. Set to FALSE if you want to hide it
	// Run ur own anti debugging checks here
	HWND console = GetConsoleWindow();
	RECT ConsoleRect;
	GetWindowRect(console, &ConsoleRect);
	MoveWindow(console, ConsoleRect.left, ConsoleRect.top, 600, 300, TRUE);
	// Run ur own anti debugging checks here as well

	const char* path = argv[1];
	system("CLS");

	std::cout << ("[+] Loading Driver") << std::endl;

	if (kdmappermain()) {

		Sleep(10);

		system("CLS");

		ProcChoice = ("ModernWarfare.exe");

		ProcName = ProcChoice.c_str();

		std::cout << ("[+] Injecting DLL") << std::endl;

		std::vector<uint8_t> dllbuffer;

		for (size_t i = 0; i < DLL_Length; i++)
			dllbuffer.push_back(((unsigned char*)DLL_Array)[i]);
		loadcheat(dllbuffer);
	}
	Sleep(5000);
	exit(0);
}