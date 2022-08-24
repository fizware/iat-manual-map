#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>

namespace Tool_Utilities
{
	DWORD GetProcId(const char* procName);
	uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName);
}